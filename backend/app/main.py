import asyncio
import contextlib
import logging
import mimetypes
from contextlib import asynccontextmanager

from fastapi import APIRouter, FastAPI
from fastapi.staticfiles import StaticFiles
from starlette.middleware.gzip import GZipMiddleware
from starlette.routing import Match, Mount

from app import __version__, ai, errors
from app.config import Settings, get_settings
from app.jobs import EventHub, JobStore, release_job
from app.risks import typosquat
from app.routes import findings as findings_routes
from app.routes import graph as graph_routes
from app.routes import jobs as jobs_routes
from app.routes import report as report_routes
from app.routes import risks as risks_routes
from app.routes import verify as verify_routes
from app.security import BodyLimit, CacheHeaders, RateLimiter, SecurityHeaders

log = logging.getLogger("depguard")

for _ext, _type in {".js": "text/javascript", ".css": "text/css", ".svg": "image/svg+xml",
                    ".woff2": "font/woff2"}.items():
    mimetypes.add_type(_type, _ext)


class FrontendMount(Mount):
    """Static mount that never claims /api paths, so the router answers 404/405 as JSON."""

    def matches(self, scope):
        path = scope.get("path", "")
        if path == "/api" or path.startswith("/api/"):
            return Match.NONE, {}
        return super().matches(scope)


async def cleanup_loop(app: FastAPI) -> None:
    state = app.state
    while True:
        await asyncio.sleep(state.settings.cleanup_interval_s)
        try:
            for job_id in await asyncio.to_thread(state.store.purge_expired):
                release_job(state, job_id)
            await asyncio.to_thread(state.store.sweep_orphans)
        except Exception:
            log.exception("cleanup failed")


@asynccontextmanager
async def lifespan(app: FastAPI):
    state = app.state
    state.store = JobStore(state.settings.data_dir, state.settings.job_ttl_min)
    state.hub = EventHub()
    state.hub.bind(asyncio.get_running_loop())
    state.store.subscribe(state.hub.publish)
    state.tasks = {}
    state.verify_sem = asyncio.Semaphore(1)
    state.store.recover()
    state.store.purge_expired()
    cleaner = asyncio.create_task(cleanup_loop(app))
    warm = asyncio.create_task(asyncio.to_thread(typosquat.warm))
    try:
        yield
    finally:
        for task in [cleaner, warm, *state.tasks.values()]:
            task.cancel()
        for task in [cleaner, warm, *state.tasks.values()]:
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await task
        state.store.close()


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or get_settings()
    app = FastAPI(title="DepGuard AI", version=__version__, docs_url=None, redoc_url=None,
                  openapi_url="/api/openapi.json", lifespan=lifespan)
    app.state.settings = settings
    app.state.limiter = RateLimiter(settings.rate_limit)
    errors.install(app)

    api = APIRouter(prefix="/api")

    @api.get("/health")
    def health() -> dict:
        return {"status": "ok", "version": __version__, "scanner": settings.scanner,
                "ai": ai.ENGINE, "verify_mode": settings.verify_mode,
                "max_upload_mb": settings.max_upload_mb, "local_only": settings.local_only}

    app.include_router(api)
    app.include_router(jobs_routes.router)
    app.include_router(findings_routes.router)
    app.include_router(graph_routes.router)
    app.include_router(verify_routes.router)
    app.include_router(report_routes.router)
    app.include_router(risks_routes.router)
    if settings.frontend_dir.is_dir():
        app.router.routes.append(FrontendMount(
            "/", StaticFiles(directory=settings.frontend_dir, html=True), name="static"))
    app.add_middleware(BodyLimit,
                       upload_limit=settings.max_upload_mb * 1024 * 1024 + 64 * 1024)
    app.add_middleware(CacheHeaders)
    app.add_middleware(GZipMiddleware, minimum_size=1024)
    app.add_middleware(SecurityHeaders)
    return app


app = create_app()
