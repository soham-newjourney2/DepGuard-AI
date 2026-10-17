import mimetypes

from fastapi import APIRouter, FastAPI
from fastapi.staticfiles import StaticFiles

from app import __version__, errors
from app.config import Settings, get_settings
from app.security import SecurityHeaders

for _ext, _type in {".js": "text/javascript", ".css": "text/css", ".svg": "image/svg+xml",
                    ".woff2": "font/woff2"}.items():
    mimetypes.add_type(_type, _ext)


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or get_settings()
    app = FastAPI(title="DepGuard AI", version=__version__, docs_url=None, redoc_url=None,
                  openapi_url="/api/openapi.json")
    app.state.settings = settings
    errors.install(app)

    api = APIRouter(prefix="/api")

    @api.get("/health")
    def health() -> dict:
        return {"status": "ok", "version": __version__, "scanner": settings.scanner,
                "ai": settings.ai_effective, "verify_mode": settings.verify_mode}

    app.include_router(api)
    if settings.frontend_dir.is_dir():
        app.mount("/", StaticFiles(directory=settings.frontend_dir, html=True), name="static")
    app.add_middleware(SecurityHeaders)
    return app


app = create_app()
