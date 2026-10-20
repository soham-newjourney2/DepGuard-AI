import logging

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException

log = logging.getLogger("depguard")


class AppError(Exception):
    def __init__(self, code: str, message: str, hint: str = "", status: int = 400,
                 headers: dict[str, str] | None = None, options: list[str] | None = None):
        super().__init__(message)
        self.code, self.message, self.hint, self.status = code, message, hint, status
        self.headers = headers
        self.options = options


def envelope(code: str, message: str, hint: str, status: int,
             headers: dict[str, str] | None = None,
             options: list[str] | None = None) -> JSONResponse:
    error = {"code": code, "message": message, "hint": hint}
    if options:
        error["options"] = options
    return JSONResponse({"error": error}, status, headers=headers)


HTTP_CODES = {404: "E_NOT_FOUND", 405: "E_METHOD", 413: "E_TOO_LARGE", 429: "E_RATE_LIMIT"}


def install(app: FastAPI) -> None:
    @app.exception_handler(AppError)
    async def _app(_: Request, exc: AppError):
        return envelope(exc.code, exc.message, exc.hint, exc.status, exc.headers,
                        exc.options)

    @app.exception_handler(HTTPException)
    async def _http(_: Request, exc: HTTPException):
        code = HTTP_CODES.get(exc.status_code, "E_HTTP")
        return envelope(code, str(exc.detail), "", exc.status_code)

    @app.exception_handler(RequestValidationError)
    async def _invalid(_: Request, exc: RequestValidationError):
        first = exc.errors()[0] if exc.errors() else {}
        where = ".".join(str(p) for p in first.get("loc", ()))
        return envelope("E_INVALID", f"{where}: {first.get('msg', 'invalid request')}",
                        "Check the request parameters.", 422)

    @app.exception_handler(Exception)
    async def _crash(_: Request, exc: Exception):
        log.exception("unhandled error", exc_info=exc)
        return envelope("E_INTERNAL", "Internal error.", "Retry; if it persists, report it.", 500)
