"""Structured JSON errors:  {"error": {"code", "message", "details"}}"""
from __future__ import annotations

import logging
from typing import Any

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from sqlalchemy.exc import IntegrityError
from starlette.exceptions import HTTPException as StarletteHTTPException

from ..validators import ValidationError

log = logging.getLogger("nmp.api")


class ApiError(Exception):
    def __init__(self, status: int, code: str, message: str, details: Any = None):
        super().__init__(message)
        self.status = status
        self.code = code
        self.message = message
        self.details = details


def error_body(code: str, message: str, details: Any = None) -> dict:
    return {"error": {"code": code, "message": message, "details": details}}


def install_handlers(app: FastAPI) -> None:
    @app.exception_handler(ApiError)
    async def _api(_: Request, exc: ApiError):
        return JSONResponse(error_body(exc.code, exc.message, exc.details), status_code=exc.status)

    @app.exception_handler(ValidationError)
    async def _val(_: Request, exc: ValidationError):
        return JSONResponse(error_body("validation_error", "Invalid input",
                                       [{"field": exc.field, "message": exc.message}]), status_code=422)

    @app.exception_handler(RequestValidationError)
    async def _req(_: Request, exc: RequestValidationError):
        details = []
        for e in exc.errors():
            loc = ".".join(str(x) for x in e.get("loc", []) if x not in ("body", "query", "path"))
            msg = e.get("msg", "invalid")
            ctx = e.get("ctx") or {}
            if isinstance(ctx.get("error"), ValidationError):
                msg = ctx["error"].message
            elif msg.startswith("Value error, "):
                msg = msg[len("Value error, "):]
            details.append({"field": loc, "message": msg})
        return JSONResponse(error_body("validation_error", "Invalid input", details), status_code=422)

    @app.exception_handler(IntegrityError)
    async def _integrity(_: Request, exc: IntegrityError):
        msg = str(exc.orig) if exc.orig else "constraint violation"
        if "Duplicate entry" in msg or "UNIQUE" in msg.upper():
            return JSONResponse(error_body("conflict", "An object with the same unique name already exists"), status_code=409)
        if "foreign key" in msg.lower():
            return JSONResponse(error_body("conflict", "The object is referenced by other objects"), status_code=409)
        log.exception("integrity error")
        return JSONResponse(error_body("conflict", "Database constraint violation"), status_code=409)

    @app.exception_handler(StarletteHTTPException)
    async def _http(_: Request, exc: StarletteHTTPException):
        code = {404: "not_found", 405: "method_not_allowed", 401: "unauthenticated", 403: "forbidden"}.get(exc.status_code, "http_error")
        return JSONResponse(error_body(code, str(exc.detail)), status_code=exc.status_code)

    @app.exception_handler(Exception)
    async def _any(_: Request, exc: Exception):
        log.exception("unhandled error: %s", type(exc).__name__)
        return JSONResponse(error_body("internal_error", "An internal error occurred. See error.log."), status_code=500)
