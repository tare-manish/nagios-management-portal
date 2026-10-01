"""FastAPI application factory."""
from __future__ import annotations

import logging
from pathlib import Path

from fastapi import Depends, FastAPI, Request
from fastapi.openapi.docs import get_swagger_ui_html
from fastapi.responses import FileResponse, JSONResponse
from sqlalchemy import text
from starlette.middleware.base import BaseHTTPMiddleware

from . import __version__
from .api.deps import Principal, client_ip, get_principal
from .api.errors import error_body, install_handlers
from .api.routers import admin, auth, catalog, config, maintenance, monitoring, notifications, reports, servers
from .config import get_settings
from .db import SessionLocal
from .logging_setup import setup_logging
from .security.sessions import SlidingWindowLimiter

log = logging.getLogger("nmp.api")

MAX_BODY = 2 * 1024 * 1024

CSP = ("default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; "
       "font-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'; "
       "object-src 'none'")


class SecurityMiddleware(BaseHTTPMiddleware):
    def __init__(self, app, limiter: SlidingWindowLimiter):
        super().__init__(app)
        self.limiter = limiter

    async def dispatch(self, request: Request, call_next):
        if request.url.path.startswith("/api/"):
            cl = request.headers.get("content-length")
            if cl and cl.isdigit() and int(cl) > MAX_BODY:
                return JSONResponse(error_body("payload_too_large", "Request body too large"), status_code=413)
            if not self.limiter.allow(client_ip(request)):
                return JSONResponse(error_body("rate_limited", "Too many requests"), status_code=429,
                                    headers={"Retry-After": "30"})
            origin = request.headers.get("origin")
            allowed = get_settings().allowed_origins
            if origin and request.method not in ("GET", "HEAD", "OPTIONS"):
                host_origin = f"{request.url.scheme}://{request.headers.get('host', '')}"
                fwd = request.headers.get("x-forwarded-proto")
                candidates = {host_origin, f"{fwd}://{request.headers.get('host', '')}" if fwd else host_origin}
                if origin not in candidates and origin not in allowed:
                    return JSONResponse(error_body("bad_origin", "Cross-origin request rejected"), status_code=403)
        response = await call_next(request)
        h = response.headers
        h.setdefault("X-Content-Type-Options", "nosniff")
        h.setdefault("X-Frame-Options", "DENY")
        h.setdefault("Referrer-Policy", "no-referrer")
        h.setdefault("Permissions-Policy", "geolocation=(), camera=(), microphone=()")
        h.setdefault("Cross-Origin-Opener-Policy", "same-origin")
        if request.url.path.startswith("/api/"):
            h.setdefault("Cache-Control", "no-store")
            if request.url.path != "/api/docs":
                h.setdefault("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
        else:
            h.setdefault("Content-Security-Policy", CSP)
        return response


def create_app() -> FastAPI:
    setup_logging()
    s = get_settings()
    app = FastAPI(title="Nagios Management Portal API", version=__version__, docs_url=None, redoc_url=None,
                  openapi_url=None)
    install_handlers(app)
    app.add_middleware(SecurityMiddleware, limiter=SlidingWindowLimiter(s.api_rate_limit_per_minute))
    for r in (auth.router, servers.router, config.router, config.backups_router, config.import_router,
              catalog.router, monitoring.router, reports.router, admin.router, notifications.router, maintenance.router):
        app.include_router(r)

    @app.get("/api/healthz", include_in_schema=False)
    def healthz():
        try:
            with SessionLocal() as db:
                db.execute(text("SELECT 1"))
            return {"status": "ok"}
        except Exception:
            return JSONResponse({"status": "db_error"}, status_code=503)

    if s.enable_api_docs:
        @app.get("/api/openapi.json", include_in_schema=False)
        def openapi(principal: Principal = Depends(get_principal)):
            return app.openapi()

        @app.get("/api/docs", include_in_schema=False)
        def docs(principal: Principal = Depends(get_principal)):
            return get_swagger_ui_html(openapi_url="/api/openapi.json", title="Nagios Management Portal API")

    dist = Path(s.frontend_dist)
    if dist.is_dir():  # Apache normally serves the SPA; this is for development / direct access
        @app.get("/{full_path:path}", include_in_schema=False)
        def spa(full_path: str):
            if full_path.startswith("api/"):
                return JSONResponse(error_body("not_found", "Not found"), status_code=404)
            target = (dist / full_path).resolve()
            if full_path and target.is_file() and dist.resolve() in target.parents:
                return FileResponse(target)
            return FileResponse(dist / "index.html")

    return app


app = create_app()
