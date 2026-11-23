"""Punto de entrada FastAPI de IncidentAnalyzer."""
from __future__ import annotations

import logging
import re
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from starlette.exceptions import HTTPException as StarletteHTTPException

from app import settings
from app.api import core, intel, report
from app.i18n import request_lang, tr
from app.session import store

# Nunca se loguea contenido de celdas: solo conteos, IDs y tiempos.
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
logging.getLogger("httpx").setLevel(logging.WARNING)  # no registrar URLs de consultas externas

_SESSION_PATH = re.compile(r"^/api/sessions/([A-Za-z0-9_-]+)/")

app = FastAPI(title="IncidentAnalyzer", version="1.0.0", docs_url="/api/docs", openapi_url="/api/openapi.json")
app.add_middleware(CORSMiddleware, allow_origins=settings.CORS_ORIGINS, allow_credentials=False,
                   allow_methods=["GET", "POST", "PUT", "DELETE"], allow_headers=["Content-Type", "Accept-Language"])


@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    # guardado automático: cada cambio exitoso en una sesión se persiste (cifrado) para no perder el trabajo
    if request.method in ("POST", "PUT") and response.status_code < 400:
        m = _SESSION_PATH.match(request.url.path)
        if m:
            store.persist_id(m.group(1))
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    if request.url.path.startswith("/api"):
        response.headers["Cache-Control"] = "no-store"
    else:
        # el frontend compilado no necesita scripts inline ni orígenes externos
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; "
            "connect-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'")
    return response


@app.exception_handler(StarletteHTTPException)
async def http_error(request: Request, exc: StarletteHTTPException):
    # los mensajes se escriben en español y se traducen al idioma de la interfaz en el borde de la API
    detail = tr(exc.detail, request_lang(request)) if isinstance(exc.detail, str) else exc.detail
    return JSONResponse({"detail": detail}, status_code=exc.status_code, headers=getattr(exc, "headers", None))


@app.exception_handler(Exception)
async def unhandled(request: Request, exc: Exception):
    logging.getLogger("soc").exception("Error no controlado en %s", request.url.path)
    return JSONResponse({"detail": tr("Error interno del servidor. Revisá los logs del backend.", request_lang(request))}, status_code=500)


app.include_router(core.router)
app.include_router(report.router)
app.include_router(intel.router)

# Sirve el frontend compilado (modo producción / Docker de un solo contenedor)
STATIC = Path(__file__).resolve().parents[1] / "static"
if STATIC.is_dir():
    app.mount("/assets", StaticFiles(directory=STATIC / "assets"), name="assets")

    @app.get("/{path:path}", include_in_schema=False)
    def spa(path: str):
        target = STATIC / path
        if path and target.is_file() and STATIC in target.resolve().parents:
            return FileResponse(target)
        return FileResponse(STATIC / "index.html")
