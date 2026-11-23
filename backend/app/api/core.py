"""Endpoints de carga, mapeo, eventos, análisis y dashboard."""
from __future__ import annotations

import logging

from fastapi import APIRouter, File, HTTPException, Request, UploadFile
from pydantic import BaseModel, Field

from app import settings
from app.analytics.dashboard import build_dashboard
from app.analytics.query import (Filters, filter_events, row_finding_index, serialize_rows, sort_events)
from app.detection.engine import catalog, run_analysis
from app.i18n import FIELD_LABELS_EN, request_lang, tr_deep
from app.ingest.mapper import CANONICAL_FIELDS, suggest_mapping
from app.ingest.normalizer import build_events
from app.ingest.reader import UploadError, read_workbook, validate_upload
from app.ingest.sanitizer import clean_text
from app.scoring.risk import methodology
from app.session import Session, store

log = logging.getLogger("soc.api")
router = APIRouter(prefix="/api")


def get_session(sid: str) -> Session:
    s = store.get(sid)
    if not s:
        raise HTTPException(404, "Sesión inexistente o expirada. Volvé a cargar el archivo.")
    return s


def require_events(s: Session) -> None:
    if s.events is None:
        raise HTTPException(409, "Primero confirmá el mapeo de columnas.")


def require_analysis(s: Session) -> None:
    require_events(s)
    if s.analysis is None:
        raise HTTPException(409, "Primero ejecutá el análisis.")


@router.get("/health")
def health():
    return {"status": "ok", "ai_enabled": settings.ai_key() is not None,
            "model": settings.AI_MODEL if settings.ai_key() else None,
            "max_upload_mb": settings.MAX_UPLOAD_MB, "session_ttl_hours": settings.SESSION_TTL_HOURS,
            "session_store": store.mode}


@router.get("/rules")
def rules():
    cfg = settings.rules_config()
    return {"rules": catalog(), "methodology": methodology(cfg), "config": cfg}


@router.post("/upload")
async def upload(file: UploadFile = File(...)):
    data = await file.read(int(settings.MAX_UPLOAD_MB * 1024 * 1024) + 1)
    return _ingest(file.filename or "archivo.xlsx", data)


@router.post("/upload/sample")
def upload_sample():
    """Carga el dataset SINTÉTICO incluido en sample_data/ (para demos y pruebas)."""
    if not settings.SAMPLE_FILE.is_file():
        raise HTTPException(404, "No se encontró el dataset sintético (ejecutá sample_data/generate_synthetic.py).")
    out = _ingest(settings.SAMPLE_FILE.name, settings.SAMPLE_FILE.read_bytes())
    out["default_timezone"] = "Europe/Stockholm"  # el dataset sintético se generó con hora de Estocolmo
    s = store.get(out["session_id"])
    s.default_timezone = out["default_timezone"]
    store.persist(s)
    return out


def _ingest(filename: str, data: bytes) -> dict:
    try:
        validate_upload(filename, data)
        sheets = read_workbook(data)
    except UploadError as exc:
        raise HTTPException(400, str(exc)) from exc
    s = store.create(filename, len(data), sheets)
    del data
    s.default_timezone = settings.rules_config()["general"]["timezone"]
    log.info("Archivo cargado: %d hojas, %d bytes", len(sheets), s.size)
    return upload_payload(s)


def upload_payload(s: Session) -> dict:
    """Descripción de las hojas cargadas (se reutiliza al restaurar una sesión)."""
    out = []
    for name, df in s.sheets.items():
        mapping, scores = suggest_mapping(df)
        preview = [{str(c): clean_text(v) for c, v in row.items()} for row in df.head(8).to_dict("records")]
        out.append({"name": name, "rows": int(len(df)), "columns": [str(c) for c in df.columns],
                    "preview": preview, "suggested_mapping": mapping, "scores": scores,
                    "selected": "timestamp" in mapping and len(df) > 0})
    return {"session_id": s.id, "filename": s.filename, "size": s.size, "sheets": out,
            "fields": CANONICAL_FIELDS,
            "fields_en": FIELD_LABELS_EN,
            "default_timezone": s.default_timezone or settings.rules_config()["general"]["timezone"]}


@router.get("/sessions/{sid}/state")
def session_state(sid: str, request: Request):
    """Todo lo necesario para que el navegador retome la sesión tras recargar o reiniciar."""
    from app.intel.service import public_view
    s = get_session(sid)
    return {"upload": upload_payload(s), "quality": s.quality, "analysis": s.analysis_in(request_lang(request)),
            "reports": s.reports or None, "intel": tr_deep(public_view(s.intel), request_lang(request)),
            "expires_at": s.expires_at(), "store": store.mode}


class SheetSelection(BaseModel):
    name: str
    mapping: dict[str, str | None] = Field(default_factory=dict)


class MappingRequest(BaseModel):
    sheets: list[SheetSelection]
    timezone: str = Field(default_factory=lambda: settings.rules_config()["general"]["timezone"])
    dayfirst: bool = True


@router.post("/sessions/{sid}/mapping")
def confirm_mapping(sid: str, body: MappingRequest):
    s = get_session(sid)
    if not body.sheets:
        raise HTTPException(400, "Seleccioná al menos una hoja.")
    from zoneinfo import ZoneInfo, ZoneInfoNotFoundError
    try:
        ZoneInfo(body.timezone)
    except (ZoneInfoNotFoundError, ValueError) as exc:
        raise HTTPException(400, f"Zona horaria desconocida: {body.timezone}") from exc
    for sel in body.sheets:
        if sel.name not in s.sheets:
            raise HTTPException(400, f"Hoja inexistente: {sel.name}")
        cols = set(s.sheets[sel.name].columns)
        bad = [c for c in sel.mapping.values() if c and c not in cols]
        if bad:
            raise HTTPException(400, f"Columnas inexistentes en {sel.name}: {', '.join(bad)}")
        unknown = [k for k in sel.mapping if k not in CANONICAL_FIELDS]
        if unknown:
            raise HTTPException(400, f"Campos desconocidos: {', '.join(unknown)}")
    events, quality = build_events(s.sheets, [sel.model_dump() for sel in body.sheets], body.timezone, body.dayfirst)
    if s.intel:
        s.intel["cancel"] = True
    s.events, s.quality, s.analysis, s.analysis_en, s.intel = events, quality, None, None, None
    s.reports = {}
    return quality


@router.get("/sessions/{sid}/quality")
def quality(sid: str):
    s = get_session(sid)
    require_events(s)
    return s.quality


@router.get("/sessions/{sid}/events")
def events(sid: str, request: Request):
    s = get_session(sid)
    require_events(s)
    params = dict(request.query_params)
    page = max(1, int(params.get("page", 1) or 1))
    size = min(500, max(1, int(params.get("size", 50) or 50)))
    f = Filters.from_params(params)
    df = filter_events(s.events, f, s.quality["timezone"], s.analysis)
    df = sort_events(df, params.get("sort"), params.get("order"))
    total = int(len(df))
    chunk = df.iloc[(page - 1) * size: page * size]
    return {"total": total, "page": page, "size": size,
            "rows": serialize_rows(chunk, row_finding_index(s.analysis))}


@router.post("/sessions/{sid}/analyze")
def analyze(sid: str, request: Request):
    s = get_session(sid)
    require_events(s)
    s.analysis, s.analysis_en = run_analysis(s.events), None
    s.reports = {}
    return s.analysis_in(request_lang(request))


@router.get("/sessions/{sid}/analysis")
def get_analysis(sid: str, request: Request):
    s = get_session(sid)
    require_analysis(s)
    return s.analysis_in(request_lang(request))


@router.get("/sessions/{sid}/dashboard")
def dashboard(sid: str, request: Request):
    s = get_session(sid)
    require_analysis(s)
    return build_dashboard(s, dict(request.query_params), lang=request_lang(request))


@router.delete("/sessions/{sid}")
def delete_session(sid: str):
    s = store.get(sid)
    if s and s.intel:
        s.intel["cancel"] = True  # detiene consultas externas en curso
    return {"deleted": store.delete(sid)}
