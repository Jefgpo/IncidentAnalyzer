"""Endpoints de reputación de IPs (AbuseIPDB)."""
from __future__ import annotations

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, Field

from app import settings
from app.api.core import get_session, require_analysis
from app.i18n import request_lang, tr_deep
from app.intel import service

router = APIRouter(prefix="/api")


class IntelRequest(BaseModel):
    # Clave opcional ingresada en la UI: solo se usa durante este job; no se guarda ni se devuelve.
    abuseipdb_key: str | None = Field(None, max_length=200)
    max_ips: int = Field(default_factory=lambda: settings.INTEL_MAX_IPS, ge=1, le=500)


@router.get("/intel/status")
def intel_status():
    return {"providers": service.status(), "default_max_ips": settings.INTEL_MAX_IPS}


@router.get("/sessions/{sid}/intel/candidates")
def intel_candidates(sid: str, request: Request):
    s = get_session(sid)
    require_analysis(s)
    public, skipped = service.candidate_ips(s)
    return tr_deep({"public": public, "skipped": skipped}, request_lang(request))


@router.post("/sessions/{sid}/intel")
def intel_start(sid: str, body: IntelRequest, request: Request):
    s = get_session(sid)
    require_analysis(s)
    try:
        return tr_deep(service.start_job(s, {"abuseipdb": body.abuseipdb_key}, body.max_ips), request_lang(request))
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    except RuntimeError as exc:
        raise HTTPException(409, str(exc)) from exc


@router.get("/sessions/{sid}/intel")
def intel_get(sid: str, request: Request):
    s = get_session(sid)
    return tr_deep(service.public_view(s.intel) or {"status": "sin_ejecutar"}, request_lang(request))


@router.delete("/sessions/{sid}/intel")
def intel_cancel(sid: str, request: Request):
    s = get_session(sid)
    if s.intel and s.intel.get("status") == "en_curso":
        s.intel["cancel"] = True
    return tr_deep(service.public_view(s.intel) or {"status": "sin_ejecutar"}, request_lang(request))
