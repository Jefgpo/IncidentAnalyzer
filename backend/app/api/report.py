"""Endpoints de informe, IA y exportación."""
from __future__ import annotations

import csv
import io

from fastapi import APIRouter, HTTPException, Query, Request
from fastapi.responses import Response
from pydantic import BaseModel, Field

from app.ai import client as ai
from app.analytics.dashboard import build_dashboard
from app.api.core import get_session, require_analysis
from app.i18n import request_lang
from app.ingest.sanitizer import neutralize_formula
from app.pdf.builder import build_pdf
from app.report.builder import build_report, find_block
from app.report.executive import build_executive_report

router = APIRouter(prefix="/api/sessions/{sid}")


class GenerateRequest(BaseModel):
    lang: str = "es"
    client: str = Field("Cliente (confidencial)", max_length=120)
    analyst: str = Field("Analista SOC N2", max_length=120)


class BlockUpdate(BaseModel):
    text: str | None = Field(None, max_length=8000)
    items: list[str] | None = None


class MetaUpdate(BaseModel):
    client: str | None = Field(None, max_length=120)
    analyst: str | None = Field(None, max_length=120)
    title: str | None = Field(None, max_length=160)


class ChatRequest(BaseModel):
    message: str = Field(..., min_length=1, max_length=2000)


KINDS = ("ejecutivo", "tecnico")
FILE_PREFIX = {"ejecutivo": "informe_ejecutivo", "tecnico": "informe_tecnico"}


def _require_report(s, kind: str | None = None):
    require_analysis(s)
    if not s.reports:
        raise HTTPException(409, "Primero generá los informes.")
    if kind is not None and kind not in KINDS:
        raise HTTPException(404, f"Tipo de informe desconocido: {kind}. Usá «ejecutivo» o «tecnico».")


@router.post("/report/generate")
def generate(sid: str, body: GenerateRequest):
    """Genera los dos informes a la vez: ejecutivo (negocio) y técnico (detallado)."""
    s = get_session(sid)
    require_analysis(s)
    s.reports = {
        "ejecutivo": build_executive_report(s, client=body.client, analyst=body.analyst, lang=body.lang),
        "tecnico": build_report(s, client=body.client, analyst=body.analyst, lang=body.lang),
    }
    return s.reports


@router.get("/report")
def get_reports(sid: str):
    s = get_session(sid)
    _require_report(s)
    return s.reports


@router.get("/report/{kind}")
def get_report(sid: str, kind: str):
    s = get_session(sid)
    _require_report(s, kind)
    return s.reports[kind]


@router.put("/report/{kind}/blocks/{block_id}")
def update_block(sid: str, kind: str, block_id: str, body: BlockUpdate):
    s = get_session(sid)
    _require_report(s, kind)
    block = find_block(s.reports[kind], block_id)
    if not block:
        raise HTTPException(404, "Bloque inexistente.")
    if not block.get("editable"):
        raise HTTPException(400, "Este bloque reproduce evidencia literal y no es editable.")
    if body.text is not None and block["type"] == "paragraph":
        block["text"] = body.text.strip()
    elif body.items is not None and block["type"] == "list":
        block["items"] = [i.strip() for i in body.items if i.strip()][:100]
    else:
        raise HTTPException(400, "Contenido incompatible con el tipo de bloque.")
    block["origin"] = "editado"
    block["review"] = []
    return s.reports


@router.put("/report/meta")
def update_meta(sid: str, body: MetaUpdate):
    """Cliente y analista son comunes a ambos informes."""
    s = get_session(sid)
    _require_report(s)
    for k, v in body.model_dump(exclude_none=True).items():
        for rep in s.reports.values():
            rep["meta"][k] = v.strip()
    return s.reports


@router.post("/report/ai")
def ai_report(sid: str):
    """La IA redacta sobre el informe técnico (con evidencia validada)."""
    s = get_session(sid)
    _require_report(s)
    try:
        ai.enrich_report(s)
        return s.reports
    except ai.AIError as exc:
        raise HTTPException(503, str(exc)) from exc


@router.post("/ai/chat")
def ai_chat(sid: str, body: ChatRequest, request: Request):
    s = get_session(sid)
    require_analysis(s)
    try:
        return ai.chat(s, body.message, request_lang(request))
    except ai.AIError as exc:
        raise HTTPException(503, str(exc)) from exc


@router.post("/export/pdf")
def export_pdf(sid: str, kind: str = Query("tecnico")):
    s = get_session(sid)
    _require_report(s, kind)
    rep = s.reports[kind]
    version = s.report_versions.get(kind, 0) + 1
    s.report_versions[kind] = version
    rep["meta"]["version"] = version          # versión que se imprime en este PDF
    pdf = build_pdf(rep, build_dashboard(s, {}, lang=rep["meta"].get("lang", "es")))
    rep["meta"]["version"] = version + 1      # próxima exportación
    name = f"{FILE_PREFIX[kind]}_v{version}.pdf"
    return Response(pdf, media_type="application/pdf", headers={"Content-Disposition": f'attachment; filename="{name}"'})


@router.get("/export/iocs.csv")
def export_iocs(sid: str, request: Request):
    s = get_session(sid)
    require_analysis(s)
    lang = request_lang(request)
    out = io.StringIO()
    w = csv.writer(out)
    w.writerow(["id", "type", "value", "context", "count", "findings", "rows"] if lang == "en" else
               ["id", "tipo", "valor", "contexto", "frecuencia", "hallazgos", "filas"])
    for i in s.analysis_in(lang)["iocs"]:
        # neutraliza inyección de fórmulas al abrir el CSV en Excel
        w.writerow([neutralize_formula(str(x)) for x in (i["id"], i["type"], i["value"], i["context"], i["count"],
                                                          " ".join(i["finding_ids"]), " ".join(i["rows"][:50]))])
    return Response("﻿" + out.getvalue(), media_type="text/csv; charset=utf-8",
                    headers={"Content-Disposition": 'attachment; filename="iocs.csv"'})
