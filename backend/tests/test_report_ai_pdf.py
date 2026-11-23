"""Informe determinístico, validación de IA (con un modelo simulado) y exportación PDF."""
import io

import pypdfium2 as pdfium
import pytest
from fastapi.testclient import TestClient

from app import settings
from app.ai import client as ai
from app.ai.validator import Validator
from app.main import app
from app.session import store


@pytest.fixture(scope="module")
def api():
    return TestClient(app)


@pytest.fixture(scope="module")
def sid(api):
    up = api.post("/api/upload/sample").json()
    sheets = [{"name": s["name"], "mapping": s["suggested_mapping"]} for s in up["sheets"] if s["selected"]]
    api.post(f"/api/sessions/{up['session_id']}/mapping", json={"sheets": sheets, "timezone": "Europe/Stockholm"})
    api.post(f"/api/sessions/{up['session_id']}/analyze")
    r = api.post(f"/api/sessions/{up['session_id']}/report/generate", json={"client": "Cliente X", "analyst": "Ana"})
    assert r.status_code == 200
    return up["session_id"]


def test_report_has_required_sections(api, sid):
    rep = api.get(f"/api/sessions/{sid}/report/tecnico").json()
    assert rep["meta"]["kind"] == "tecnico"
    titles = [s["title"] for s in rep["sections"]]
    for expected in ("Resumen técnico", "Hallazgos identificados", "Explicación técnica de cada hallazgo",
                     "Evidencias encontradas en los logs", "Criticidad y justificación",
                     "Posible impacto en la organización", "Plan de acción: investigar, contener y remediar",
                     "Recomendaciones generales de seguridad", "Alcance y metodología", "Limitaciones del análisis",
                     "Línea de tiempo"):
        assert expected in titles
    plan = next(s for s in rep["sections"] if s["id"] == "plan")
    assert [b["title"] for b in plan["blocks"]] == ["9.1 Investigar", "9.2 Contener", "9.3 Remediar"]
    assert all(b["items"] for b in plan["blocks"])


def test_evidence_tables_quote_real_cells(api, sid):
    s = store.get(sid)
    rep = s.reports["tecnico"]
    ev = next(sec for sec in rep["sections"] if sec["id"] == "evidencias")
    table = next(b for b in ev["blocks"] if b["type"] == "table")
    by_id = s.events.set_index("row_id")
    for row in table["rows"]:
        rid, fragment = row[0].split(" · ")[0], row[-1]
        cell = by_id.loc[rid]
        literal = [v for v in (cell["command_line"], cell["message"], cell["group"], cell["privileges"], cell["share"],
                               cell["service"], cell["process"], cell["outcome"]) if isinstance(v, str)]
        text = fragment.split("] ", 1)[-1].replace(" […]", "")
        text = text.split(": ", 1)[-1] if text.startswith(("Grupo:", "Recurso:", "Servicio:", "Privilegios:", "Resultado:")) else text
        assert any(v.startswith(text) for v in literal), (rid, fragment)


def test_block_editing_marks_origin(api, sid):
    for kind in ("tecnico", "ejecutivo"):
        rep = api.get(f"/api/sessions/{sid}/report/{kind}").json()
        block = next(b for b in rep["sections"][0]["blocks"] if b["type"] == "paragraph")
        r = api.put(f"/api/sessions/{sid}/report/{kind}/blocks/{block['id']}", json={"text": f"Texto revisado ({kind})."})
        assert r.status_code == 200
        edited = next(b for b in r.json()[kind]["sections"][0]["blocks"] if b["id"] == block["id"])
        assert edited["origin"] == "editado" and edited["text"] == f"Texto revisado ({kind})."
        table = next(b for sec in rep["sections"] for b in sec["blocks"] if b["type"] == "table")
        assert api.put(f"/api/sessions/{sid}/report/{kind}/blocks/{table['id']}", json={"text": "x"}).status_code == 400
    assert api.get(f"/api/sessions/{sid}/report/otro").status_code == 404


def test_ai_disabled_without_key(api, sid, monkeypatch):
    monkeypatch.setattr(settings, "ai_key", lambda: None)
    assert api.get("/api/health").json()["ai_enabled"] is False
    assert api.post(f"/api/sessions/{sid}/report/ai").status_code == 503
    assert api.post(f"/api/sessions/{sid}/ai/chat", json={"message": "hola"}).status_code == 503


def _validator(sid):
    s = store.get(sid)
    return s, Validator(s.events, s.analysis)


def test_validator_accepts_grounded_claim(sid):
    s, v = _validator(sid)
    f = next(x for x in s.analysis["findings"] if x["rule_id"] == "BF-002")
    ok, why = v.check({"text": "La IP 203.0.113.45 falló contra múltiples cuentas.", "kind": "hecho_observado",
                       "row_ids": f["rows"][:3], "finding_ids": [f["id"]]})
    assert ok, why


@pytest.mark.parametrize("claim,reason", [
    ({"text": "Hubo acceso.", "kind": "hecho_observado", "row_ids": ["Security!999999"], "finding_ids": []},
     "inexistente"),
    ({"text": "Acceso desde 8.8.8.8.", "kind": "hecho_observado", "row_ids": ["VPN!49"], "finding_ids": []},
     "no aparece en los logs"),
    ({"text": "La cuenta svc_backup fue comprometida.", "kind": "inferencia", "row_ids": ["VPN!49"], "finding_ids": []},
     "svc_backup"),
    ({"text": "Algo pasó.", "kind": "hecho_observado", "row_ids": [], "finding_ids": []}, "sin IDs de fila"),
    ({"text": "Ver F-999.", "kind": "hipotesis", "row_ids": [], "finding_ids": ["F-999"]}, "inexistente"),
    ({"text": "APT29 está detrás.", "kind": "opinion", "row_ids": ["VPN!49"], "finding_ids": []}, "tipo"),
])
def test_validator_rejects_ungrounded_claims(sid, claim, reason):
    _, v = _validator(sid)
    ok, why = v.check(claim)
    assert not ok and reason in why


def test_validator_rejects_rows_outside_cited_finding(sid):
    s, v = _validator(sid)
    f = next(x for x in s.analysis["findings"] if x["rule_id"] == "EX-005")
    other = next(x for x in s.analysis["findings"] if x["rule_id"] == "BF-002")
    ok, why = v.check({"text": "Volcado de LSASS.", "kind": "hecho_observado", "row_ids": other["rows"][:1],
                       "finding_ids": [f["id"]]})
    assert not ok and "no pertenecen" in why


def test_ai_enrichment_with_fake_model(api, sid, monkeypatch):
    s = store.get(sid)
    f = next(x for x in s.analysis["findings"] if x["rule_id"] == "EX-005")
    good = {"text": "Se ejecutó un volcado de LSASS con comsvcs.dll en WS-017.", "kind": "hecho_observado",
            "row_ids": f["rows"], "finding_ids": [f["id"]]}
    bad = {"text": "El grupo APT inventado usó 10.99.99.99.", "kind": "inferencia", "row_ids": f["rows"],
           "finding_ids": [f["id"]]}

    def fake(system, user, schema):
        assert "Usá únicamente la evidencia provista" in system
        assert "evidence_sample" in user and len(user) < 400_000  # agregados y muestras, no el Excel completo
        return {"executive_summary": [good, bad], "technical": [{"finding_id": f["id"], "claims": [good]}],
                "impact": [], "action_plan": {"investigate": [], "contain": [], "remediate": []}, "recommendations": []}

    monkeypatch.setattr(settings, "ai_key", lambda: "test-key")
    monkeypatch.setattr(ai, "model_call", fake)
    rep = api.post(f"/api/sessions/{sid}/report/ai").json()["tecnico"]
    resumen = next(sec for sec in rep["sections"] if sec["id"] == "resumen")
    ai_blocks = [b for b in resumen["blocks"] if b["origin"] == "ia"]
    assert len(ai_blocks) == 1 and ai_blocks[0]["text"] == good["text"]
    assert len(rep["ai_review"]) == 1 and "10.99.99.99" in rep["ai_review"][0]["reason"]
    assert rep["meta"]["ai_used"] is True


def test_chat_with_fake_model(api, sid, monkeypatch):
    s = store.get(sid)
    f = next(x for x in s.analysis["findings"] if x["rule_id"] == "BF-003")

    def fake(system, user, schema):
        return {"claims": [{"text": "m.lindqvist inició sesión tras 18 fallos.", "kind": "hecho_observado",
                            "row_ids": f["rows"][-1:], "finding_ids": [f["id"]]},
                           {"text": "También accedió a SRV-XYZ99.", "kind": "hecho_observado", "row_ids": ["Nope!1"],
                            "finding_ids": []}], "no_evidence": False}

    monkeypatch.setattr(settings, "ai_key", lambda: "test-key")
    monkeypatch.setattr(ai, "model_call", fake)
    r = api.post(f"/api/sessions/{sid}/ai/chat", json={"message": "¿Qué pasó con m.lindqvist?"}).json()
    assert r["rejected"] == 1 and "18 fallos" in r["answer"] and "SRV-XYZ99" not in r["answer"]


def test_pdf_export(api, sid):
    r = api.post(f"/api/sessions/{sid}/export/pdf", params={"kind": "tecnico"})
    assert r.headers["content-disposition"].endswith('informe_tecnico_v1.pdf"')
    assert r.status_code == 200 and r.headers["content-type"] == "application/pdf"
    pdf = pdfium.PdfDocument(io.BytesIO(r.content))
    assert len(pdf) >= 10
    first = pdf[0].get_textpage().get_text_range()
    assert "CONFIDENCIAL" in first and "Informe técnico" in first
    page3 = pdf[2].get_textpage().get_text_range()
    assert "Página 3 de" in page3
    all_text = " ".join(pdf[i].get_textpage().get_text_range() for i in range(len(pdf)))
    assert "Generado por IA" in all_text  # bloques de IA rotulados (del test anterior)
    assert "Editado por analista" in all_text


def test_iocs_csv_neutralizes_formulas(api, sid):
    r = api.get(f"/api/sessions/{sid}/export/iocs.csv")
    assert r.status_code == 200 and "203.0.113.45" in r.text
    for line in r.text.splitlines()[1:]:
        assert not line.startswith(("=", "+", "@"))


# ------------------------------------------------------------------ informe ejecutivo
JARGON = ("MITRE", "T1110", "T1078", "EventID", "4625", "4624", "IoC", "logon", "LM-0", "EX-0", "BF-0", "Hoja!", "!1",
          "hash", "SHA", "lsass", "PowerShell", "Hallazgo F-")


def test_executive_report_is_business_language(api, sid):
    rep = api.get(f"/api/sessions/{sid}/report/ejecutivo").json()
    assert rep["meta"]["kind"] == "ejecutivo" and "ejecutivo" in rep["meta"]["title"].lower()
    titles = [s["title"] for s in rep["sections"]]
    assert titles[0] == "En resumen"
    for expected in ("Cifras clave", "Qué ocurrió, explicado sin tecnicismos", "Qué puede afectar al negocio",
                     "Prioridad de atención", "Qué recomendamos hacer", "Glosario y próximos pasos"):
        assert expected in titles
    text = " ".join((b.get("text") or "") + " " + " ".join(b.get("items") or []) + " " +
                    " ".join(" ".join(str(c) for c in r) for r in b.get("rows") or [])
                    for sec in rep["sections"] for b in sec["blocks"])
    leaked = [j for j in JARGON if j in text]
    assert not leaked, leaked
    one_liners = next(b for b in rep["sections"][0]["blocks"] if b.get("title") == "Los incidentes en una línea")
    assert len(one_liners["items"]) == 2 and "nivel crítico" in one_liners["items"][0]
    assert "Robo de la contraseña" in text or "Acceso no autorizado" in text
    decisions = next(b for b in rep["sections"][0]["blocks"] if b.get("title") == "¿Qué necesitamos que decida la dirección?")
    assert decisions["items"]
    impact = next(b for sec in rep["sections"] if sec["id"] == "ej_impacto" for b in sec["blocks"] if b["type"] == "table")
    areas = {r[0]: r[1] for r in impact["rows"]}
    assert areas["Información de la empresa"] == "Alto"  # el escenario incluye exfiltración
    assert areas["Continuidad de la operación"] in ("Medio", "Alto")


def test_executive_pdf_export(api, sid):
    r = api.post(f"/api/sessions/{sid}/export/pdf", params={"kind": "ejecutivo"})
    assert r.status_code == 200 and r.headers["content-disposition"].endswith('informe_ejecutivo_v1.pdf"')
    pdf = pdfium.PdfDocument(io.BytesIO(r.content))
    text = " ".join(pdf[i].get_textpage().get_text_range() for i in range(len(pdf)))
    assert "Informe ejecutivo" in text and "CONFIDENCIAL" in text and "Qué recomendamos hacer" in text
    assert "[Hecho observado]" not in text  # sin etiquetas técnicas en el ejecutivo
    assert len(pdf) < 12  # breve


def test_technical_report_has_mitre_annex(api, sid):
    rep = api.get(f"/api/sessions/{sid}/report/tecnico").json()
    annex = next(sec for sec in rep["sections"] if sec["id"] == "anexo_d")
    table = next(b for b in annex["blocks"] if b["type"] == "table")
    techniques = {r[2] for r in table["rows"]}
    assert {"T1110.003", "T1003.001", "T1021.002"} <= techniques


def test_ai_key_generic_name_with_legacy_alias(monkeypatch):
    monkeypatch.delenv("AI_API_KEY", raising=False)
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    assert settings.ai_key() is None
    monkeypatch.setenv("ANTHROPIC_API_KEY", "legacy")
    assert settings.ai_key() == "legacy"          # alias por compatibilidad
    monkeypatch.setenv("AI_API_KEY", "nueva")
    assert settings.ai_key() == "nueva"           # el nombre genérico tiene prioridad
