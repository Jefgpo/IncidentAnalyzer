"""Análisis e informes en inglés: mismos resultados, textos traducidos."""
import re

from fastapi.testclient import TestClient

from app.detection.engine import run_analysis
from app.main import app

client = TestClient(app)
# marcas inequívocas de español en texto generado (no en datos del cliente)
SPANISH = re.compile(r"[¿«»]|\b(hallazgos?|filas|desde la|cuenta de servicio|según|fuera del horario|incidentes? candidatos?)\b",
                     re.IGNORECASE)


def _texts(obj, keys=("title", "summary", "fp_notes", "text", "justification", "factor", "label", "items", "context",
                      "detail", "formula", "rule_name")):
    if isinstance(obj, dict):
        for k, v in obj.items():
            if k in keys:
                yield from (v if isinstance(v, list) else [v])
            yield from _texts(v, keys)
    elif isinstance(obj, list):
        for v in obj:
            yield from _texts(v, keys)


def test_english_analysis_has_same_results(sample_events, analysis):
    events, _ = sample_events
    en = run_analysis(events, lang="en")
    assert [f["id"] for f in en["findings"]] == [f["id"] for f in analysis["findings"]]
    assert [(f["rule_id"], f["score"], f["severity"], f["rows"]) for f in en["findings"]] == \
           [(f["rule_id"], f["score"], f["severity"], f["rows"]) for f in analysis["findings"]]
    assert [(i["id"], i["finding_ids"], i["score"]) for i in en["incidents"]] == \
           [(i["id"], i["finding_ids"], i["score"]) for i in analysis["incidents"]]
    assert en["conclusion"]["verdict"] == analysis["conclusion"]["verdict"]


def test_english_analysis_texts_are_english(sample_events):
    events, _ = sample_events
    en = run_analysis(events, lang="en")
    # se excluyen las citas literales de los logs (ejemplos entre comillas y detalles con contenido de celdas)
    leftovers = [t for t in _texts({k: en[k] for k in ("findings", "incidents", "conclusion", "methodology")})
                 if isinstance(t, str) and SPANISH.search(re.sub(r"“[^”]*”", "", t))]
    assert not leftovers, leftovers[:5]
    assert en["findings"][0]["rule_name"] != ""
    assert any(f["title"].startswith(("Brute force", "Password spraying", "Success after")) for f in en["findings"])


def test_spanish_is_default(analysis):
    assert any("hallazgos" in i["summary"] for i in analysis["incidents"])


def _session_with_reports(lang: str):
    sid = client.post("/api/upload/sample").json()["session_id"]
    up = client.get(f"/api/sessions/{sid}/state").json()["upload"]
    sheets = [{"name": s["name"], "mapping": s["suggested_mapping"]} for s in up["sheets"] if s["selected"]]
    assert client.post(f"/api/sessions/{sid}/mapping", json={"sheets": sheets, "timezone": "Europe/Stockholm"}).status_code == 200
    a = client.post(f"/api/sessions/{sid}/analyze", headers={"Accept-Language": lang}).json()
    reps = client.post(f"/api/sessions/{sid}/report/generate", json={"lang": lang}).json()
    return sid, a, reps


def test_api_serves_analysis_and_reports_in_english():
    sid, a, reps = _session_with_reports("en")
    try:
        assert a["incidents"] and not SPANISH.search(a["conclusion"]["text"])
        # el mismo análisis en español sigue disponible para otra pestaña/idioma
        es = client.get(f"/api/sessions/{sid}/analysis").json()
        assert [f["id"] for f in es["findings"]] == [f["id"] for f in a["findings"]]
        assert es["conclusion"]["text"] != a["conclusion"]["text"]
        for kind in ("ejecutivo", "tecnico"):
            rep = reps[kind]
            assert rep["meta"]["lang"] == "en" and rep["meta"]["classification"] == "CONFIDENTIAL"
            titles = [s["title"] for s in rep["sections"]]
            assert not any(SPANISH.search(t) for t in titles), titles
        assert reps["ejecutivo"]["sections"][0]["title"] == "In summary"
        assert reps["tecnico"]["sections"][0]["title"] == "Technical summary"
        pdf = client.post(f"/api/sessions/{sid}/export/pdf?kind=ejecutivo")
        assert pdf.status_code == 200 and pdf.content[:4] == b"%PDF"
        csv = client.get(f"/api/sessions/{sid}/export/iocs.csv", headers={"Accept-Language": "en"}).text
        assert csv.lstrip("﻿").startswith("id,type,value,context")
        dash = client.get(f"/api/sessions/{sid}/dashboard", headers={"Accept-Language": "en"}).json()
        assert dash["incidents"][0]["title"] == a["incidents"][0]["title"]
    finally:
        client.delete(f"/api/sessions/{sid}")


def test_executive_report_in_english_avoids_jargon():
    sid, _, reps = _session_with_reports("en")
    try:
        text = " ".join(" ".join([b.get("text") or "", *(b.get("items") or [])])
                        for s in reps["ejecutivo"]["sections"] for b in s["blocks"])
        assert "MITRE" not in text and "EventID" not in text and "T1" not in text
        assert "We analyzed the activity logs" in text
    finally:
        client.delete(f"/api/sessions/{sid}")
