"""Mensajes del backend en el idioma de la interfaz (Accept-Language)."""
import re
from pathlib import Path

from fastapi.testclient import TestClient

from app.i18n import FIELD_LABELS_EN, lang_of, tr, tr_deep
from app.ingest.mapper import CANONICAL_FIELDS
from app.main import app

client = TestClient(app)
APP_DIR = Path(__file__).resolve().parents[1] / "app"


def test_lang_of():
    assert lang_of("en") == "en"
    assert lang_of("en-US,en;q=0.9") == "en"
    assert lang_of("es-AR") == "es"
    assert lang_of(None) == "es"
    assert lang_of("fr") == "es"


def test_tr_with_parameters():
    assert tr("Zona horaria desconocida: Mars/Base", "en") == "Unknown timezone: Mars/Base"
    assert tr("El libro tiene 500001 filas; el máximo es 500000.", "en") == "The workbook has 500001 rows; the maximum is 500000."
    assert tr("Zona horaria desconocida: Mars/Base", "es") == "Zona horaria desconocida: Mars/Base"
    assert tr("mensaje desconocido", "en") == "mensaje desconocido"


def test_tr_deep_only_touches_text_fields():
    job = {"status": "en_curso", "providers": {"abuseipdb": {"key_source": "pantalla", "note": "Límite de velocidad; reintentando en 30 s"}},
           "skipped": [{"ip": "10.0.0.1", "reason": "IP privada/interna"}]}
    out = tr_deep(job, "en")
    assert out["status"] == "en_curso"  # los códigos de estado no se traducen (el frontend los interpreta)
    assert out["providers"]["abuseipdb"] == {"key_source": "screen", "note": "Rate limited; retrying in 30 s"}
    assert out["skipped"][0]["reason"] == "private/internal IP"


def test_every_static_error_message_has_english():
    """Cada mensaje de error literal del código tiene traducción: evita regresiones al agregar mensajes nuevos."""
    pattern = re.compile(r'(?:HTTPException\(\d+, |UploadError\(|AIError\(|RuntimeError\()"([^"{}]+)"')
    missing = []
    for path in APP_DIR.rglob("*.py"):
        for msg in pattern.findall(path.read_text(encoding="utf-8")):
            if tr(msg, "en") == msg:
                missing.append(f"{path.name}: {msg}")
    assert not missing, missing


def test_field_labels_cover_all_fields():
    assert set(FIELD_LABELS_EN) == set(CANONICAL_FIELDS)


def test_api_errors_follow_accept_language():
    r = client.get("/api/sessions/nope/state", headers={"Accept-Language": "en"})
    assert r.status_code == 404
    assert r.json()["detail"] == "Session not found or expired. Upload the file again."
    r = client.get("/api/sessions/nope/state")
    assert r.json()["detail"] == "Sesión inexistente o expirada. Volvé a cargar el archivo."


def test_upload_error_in_english():
    r = client.post("/api/upload", files={"file": ("x.csv", b"a,b\n1,2", "text/csv")}, headers={"Accept-Language": "en"})
    assert r.status_code == 400
    assert r.json()["detail"] == "Only .xlsx files are accepted (Excel 2007+)."


def test_upload_payload_includes_english_field_labels():
    r = client.post("/api/upload/sample")
    if r.status_code == 404:  # dataset sintético no generado en este entorno
        return
    body = r.json()
    assert body["fields_en"]["src_ip"] == "Source IP"
    client.delete(f"/api/sessions/{body['session_id']}")
