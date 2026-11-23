"""Persistencia de sesiones: cifrado en disco, restauración tras reinicio, vencimiento y borrado."""
import os
import time

import pandas as pd
import pytest
from cryptography.fernet import Fernet
from fastapi.testclient import TestClient

from app import settings
from app.main import app
from app.session import SessionStore, store


@pytest.fixture
def key():
    return Fernet.generate_key()


def sheets():
    return {"Hoja": pd.DataFrame({"Usuario": ["ana", "bo"], "IP": ["10.0.0.1", "8.8.8.8"]})}


def test_session_survives_restart_and_is_encrypted(tmp_path, key):
    a = SessionStore("disk", tmp_path, key)
    s = a.create("logs.xlsx", 123, sheets())
    s.quality = {"total_rows": 2}
    s.intel = {"status": "en_curso", "results": {}, "providers": {}}
    a.persist(s)
    raw = (tmp_path / f"{s.id}.session").read_bytes()
    assert b"ana" not in raw and b"10.0.0.1" not in raw  # cifrado: nada legible en disco
    b = SessionStore("disk", tmp_path, key)               # «reinicio» del backend
    r = b.get(s.id)
    assert r is not None and r.filename == "logs.xlsx" and r.quality == {"total_rows": 2}
    pd.testing.assert_frame_equal(r.sheets["Hoja"], s.sheets["Hoja"])
    assert r.intel["status"] == "cancelado" and r.intel["interrupted"]  # el hilo no sobrevive


def test_wrong_key_and_tampered_files_are_discarded(tmp_path, key):
    a = SessionStore("disk", tmp_path, key)
    s = a.create("x.xlsx", 1, sheets())
    assert SessionStore("disk", tmp_path, Fernet.generate_key()).get(s.id) is None
    assert not (tmp_path / f"{s.id}.session").exists()


def test_invalid_ids_cannot_escape_directory(tmp_path, key):
    a = SessionStore("disk", tmp_path, key)
    for bad in ("../../etc/passwd", "a/b", "..", r"x.session\..\y"):
        assert a.get(bad) is None


def test_delete_removes_file(tmp_path, key):
    a = SessionStore("disk", tmp_path, key)
    s = a.create("x.xlsx", 1, sheets())
    assert a.delete(s.id) and not (tmp_path / f"{s.id}.session").exists()
    assert SessionStore("disk", tmp_path, key).get(s.id) is None


def test_expired_sessions_are_purged(tmp_path, key, monkeypatch):
    a = SessionStore("disk", tmp_path, key)
    s = a.create("x.xlsx", 1, sheets())
    old = time.time() - 3 * 3600
    os.utime(tmp_path / f"{s.id}.session", (old, old))
    s.touched = old
    monkeypatch.setattr(settings, "SESSION_TTL_HOURS", 1)
    assert a.get(s.id) is None and not (tmp_path / f"{s.id}.session").exists()


def test_memory_mode_never_writes(tmp_path):
    m = SessionStore("memory", tmp_path)
    s = m.create("x.xlsx", 1, sheets())
    assert m.get(s.id) is s and not list(tmp_path.iterdir())


def test_state_endpoint_restores_full_workflow_after_restart():
    c = TestClient(app)
    up = c.post("/api/upload/sample").json()
    sid = up["session_id"]
    sh = [{"name": s["name"], "mapping": s["suggested_mapping"]} for s in up["sheets"] if s["selected"]]
    c.post(f"/api/sessions/{sid}/mapping", json={"sheets": sh, "timezone": "Europe/Stockholm"})
    c.post(f"/api/sessions/{sid}/analyze")
    c.post(f"/api/sessions/{sid}/report/generate", json={"client": "C", "analyst": "A"})
    store._items.clear()                                   # simula reinicio: memoria vacía
    st = c.get(f"/api/sessions/{sid}/state")
    assert st.status_code == 200
    body = st.json()
    assert body["upload"]["session_id"] == sid and body["upload"]["default_timezone"] == "Europe/Stockholm"
    assert body["quality"]["total_rows"] > 0 and len(body["analysis"]["incidents"]) == 2
    assert set(body["reports"]) == {"ejecutivo", "tecnico"} and body["expires_at"] > time.time()
    assert c.get(f"/api/sessions/{sid}/events", params={"size": 1}).json()["total"] > 0
    assert c.get("/api/health").json()["session_store"] == "disk"
    c.delete(f"/api/sessions/{sid}")
    assert c.get(f"/api/sessions/{sid}/state").status_code == 404
