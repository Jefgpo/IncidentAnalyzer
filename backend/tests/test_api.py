import pytest
from fastapi.testclient import TestClient

from app.main import app


@pytest.fixture(scope="module")
def client():
    return TestClient(app)


@pytest.fixture(scope="module")
def sid(client, sample_bytes):
    r = client.post("/api/upload", files={"file": ("SINTETICO.xlsx", sample_bytes,
                                                   "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")})
    assert r.status_code == 200, r.text
    body = r.json()
    sheets = [{"name": s["name"], "mapping": s["suggested_mapping"]} for s in body["sheets"] if s["selected"]]
    assert [s["name"] for s in sheets] == ["Security", "Sysmon_Procesos", "VPN"]
    r = client.post(f"/api/sessions/{body['session_id']}/mapping",
                    json={"sheets": sheets, "timezone": "Europe/Stockholm"})
    assert r.status_code == 200, r.text
    assert r.json()["invalid_rows"] == 9
    return body["session_id"]


def test_rejects_non_xlsx(client):
    r = client.post("/api/upload", files={"file": ("x.csv", b"a,b", "text/csv")})
    assert r.status_code == 400


def test_events_pagination_search_and_sort(client, sid):
    r = client.get(f"/api/sessions/{sid}/events", params={"page": 1, "size": 25})
    body = r.json()
    assert body["total"] == 3239 + 9 and len(body["rows"]) == 25
    r = client.get(f"/api/sessions/{sid}/events", params={"q": "certutil"})
    assert r.json()["total"] == 1
    r = client.get(f"/api/sessions/{sid}/events", params={"sort": "ts", "order": "desc", "size": 1})
    assert r.json()["rows"][0]["ts_iso"].startswith("2026-10-25")
    r = client.get(f"/api/sessions/{sid}/events", params={"only_issues": "true"})
    assert r.json()["total"] == 10


def test_analysis_dashboard_and_drilldown(client, sid):
    assert client.get(f"/api/sessions/{sid}/dashboard").status_code == 409
    r = client.post(f"/api/sessions/{sid}/analyze")
    assert r.status_code == 200
    a = r.json()
    assert len(a["incidents"]) == 2
    d = client.get(f"/api/sessions/{sid}/dashboard").json()
    assert d["kpis"]["incidents"] == 2 and d["kpis"]["by_severity"]["Crítico"] > 0
    assert len(d["heatmap"]) == 7 * 24
    assert any(e["target"] == "SRV-SQL01" for e in d["lateral"]["edges"])
    d2 = client.get(f"/api/sessions/{sid}/dashboard", params={"severity": "Crítico"}).json()
    assert d2["kpis"]["findings"] == d["kpis"]["by_severity"]["Crítico"]
    assert d2["kpis"]["total_events"] < d["kpis"]["total_events"]
    f = a["findings"][0]
    ev = client.get(f"/api/sessions/{sid}/events", params={"finding": f["id"], "size": 500}).json()
    assert {row["row_id"] for row in ev["rows"]} == set(f["rows"])
    hm = client.get(f"/api/sessions/{sid}/events", params={"weekday": 4, "hour": 2}).json()
    assert hm["total"] > 50


def test_delete_session(client, sample_bytes):
    r = client.post("/api/upload", files={"file": ("a.xlsx", sample_bytes, "application/octet-stream")})
    sid = r.json()["session_id"]
    assert client.delete(f"/api/sessions/{sid}").json()["deleted"] is True
    assert client.get(f"/api/sessions/{sid}/quality").status_code == 404


def test_cors_restricted(client):
    r = client.options("/api/health", headers={"Origin": "http://evil.example", "Access-Control-Request-Method": "GET"})
    assert "access-control-allow-origin" not in {k.lower() for k in r.headers}
