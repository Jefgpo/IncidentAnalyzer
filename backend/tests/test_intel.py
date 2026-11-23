"""Reputación de IPs con AbuseIPDB usando un transporte HTTP simulado: sin red ni claves reales."""
import json
import time

import httpx
import pytest
from fastapi.testclient import TestClient

from app.detection.engine import run_analysis
from app.intel import service
from app.intel.providers import PROVIDERS
from app.main import app
from app.session import store
from tests.conftest import make_events

ABUSE_KEY = "abuse-test-key-123"

# IP → abuseConfidenceScore
REPUTATION = {
    "45.155.205.10": 100,  # maliciosa
    "185.220.101.4": 85,   # maliciosa
    "1.1.1.1": 30,         # sospechosa
    "8.8.8.8": 0,          # limpia
}


def handler(calls: list, fail: dict | None = None):
    fail = fail or {}

    def _h(request: httpx.Request) -> httpx.Response:
        calls.append(request.url.host)
        if fail.get("status") == 401:
            return httpx.Response(401, json={"errors": [{"detail": "Authentication failed"}]})
        if fail.get("rate_limited", 0) > 0:
            fail["rate_limited"] -= 1
            return httpx.Response(429, headers={"Retry-After": "1", "X-RateLimit-Remaining": "5"})
        ip = request.url.params["ipAddress"]
        assert request.headers["Key"] == ABUSE_KEY
        return httpx.Response(200, json={"data": {"ipAddress": ip, "abuseConfidenceScore": REPUTATION[ip],
                                                  "countryCode": "NL", "totalReports": 40, "isp": "Ejemplo ISP"}})
    return _h


@pytest.fixture(autouse=True)
def isolate(monkeypatch):
    service._cache.clear()
    monkeypatch.setattr(service, "sleep", lambda s: None)
    monkeypatch.delenv("ABUSEIPDB_API_KEY", raising=False)


def use_transport(monkeypatch, calls, fail=None):
    monkeypatch.setattr(service, "client_factory",
                        lambda: httpx.Client(transport=httpx.MockTransport(handler(calls, fail))))


def make_session():
    rows = []
    for i, ip in enumerate(list(REPUTATION) + ["10.0.0.5", "203.0.113.9"]):
        for k in range(12):  # 12 fallos → fuerza bruta (hallazgo) por cada IP
            rows.append({"timestamp": f"2026-03-02 10:{i:02d}:{k:02d}", "user": f"u{i}", "event_id": "4625",
                         "src_ip": ip, "host": "SRV-1", "logon_type": "3"})
    events = make_events(rows)
    s = store.create("t.xlsx", 1, {})
    s.events, s.quality, s.analysis = events, {"timezone": "Europe/Stockholm"}, run_analysis(events)
    return s


def wait(s, timeout=10):
    t0 = time.time()
    while s.intel["status"] == "en_curso" and time.time() - t0 < timeout:
        time.sleep(0.05)
    return service.public_view(s.intel)


def test_only_abuseipdb_provider():
    assert set(PROVIDERS) == {"abuseipdb"}


def test_ip_scope_excludes_private_and_reserved():
    assert service.ip_scope("10.1.2.3") == "IP privada/interna"
    assert "documentación" in service.ip_scope("203.0.113.9")
    assert service.ip_scope("8.8.8.8") is None
    assert service.ip_scope("no-ip") == "no es una IP válida"


def test_candidates_prioritize_findings_and_skip_private():
    s = make_session()
    public, skipped = service.candidate_ips(s)
    assert {p["ip"] for p in public} == set(REPUTATION)
    assert {p["ip"] for p in skipped} == {"10.0.0.5", "203.0.113.9"}
    assert all(p["finding_ids"] for p in public)


def test_job_classifies_reputation(monkeypatch):
    calls = []
    use_transport(monkeypatch, calls)
    s = make_session()
    service.start_job(s, {"abuseipdb": ABUSE_KEY}, max_ips=25)
    view = wait(s)
    assert view["status"] == "completado"
    summ = view["summary"]
    assert set(summ["bad_abuseipdb"]) == {"45.155.205.10", "185.220.101.4"}
    assert summ["suspicious"] == ["1.1.1.1"]
    assert "bad_virustotal" not in summ and "bad_both" not in summ
    by_ip = {r["ip"]: r for r in view["results"]}
    assert by_ip["8.8.8.8"]["abuseipdb"]["verdict"] == "limpio"
    assert by_ip["45.155.205.10"]["abuseipdb"]["link"].endswith("/45.155.205.10")
    # solo IPs públicas viajan al servicio externo
    assert calls == ["api.abuseipdb.com"] * len(REPUTATION)
    # la clave nunca aparece en la respuesta
    assert ABUSE_KEY not in json.dumps(view)
    assert view["providers"]["abuseipdb"]["key_source"] == "pantalla"


def test_cache_avoids_repeated_queries(monkeypatch):
    calls = []
    use_transport(monkeypatch, calls)
    s = make_session()
    service.start_job(s, {"abuseipdb": ABUSE_KEY}, max_ips=25)
    wait(s)
    n = len(calls)
    service.start_job(s, {"abuseipdb": ABUSE_KEY}, max_ips=25)
    view = wait(s)
    assert len(calls) == n and all(r["abuseipdb"].get("cached") for r in view["results"])


def test_invalid_key_reports_error(monkeypatch):
    use_transport(monkeypatch, [], fail={"status": 401})
    s = make_session()
    service.start_job(s, {"abuseipdb": ABUSE_KEY}, max_ips=25)
    view = wait(s)
    assert view["providers"]["abuseipdb"]["state"] == "error"
    assert "API key" in view["providers"]["abuseipdb"]["error"]
    assert view["summary"]["bad_abuseipdb"] == []


def test_rate_limit_is_retried(monkeypatch):
    use_transport(monkeypatch, [], fail={"rate_limited": 2})
    s = make_session()
    service.start_job(s, {"abuseipdb": ABUSE_KEY}, max_ips=25)
    view = wait(s)
    assert view["providers"]["abuseipdb"]["state"] == "completado"
    assert len(view["summary"]["bad_abuseipdb"]) == 2


def test_env_key_is_used(monkeypatch):
    use_transport(monkeypatch, [])
    monkeypatch.setenv("ABUSEIPDB_API_KEY", ABUSE_KEY)
    assert service.status()["abuseipdb"]["configured"] is True
    s = make_session()
    service.start_job(s, {}, max_ips=2)
    view = wait(s)
    assert view["providers"]["abuseipdb"]["key_source"] == "entorno"
    assert view["selected"] == 2 and len(view["not_queried"]) == len(REPUTATION) - 2


def test_api_without_key_returns_400_and_status_endpoint():
    c = TestClient(app)
    st = c.get("/api/intel/status").json()
    assert set(st["providers"]) == {"abuseipdb"} and not st["providers"]["abuseipdb"]["configured"]
    s = make_session()
    r = c.post(f"/api/sessions/{s.id}/intel", json={})
    assert r.status_code == 400 and "ABUSEIPDB_API_KEY" in r.json()["detail"]
    assert c.get(f"/api/sessions/{s.id}/intel").json()["status"] == "sin_ejecutar"


@pytest.mark.parametrize("score,expected", [(0, "limpio"), (24, "limpio"), (25, "sospechoso"), (50, "malicioso"), (100, "malicioso")])
def test_abuseipdb_thresholds(score, expected):
    def h(request):
        return httpx.Response(200, json={"data": {"abuseConfidenceScore": score}})
    with httpx.Client(transport=httpx.MockTransport(h)) as client:
        cfg = __import__("app.settings", fromlist=["x"]).rules_config()["threat_intel"]["abuseipdb"]
        res = PROVIDERS["abuseipdb"].check(client, "8.8.8.8", ABUSE_KEY, cfg)
    assert res["verdict"] == expected
