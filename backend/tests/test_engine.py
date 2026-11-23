"""Tests del motor de detección sobre el dataset sintético y sobre casos benignos."""
from datetime import datetime, timedelta

from app.detection.engine import ALL_RULES, run_analysis
from tests.conftest import make_events


def by_rule(analysis, rule_id):
    return [f for f in analysis["findings"] if f["rule_id"] == rule_id]


def rows_of(analysis, rule_id):
    return {r for f in by_rule(analysis, rule_id) for r in f["rows"]}


def test_every_rule_reports_a_status(analysis):
    statuses = {s["id"]: s["status"] for s in analysis["rules"]}
    assert set(statuses) == {r.id for r in ALL_RULES}
    assert all(v in ("con_hallazgos", "sin_hallazgos", "no_evaluable") for v in statuses.values())
    assert statuses["PE-004"] == "sin_hallazgos"  # evaluable pero sin evidencia de runas/sudo


def test_bruteforce_and_spraying(analysis):
    spray = by_rule(analysis, "BF-002")
    assert len(spray) == 1 and spray[0]["entities"]["src_ip"] == ["203.0.113.45"]
    assert spray[0]["metrics"]["distinct_users"] >= 25
    bf_users = {f["entities"]["user"][0] for f in by_rule(analysis, "BF-001")}
    assert bf_users == {"m.lindqvist", "svc_sql", "administrator"}
    success = by_rule(analysis, "BF-003")
    assert len(success) == 1 and success[0]["entities"]["user"] == ["m.lindqvist"]
    assert success[0]["auth_success"] is True
    # el BF-001 de INC-02 no tuvo éxito → solo intento
    svc = [f for f in by_rule(analysis, "BF-001") if f["entities"]["user"] == ["svc_sql"]][0]
    assert svc["auth_success"] is False


def test_suspicious_logons(analysis):
    assert {f["entities"]["user"][0] for f in by_rule(analysis, "LOG-003")} == {"svc_sql"}
    travel = by_rule(analysis, "LOG-004")
    assert len(travel) == 1 and travel[0]["metrics"]["max_speed_kmh"] > 900
    assert by_rule(analysis, "LOG-005")[0]["metrics"]["distinct_ips"] == 2
    log001 = by_rule(analysis, "LOG-001")
    assert [f["entities"]["src_ip"] for f in log001] == [["203.0.113.45"]]


def test_privilege_escalation(analysis):
    pe1 = by_rule(analysis, "PE-001")
    assert len(pe1) == 1 and "m.lindqvist" in pe1[0]["entities"]["user"]
    assert "Domain Admins" in pe1[0]["title"]
    pe2 = by_rule(analysis, "PE-002")
    assert len(pe2) == 1 and pe2[0]["entities"]["user"] == ["m.lindqvist"]  # it.admin no dispara (línea base)


def test_execution_rules_hit_exact_rows(analysis):
    for rule in ("EX-001", "EX-002", "EX-003", "EX-004", "EX-005", "EX-006", "EX-007", "EX-008", "EX-009"):
        assert by_rule(analysis, rule), rule
    ex1 = by_rule(analysis, "EX-001")[0]
    assert any("DownloadString" in d for d in ex1["details"])  # payload decodificado
    assert all(r.startswith("Sysmon_Procesos!") for r in rows_of(analysis, "EX-001"))
    assert any(r.startswith("Security!") for r in rows_of(analysis, "EX-007"))  # evento 1102


def test_lateral_movement(analysis):
    lm1 = by_rule(analysis, "LM-001")
    assert len(lm1) == 1 and lm1[0]["metrics"]["distinct_hosts"] >= 3
    lm3_hosts = {h for f in by_rule(analysis, "LM-003") for h in f["entities"]["host"]}
    assert {"WS-017", "SRV-SQL01"} <= lm3_hosts
    assert {f["entities"]["user"][0] for f in by_rule(analysis, "LM-004")} == {"m.lindqvist"}


def test_benign_activity_does_not_fire_high_severity(analysis):
    high = [f for f in analysis["findings"] if f["severity"] in ("Crítico", "Alto")]
    benign_users = {"k.nilsson", "it.admin", "n.ekstrom", "svc_backup"}
    for f in high:
        assert not (set(f["entities"].get("user", [])) & benign_users), f["title"]
    # el backup nocturno (logon type 5) nunca dispara reglas de logon
    assert not [f for f in analysis["findings"] if "svc_backup" in f["entities"].get("user", [])]
    # PowerShell administrativo no codificado y curl de healthcheck no disparan
    assert not [f for f in by_rule(analysis, "EX-001") + by_rule(analysis, "EX-002")
                if "it.admin" in f["entities"].get("user", [])]


def test_correlation_two_independent_incidents(analysis):
    incs = analysis["incidents"]
    assert len(incs) == 2
    assert analysis["conclusion"]["verdict"] == "multiple"
    a, b = incs
    assert a["severity"] == "Crítico" and "m.lindqvist" in a["entities"]["user"]
    assert b["severity"] in ("Alto", "Medio") and "svc_sql" in b["entities"]["user"]
    assert not set(a["entities"]["src_ip"]) & set(b["entities"]["src_ip"])
    phases = {p["tactic"] for p in a["phases"]}
    assert {"initial_access", "execution", "privilege_escalation", "lateral_movement", "exfiltration"} <= phases
    assert any("Sin ninguna entidad en común: INC-01–INC-02" in line for line in analysis["conclusion"]["justification"])
    # los casos benignos quedan como hallazgos aislados de baja criticidad
    isolated = [f for f in analysis["findings"] if f["id"] in analysis["isolated"]]
    assert isolated and all(f["severity"] == "Bajo" for f in isolated)


def test_scores_are_reproducible_and_explained(analysis, sample_events):
    events, _ = sample_events
    again = run_analysis(events)
    assert [(f["id"], f["score"]) for f in again["findings"]] == [(f["id"], f["score"]) for f in analysis["findings"]]
    for f in analysis["findings"]:
        assert sum(x["points"] for x in f["score_factors"]) == f["score"] or f["score"] == 100
    assert all(f["severity"] in ("Bajo", "Medio") for f in analysis["findings"] if f["is_anomaly"])


def test_every_finding_cites_existing_rows(analysis, sample_events):
    events, _ = sample_events
    ids = set(events["row_id"])
    for f in analysis["findings"]:
        assert f["rows"] and set(f["rows"]) <= ids


def test_iocs(analysis):
    values = {(i["type"], i["value"]) for i in analysis["iocs"]}
    assert ("ip", "203.0.113.45") in values and ("ip", "198.51.100.77") in values
    assert ("domain", "cdn-update.example") in values
    assert ("domain", "files.transfer-drop.example") in values
    assert any(t == "hash" for t, _ in values)
    assert ("user", "k.nilsson") not in values  # solo entidades de incidentes


# ----------------------------------------------------------------- casos benignos aislados
BASE = datetime(2026, 3, 2, 9, 0)  # lunes


def _row(minutes, **kw):
    r = {"timestamp": (BASE + timedelta(minutes=minutes)).strftime("%Y-%m-%d %H:%M:%S")}
    r.update(kw)
    return r


def test_typos_do_not_trigger_bruteforce():
    rows = []
    for d in range(5):
        for u in ("ana", "bo", "carl"):
            rows.append(_row(d * 1440, user=u, event_id="4625", src_ip="10.0.0.5", logon_type="2"))
            rows.append(_row(d * 1440 + 1, user=u, event_id="4624", src_ip="10.0.0.5", logon_type="2"))
    res = run_analysis(make_events(rows))
    assert not [f for f in res["findings"] if f["category"] == "bruteforce"]
    assert res["incidents"] == []


def test_missing_fields_mark_rules_not_evaluable():
    rows = [_row(i, user="ana", host="WS-1") for i in range(10)]
    res = run_analysis(make_events(rows))
    st = {s["id"]: s for s in res["rules"]}
    assert st["BF-001"]["status"] == "no_evaluable" and "auth" in st["BF-001"]["missing"]
    assert st["EX-001"]["status"] == "no_evaluable" and "command_line" in st["EX-001"]["missing"]
    assert st["LOG-004"]["status"] == "no_evaluable"
    assert res["findings"] == [] or all(f["is_anomaly"] for f in res["findings"])


def test_outcome_column_without_event_id_is_enough_for_auth():
    rows = [_row(i, user="ana", src_ip="203.0.113.9", outcome="failed") for i in range(12)]
    res = run_analysis(make_events(rows))
    assert [f for f in res["findings"] if f["rule_id"] == "BF-001"]


def test_single_day_file_is_json_safe_and_no_rule_errors():
    """Regresión: un Excel de un solo día producía NaN (AN-001) y reglas en estado «error» (máscaras vacías)."""
    import json
    rows = [_row(i, user=f"u{i % 5}", event_id="4624", src_ip="10.0.0.5", host="WS-1", logon_type="2") for i in range(30)]
    rows += [_row(300 + i // 3, user="x", event_id="4625", src_ip="10.0.0.9", host="WS-2", logon_type="3")
             for i in range(60)]
    res = run_analysis(make_events(rows))
    json.dumps(res, allow_nan=False)  # lanza ValueError si queda algún NaN/inf
    assert not [s["id"] for s in res["rules"] if s["status"] == "error"]
    assert not [f for f in res["findings"] if f["rule_id"] == "AN-001"]  # sin otros días no hay línea base


def test_admin_rdp_seen_in_baseline_is_not_new_remote_logon():
    rows = [_row(d * 1440, user="it.admin", host="SRV-APP01", src_ip="10.0.0.9", event_id="4624", logon_type="10")
            for d in range(6)]
    res = run_analysis(make_events(rows))
    assert not [f for f in res["findings"] if f["rule_id"] == "LM-002"]
