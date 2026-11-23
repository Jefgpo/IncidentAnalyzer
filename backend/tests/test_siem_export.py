"""Formato «SIEM Export» (una sola hoja, columnas en inglés, campos embebidos en la descripción).

Reproduce en miniatura los patrones del archivo de ejemplo del bootcamp: varios incidentes
independientes en pocas horas, sin columna de tipo de logon ni geolocalización.
"""
from datetime import datetime, timedelta

import pandas as pd
import pytest

from app.detection.engine import run_analysis
from app.ingest.mapper import suggest_mapping
from app.ingest.normalizer import build_events

TZ = "America/Argentina/Buenos_Aires"
T0 = datetime(2026, 10, 23, 7, 45)
COLS = ["Log_ID", "Timestamp", "Hostname", "Event_ID", "User", "Source_IP", "Destination", "Log_Source",
        "Event_Description", "Process_CommandLine", "Result", "Severity"]


def build() -> pd.DataFrame:
    rows = []

    def add(minutes, host, eid, user, ip, dest, src, desc, cmd=None, result="Success", sev="Informational"):
        rows.append([f"EVT-{len(rows) + 1:05d}", (T0 + timedelta(minutes=minutes)).strftime("%Y-%m-%d %H:%M:%S"), host,
                     eid, user, ip, dest, src, desc, cmd, result, sev])

    users = ["jlopez", "aperez", "mgarcia", "rrojas", "slopez", "dtorres", "helpdesk", "mruiz"]
    # ruido benigno: logons sin tipo en varios servidores, procesos y accesos a recursos compartidos
    for i in range(120):
        u = users[i % len(users)]
        host = ["DC-01", "FS-SRV01", "APP-SRV01", f"WS-0{10 + i % 9}"][i % 4]
        add(i * 2, host, 4624, f"CORP\\{u}", f"10.10.1.{20 + i % 9}", "DC-01", "Security",
            "An account was successfully logged on")
        if i % 3 == 0:
            add(i * 2 + 1, host, 4688, f"CORP\\{u}", f"10.10.1.{20 + i % 9}", None, "Security",
                "A new process has been created", "explorer.exe")
        if i % 4 == 0:
            add(i * 2 + 1, "FS-SRV01", 5140, f"CORP\\{u}", f"10.10.1.{20 + i % 9}", "\\\\FS-SRV01\\Finance", "Security",
                "A network share object was accessed")
    # INC: password spraying + acceso exitoso
    for k in range(16):
        add(40 + k * 0.3, "DC-01", 4625, f"CORP\\{users[k % 8]}", "203.0.113.74", "DC-01", "Security",
            "An account failed to log on", result="Failure", sev="Warning")
    add(46, "DC-01", 4624, "CORP\\mgarcia", "203.0.113.74", "DC-01", "Security", "An account was successfully logged on")
    # INC: RDP desde IP externa, ejecución, reconocimiento y C2
    for k in range(4):
        add(77 + k, "APP-SRV01", 4625, "CORP\\admin", "198.51.100.77", "APP-SRV01", "Security",
            "An account failed to log on (LogonType=10; RDP)", result="Failure", sev="Medium")
    add(81, "APP-SRV01", 4624, "CORP\\admin", "198.51.100.77", "APP-SRV01", "Security",
        "An account was successfully logged on (LogonType=10; RDP)")
    add(84, "APP-SRV01", 4688, "CORP\\admin", "198.51.100.77", None, "Security", "New process created; parent=cmd.exe",
        "powershell.exe -NoProfile -EncodedCommand [REDACTED_SYNTHETIC]", sev="High")
    add(86, "APP-SRV01", 4104, "CORP\\admin", "198.51.100.77", None, "PowerShell",
        "PowerShell Script Block: Get-LocalGroupMember Administrators; Get-SmbShare", "powershell.exe")
    add(91, "FS-SRV01", 4624, "CORP\\admin", "10.10.2.15", "FS-SRV01", "Security",
        "An account was successfully logged on (LogonType=3; source=APP-SRV01)")
    add(96, "APP-SRV01", 5156, "CORP\\admin", "10.10.2.15", "203.0.113.88:443", "Firewall",
        "Allowed outbound connection to 203.0.113.88:443 (process=powershell.exe)", "powershell.exe", result="Allowed")
    # INC: preparación de ransomware con una cuenta de servicio
    add(111, "WS-023", 4688, "CORP\\backupsvc", "10.10.1.44", None, "Security", "A new process has been created",
        "powershell.exe -NoProfile -EncodedCommand <base64_redacted>")
    for k in range(14):
        add(112 + k * 0.25, "FS-SRV01", 4663, "CORP\\backupsvc", "10.10.1.44", "\\\\FS-SRV01\\Finance", "Security",
            "An attempt was made to access an object", f"File access: Finance\\FY2026\\document_{k:03d}.xlsx")
    add(117, "WS-023", 4688, "CORP\\backupsvc", "10.10.1.44", None, "Security", "A new process has been created",
        "vssadmin.exe delete shadows /all /quiet", sev="High")
    # INC: exfiltración por proxy
    add(177, "WS-018", 4688, "CORP\\rrojas", "10.10.1.31", None, "Security", "A new process has been created",
        "7z.exe a C:\\Users\\Public\\archive.7z C:\\Legal\\*.docx")
    for k in range(10):
        add(178 + k * 0.3, "WS-018", "PROXY_ACCESS", "CORP\\rrojas", "10.10.1.31", "198.51.100.88:443", "Proxy",
            "HTTPS POST outbound", f"bytes_out={9_000_000 + k} uri=/upload/session/{k}")
    # INC: web shell en IIS
    for k in range(3):
        add(265 + k * 0.2, "WEB-01", "HTTP_ACCESS", "-", "192.0.2.91", "WEB-01:443", "IIS", "HTTP request",
            "/uploads/test.aspx?cmd=whoami", result="200")
    add(270, "WEB-01", 4688, "IIS APPPOOL\\DefaultAppPool", "192.0.2.91", None, "Security",
        "A new process has been created", "cmd.exe /c whoami", sev="High")
    return pd.DataFrame(rows, columns=COLS)


@pytest.fixture(scope="module")
def result():
    df = build()
    mapping, _ = suggest_mapping(df)
    events, quality = build_events({"SIEM Export": df}, [{"name": "SIEM Export", "mapping": mapping}], TZ)
    return mapping, events, quality, run_analysis(events)


def rules_hit(analysis):
    return {f["rule_id"] for f in analysis["findings"]}


def test_mapping_of_siem_export_columns(result):
    mapping, events, quality, _ = result
    assert mapping["log_id"] == "Log_ID" and mapping["destination"] == "Destination"
    assert mapping["log_source"] == "Log_Source" and mapping["message"] == "Event_Description"
    assert mapping["command_line"] == "Process_CommandLine" and mapping["siem_severity"] == "Severity"
    assert "dst_ip" not in mapping  # «Destination» mezcla hosts, IP:puerto y rutas UNC: se deriva
    row = events[events["log_id"] == "EVT-00001"].iloc[0]
    assert row["ts"].utcoffset().total_seconds() == -3 * 3600  # Buenos Aires


def test_embedded_fields_are_derived(result):
    _, events, _, _ = result
    proxy = events[events["sem"] == "proxy_request"].iloc[0]
    assert proxy["dst_ip"] == "198.51.100.88" and proxy["port"] == "443" and proxy["bytes_out_n"] >= 9e6
    share = events[events["destination"] == "\\\\FS-SRV01\\Finance"].iloc[0]
    assert share["dst_host"] == "FS-SRV01" and share["share"] == "\\\\*\\Finance"
    rdp = events[events["message"].str.contains("LogonType=10", na=False)]
    assert set(rdp["logon_type"]) == {"10"}


def test_expected_detections(result):
    *_, analysis = result
    expected = {"BF-002", "BF-003", "LOG-001", "LM-002", "EX-001", "EX-010", "C2-001", "COL-001", "EX-011",
                "EX-009", "EXF-001", "WEB-001"}
    assert expected <= rules_hit(analysis), expected - rules_hit(analysis)


def test_benign_noise_does_not_create_lateral_movement(result):
    *_, analysis = result
    # logons sin tipo en varios servidores no son movimiento lateral
    assert not [f for f in analysis["findings"] if f["rule_id"] == "LM-001"]


def test_independent_incidents_are_not_merged(result):
    *_, analysis = result
    titles = [i["title"] for i in analysis["incidents"]]
    assert len(analysis["incidents"]) >= 5, titles
    by_user = {u: i["id"] for i in analysis["incidents"] for u in i["entities"]["user"]}
    assert len({by_user["admin"], by_user["backupsvc"], by_user["rrojas"]}) == 3
    assert any("web shell" in t for t in titles) and any("ransomware" in t for t in titles)
    assert any("solo comparten el/los servidor(es) FS-SRV01" in line for line in analysis["conclusion"]["justification"])
