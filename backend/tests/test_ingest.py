import io

import pandas as pd
import pytest
from openpyxl import Workbook

from app.ingest.mapper import normalize_header, suggest_mapping
from app.ingest.normalizer import parse_timestamps
from app.ingest.reader import UploadError, read_workbook, validate_upload
from app.ingest.sanitizer import looks_like_formula, neutralize_formula


def test_header_normalization():
    assert normalize_header("Tipo de inicio de sesión") == "tipodeiniciodesesion"
    assert normalize_header(" IP Origen ") == "iporigen"


def test_mapping_spanish_and_english_synonyms(sample_bytes):
    sheets = read_workbook(sample_bytes)
    sec, _ = suggest_mapping(sheets["Security"])
    assert sec["timestamp"] == "Fecha/Hora"
    assert sec["user"] == "Cuenta"
    assert sec["host"] == "Equipo"
    assert sec["src_ip"] == "IP Origen"
    assert sec["event_id"] == "EventID"
    assert sec["logon_type"] == "Tipo de inicio de sesión"
    assert sec["target_user"] == "Cuenta destino"
    sysmon, _ = suggest_mapping(sheets["Sysmon_Procesos"])
    assert sysmon["command_line"] == "CommandLine"
    assert sysmon["process"] == "Image"
    assert sysmon["hash"] == "SHA256"
    vpn, _ = suggest_mapping(sheets["VPN"])
    assert vpn["outcome"] == "status" and vpn["lat"] == "latitude"
    leeme, _ = suggest_mapping(sheets["LEEME_SINTETICO"])
    assert "timestamp" not in leeme


def test_mapping_by_content_when_header_is_unknown():
    df = pd.DataFrame({"col_a": ["2026-10-01 10:00:00"] * 5, "col_b": ["10.0.0.1"] * 5})
    mapping, scores = suggest_mapping(df)
    assert mapping["timestamp"] == "col_a"
    assert mapping["src_ip"] == "col_b"
    assert scores["timestamp"] < 1


def test_timestamps_formats_and_timezone():
    values = pd.Series(["19/10/2026 08:00:00", "2026-10-19T06:00:00Z", 46314.5, None, "basura",
                        pd.Timestamp("2026-10-19 08:00:00")], dtype=object)
    ts, issues = parse_timestamps(values, "Europe/Stockholm")
    assert ts[0].isoformat() == "2026-10-19T08:00:00+02:00"
    assert ts[1].isoformat() == "2026-10-19T08:00:00+02:00"  # UTC → hora de Estocolmo (CEST)
    assert ts[2].year == 2026  # serial de Excel
    assert pd.isna(ts[3]) and pd.isna(ts[4])
    assert "vacía" in issues[3][0] and "inválida" in issues[4][0]
    assert ts[5].isoformat() == "2026-10-19T08:00:00+02:00"


def test_dst_ambiguous_hour_is_flagged():
    ts, issues = parse_timestamps(pd.Series(["25/10/2026 02:30:00"], dtype=object), "Europe/Stockholm")
    assert ts[0].utcoffset().total_seconds() == 3600  # se asume horario estándar
    assert "ambigua" in issues[0][0]


def test_invalid_rows_are_reported_not_dropped(sample_events):
    events, quality = sample_events
    assert quality["invalid_rows"] == 9
    assert quality["total_rows"] == len(events)
    invalid = [r for r in quality["issue_rows"] if not r["valid"]]
    assert len(invalid) == 9 and all(r["issues"] for r in invalid)
    assert "Security!1070" in {r["row_id"] for r in invalid}


def test_row_ids_are_stable_excel_rows(sample_events):
    events, _ = sample_events
    first = events[events["sheet"] == "Security"].iloc[0]
    assert first["row_id"] == "Security!2" and first["excel_row"] == 2


def test_formula_injection_detected(sample_events):
    events, quality = sample_events
    assert quality["formula_cells"] == 1
    assert looks_like_formula('=HYPERLINK("x")')
    assert neutralize_formula("=1+1") == "'=1+1"
    assert not looks_like_formula("-5") and not looks_like_formula("- guion")
    flagged = [r for r in quality["issue_rows"] if any("fórmula" in i for i in r["issues"])]
    assert flagged[0]["row_id"].startswith("Sysmon_Procesos!")


def _xlsx(rows) -> bytes:
    wb = Workbook()
    for r in rows:
        wb.active.append(r)
    buf = io.BytesIO()
    wb.save(buf)
    return buf.getvalue()


def test_upload_validation():
    with pytest.raises(UploadError):
        validate_upload("a.csv", b"x")
    with pytest.raises(UploadError):
        validate_upload("a.xlsx", b"not a zip file")
    validate_upload("ok.xlsx", _xlsx([["a"], [1]]))
