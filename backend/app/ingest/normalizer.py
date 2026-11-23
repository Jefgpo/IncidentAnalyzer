"""Normalización de hojas mapeadas a un DataFrame canónico de eventos.

Cada fila conserva un ID estable `Hoja!fila_excel` para citarla como evidencia.
Las filas con problemas NO se descartan: se marcan en `issues` y se reportan.
"""
from __future__ import annotations

import ipaddress
import re
from datetime import datetime

import numpy as np
import pandas as pd

from app import settings
from app.ingest.mapper import CANONICAL_FIELDS
from app.ingest.sanitizer import clean_text, looks_like_formula

TEXT_FIELDS = [f for f in CANONICAL_FIELDS if f not in ("timestamp", "lat", "lon")]
_TZ_SUFFIX = re.compile(r"(?:Z|[+-]\d{2}:?\d{2})$", re.IGNORECASE)
_NAIVE_FORMATS = ["%d/%m/%Y %H:%M:%S", "%d/%m/%Y %H:%M", "%d/%m/%Y", "%d-%m-%Y %H:%M:%S", "%d.%m.%Y %H:%M:%S",
                  "%Y/%m/%d %H:%M:%S"]
_US_FORMATS = ["%m/%d/%Y %H:%M:%S", "%m/%d/%Y %I:%M:%S %p", "%m/%d/%Y %H:%M"]
LOGON_TYPE_NAMES = {
    "interactive": "2", "network": "3", "batch": "4", "service": "5", "unlock": "7",
    "networkcleartext": "8", "newcredentials": "9", "remoteinteractive": "10", "rdp": "10",
    "cachedinteractive": "11",
}


def _range_ok(ts: pd.Series) -> pd.Series:
    years = ts.dt.year
    return years.between(2000, 2100)


def parse_timestamps(values: pd.Series, tz: str, dayfirst: bool = True) -> tuple[pd.Series, dict]:
    """Convierte valores heterogéneos a Timestamps con zona `tz`.

    Soporta: datetime nativo de Excel, serial numérico de Excel, epoch (s/ms), ISO-8601 con o sin
    zona, y formatos dd/mm/aaaa. Los valores sin zona se interpretan en `tz` (supuesto documentado).
    Devuelve (serie, {índice: [problemas]}).
    """
    issues: dict = {}
    out = pd.Series(pd.NaT, index=values.index, dtype=f"datetime64[us, {tz}]")
    naive = pd.Series(pd.NaT, index=values.index, dtype="datetime64[us]")

    is_dt = values.map(lambda v: isinstance(v, (datetime, pd.Timestamp)) and not pd.isna(v))
    is_num = values.map(lambda v: isinstance(v, (int, float, np.integer, np.floating))
                        and not isinstance(v, bool) and not pd.isna(v))
    as_text = values.map(lambda v: None if v is None or (not isinstance(v, str) and pd.isna(v)) else str(v).strip())
    is_str = ~is_dt & ~is_num & as_text.notna() & (as_text != "")

    # 1) datetime nativos
    for idx in values.index[is_dt]:
        ts = pd.Timestamp(values[idx])
        if ts.tzinfo is not None:
            out[idx] = ts.tz_convert(tz)
        else:
            naive[idx] = ts
    # 2) numéricos: serial Excel o epoch
    if is_num.any():
        nums = values[is_num].astype(float)
        serial = nums.between(20000, 80000)
        naive.loc[nums.index[serial]] = (pd.Timestamp("1899-12-30") + pd.to_timedelta(nums[serial], unit="D")).values
        epoch_s = nums.between(9e8, 4.2e9)
        aware = pd.to_datetime(nums[epoch_s], unit="s", utc=True)
        out.loc[aware.index] = aware.dt.tz_convert(tz)
        epoch_ms = nums.between(9e11, 4.2e12)
        aware = pd.to_datetime(nums[epoch_ms], unit="ms", utc=True)
        out.loc[aware.index] = aware.dt.tz_convert(tz)
    # 3) texto
    texts = as_text[is_str]
    with_tz = texts[texts.str.contains(_TZ_SUFFIX)]
    if not with_tz.empty:
        parsed = pd.to_datetime(with_tz, utc=True, errors="coerce", format="ISO8601")
        ok = parsed.notna()
        out.loc[parsed.index[ok]] = parsed[ok].dt.tz_convert(tz)
    pending = texts.drop(with_tz.index[with_tz.index.isin(out.dropna().index)], errors="ignore")
    pending = pending[~pending.index.isin(out.dropna().index)]
    formats = ["ISO8601"] + (_NAIVE_FORMATS + _US_FORMATS if dayfirst else _US_FORMATS + _NAIVE_FORMATS)
    for fmt in formats:
        if pending.empty:
            break
        parsed = pd.to_datetime(pending, errors="coerce", format=fmt)
        if getattr(parsed.dt, "tz", None) is not None:
            parsed = parsed.dt.tz_convert(tz).dt.tz_localize(None)
        ok = parsed.notna()
        naive.loc[parsed.index[ok]] = parsed[ok].values
        pending = pending[~ok]
    if not pending.empty:
        parsed = pd.to_datetime(pending, errors="coerce", format="mixed", dayfirst=dayfirst)
        ok = parsed.notna()
        for idx in parsed.index[ok]:
            ts = parsed[idx]
            if ts.tzinfo is not None:
                out[idx] = ts.tz_convert(tz)
            else:
                naive[idx] = ts
            issues.setdefault(idx, []).append("formato de fecha no estándar (interpretado)")

    # 4) localizar valores sin zona en la zona del cliente, manejando el cambio de horario
    has_naive = naive.notna()
    if has_naive.any():
        sub = naive[has_naive]
        loc = sub.dt.tz_localize(tz, ambiguous="NaT", nonexistent="shift_forward")
        amb = loc.isna()
        if amb.any():
            fallback = sub[amb].dt.tz_localize(tz, ambiguous=np.zeros(int(amb.sum()), dtype=bool),
                                               nonexistent="shift_forward")
            loc[amb] = fallback
            for idx in sub.index[amb]:
                issues.setdefault(idx, []).append("hora ambigua por cambio de horario; se asumió horario estándar")
        out.loc[loc.index] = loc

    # 5) validación de rango y vacíos
    valid = out.notna()
    valid.loc[valid] = _range_ok(out[valid])
    for idx in values.index[~valid]:
        raw = _txt(as_text.get(idx))
        reason = "marca de tiempo vacía" if not raw else f"marca de tiempo inválida: «{str(raw)[:40]}»"
        issues.setdefault(idx, []).append(reason)
    out[~valid] = pd.NaT
    return out, issues


def _txt(v) -> str | None:
    return v if isinstance(v, str) and v else None


def _norm_user(v: str | None) -> str | None:
    v = _txt(v)
    if not v:
        return None
    u = v.strip()
    if "\\" in u:
        u = u.split("\\")[-1]
    if "@" in u and not u.startswith("@"):
        u = u.split("@")[0]
    return u.lower() or None


def _norm_host(v: str | None) -> str | None:
    v = _txt(v)
    if not v:
        return None
    h = v.strip().strip("\\")
    try:
        ipaddress.ip_address(h)
        return h
    except ValueError:
        pass
    return h.split(".")[0].upper() or None


def _norm_ip(v: str | None) -> str | None:
    v = _txt(v)
    if not v:
        return None
    s = v.strip()
    if s.startswith("::ffff:"):
        s = s[7:]
    m = re.match(r"^\[?([0-9a-fA-F:.]+)\]?(?::\d+)?$", s)
    candidate = m.group(1) if m else s
    try:
        return str(ipaddress.ip_address(candidate))
    except ValueError:
        return s


def _norm_logon_type(v: str | None) -> str | None:
    v = _txt(v)
    if not v:
        return None
    s = v.strip().lower().replace(" ", "")
    if re.fullmatch(r"\d+(\.0+)?", s):
        return str(int(float(s)))
    return LOGON_TYPE_NAMES.get(s, v.strip())


def _norm_event_id(v: str | None) -> str | None:
    v = _txt(v)
    if not v:
        return None
    s = v.strip()
    if re.fullmatch(r"\d+(\.0+)?", s):
        return str(int(float(s)))
    return s


_DEST_IP_PORT = re.compile(r"^\[?([0-9a-fA-F:.]+?)\]?(?::(\d{1,5}))?$")
_DEST_HOST_PORT = re.compile(r"^([A-Za-z0-9][A-Za-z0-9_.-]*)(?::(\d{1,5}))?$")
_UNC = re.compile(r"^\\\\([^\\]+)\\([^\\]+)")
_LOGON_TYPE_TXT = re.compile(r"logon\s*type\s*[=:]?\s*(\d{1,2})", re.IGNORECASE)
_SOURCE_HOST_TXT = re.compile(r"\b(?:source|workstation(?:\s*name)?)\s*[=:]\s*([A-Za-z0-9][A-Za-z0-9_.-]*)", re.IGNORECASE)
_BYTES_OUT_TXT = re.compile(r"\b(?:bytes_out|bytesout|sent_bytes|bytes_sent|cs-bytes)\s*[=:]\s*(\d+)", re.IGNORECASE)


def _split_destination(value):
    """«DC-01», «198.51.100.88:443» o «\\\\FS-SRV01\\Finance» → (ip, puerto, host, share)."""
    if not isinstance(value, str) or not value:
        return None, None, None, None
    v = value.strip()
    m = _UNC.match(v)
    if m:
        return None, None, _norm_host(m.group(1)), f"\\\\*\\{m.group(2)}"
    m = _DEST_IP_PORT.match(v)
    if m:
        try:
            return str(ipaddress.ip_address(m.group(1))), m.group(2), None, None
        except ValueError:
            pass
    m = _DEST_HOST_PORT.match(v)
    if m:
        return None, m.group(2), _norm_host(m.group(1)), None
    return None, None, None, None


def derive_embedded_fields(df: pd.DataFrame) -> None:
    """Completa campos canónicos que algunos SIEM embeben en otras columnas.

    Solo rellena valores vacíos: lo mapeado explícitamente por el analista siempre tiene prioridad.
    """
    if df["destination"].notna().any():
        parts = df["destination"].map(_split_destination)
        for i, col in enumerate(("dst_ip", "port", "dst_host", "share")):
            derived = parts.map(lambda p: p[i])
            df[col] = df[col].where(df[col].notna(), derived)
    text = (df["message"].fillna("") + " " + df["command_line"].fillna(""))
    lt = text.str.extract(_LOGON_TYPE_TXT, expand=False)
    df["logon_type"] = df["logon_type"].where(df["logon_type"].notna(), lt.map(_norm_logon_type))
    src_host = text.str.extract(_SOURCE_HOST_TXT, expand=False).map(_norm_host)
    df["src_host"] = df["src_host"].where(df["src_host"].notna(), src_host)
    by_text = pd.to_numeric(text.str.extract(_BYTES_OUT_TXT, expand=False), errors="coerce")
    by_col = pd.to_numeric(df["bytes_out"], errors="coerce")
    df["bytes_out_n"] = by_col.where(by_col.notna(), by_text)


def derive_semantics(df: pd.DataFrame) -> pd.Series:
    sem_cfg = settings.event_semantics()
    id_map = {str(k): v for k, v in sem_cfg["event_ids"].items()}
    ok_words = {str(w).lower() for w in sem_cfg["outcome_keywords"]["success"]}
    fail_words = {str(w).lower() for w in sem_cfg["outcome_keywords"]["failure"]}
    sem = pd.Series([id_map.get(e) if isinstance(e, str) else None for e in df["event_id"]], index=df.index, dtype=object)
    outcome = df["outcome"].fillna("").str.lower().str.strip()
    no_proc = df["process"].isna() & df["command_line"].isna()
    looks_auth = no_proc & (df["user"].notna()) & (df["src_ip"].notna() | df["logon_type"].notna())
    action = df["action"].fillna("").str.lower()
    looks_auth |= no_proc & action.str.contains(r"log ?on|login|inicio de sesi|auth", regex=True)
    missing = sem.isna()
    sem[missing & looks_auth & outcome.isin(ok_words)] = "auth_ok"
    sem[missing & looks_auth & outcome.isin(fail_words)] = "auth_fail"
    sem[sem.isna() & ~no_proc] = "process_create"
    return sem


def build_events(sheets: dict[str, pd.DataFrame], selections: list[dict], tz: str,
                 dayfirst: bool = True) -> tuple[pd.DataFrame, dict]:
    """selections: [{"name": hoja, "mapping": {campo: columna}}]."""
    frames = []
    quality = {"total_rows": 0, "valid_rows": 0, "invalid_rows": 0, "issue_rows": [], "formula_cells": 0,
               "fields_present": [], "sheets": [], "timezone": tz, "dayfirst": dayfirst}
    for sel in selections:
        name = sel["name"]
        mapping = {k: v for k, v in (sel.get("mapping") or {}).items() if v}
        src = sheets[name]
        n = len(src)
        data: dict[str, object] = {
            "row_id": [f"{name}!{int(i) + 2}" for i in src.index],
            "sheet": name,
            "excel_row": [int(i) + 2 for i in src.index],
        }
        row_issues: dict = {}
        formula_cells = 0
        for field in TEXT_FIELDS:
            col = mapping.get(field)
            if col and col in src.columns:
                cleaned = [clean_text(v) for v in src[col]]
                for idx, value in zip(src.index, cleaned):
                    if looks_like_formula(value):
                        formula_cells += 1
                        row_issues.setdefault(idx, []).append(f"posible inyección de fórmula en «{col}» (neutralizada)")
                data[field] = cleaned
            else:
                data[field] = [None] * n
        for field in ("lat", "lon"):
            col = mapping.get(field)
            data[field] = pd.to_numeric(src[col], errors="coerce").values if col in src.columns else np.nan
        ts_col = mapping.get("timestamp")
        if ts_col and ts_col in src.columns:
            ts, ts_issues = parse_timestamps(src[ts_col], tz, dayfirst)
            for idx, iss in ts_issues.items():
                row_issues.setdefault(idx, []).extend(iss)
            data["ts"] = ts.values
        else:
            data["ts"] = pd.Series(pd.NaT, index=src.index, dtype=f"datetime64[us, {tz}]").values
            for idx in src.index:
                row_issues.setdefault(idx, []).append("hoja sin columna de fecha mapeada")
        raw_cols = list(src.columns)
        data["raw"] = [{c: clean_text(v) for c, v in zip(raw_cols, row)} for row in src.itertuples(index=False)]
        frame = pd.DataFrame(data, index=src.index)
        frame["issues"] = [row_issues.get(i, []) for i in src.index]
        frames.append(frame)
        quality["sheets"].append({"name": name, "rows": n, "mapping": mapping})
        quality["formula_cells"] += formula_cells

    df = pd.concat(frames, ignore_index=True) if frames else pd.DataFrame()
    df["ts"] = pd.to_datetime(df["ts"], utc=True).dt.tz_convert(tz)
    df["user"] = df["user"].map(_norm_user)
    df["target_user"] = df["target_user"].map(_norm_user)
    df["host"] = df["host"].map(_norm_host)
    df["src_host"] = df["src_host"].map(_norm_host)
    df["dst_host"] = df["dst_host"].map(_norm_host)
    df["src_ip"] = df["src_ip"].map(_norm_ip)
    df["dst_ip"] = df["dst_ip"].map(_norm_ip)
    df["assigned_ip"] = df["assigned_ip"].map(_norm_ip)
    df["logon_type"] = df["logon_type"].map(_norm_logon_type)
    df["event_id"] = df["event_id"].map(_norm_event_id)
    df["country"] = df["country"].map(lambda c: c.upper() if isinstance(c, str) else None)
    derive_embedded_fields(df)
    df["sem"] = derive_semantics(df)
    df["valid_ts"] = df["ts"].notna()
    df["ts_iso"] = df["ts"].map(lambda t: t.isoformat() if pd.notna(t) else None)

    quality["total_rows"] = int(len(df))
    quality["valid_rows"] = int(df["valid_ts"].sum())
    quality["invalid_rows"] = int((~df["valid_ts"]).sum())
    quality["issue_rows"] = [{"row_id": r, "issues": i, "valid": bool(v)}
                             for r, i, v in zip(df["row_id"], df["issues"], df["valid_ts"]) if i]
    quality["fields_present"] = [f for f in CANONICAL_FIELDS
                                 if (f == "timestamp" and quality["valid_rows"] > 0)
                                 or (f in df.columns and f != "timestamp" and df[f].notna().any())]
    if quality["valid_rows"]:
        quality["date_min"] = df.loc[df["valid_ts"], "ts"].min().isoformat()
        quality["date_max"] = df.loc[df["valid_ts"], "ts"].max().isoformat()
    return df, quality
