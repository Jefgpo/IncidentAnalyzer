"""Mapeo automático de columnas a campos canónicos (por nombre y por contenido)."""
from __future__ import annotations

import difflib
import ipaddress
import re
import unicodedata

import pandas as pd

from app import settings

CANONICAL_FIELDS: dict[str, str] = {
    "timestamp": "Fecha/hora del evento",
    "log_id": "ID del evento en el SIEM",
    "log_source": "Fuente del log (Security, Proxy…)",
    "user": "Usuario / cuenta",
    "target_user": "Cuenta destino / miembro",
    "host": "Host / equipo",
    "src_ip": "IP origen",
    "dst_ip": "IP destino",
    "destination": "Destino (host, IP:puerto o ruta)",
    "dst_host": "Host destino",
    "src_host": "Host origen",
    "event_id": "EventID",
    "action": "Acción / tipo de evento",
    "outcome": "Resultado",
    "logon_type": "Tipo de inicio de sesión",
    "process": "Proceso / imagen",
    "parent_process": "Proceso padre",
    "command_line": "Línea de comando",
    "hash": "Hash",
    "group": "Grupo",
    "privileges": "Privilegios",
    "share": "Recurso compartido",
    "service": "Servicio",
    "country": "País (geo)",
    "city": "Ciudad (geo)",
    "lat": "Latitud",
    "lon": "Longitud",
    "domain": "Dominio / URL",
    "port": "Puerto",
    "bytes_out": "Bytes enviados",
    "siem_severity": "Severidad del SIEM",
    "message": "Mensaje",
    "assigned_ip": "IP asignada (VPN)",
}


def normalize_header(name: str) -> str:
    text = unicodedata.normalize("NFKD", str(name)).encode("ascii", "ignore").decode().lower()
    return re.sub(r"[^a-z0-9]", "", text)


def _name_score(header: str, synonyms: list[str]) -> float:
    h = normalize_header(header)
    if not h:
        return 0.0
    best = 0.0
    for syn in synonyms:
        if h == syn:
            return 1.0
        ratio = difflib.SequenceMatcher(None, h, syn).ratio()
        if ratio >= 0.85:
            best = max(best, ratio * 0.9)
        elif len(syn) >= 6 and syn in h:
            best = max(best, 0.7)
    return best


def _is_ip(value) -> bool:
    try:
        ipaddress.ip_address(str(value).strip())
        return True
    except ValueError:
        return False


def _content_profile(series: pd.Series) -> dict[str, float]:
    sample = series.dropna().astype(str).str.strip()
    sample = sample[sample != ""].head(200)
    if sample.empty:
        return {}
    n = len(sample)
    ts = pd.to_datetime(sample, errors="coerce", dayfirst=True, format="mixed")
    return {
        "timestamp": float(ts.notna().sum()) / n,
        "ip": float(sum(_is_ip(v) for v in sample)) / n,
        "event_id": float(sample.str.fullmatch(r"\d{1,5}(\.0)?").sum()) / n,
    }


def suggest_mapping(df: pd.DataFrame) -> tuple[dict[str, str], dict[str, float]]:
    """Devuelve ({campo: columna}, {campo: confianza 0–1})."""
    syn = settings.synonyms()
    candidates: list[tuple[float, str, str]] = []
    for col in df.columns:
        for field, words in syn.items():
            score = _name_score(col, words)
            if score > 0:
                candidates.append((score, field, col))
    candidates.sort(reverse=True)
    mapping: dict[str, str] = {}
    scores: dict[str, float] = {}
    used: set[str] = set()
    for score, field, col in candidates:
        if field in mapping or col in used:
            continue
        mapping[field] = col
        scores[field] = round(score, 2)
        used.add(col)

    # Heurística por contenido para los campos más importantes
    profiles = {c: _content_profile(df[c]) for c in df.columns if c not in used}
    if "timestamp" in mapping:
        prof = _content_profile(df[mapping["timestamp"]])
        if prof.get("timestamp", 0) < 0.5:  # el nombre engañó; liberar
            used.discard(mapping.pop("timestamp"))
            scores.pop("timestamp", None)
    if "timestamp" not in mapping:
        best = max(profiles.items(), key=lambda kv: kv[1].get("timestamp", 0), default=None)
        if best and best[1].get("timestamp", 0) >= 0.8 and best[1].get("event_id", 0) < 0.5:
            mapping["timestamp"] = best[0]
            scores["timestamp"] = 0.6
            used.add(best[0])
    if "src_ip" not in mapping:
        for col, prof in profiles.items():
            if col not in used and prof.get("ip", 0) >= 0.8:
                mapping["src_ip"] = col
                scores["src_ip"] = 0.6
                used.add(col)
                break
    return mapping, scores
