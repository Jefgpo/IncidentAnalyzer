"""Filtrado, búsqueda, orden y serialización de eventos y hallazgos."""
from __future__ import annotations

import math
from dataclasses import dataclass, field

import pandas as pd

from app.ingest.mapper import CANONICAL_FIELDS

ROW_FIELDS = ["row_id", "sheet", "excel_row", "ts_iso"] + [f for f in CANONICAL_FIELDS if f != "timestamp"] + ["sem"]
SEARCH_FIELDS = ["row_id", "user", "target_user", "host", "src_ip", "dst_ip", "event_id", "outcome", "process",
                 "command_line", "group", "message", "hash", "country", "share", "service"]


def _clean(v):
    if v is None:
        return None
    if isinstance(v, float) and math.isnan(v):
        return None
    if isinstance(v, pd.Timestamp):
        return v.isoformat()
    return v


def serialize_rows(df: pd.DataFrame, row_findings: dict[str, list[str]] | None = None,
                   include_raw: bool = True) -> list[dict]:
    out = []
    cols = [c for c in ROW_FIELDS if c in df.columns]
    for rec in df[cols + (["raw"] if include_raw else []) + ["issues"]].to_dict("records"):
        item = {k: _clean(rec.get(k)) for k in cols}
        item["issues"] = rec.get("issues") or []
        if include_raw:
            item["raw"] = rec.get("raw") or {}
        if row_findings is not None:
            item["finding_ids"] = row_findings.get(item["row_id"], [])
        out.append(item)
    return out


def row_finding_index(analysis: dict | None) -> dict[str, list[str]]:
    idx: dict[str, list[str]] = {}
    if not analysis:
        return idx
    for f in analysis["findings"]:
        for r in f["rows"]:
            idx.setdefault(r, []).append(f["id"])
    return idx


@dataclass
class Filters:
    severity: list[str] = field(default_factory=list)
    category: list[str] = field(default_factory=list)
    host: list[str] = field(default_factory=list)
    user: list[str] = field(default_factory=list)
    src_ip: list[str] = field(default_factory=list)
    date_from: str | None = None
    date_to: str | None = None
    finding: list[str] = field(default_factory=list)
    incident: list[str] = field(default_factory=list)
    hour: int | None = None
    weekday: int | None = None
    sheet: list[str] = field(default_factory=list)
    event_id: list[str] = field(default_factory=list)
    rows: list[str] = field(default_factory=list)
    q: str | None = None
    only_issues: bool = False
    only_evidence: bool = False

    @staticmethod
    def _split(v) -> list[str]:
        if not v:
            return []
        if isinstance(v, list):
            return [x for item in v for x in str(item).split(",") if x]
        return [x for x in str(v).split(",") if x]

    @classmethod
    def from_params(cls, p: dict) -> "Filters":
        def to_int(v):
            try:
                return int(v) if v not in (None, "") else None
            except ValueError:
                return None
        return cls(severity=cls._split(p.get("severity")), category=cls._split(p.get("category")),
                   host=cls._split(p.get("host")), user=cls._split(p.get("user")), src_ip=cls._split(p.get("src_ip")),
                   date_from=p.get("date_from") or None, date_to=p.get("date_to") or None,
                   finding=cls._split(p.get("finding")), incident=cls._split(p.get("incident")),
                   hour=to_int(p.get("hour")), weekday=to_int(p.get("weekday")), sheet=cls._split(p.get("sheet")),
                   event_id=cls._split(p.get("event_id")), rows=cls._split(p.get("rows")), q=p.get("q") or None,
                   only_issues=str(p.get("only_issues", "")).lower() in ("1", "true"),
                   only_evidence=str(p.get("only_evidence", "")).lower() in ("1", "true"))


def _ts_bound(value: str | None, tz: str, end: bool = False):
    if not value:
        return None
    ts = pd.Timestamp(value)
    if ts.tzinfo is None:
        ts = ts.tz_localize(tz)
    if end and len(value) <= 10:  # solo fecha → incluir el día completo
        ts = ts + pd.Timedelta(days=1) - pd.Timedelta(microseconds=1)
    return ts


def filter_findings(analysis: dict, f: Filters, tz: str) -> list[dict]:
    items = analysis["findings"]
    if f.severity:
        items = [x for x in items if x["severity"] in f.severity]
    if f.category:
        items = [x for x in items if x["category"] in f.category]
    if f.finding:
        items = [x for x in items if x["id"] in f.finding]
    if f.incident:
        items = [x for x in items if x["incident_id"] in f.incident]

    def ent(x, key):
        return {v.lower() for v in x["entities"].get(key, []) + x["related"].get(key, [])}
    for key in ("host", "user", "src_ip"):
        wanted = {v.lower() for v in getattr(f, key)}
        if wanted:
            items = [x for x in items if ent(x, key) & wanted]
    lo, hi = _ts_bound(f.date_from, tz), _ts_bound(f.date_to, tz, end=True)
    if lo is not None:
        items = [x for x in items if x["end"] and pd.Timestamp(x["end"]) >= lo]
    if hi is not None:
        items = [x for x in items if x["start"] and pd.Timestamp(x["start"]) <= hi]
    return items


def filter_events(df: pd.DataFrame, f: Filters, tz: str, analysis: dict | None) -> pd.DataFrame:
    out = df
    finding_filters = f.severity or f.category or f.finding or f.incident or f.only_evidence
    if finding_filters and analysis:
        sel = filter_findings(analysis, Filters(severity=f.severity, category=f.category, finding=f.finding,
                                                incident=f.incident), tz)
        rows = {r for x in sel for r in x["rows"]}
        out = out[out["row_id"].isin(rows)]
    if f.rows:
        out = out[out["row_id"].isin(set(f.rows))]
    for key in ("host", "user", "src_ip"):
        wanted = {v.lower() for v in getattr(f, key)}
        if wanted:
            col = out[key].fillna("").str.lower()
            mask = col.isin(wanted)
            if key == "user":
                mask |= out["target_user"].fillna("").str.lower().isin(wanted)
            if key == "src_ip":
                mask |= out["dst_ip"].fillna("").str.lower().isin(wanted)
            out = out[mask]
    if f.sheet:
        out = out[out["sheet"].isin(f.sheet)]
    if f.event_id:
        out = out[out["event_id"].isin(f.event_id)]
    lo, hi = _ts_bound(f.date_from, tz), _ts_bound(f.date_to, tz, end=True)
    if lo is not None:
        out = out[out["ts"] >= lo]
    if hi is not None:
        out = out[out["ts"] <= hi]
    if f.hour is not None or f.weekday is not None:
        local = out["ts"].dt.tz_convert(tz)
        if f.hour is not None:
            out = out[local.dt.hour == f.hour]
            local = out["ts"].dt.tz_convert(tz)
        if f.weekday is not None:
            out = out[local.dt.weekday == f.weekday]
    if f.only_issues:
        out = out[out["issues"].map(bool).astype(bool)]
    if f.q:
        q = f.q.lower()
        mask = pd.Series(False, index=out.index)
        for col in SEARCH_FIELDS:
            if col in out:
                mask |= out[col].fillna("").astype(str).str.lower().str.contains(q, regex=False)
        out = out[mask]
    return out


def sort_events(df: pd.DataFrame, sort: str | None, order: str | None) -> pd.DataFrame:
    col = sort if sort in df.columns and sort not in ("raw", "issues") else "ts"
    if col == "ts_iso":
        col = "ts"
    asc = (order or "asc").lower() != "desc"
    if col == "row_id":
        return df.sort_values(["sheet", "excel_row"], ascending=asc, kind="stable")
    return df.sort_values(col, ascending=asc, kind="stable", na_position="last")
