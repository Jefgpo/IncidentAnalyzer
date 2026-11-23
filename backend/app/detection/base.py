"""Tipos base del motor de detección: Rule, Finding y Context."""
from __future__ import annotations

import ipaddress
import re
from dataclasses import asdict, dataclass, field
from functools import lru_cache
from typing import Callable

import numpy as np
import pandas as pd

TACTICS: dict[str, dict] = {
    "initial_access": {"es": "Acceso inicial", "en": "Initial Access", "id": "TA0001"},
    "execution": {"es": "Ejecución", "en": "Execution", "id": "TA0002"},
    "persistence": {"es": "Persistencia", "en": "Persistence", "id": "TA0003"},
    "privilege_escalation": {"es": "Escalamiento de privilegios", "en": "Privilege Escalation", "id": "TA0004"},
    "defense_evasion": {"es": "Evasión de defensas", "en": "Defense Evasion", "id": "TA0005"},
    "credential_access": {"es": "Acceso a credenciales", "en": "Credential Access", "id": "TA0006"},
    "discovery": {"es": "Descubrimiento", "en": "Discovery", "id": "TA0007"},
    "lateral_movement": {"es": "Movimiento lateral", "en": "Lateral Movement", "id": "TA0008"},
    "collection": {"es": "Recolección", "en": "Collection", "id": "TA0009"},
    "command_and_control": {"es": "Comando y control", "en": "Command and Control", "id": "TA0011"},
    "exfiltration": {"es": "Exfiltración", "en": "Exfiltration", "id": "TA0010"},
    "impact": {"es": "Impacto", "en": "Impact", "id": "TA0040"},
    "anomaly": {"es": "Anomalía (sin táctica)", "en": "Anomaly (no tactic)", "id": "—"},
}

CATEGORIES: dict[str, dict] = {
    "bruteforce": {"es": "Fuerza bruta", "en": "Brute force"},
    "suspicious_logon": {"es": "Inicios de sesión sospechosos", "en": "Suspicious logons"},
    "privesc": {"es": "Escalamiento de privilegios", "en": "Privilege escalation"},
    "execution": {"es": "Comandos y procesos sospechosos", "en": "Suspicious commands & processes"},
    "lateral": {"es": "Movimiento lateral", "en": "Lateral movement"},
    "collection": {"es": "Recolección y exfiltración", "en": "Collection & exfiltration"},
    "web": {"es": "Ataques a servicios web", "en": "Web attacks"},
    "anomaly": {"es": "Otras anomalías", "en": "Other anomalies"},
}

ENTITY_KEYS = ("user", "host", "src_ip", "hash")


@dataclass
class Finding:
    rule_id: str
    title: str
    summary: str
    rows: list[str]
    start: str | None
    end: str | None
    entities: dict[str, list[str]] = field(default_factory=dict)   # vinculan en la correlación
    related: dict[str, list[str]] = field(default_factory=dict)    # solo informativas
    metrics: dict = field(default_factory=dict)
    auth_success: bool | None = None      # None = no aplica (no es una regla de autenticación)
    confidence: str = "media"
    fp_notes: list[str] = field(default_factory=list)
    details: list[str] = field(default_factory=list)
    # completados por el motor
    id: str = ""
    rule_name: str = ""
    category: str = ""
    tactic: str = ""
    mitre: list[dict] = field(default_factory=list)
    is_anomaly: bool = False
    score: int = 0
    severity: str = ""
    score_factors: list[dict] = field(default_factory=list)
    incident_id: str | None = None

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class Rule:
    id: str
    name: str
    name_en: str
    category: str
    tactic: str
    mitre: list[tuple[str, str]]
    description: str
    description_en: str
    requires: list[str]                 # cada elemento: "campo" o "campoA|campoB" (cualquiera)
    fn: Callable[["Context", dict], list[Finding]]
    fp_hint: str = ""

    def missing(self, ctx: "Context") -> list[str]:
        return [req for req in self.requires if not any(ctx.has(f) for f in req.split("|"))]

    def meta(self) -> dict:
        return {"id": self.id, "name": self.name, "name_en": self.name_en, "category": self.category,
                "tactic": self.tactic, "mitre": [{"id": m, "name": n} for m, n in self.mitre],
                "description": self.description, "description_en": self.description_en,
                "requires": self.requires, "fp_hint": self.fp_hint}


class Context:
    """Datos + configuración + utilidades compartidas por todas las reglas."""

    def __init__(self, events: pd.DataFrame, cfg: dict):
        self.cfg = cfg
        g = cfg["general"]
        self.general = g
        self.all = events
        self.df = events[events["valid_ts"]].sort_values("ts", kind="stable").reset_index(drop=True)
        # la zona horaria es la que eligió el analista al normalizar (la del config es solo el valor por defecto)
        ts_tz = getattr(getattr(events.get("ts"), "dt", None), "tz", None) if len(events) else None
        self.tz = str(ts_tz) if ts_tz is not None else g["timezone"]
        self._nets = [ipaddress.ip_network(n) for n in g["internal_networks"]]
        self._svc = [re.compile(p, re.IGNORECASE) for p in g["service_account_patterns"]]
        self._crit = [re.compile(p, re.IGNORECASE) for p in g["critical_host_patterns"]]
        self.priv_groups = {x.lower() for x in g["privileged_groups"]}
        self.ignore = {str(x).lower() for x in g["ignore_entities"]}
        self.remote_types = {str(x) for x in g["remote_logon_types"]}
        self.interactive_types = {str(x) for x in g["interactive_logon_types"]}
        self.present = {c for c in events.columns if events[c].notna().any()}
        if self.df.empty:
            self.baseline_end = None
            self.span_hours = 0.0
        else:
            tmin, tmax = self.df["ts"].min(), self.df["ts"].max()
            self.span_hours = (tmax - tmin).total_seconds() / 3600
            # Con pocas horas de logs la «primera mitad» no representa el comportamiento normal:
            # sin línea base, las reglas que la usan aplican su criterio alternativo.
            if self.span_hours >= float(g.get("min_baseline_hours", 48)):
                self.baseline_end = tmin + (tmax - tmin) * float(g.get("baseline_fraction", 0.5))
            else:
                self.baseline_end = None
        self._allow = [ipaddress.ip_network(n, strict=False) for n in g.get("external_ip_allowlist") or []]
        # texto buscable: línea de comando + imagen + descripción (algunos SIEM ponen el comando en la descripción)
        text = (self.df["command_line"].fillna("") + " " + self.df["process"].fillna("") + " "
                + self.df["message"].fillna("")).str.lower()
        self.cmd_text = text
        self.covered_rows: set[str] = set()
        self._compute_privileged()

    # ------------------------------------------------------------------ utilidades
    def has(self, field_name: str) -> bool:
        if field_name == "timestamp":
            return bool(self.df.shape[0])
        if field_name == "auth":
            return self.has("event_id") or self.has("outcome")
        if field_name == "geo":
            return self.has("lat") and self.has("lon")
        if field_name == "bytes_out":
            return "bytes_out_n" in self.present
        return field_name in self.present

    @lru_cache(maxsize=65536)
    def ip_kind(self, ip: str) -> str:
        try:
            addr = ipaddress.ip_address(ip)
        except (ValueError, TypeError):
            return "invalid"
        return "internal" if any(addr in n for n in self._nets if addr.version == n.version) else "external"

    def is_external(self, ip) -> bool:
        return isinstance(ip, str) and self.ip_kind(ip) == "external"

    def is_allowlisted(self, ip) -> bool:
        try:
            addr = ipaddress.ip_address(ip)
        except (ValueError, TypeError):
            return False
        return any(addr in n for n in self._allow if addr.version == n.version)

    def is_service(self, user) -> bool:
        return isinstance(user, str) and any(p.search(user) for p in self._svc)

    def is_critical(self, host) -> bool:
        return isinstance(host, str) and any(p.search(host) for p in self._crit)

    def is_ignored(self, value) -> bool:
        return not isinstance(value, str) or value.lower() in self.ignore

    def is_privileged(self, user, at=None) -> bool:
        """Cuenta privilegiada; con `at`, solo cuenta promociones/4672 observados hasta ese momento."""
        if not isinstance(user, str):
            return False
        u = user.lower()
        if u in self.privileged_baseline or "admin" in u:
            return True
        since = self.privileged_since.get(u)
        if since is None:
            return False
        return at is None or since <= pd.Timestamp(at)

    def off_hours(self, ts: pd.Series) -> pd.Series:
        bh = self.general["business_hours"]
        local = ts.dt.tz_convert(self.tz)
        in_day = local.dt.weekday.isin(bh["weekdays"])
        in_hours = (local.dt.hour >= bh["start"]) & (local.dt.hour < bh["end"])
        return ~(in_day & in_hours)

    def after_baseline(self, ts: pd.Series) -> pd.Series:
        if self.baseline_end is None:
            return pd.Series(False, index=ts.index)
        return ts > self.baseline_end

    def in_priv_group(self, group) -> bool:
        return isinstance(group, str) and group.strip().lower() in self.priv_groups

    def _compute_privileged(self) -> None:
        df = self.df
        configured = {str(a).lower() for a in self.general["privileged_accounts"]}
        base = df[~self.after_baseline(df["ts"])] if len(df) else df
        holders = set(base.loc[base["sem"] == "special_priv", "user"].dropna().str.lower())
        self.privileged_baseline = configured | holders
        adds = df[(df["sem"] == "group_add") & df["group"].map(self.in_priv_group)]
        member = adds["target_user"].fillna(adds["user"]).str.lower()
        holders_all = df[df["sem"] == "special_priv"]
        since = pd.concat([pd.Series(adds["ts"].tolist(), index=member.tolist(), dtype=object),
                           pd.Series(holders_all["ts"].tolist(),
                                     index=holders_all["user"].fillna("").str.lower().tolist(), dtype=object)])
        since = since[since.index != ""]
        self.privileged_since = since.groupby(level=0).min().to_dict() if len(since) else {}


# ---------------------------------------------------------------------- helpers
def iso(ts) -> str | None:
    return ts.isoformat() if ts is not None and pd.notna(ts) else None


def uniq(values) -> list[str]:
    out: list[str] = []
    for v in values:
        if isinstance(v, str) and v and v not in out:
            out.append(v)
    return out


def make_finding(rule_id: str, sub: pd.DataFrame, title: str, summary: str, ctx: Context,
                 entity_cols=("user", "host", "src_ip"), related_cols=(), **kw) -> Finding:
    entities = {}
    for col in entity_cols:
        vals = [v for v in uniq(sub[col]) if not ctx.is_ignored(v)] if col in sub else []
        if vals:
            entities[col] = vals
    related = {}
    for col in related_cols:
        vals = uniq(sub[col]) if col in sub else []
        if vals:
            related[col] = vals[:50]
    return Finding(rule_id=rule_id, title=title, summary=summary, rows=list(sub["row_id"]),
                   start=iso(sub["ts"].min()), end=iso(sub["ts"].max()), entities=entities,
                   related=related, **kw)


def bursts(times: np.ndarray, window: pd.Timedelta, k: int) -> list[tuple[int, int]]:
    """Tramos (i0, i1) donde cada evento pertenece a alguna ventana con ≥ k eventos."""
    if len(times) < k:
        return []
    t = times.astype("datetime64[ns]").astype(np.int64)
    ends = np.searchsorted(t, t + window.value, side="right")
    counts = ends - np.arange(len(t))
    spans: list[list[int]] = []
    for i in np.where(counts >= k)[0]:
        s, e = int(i), int(ends[i] - 1)
        if spans and s <= spans[-1][1]:
            spans[-1][1] = max(spans[-1][1], e)
        else:
            spans.append([s, e])
    return [(a, b) for a, b in spans]


def distinct_bursts(times: np.ndarray, keys: list, window: pd.Timedelta, k: int) -> list[tuple[int, int]]:
    """Como `bursts`, pero exige ≥ k valores distintos de `keys` dentro de la ventana."""
    t = times.astype("datetime64[ns]").astype(np.int64)
    ends = np.searchsorted(t, t + window.value, side="right")
    spans: list[list[int]] = []
    for i in range(len(t)):
        if len(set(keys[i:ends[i]])) >= k:
            s, e = i, int(ends[i] - 1)
            if spans and s <= spans[-1][1]:
                spans[-1][1] = max(spans[-1][1], e)
            else:
                spans.append([s, e])
    return [(a, b) for a, b in spans]


def clusters(sub: pd.DataFrame, keys: list[str], gap: pd.Timedelta):
    """Agrupa filas por `keys` y separa en tramos cuando el hueco temporal supera `gap`."""
    if sub.empty:
        return
    grouped = sub.groupby(keys, dropna=False, sort=False) if keys else [((), sub)]
    for key, g in grouped:
        g = g.sort_values("ts")
        split = (g["ts"].diff() > gap).cumsum()
        for _, part in g.groupby(split, sort=False):
            yield key, part
