"""Agregados del dashboard (los mismos alimentan los gráficos del PDF)."""
from __future__ import annotations

import re

import pandas as pd

from app.analytics.query import Filters, filter_events, filter_findings
from app.detection.base import CATEGORIES
from app.scoring.risk import SEVERITIES

WEEKDAYS_ES = ["Lun", "Mar", "Mié", "Jue", "Vie", "Sáb", "Dom"]
_TARGET_RX = re.compile(r"\\\\([A-Za-z0-9_.-]+)\\|/node:\"?([A-Za-z0-9_.-]+)|-computername\s+([A-Za-z0-9_.-]+)",
                        re.IGNORECASE)


def _top(series: pd.Series, evidence: pd.Series, n: int = 10) -> list[dict]:
    counts = series.dropna().value_counts().head(n)
    ev_counts = evidence.dropna().value_counts()
    return [{"value": k, "events": int(v), "evidence": int(ev_counts.get(k, 0))} for k, v in counts.items()]


def lateral_graph(df: pd.DataFrame, findings: list[dict]) -> dict:
    """Grafo de movimiento lateral a partir de las filas de evidencia de hallazgos (no anomalías)."""
    ev_rows = {r for f in findings if f["category"] != "anomaly" for r in f["rows"]}
    lm_rows = {r for f in findings if f["category"] == "lateral" for r in f["rows"]}
    local = df[(df["sem"] == "auth_ok") & (df["logon_type"] == "2") & df["host"].notna() & df["src_ip"].notna()]
    ip_to_host = local.groupby("src_ip")["host"].agg(lambda s: s.value_counts().index[0]).to_dict()
    ev = df[df["row_id"].isin(ev_rows)]
    edges: dict[tuple[str, str], dict] = {}

    def add(src, dst, row_id, kind, user):
        if not src or not dst or src == dst:
            return
        e = edges.setdefault((src, dst), {"source": src, "target": dst, "count": 0, "rows": [], "kinds": [],
                                          "users": [], "lateral": False})
        e["count"] += 1
        if len(e["rows"]) < 20:
            e["rows"].append(row_id)
        if kind not in e["kinds"]:
            e["kinds"].append(kind)
        if isinstance(user, str) and user not in e["users"]:
            e["users"].append(user)
        e["lateral"] |= row_id in lm_rows

    remote = ev[(ev["sem"] == "auth_ok") & ev["logon_type"].isin(["3", "10"]) & ev["host"].notna()]
    for r in remote.itertuples():
        src = r.src_host if isinstance(r.src_host, str) else ip_to_host.get(r.src_ip, r.src_ip)
        add(src, r.host, r.row_id, "RDP" if r.logon_type == "10" else "logon de red", r.user)
    for r in ev[ev["command_line"].notna()].itertuples():
        for m in _TARGET_RX.finditer(r.command_line):
            target = next(g for g in m.groups() if g).split(".")[0].upper()
            if target and not target.endswith("$") and r.host:
                add(r.host, target, r.row_id, "ejecución remota", r.user)
    for r in ev[ev["share"].notna() & ev["src_ip"].notna()].itertuples():
        add(ip_to_host.get(r.src_ip, r.src_ip), r.host, r.row_id, f"share {r.share}", r.user)
    nodes: dict[str, dict] = {}
    for e in edges.values():
        for name in (e["source"], e["target"]):
            nodes.setdefault(name, {"id": name, "kind": "ip" if re.fullmatch(r"[\d.:a-f]+", name, re.I) else "host",
                                    "in": 0, "out": 0})
        nodes[e["source"]]["out"] += e["count"]
        nodes[e["target"]]["in"] += e["count"]
    return {"nodes": list(nodes.values()), "edges": list(edges.values())}


def build_dashboard(session, params: dict, lang: str = "es") -> dict:
    analysis = session.analysis_in(lang)
    df = session.events
    tz = session.quality["timezone"]
    f = Filters.from_params(params)
    findings = filter_findings(analysis, f, tz) if analysis else []
    events = filter_events(df[df["valid_ts"]], f, tz, analysis)
    ev_rows = {r for x in findings if x["category"] != "anomaly" for r in x["rows"]}
    evidence = events[events["row_id"].isin(ev_rows)]
    incidents = [i for i in (analysis or {}).get("incidents", [])
                 if set(i["finding_ids"]) & {x["id"] for x in findings}]

    sev_counts = {s: 0 for s in SEVERITIES}
    for x in findings:
        sev_counts[x["severity"]] = sev_counts.get(x["severity"], 0) + 1
    cat_counts = []
    for key, label in CATEGORIES.items():
        sub = [x for x in findings if x["category"] == key]
        cat_counts.append({"category": key, "label": label["es"], "label_en": label["en"], "count": len(sub),
                           **{s: sum(1 for x in sub if x["severity"] == s) for s in SEVERITIES}})

    def affected(key):
        # solo entidades de hallazgos que forman parte de incidentes candidatos (no aislados/anomalías)
        return sorted({v for x in findings if x["category"] != "anomaly" and x["incident_id"]
                       for v in x["entities"].get(key, [])})

    local = events["ts"].dt.tz_convert(tz)
    hourly = local.dt.floor("h", ambiguous="NaT", nonexistent="shift_forward") if len(events) else local
    by_hour = events.groupby(hourly).size()
    ev_local = evidence["ts"].dt.tz_convert(tz)
    ev_hour = evidence.groupby(ev_local.dt.floor("h", ambiguous="NaT", nonexistent="shift_forward")).size() \
        if len(evidence) else pd.Series(dtype=int)
    spikes = {pd.Timestamp(x["start"]).tz_convert(tz).floor("h").isoformat()
              for x in (analysis or {}).get("findings", []) if x["rule_id"] == "AN-001"}
    timeline = []
    if len(by_hour):
        full = pd.date_range(by_hour.index.min(), by_hour.index.max(), freq="h")
        for ts in full:
            timeline.append({"ts": ts.isoformat(), "events": int(by_hour.get(ts, 0)),
                             "evidence": int(ev_hour.get(ts, 0)), "spike": ts.isoformat() in spikes})
    heat = pd.crosstab(local.dt.weekday, local.dt.hour) if len(events) else pd.DataFrame()
    heat_ev = pd.crosstab(ev_local.dt.weekday, ev_local.dt.hour) if len(evidence) else pd.DataFrame()
    heatmap = [{"weekday": d, "label": WEEKDAYS_ES[d], "hour": h,
                "events": int(heat.at[d, h]) if d in heat.index and h in heat.columns else 0,
                "evidence": int(heat_ev.at[d, h]) if d in heat_ev.index and h in heat_ev.columns else 0}
               for d in range(7) for h in range(24)]

    return {
        "filters": params,
        "kpis": {
            "total_events": int(len(events)),
            "total_rows": int(len(df)),
            "invalid_rows": int((~df["valid_ts"]).sum()),
            "findings": len(findings),
            "findings_core": sum(1 for x in findings if x["category"] != "anomaly"),
            "anomalies": sum(1 for x in findings if x["category"] == "anomaly"),
            "incidents": len(incidents),
            "by_severity": sev_counts,
            "affected_hosts": affected("host"),
            "affected_users": affected("user"),
            "affected_ips": affected("src_ip"),
        },
        "by_severity": [{"severity": s, "count": c} for s, c in sev_counts.items()],
        "by_category": cat_counts,
        "timeline": timeline,
        "top_ips": _top(events["src_ip"], evidence["src_ip"]),
        "top_users": _top(events["user"], evidence["user"]),
        "top_hosts": _top(events["host"], evidence["host"]),
        "heatmap": heatmap,
        "lateral": lateral_graph(df[df["valid_ts"]], findings),
        "incidents": [{"id": i["id"], "title": i["title"], "severity": i["severity"], "score": i["score"],
                       "start": i["start"], "end": i["end"]} for i in incidents],
        "date_range": {"min": session.quality.get("date_min"), "max": session.quality.get("date_max")},
        "options": {
            "hosts": sorted(df["host"].dropna().unique().tolist()),
            "users": sorted(df["user"].dropna().unique().tolist()),
        },
    }
