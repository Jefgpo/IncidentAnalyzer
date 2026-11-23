"""Correlación de hallazgos en incidentes candidatos y conclusión «uno vs varios»."""
from __future__ import annotations

import re

import pandas as pd

from app.detection.base import TACTICS, Context, Finding, uniq
from app.lang import sev, tx
from app.scoring.risk import score_finding, score_incident


def _entity_label(kind: str) -> str:
    labels = {"user": tx("usuario", "user"), "host": "host", "src_ip": "IP", "hash": "hash",
              "pivote": tx("ejecución remota hacia", "remote execution to")}
    return labels.get(kind, kind)


def _ts(value: str | None) -> pd.Timestamp | None:
    return pd.Timestamp(value) if value else None


def _gap_hours(a: Finding, b: Finding) -> float:
    a0, a1, b0, b1 = _ts(a.start), _ts(a.end), _ts(b.start), _ts(b.end)
    if None in (a0, a1, b0, b1):
        return 0.0
    gap = max(pd.Timedelta(0), b0 - a1, a0 - b1)
    return gap.total_seconds() / 3600


def _keys(f: Finding) -> set[tuple[str, str]]:
    return {(k, v.lower()) for k, vals in f.entities.items() for v in vals}


class _UF:
    def __init__(self, n: int):
        self.p = list(range(n))

    def find(self, x: int) -> int:
        while self.p[x] != x:
            self.p[x] = self.p[self.p[x]]
            x = self.p[x]
        return x

    def union(self, a: int, b: int) -> None:
        self.p[self.find(a)] = self.find(b)


_REMOTE_TARGET = re.compile(r"\\\\([A-Za-z0-9_.-]+)|/node:\"?([A-Za-z0-9_.-]+)|-computername\s+([A-Za-z0-9_.-]+)",
                            re.IGNORECASE)


def _remote_targets(ctx: Context, core: list[Finding]) -> dict[str, set[str]]:
    """Hosts a los que apuntan herramientas de ejecución remota (PsExec \\\\HOST, WMIC /node:HOST, WinRM)."""
    out: dict[str, set[str]] = {}
    for f in core:
        if f.rule_id != "LM-003":
            continue
        rows = ctx.df[ctx.df["row_id"].isin(f.rows)]
        for cmd in rows["command_line"].dropna():
            for m in _REMOTE_TARGET.finditer(cmd):
                target = next(g for g in m.groups() if g).split(".")[0].upper()
                if not target.endswith("$"):
                    out.setdefault(f.id, set()).add(target)
    return out


def _rows_with(ctx: Context, f: Finding, key: str, value: str, limit: int = 3) -> list[str]:
    rows = ctx.df[ctx.df["row_id"].isin(f.rows)]
    if key not in rows:  # vínculos derivados (p. ej. pivote) no corresponden a una columna
        return f.rows[:limit]
    col = rows[key].fillna("").str.lower()
    hit = rows.loc[col == value, "row_id"].tolist()
    return hit[:limit] or f.rows[:1]


def describe_row(r) -> str:
    parts = []
    log_id = r.get("log_id")
    if isinstance(log_id, str) and log_id:
        parts.append(log_id)
    eid = r.get("event_id")
    if isinstance(eid, str):
        parts.append(f"EventID {eid}")
    for label, col in ((tx("usuario", "user"), "user"), ("host", "host"), ("IP", "src_ip")):
        v = r.get(col)
        if isinstance(v, str):
            parts.append(f"{label} {v}")
    lt = r.get("logon_type")
    if isinstance(lt, str):
        parts.append(tx("logon tipo ", "logon type ") + lt)
    for col in ("command_line", "group", "service", "share"):
        v = r.get(col)
        if isinstance(v, str):
            parts.append(f"{col}: {v[:160]}")
            break
    out = r.get("outcome")
    if isinstance(out, str):
        parts.append(tx("resultado ", "outcome ") + out)
    return " · ".join(parts)


def correlate(findings: list[Finding], ctx: Context, cfg: dict) -> tuple[list[dict], list[str], dict]:
    cc = cfg["correlation"]
    core = [f for f in findings if not f.is_anomaly]
    anomalies = [f for f in findings if f.is_anomaly]
    # puntaje preliminar (sin bonus de correlación) para decidir qué grupos califican como incidente
    for f in findings:
        score_finding(f, ctx, cfg, 1)

    total = max(len(ctx.df), 1)
    hubs = set()
    for k in ("user", "host", "src_ip", "hash"):
        if k in ctx.df:
            share = ctx.df[k].dropna().str.lower().value_counts() / total
            hubs |= {(k, v) for v in share[share > cc.get("hub_event_share", 0.3)].index}
    hubs &= {k for f in core for k in _keys(f)}
    uf = _UF(len(core))
    edges: list[dict] = []
    pivots = _remote_targets(ctx, core)
    for i in range(len(core)):
        ki = _keys(core[i]) - hubs
        for j in range(i + 1, len(core)):
            shared = ki & (_keys(core[j]) - hubs)
            # pivote: una herramienta de ejecución remota de un hallazgo apunta al host donde ocurre el otro
            hosts_i = {h.upper() for h in core[i].entities.get("host", [])}
            hosts_j = {h.upper() for h in core[j].entities.get("host", [])}
            pivot = (pivots.get(core[i].id, set()) & hosts_j) | (pivots.get(core[j].id, set()) & hosts_i)
            shared |= {("pivote", h.lower()) for h in pivot}
            if not shared or _gap_hours(core[i], core[j]) > cc["max_gap_hours"]:
                continue
            # un servidor crítico compartido solo indica un destino común (lo atacan o usan muchos actores):
            # no alcanza para unir hallazgos sin otra entidad en común (cuenta, IP, hash o host no crítico)
            strong = {(k, v) for k, v in shared if not (k == "host" and ctx.is_critical(v))}
            if not strong:
                continue
            uf.union(i, j)
            k, v = sorted(strong)[0]
            edges.append({"a": core[i].id, "b": core[j].id, "entity_type": k, "value": v,
                          "shared": [f"{_entity_label(a)} {b}" for a, b in sorted(shared)],
                          "rows_a": _rows_with(ctx, core[i], k, v), "rows_b": _rows_with(ctx, core[j], k, v)})

    groups: dict[int, list[Finding]] = {}
    for i, f in enumerate(core):
        groups.setdefault(uf.find(i), []).append(f)
    by_id = {f.id: f for f in findings}
    order = {"Crítico": 0, "Alto": 1, "Medio": 2, "Bajo": 3}
    incidents, isolated = [], []
    candidates = sorted(groups.values(), key=lambda g: min(_ts(f.start) for f in g))
    for g in candidates:
        if len(g) < 2 and order[g[0].severity] > order["Medio"]:
            isolated.extend(f.id for f in g)
            continue
        incidents.append(g)

    result = []
    for n, g in enumerate(incidents, 1):
        inc_id = f"INC-{n:02d}"
        ids = {f.id for f in g}
        ents = {k: uniq(v for f in g for v in f.entities.get(k, [])) for k in ("user", "host", "src_ip", "hash")}
        start = min(_ts(f.start) for f in g)
        end = max(_ts(f.end) for f in g)
        keyset = set().union(*(_keys(f) for f in g))
        attached = []
        for a in anomalies:
            if a.incident_id:
                continue
            related = {(k, v.lower()) for k, vals in {**a.related, **a.entities}.items()
                       if k in ("user", "host", "src_ip") for v in vals}
            a0, a1 = _ts(a.start), _ts(a.end)
            window = pd.Timedelta(minutes=cc["anomaly_attach_minutes"])
            overlaps = a0 is not None and a0 <= end + window and a1 >= start - window
            if (_keys(a) & keyset) or (overlaps and related & keyset):
                a.incident_id = inc_id
                attached.append(a.id)
        tactics_seen: dict[str, dict] = {}
        for f in sorted(g, key=lambda f: f.start or ""):
            t = tactics_seen.setdefault(f.tactic, {"tactic": f.tactic, "label": tx(TACTICS[f.tactic]["es"], TACTICS[f.tactic]["en"]),
                                                   "label_en": TACTICS[f.tactic]["en"],
                                                   "mitre_tactic": TACTICS[f.tactic]["id"],
                                                   "first_seen": f.start, "finding_ids": []})
            t["finding_ids"].append(f.id)
        phases = sorted(tactics_seen.values(), key=lambda t: t["first_seen"] or "")
        for f in g:
            f.incident_id = inc_id
            score_finding(f, ctx, cfg, len(phases))
        score, severity, factors = score_incident(g, len(phases), cfg)
        # línea de tiempo: filas de evidencia ordenadas
        row_map: dict[str, list[str]] = {}
        for f in g:
            for r in f.rows:
                row_map.setdefault(r, []).append(f.id)
        rows = ctx.df[ctx.df["row_id"].isin(row_map)].sort_values("ts")
        timeline = [{"ts": r["ts_iso"], "row_id": r["row_id"], "finding_ids": row_map[r["row_id"]],
                     "rule_ids": uniq(by_id[x].rule_id for x in row_map[r["row_id"]]),
                     "tactics": uniq(by_id[x].tactic for x in row_map[r["row_id"]]),
                     "description": describe_row(r)} for _, r in rows.iterrows()]
        links = [e for e in edges if e["a"] in ids and e["b"] in ids]
        main_user = ents["user"][0] if ents["user"] else None
        title = _incident_title(g, phases, ents)
        result.append({
            "id": inc_id, "title": title, "finding_ids": [f.id for f in sorted(g, key=lambda f: f.start or "")],
            "anomaly_ids": attached, "start": start.isoformat(), "end": end.isoformat(), "entities": ents,
            "phases": phases, "timeline": timeline, "links": links, "score": score, "severity": severity,
            "score_factors": factors, "main_user": main_user,
            "summary": _incident_summary(g, phases, ents, start, end, links),
        })
    for f in core:
        if f.id in isolated:
            score_finding(f, ctx, cfg, 1)
    conclusion = _conclusion(result, isolated, by_id, hubs, ctx.is_critical)
    loose = [a.id for a in anomalies if not a.incident_id]
    if loose:
        listed = ", ".join(loose[:8]) + (" …" if len(loose) > 8 else "")
        conclusion["justification"].append(tx(
            f"{len(loose)} anomalía(s) estadística(s) sin relación con los incidentes ({listed}); "
            "se informan como anomalías, no como incidentes.",
            f"{len(loose)} statistical anomaly(ies) unrelated to the incidents ({listed}); "
            "they are reported as anomalies, not incidents."))
    conclusion["unattached_anomalies"] = loose
    return result, isolated, conclusion


def _incident_title(g: list[Finding], phases: list[dict], ents: dict) -> str:
    tactic_ids = {p["tactic"] for p in phases}
    if ents["user"]:
        who = tx(f"«{ents['user'][0]}»", f"“{ents['user'][0]}”")
    else:
        who = ents["src_ip"][0] if ents["src_ip"] else tx("entidades vinculadas", "linked entities")
    host = ents["host"][0] if ents["host"] else tx("host no informado", "unreported host")
    categories = {f.category for f in g}
    if {"credential_access", "initial_access"} & tactic_ids and "lateral_movement" in tactic_ids and len(tactic_ids) >= 4:
        return tx(f"Compromiso de cuenta {who} con escalamiento y movimiento lateral",
                  f"Compromise of account {who} with escalation and lateral movement")
    if "web" in categories:
        web_host = next((h for f in g if f.category == "web" for h in f.entities.get("host", [])), host)
        return tx(f"Compromiso de la aplicación web en {web_host} (posible web shell)",
                  f"Web application compromise on {web_host} (possible web shell)")
    if "impact" in tactic_ids:
        return tx(f"Actividad previa a ransomware: borrado de copias de recuperación – {who}",
                  f"Pre-ransomware activity: recovery copies deleted – {who}")
    if "exfiltration" in tactic_ids:
        return tx(f"Posible exfiltración de datos desde {host} – {who}", f"Possible data exfiltration from {host} – {who}")
    if tactic_ids <= {"persistence", "execution"} and "persistence" in tactic_ids:
        return tx(f"Mecanismo de persistencia en {host} – {who}", f"Persistence mechanism on {host} – {who}")
    if any(f.rule_id == "BF-002" for f in g) and any(f.auth_success for f in g):
        ip = next(iter(next(f for f in g if f.rule_id == "BF-002").entities.get("src_ip", [])), tx("IP externa", "external IP"))
        return tx(f"Password spraying desde {ip} con acceso exitoso ({who})",
                  f"Password spraying from {ip} with successful access ({who})")
    if tactic_ids <= {"credential_access", "initial_access", "lateral_movement"}:
        any_success = any(f.auth_success for f in g)
        return (tx(f"Actividad de autenticación sospechosa sobre {who}", f"Suspicious authentication activity on {who}")
                + ("" if any_success else tx(" (solo intentos)", " (attempts only)")))
    labels = ", ".join(p["label"] for p in phases[:3])
    return tx(f"Actividad maliciosa correlacionada ({labels}) – {who}", f"Correlated malicious activity ({labels}) – {who}")


def _incident_summary(g, phases, ents, start, end, links) -> str:
    t0, t1 = f"{start:%d/%m %H:%M}", f"{end:%d/%m %H:%M}"
    chain = " → ".join(p["label"] for p in phases)
    users, hosts, ips = (", ".join(ents["user"][:5]) or "—", ", ".join(ents["host"][:6]) or "—",
                         ", ".join(ents["src_ip"][:5]) or "—")
    return tx(f"{len(g)} hallazgos vinculados entre {t0} y {t1} que cubren {len(phases)} táctica(s) MITRE ({chain}). "
              f"Entidades: usuarios {users}; hosts {hosts}; IPs {ips}. {len(links)} vínculo(s) directo(s) entre hallazgos.",
              f"{len(g)} linked findings between {t0} and {t1} covering {len(phases)} MITRE tactic(s) ({chain}). "
              f"Entities: users {users}; hosts {hosts}; IPs {ips}. {len(links)} direct link(s) between findings.")


def _conclusion(incidents: list[dict], isolated: list[str], by_id: dict, hubs: set,
                ctx_is_critical=lambda h: False) -> dict:
    n = len(incidents)
    lines: list[str] = []
    if n == 0:
        verdict = "none"
        text = tx("No se identificaron incidentes candidatos: no hay hallazgos correlacionados ni hallazgos aislados de "
                  "criticidad Media o superior en los logs provistos.",
                  "No candidate incidents were identified: there are no correlated findings and no isolated findings of "
                  "Medium severity or higher in the provided logs.")
    elif n == 1:
        verdict = "single"
        text = tx("Los hallazgos correlacionados conforman UN único incidente candidato "
                  f"({incidents[0]['id']}): todos están conectados por entidades compartidas dentro de la ventana de "
                  "correlación.",
                  f"The correlated findings form ONE single candidate incident ({incidents[0]['id']}): all of them "
                  "are connected by shared entities within the correlation window.")
    else:
        verdict = "multiple"
        ids = ", ".join(i["id"] for i in incidents)
        text = tx(f"Se identificaron {n} incidentes candidatos INDEPENDIENTES "
                  f"({ids}): no comparten cuentas, IPs ni hashes (a lo sumo un servidor de destino común) dentro de la "
                  "ventana de correlación, por lo que se tratan como eventos separados.",
                  f"{n} INDEPENDENT candidate incidents were identified ({ids}): they share no accounts, IPs or hashes "
                  "(at most a common destination server) within the correlation window, so they are treated as "
                  "separate events.")
    for inc in incidents:
        if inc["links"]:
            sample = "; ".join(f"{l['a']}↔{l['b']} " + tx("por", "via") + f" {l['shared'][0]} ("
                               + tx("filas", "rows") + f" {', '.join(l['rows_a'][:1] + l['rows_b'][:1])})"
                               for l in inc["links"][:6])
            more = " …" if len(inc["links"]) > 6 else ""
            lines.append(tx(f"{inc['id']}: {len(inc['finding_ids'])} hallazgos unidos por {len(inc['links'])} vínculo(s): "
                            f"{sample}{more}.",
                            f"{inc['id']}: {len(inc['finding_ids'])} findings joined by {len(inc['links'])} link(s): "
                            f"{sample}{more}."))
        else:
            lines.append(tx(f"{inc['id']}: hallazgo único de criticidad {inc['severity']} sin vínculos con otros hallazgos.",
                            f"{inc['id']}: single {sev(inc['severity'])}-severity finding with no links to other findings."))
    unrelated: list[str] = []
    for i in range(n):
        for j in range(i + 1, n):
            a, b = incidents[i], incidents[j]
            ea = {f"{k}:{v}" for k, vs in a["entities"].items() for v in vs}
            eb = {f"{k}:{v}" for k, vs in b["entities"].items() for v in vs}
            common = sorted(ea & eb)
            gap = pd.Timestamp(b["start"]) - pd.Timestamp(a["end"])
            weak = {e for e in common if e.startswith("host:") and ctx_is_critical(e.split(":", 1)[1])}
            if common and set(common) <= weak:
                servers = ", ".join(e.split(":", 1)[1] for e in common)
                lines.append(tx(f"{a['id']} y {b['id']} solo comparten el/los servidor(es) "
                                f"{servers}, un destino común que no implica el mismo "
                                "actor; se tratan por separado (hipótesis a validar: podrían estar relacionados).",
                                f"{a['id']} and {b['id']} only share the server(s) {servers}, a common destination "
                                "that does not imply the same actor; they are treated separately (hypothesis to "
                                "validate: they could be related)."))
            elif common:
                hours = f"{gap.total_seconds() / 3600:.0f}"
                lines.append(tx(f"{a['id']} y {b['id']} comparten {', '.join(common)} pero fuera de la ventana de "
                                f"correlación (separación ≈ {hours} h); se recomienda validar si "
                                "existe relación (hipótesis a validar).",
                                f"{a['id']} and {b['id']} share {', '.join(common)} but outside the correlation "
                                f"window (gap ≈ {hours} h); validating whether they are related is recommended "
                                "(hypothesis to validate)."))
            else:
                unrelated.append(f"{a['id']}–{b['id']}")
    if unrelated:
        lines.append(tx(f"Sin ninguna entidad en común: {', '.join(unrelated)}.", f"No entities in common: {', '.join(unrelated)}."))
    if isolated:
        listed = ", ".join(isolated[:8]) + (" …" if len(isolated) > 8 else "")
        lines.append(tx(f"{len(isolated)} hallazgo(s) aislado(s) de baja criticidad no se agruparon en incidentes "
                        f"({listed}); probables falsos positivos o actividad a revisar.",
                        f"{len(isolated)} isolated low-severity finding(s) were not grouped into incidents "
                        f"({listed}); likely false positives or activity to review."))
    if hubs:
        lines.append(tx("Entidades ignoradas como vínculo por estar presentes en gran parte de todos los eventos: ",
                        "Entities ignored as links because they appear in a large share of all events: ")
                     + ", ".join(f"{k} {v}" for k, v in sorted(hubs)) + ".")
    return {"verdict": verdict, "incident_count": n, "text": text, "justification": lines,
            "kind": "inferencia"}
