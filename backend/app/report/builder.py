"""Generación determinística del informe técnico (modelo JSON por secciones y bloques).

Cada bloque declara su origen (determinista | ia | editado) y su naturaleza
(hecho_observado | inferencia | hipotesis | recomendacion | info). Los textos citan
IDs de fila para mantener la trazabilidad hallazgo → regla → filas.
El informe se genera en el idioma pedido (`lang`); la estructura y los IDs son los mismos.
"""
from __future__ import annotations

import itertools
from datetime import datetime

import pandas as pd

from app.detection.base import CATEGORIES, TACTICS
from app.detection.engine import RULES_BY_ID
from app.lang import current, sev, tx, using
from app.report.knowledge import (general_recommendations, generic_recommendations, rule_actions, rule_explain,
                                  tactic_impact)
from app.scoring.risk import SEVERITIES

SNIPPET = 180
EVIDENCE_PER_FINDING = 12


class _Ids:
    def __init__(self) -> None:
        self.n = itertools.count(1)

    def __call__(self, prefix: str) -> str:
        return f"{prefix}-{next(self.n):03d}"


def _p(bid, text, kind="info", rows=None, origin="determinista", title=None, finding_id=None):
    return {"id": bid, "type": "paragraph", "text": text, "kind": kind, "row_refs": rows or [], "origin": origin,
            "editable": True, "title": title, "finding_id": finding_id, "review": []}


def _list(bid, items, kind="info", rows=None, title=None):
    return {"id": bid, "type": "list", "items": items, "kind": kind, "row_refs": rows or [], "origin": "determinista",
            "editable": True, "title": title, "review": []}


def _table(bid, columns, rows, title=None, kind="hecho_observado"):
    return {"id": bid, "type": "table", "columns": columns, "rows": rows, "kind": kind, "origin": "determinista",
            "editable": False, "title": title, "row_refs": [], "review": []}


def _chart(bid, chart, title):
    return {"id": bid, "type": "chart", "chart": chart, "title": title, "kind": "hecho_observado",
            "origin": "determinista", "editable": False, "row_refs": [], "review": []}


def _fmt(ts: str | None) -> str:
    return pd.Timestamp(ts).strftime("%d/%m/%Y %H:%M") if ts else "—"


def _snippet(row) -> str:
    """Fragmento REAL de la celda más informativa (truncado con marca explícita, nunca parafraseado)."""
    for col in ("command_line", "message", "group", "privileges", "share", "service", "process", "outcome"):
        v = row.get(col)
        if isinstance(v, str) and v:
            text = v if len(v) <= SNIPPET else v[:SNIPPET] + " […]"
            prefix = {"group": tx("Grupo: ", "Group: "), "share": tx("Recurso: ", "Share: "),
                      "service": tx("Servicio: ", "Service: "), "privileges": tx("Privilegios: ", "Privileges: "),
                      "outcome": tx("Resultado: ", "Outcome: ")}.get(col, "")
            return prefix + text
    return ""


def _event_label(row) -> str:
    parts = []
    if isinstance(row.get("event_id"), str):
        parts.append(row["event_id"])
    elif isinstance(row.get("sem"), str):
        parts.append(row["sem"])
    if isinstance(row.get("logon_type"), str):
        parts.append(tx("tipo ", "type ") + row["logon_type"])
    if isinstance(row.get("outcome"), str):
        parts.append(row["outcome"])
    return " · ".join(parts)


def _incident_hosts(inc: dict, rows_by_id) -> list[str]:
    """Hosts del incidente; si ninguna entidad es host (p. ej. spraying), los hosts donde se registró la evidencia."""
    if inc["entities"]["host"]:
        return inc["entities"]["host"]
    hosts = []
    for t in inc["timeline"]:
        h = rows_by_id.loc[t["row_id"]].get("host") if t["row_id"] in rows_by_id.index else None
        if isinstance(h, str) and h not in hosts:
            hosts.append(h)
    return hosts


def _fill(template: str, f: dict) -> str:
    def j(key):
        vals = f["entities"].get(key, [])
        return ", ".join(vals[:4]) if vals else tx("(no informado)", "(not reported)")
    return template.format(users=j("user"), ips=j("src_ip"), hosts=j("host"))


STATUS = {"con_hallazgos": ("Con hallazgos", "With findings"), "sin_hallazgos": ("Sin hallazgos", "No findings"),
          "no_evaluable": ("No evaluable", "Not evaluable"), "error": ("Error", "Error")}


def build_report(session, client: str = "Cliente (confidencial)", analyst: str = "Analista SOC N2",
                 lang: str = "es") -> dict:
    with using(lang):
        return _build_report(session, client, analyst, lang)


def _build_report(session, client: str, analyst: str, lang: str) -> dict:
    a = session.analysis_in(lang)
    q = session.quality
    df = session.events
    ids = _Ids()
    findings = a["findings"]
    by_id = {f["id"]: f for f in findings}
    incidents = a["incidents"]
    inc_findings = [f for f in findings if f["incident_id"] and not f["is_anomaly"]]
    rows_by_id = df.set_index("row_id", drop=False)
    sev_count = {s: sum(1 for f in findings if f["severity"] == s) for s in SEVERITIES}
    sections = []
    d0, d1 = _fmt(q.get("date_min")), _fmt(q.get("date_max"))

    # 1. Resumen técnico ------------------------------------------------------------
    blocks = []
    if incidents:
        worst = max(incidents, key=lambda i: i["score"])
        c, h, m, lo = sev_count["Crítico"], sev_count["Alto"], sev_count["Medio"], sev_count["Bajo"]
        blocks.append(_p(ids("B"), tx(
            f"Entre el {d0} y el {d1} ({q['timezone']}) se analizaron "
            f"{q['total_rows']:,} filas de logs provistas por el cliente. El motor de detección identificó {len(findings)} "
            f"hallazgos ({c} críticos, {h} altos, {m} medios y {lo} bajos) y los agrupó en {len(incidents)} "
            f"incidente(s) candidato(s). El de mayor criticidad es {worst['id']} – {worst['title']} "
            f"({worst['severity']}, {worst['score']}/100).",
            f"Between {d0} and {d1} ({q['timezone']}) {q['total_rows']:,} log rows provided by the client were "
            f"analyzed. The detection engine identified {len(findings)} findings ({c} critical, {h} high, {m} medium "
            f"and {lo} low) and grouped them into {len(incidents)} candidate incident(s). The most severe is "
            f"{worst['id']} – {worst['title']} ({sev(worst['severity'])}, {worst['score']}/100)."),
            kind="hecho_observado"))
        blocks.append(_p(ids("B"), a["conclusion"]["text"], kind="inferencia"))
        for inc in incidents:
            phases = " → ".join(p["label"] for p in inc["phases"])
            users = ", ".join(inc["entities"]["user"][:5]) or "—"
            hosts = ", ".join(_incident_hosts(inc, rows_by_id)[:6]) or "—"
            i0, i1 = _fmt(inc["start"]), _fmt(inc["end"])
            blocks.append(_p(ids("B"), tx(
                f"{inc['id']} ({inc['severity']}): {inc['title']}. Actividad entre {i0} y {i1} que cubre las fases "
                f"{phases}. Cuentas involucradas: {users}; hosts: {hosts}.",
                f"{inc['id']} ({sev(inc['severity'])}): {inc['title']}. Activity between {i0} and {i1} covering the "
                f"phases {phases}. Accounts involved: {users}; hosts: {hosts}."),
                kind="hecho_observado", rows=[t["row_id"] for t in inc["timeline"][:3]]))
        blocks.append(_p(ids("B"), tx(
            "Se recomienda tratar como prioritarias las acciones de contención del apartado 9 para los incidentes de "
            "criticidad Crítica/Alta, en particular el restablecimiento de credenciales y el aislamiento de los hosts "
            "afectados.",
            "The containment actions in section 9 should be prioritized for Critical/High incidents, in particular "
            "resetting credentials and isolating the affected hosts."), kind="recomendacion"))
    else:
        blocks.append(_p(ids("B"), tx(
            f"Se analizaron {q['total_rows']:,} filas de logs. No se identificaron incidentes candidatos: ",
            f"{q['total_rows']:,} log rows were analyzed. No candidate incidents were identified: ")
            + a["conclusion"]["text"], kind="hecho_observado"))
    intel = getattr(session, "intel", None)
    intel_done = bool(intel and intel.get("summary") and intel.get("status") == "completado")
    if intel_done:
        sm = intel["summary"]
        bad = f" ({', '.join(sm['bad_abuseipdb'][:6])})" if sm["bad_abuseipdb"] else ""
        blocks.append(_p(ids("B"), tx(
            f"Reputación externa (AbuseIPDB): de {sm['queried']} IP(s) pública(s) consultada(s), "
            f"{len(sm['bad_abuseipdb'])} tienen mala reputación{bad} y {len(sm['suspicious'])} reputación sospechosa. "
            "Detalle en el Anexo E.",
            f"External reputation (AbuseIPDB): of {sm['queried']} public IP(s) queried, "
            f"{len(sm['bad_abuseipdb'])} have a bad reputation{bad} and {len(sm['suspicious'])} a suspicious one. "
            "Details in Annex E."),
            kind="hecho_observado"))
    sections.append({"id": "resumen", "number": "1", "title": tx("Resumen técnico", "Technical summary"), "blocks": blocks})

    # 2. Alcance y metodología ---------------------------------------------------------
    rules = a["rules"]
    no_eval = [r for r in rules if r["status"] == "no_evaluable"]
    sheet_rows = [[s["name"], s["rows"], ", ".join(f"{k}←{v}" for k, v in s["mapping"].items())] for s in q["sheets"]]
    order_txt = tx("día primero", "day first") if q["dayfirst"] else tx("mes primero", "month first")
    gap_h = a["config"]["correlation"]["max_gap_hours"]
    if a.get("baseline_end"):
        baseline = tx(f"Período base para comparaciones: hasta {_fmt(a.get('baseline_end'))}.",
                      f"Baseline period for comparisons: until {_fmt(a.get('baseline_end'))}.")
    else:
        span, need = f"{a.get('span_hours', 0):.1f}", a["config"].get("min_baseline_hours", 48)
        baseline = tx(f"Sin período base: el archivo cubre {span} h y se requieren al menos {need} h; las reglas que "
                      "comparan contra lo habitual aplican su criterio alternativo (documentado en cada hallazgo).",
                      f"No baseline period: the file covers {span} h and at least {need} h are required; rules that "
                      "compare against normal behavior apply their alternative criterion (documented in each finding).")
    blocks = [
        _p(ids("B"), tx(
            f"Fuente: archivo «{session.filename}» entregado por el cliente ({len(q['sheets'])} hoja(s) analizadas). "
            "El análisis se limitó exclusivamente a su contenido; no se consultaron sistemas del cliente ni SIEM. "
            f"Los timestamps sin zona horaria se interpretaron como {q['timezone']} ({order_txt}); rango cubierto: "
            f"{d0} – {d1}.",
            f"Source: file “{session.filename}” delivered by the client ({len(q['sheets'])} sheet(s) analyzed). "
            "The analysis was limited strictly to its content; no client systems or SIEM were queried. "
            f"Timestamps without a timezone were interpreted as {q['timezone']} ({order_txt}); range covered: "
            f"{d0} – {d1}."), kind="info"),
        _table(ids("T"), [tx("Hoja", "Sheet"), tx("Filas", "Rows"), tx("Mapeo de columnas (campo ← columna)",
                                                                       "Column mapping (field ← column)")],
               sheet_rows, kind="info"),
        _p(ids("B"), tx(
            f"Metodología: se evaluaron {len(rules)} reglas determinísticas mapeadas a MITRE ATT&CK "
            f"({len(rules) - len(no_eval)} evaluables con los campos disponibles). Cada hallazgo referencia las filas "
            "exactas que lo disparan (ID «Hoja!fila» del Excel). Los hallazgos se correlacionaron por entidades compartidas "
            f"(usuario, host, IP, hash) dentro de una ventana de {gap_h} h; la criticidad "
            "se calcula con el esquema reproducible del Anexo A. ",
            f"Methodology: {len(rules)} deterministic rules mapped to MITRE ATT&CK were evaluated "
            f"({len(rules) - len(no_eval)} evaluable with the available fields). Each finding references the exact "
            "rows that trigger it (Excel “Sheet!row” ID). Findings were correlated by shared entities "
            f"(user, host, IP, hash) within a {gap_h} h window; severity is computed with the reproducible scheme "
            "in Annex A. ") + baseline, kind="info"),
        _p(ids("B"), tx(
            "Convenciones: «Hecho observado» = dato presente literalmente en los logs; «Inferencia razonable» = conclusión "
            "derivada de hechos observados; «Hipótesis a validar» = explicación posible que requiere verificación "
            "adicional. Los textos marcados «Generado por IA» fueron redactados por un modelo de lenguaje a partir "
            "exclusivamente de los hallazgos y filas citadas, y validados automáticamente contra los datos.",
            "Conventions: “Observed fact” = data literally present in the logs; “Reasonable inference” = conclusion "
            "derived from observed facts; “Hypothesis to validate” = possible explanation that needs further "
            "verification. Texts marked “AI-generated” were written by a language model using only the cited findings "
            "and rows, and automatically validated against the data."), kind="info"),
    ]
    sections.append({"id": "alcance", "number": "2", "title": tx("Alcance y metodología", "Scope and methodology"),
                     "blocks": blocks})

    # 3. Hallazgos identificados ---------------------------------------------------------
    blocks = [_chart(ids("C"), "severity", tx("Hallazgos por criticidad", "Findings by severity")),
              _chart(ids("C"), "category", tx("Hallazgos por categoría", "Findings by category"))]
    rows = [[f["id"], f["rule_id"], f["title"], sev(f["severity"]), f["score"], f["incident_id"] or
             (tx("anomalía", "anomaly") if f["is_anomaly"] else tx("aislado", "isolated")), len(f["rows"])]
            for f in findings]
    blocks.append(_table(ids("T"), ["ID", tx("Regla", "Rule"), tx("Hallazgo", "Finding"), tx("Criticidad", "Severity"),
                                    tx("Puntaje", "Score"), tx("Incidente", "Incident"), tx("Filas", "Rows")], rows))
    absent = []
    for c in a["categories"]:
        if c["status"] == "sin_hallazgos":
            absent.append(tx(f"{c['label']}: no se identificó evidencia en los logs provistos.",
                             f"{c['label']}: no evidence was identified in the provided logs."))
        elif c["status"] == "no_evaluable":
            absent.append(tx(f"{c['label']}: no evaluable por falta de datos (ninguna regla de la categoría dispone de los "
                             "campos necesarios).",
                             f"{c['label']}: not evaluable due to missing data (no rule in the category has the required "
                             "fields)."))
    if absent:
        blocks.append(_list(ids("B"), absent, kind="hecho_observado", title=tx("Categorías sin hallazgos",
                                                                              "Categories without findings")))
    isolated = [by_id[x] for x in a["isolated"]]
    loose = [by_id[x] for x in a["conclusion"].get("unattached_anomalies", [])]
    if isolated or loose:
        blocks.append(_list(ids("B"), [
            f"{f['id']} ({f['rule_id']}, {sev(f['severity'])}): {f['title']} — {f['fp_notes'][0] if f['fp_notes'] else ''}"
            for f in isolated + loose], kind="hipotesis",
            title=tx("Hallazgos aislados y anomalías (probables falsos positivos a validar)",
                     "Isolated findings and anomalies (likely false positives to validate)")))
    sections.append({"id": "hallazgos", "number": "3", "title": tx("Hallazgos identificados", "Identified findings"),
                     "blocks": blocks})

    # 4. Explicación técnica -----------------------------------------------------------
    blocks = []
    explain = rule_explain()
    for f in inc_findings:
        mitre = ", ".join(f"{m['id']} {m['name']}" for m in f["mitre"])
        text = f"{explain.get(f['rule_id'], '')} " + tx("En este caso: ", "In this case: ") + f["summary"]
        blocks.append(_p(ids("B"), text, kind="hecho_observado", rows=f["rows"][:5],
                         title=f"{f['id']} · {f['title']} [{f['rule_id']} · {mitre}]", finding_id=f["id"]))
        if f["details"]:
            blocks.append(_list(ids("B"), [d[:400] for d in f["details"][:4]], kind="hecho_observado", rows=f["rows"][:4]))
        if f["fp_notes"]:
            blocks.append(_p(ids("B"), tx("Posible falso positivo / hipótesis alternativa: ",
                                          "Possible false positive / alternative hypothesis: ") + " ".join(f["fp_notes"][:2]),
                             kind="hipotesis", finding_id=f["id"]))
    if not blocks:
        blocks.append(_p(ids("B"), tx("No hay hallazgos asociados a incidentes para explicar.",
                                      "There are no incident-related findings to explain."), kind="info"))
    sections.append({"id": "tecnica", "number": "4", "title": tx("Explicación técnica de cada hallazgo",
                                                                 "Technical explanation of each finding"),
                     "blocks": blocks})

    # 5. Evidencias ---------------------------------------------------------------------
    blocks = [_p(ids("B"), tx(
        f"Las tablas reproducen fragmentos literales de las celdas del Excel (máx. {SNIPPET} caracteres, la marca «[…]» "
        f"indica truncado) y hasta {EVIDENCE_PER_FINDING} filas por hallazgo. La lista completa de filas está disponible en "
        "la aplicación y en la columna «Filas» de la sección 3.",
        f"The tables reproduce literal excerpts of the Excel cells (max {SNIPPET} characters, the “[…]” mark means "
        f"truncated) and up to {EVIDENCE_PER_FINDING} rows per finding. The full list of rows is available in the "
        "application and in the “Rows” column of section 3."), kind="info")]
    for inc in incidents:
        table_rows = []
        for fid in inc["finding_ids"]:
            f = by_id[fid]
            for rid in f["rows"][:EVIDENCE_PER_FINDING]:
                r = rows_by_id.loc[rid]
                log_id = r.get("log_id")
                cited = f"{rid} · {log_id}" if isinstance(log_id, str) and log_id else rid
                table_rows.append([cited, fid, r["ts_iso"][:19].replace("T", " ") if isinstance(r["ts_iso"], str) else "—",
                                   r["user"] if isinstance(r["user"], str) else "", r["host"] if isinstance(r["host"], str) else "",
                                   r["src_ip"] if isinstance(r["src_ip"], str) else "",
                                   f"[{_event_label(r)}] {_snippet(r)}".strip()])
        blocks.append(_table(ids("T"), [tx("ID fila", "Row ID"), tx("Hallazgo", "Finding"), "Timestamp",
                                        tx("Usuario", "User"), "Host", "IP",
                                        tx("Evento · fragmento literal", "Event · literal excerpt")],
                             table_rows, title=tx(f"Evidencia de {inc['id']} – {inc['title']}",
                                                  f"Evidence for {inc['id']} – {inc['title']}")))
    sections.append({"id": "evidencias", "number": "5", "title": tx("Evidencias encontradas en los logs",
                                                                    "Evidence found in the logs"), "blocks": blocks})

    # 6. Línea de tiempo ---------------------------------------------------------------
    blocks = [_chart(ids("C"), "timeline", tx("Eventos por hora y evidencia de hallazgos", "Events per hour and finding evidence")),
              _chart(ids("C"), "heatmap", tx("Mapa de calor día × hora", "Day × hour heatmap"))]
    for inc in incidents:
        phase_rows = [[p["label"], p["mitre_tactic"], _fmt(p["first_seen"]), ", ".join(p["finding_ids"])] for p in inc["phases"]]
        blocks.append(_table(ids("T"), [tx("Fase (táctica)", "Phase (tactic)"), "MITRE", tx("Primera evidencia", "First evidence"),
                                        tx("Hallazgos", "Findings")], phase_rows,
                             title=tx(f"Cadena de ataque de {inc['id']} (orden temporal)",
                                      f"Attack chain of {inc['id']} (chronological)")))
        tl = [[e["ts"][:19].replace("T", " "), e["row_id"], ", ".join(e["rule_ids"]), e["description"][:200]]
              for e in inc["timeline"][:80]]
        more = tx(" (primeros 80 eventos)", " (first 80 events)") if len(inc["timeline"]) > 80 else ""
        blocks.append(_table(ids("T"), ["Timestamp", tx("ID fila", "Row ID"), tx("Reglas", "Rules"), tx("Evento", "Event")], tl,
                             title=tx(f"Línea de tiempo de {inc['id']}", f"Timeline of {inc['id']}") + more))
    if any(inc["phases"] for inc in incidents) and any(f["category"] == "lateral" for f in inc_findings):
        blocks.append(_chart(ids("C"), "lateral", tx("Movimiento lateral entre hosts", "Lateral movement between hosts")))
    sections.append({"id": "timeline", "number": "6", "title": tx("Línea de tiempo", "Timeline"), "blocks": blocks})

    # 7. Criticidad y justificación ------------------------------------------------------
    blocks = []
    for inc in incidents:
        factors = "; ".join(f"{x['factor']} ({x['points']:+d})" for x in inc["score_factors"])
        blocks.append(_p(ids("B"), tx(
            f"{inc['id']} se clasifica como {inc['severity']} ({inc['score']}/100). Justificación reproducible: {factors}.",
            f"{inc['id']} is rated {sev(inc['severity'])} ({inc['score']}/100). Reproducible justification: {factors}."),
            kind="inferencia", title=inc["id"]))
    rows = [[f["id"], sev(f["severity"]), f["score"], "; ".join(f"{x['factor']} ({x['points']:+d})" for x in f["score_factors"])]
            for f in findings if not f["is_anomaly"]]
    blocks.append(_table(ids("T"), [tx("Hallazgo", "Finding"), tx("Criticidad", "Severity"), tx("Puntaje", "Score"),
                                    tx("Factores", "Factors")], rows, kind="inferencia"))
    sections.append({"id": "criticidad", "number": "7", "title": tx("Criticidad y justificación", "Severity and justification"),
                     "blocks": blocks})

    # 8. Impacto -------------------------------------------------------------------------
    blocks = []
    impact = tactic_impact()
    for inc in incidents:
        items = [f"{p['label']}: {impact[p['tactic']]}" for p in inc["phases"] if p["tactic"] in impact]
        crit_hosts = [h for h in inc["entities"]["host"] if h.upper().startswith(("SRV", "DC"))]
        if crit_hosts:
            items.append(tx(f"Hosts críticos involucrados: {', '.join(crit_hosts)}.",
                            f"Critical hosts involved: {', '.join(crit_hosts)}."))
        blocks.append(_list(ids("B"), items, kind="inferencia", title=tx(f"{inc['id']} – posible impacto",
                                                                         f"{inc['id']} – possible impact")))
    blocks.append(_p(ids("B"), tx(
        "El impacto efectivo (qué datos se accedieron o extrajeron) no puede determinarse solo con estos logs; requiere "
        "análisis forense de los hosts y del tráfico de red.",
        "The actual impact (which data was accessed or extracted) cannot be determined from these logs alone; it "
        "requires forensic analysis of the hosts and network traffic."), kind="hipotesis"))
    sections.append({"id": "impacto", "number": "8", "title": tx("Posible impacto en la organización",
                                                                 "Possible impact on the organization"), "blocks": blocks})

    # 9. Plan de acción ------------------------------------------------------------------
    plan = {"investigar": {}, "contener": {}, "remediar": {}}
    sev_rank = {s: i for i, s in enumerate(SEVERITIES)}
    actions = rule_actions()
    for f in sorted(inc_findings, key=lambda f: sev_rank[f["severity"]]):
        for block, prio, tmpl in actions.get(f["rule_id"], []):
            text = _fill(tmpl, f)
            key = (prio, text)
            if key not in plan[block]:
                plan[block][key] = {"text": text, "prio": prio, "sev": f["severity"], "refs": [f["id"]]}
            else:
                plan[block][key]["refs"].append(f["id"])
    auth_refs = [f["id"] for f in inc_findings if f["category"] in ("bruteforce", "suspicious_logon")]
    if auth_refs:
        text = tx("Endurecer el acceso remoto/VPN: MFA obligatorio, bloqueo geográfico y alertas de fuerza bruta.",
                  "Harden remote/VPN access: mandatory MFA, geographic blocking and brute-force alerts.")
        plan["remediar"][(1, text)] = {"text": text, "prio": 1, "sev": "Alto", "refs": auth_refs[:6]}
    blocks = []
    labels = {"investigar": tx("9.1 Investigar", "9.1 Investigate"), "contener": tx("9.2 Contener", "9.2 Contain"),
              "remediar": tx("9.3 Remediar", "9.3 Remediate")}
    for block, items in plan.items():
        ordered = sorted(items.values(), key=lambda x: (x["prio"], sev_rank.get(x["sev"], 9)))
        blocks.append(_list(ids("B"), [f"[P{x['prio']}] {x['text']}" + (f" (ref. {', '.join(sorted(set(x['refs'])))})"
                                                                       if x["refs"] else "") for x in ordered] or
                            [tx("Sin acciones específicas derivadas de los hallazgos.",
                                "No specific actions derived from the findings.")], kind="recomendacion",
                            title=labels[block]))
    sections.append({"id": "plan", "number": "9", "title": tx("Plan de acción: investigar, contener y remediar",
                                                              "Action plan: investigate, contain and remediate"),
                     "blocks": blocks})

    # 10. Recomendaciones generales ---------------------------------------------------------
    cats = {f["category"] for f in findings if not f["is_anomaly"]}
    general = general_recommendations()
    items = [general[c] for c in CATEGORIES if c in cats] + generic_recommendations()
    sections.append({"id": "recomendaciones", "number": "10", "title": tx("Recomendaciones generales de seguridad",
                                                                          "General security recommendations"),
                     "blocks": [_list(ids("B"), items, kind="recomendacion")]})

    # 11. Limitaciones ---------------------------------------------------------------------
    base_end = _fmt(a.get("baseline_end"))
    items = [
        tx(f"{q['invalid_rows']} fila(s) con marca de tiempo inválida o vacía se conservaron pero no participan en reglas "
           "temporales (ver reporte de calidad).",
           f"{q['invalid_rows']} row(s) with an invalid or empty timestamp were kept but do not take part in time-based "
           "rules (see the quality report)."),
        tx("El análisis depende de la completitud del export del SIEM: eventos no exportados o registros borrados "
           "localmente (ver EX-007 si aplica) no pueden evaluarse.",
           "The analysis depends on the completeness of the SIEM export: events not exported or logs cleared locally "
           "(see EX-007 if applicable) cannot be evaluated."),
        tx("La geolocalización por IP se toma tal como viene en el Excel; puede ser imprecisa.",
           "IP geolocation is taken as provided in the Excel file; it may be inaccurate."),
        tx(f"El período base para comparaciones (entidades nuevas, logons remotos nuevos) es corto (hasta {base_end}); "
           "aumenta la probabilidad de falsos positivos de anomalía.",
           f"The baseline period for comparisons (new entities, new remote logons) is short (until {base_end}); "
           "this increases the likelihood of anomaly false positives."),
    ]
    if q.get("formula_cells"):
        items.append(tx(f"{q['formula_cells']} celda(s) contenían posibles fórmulas; se neutralizaron al exportar y se "
                        "mostraron como texto.",
                        f"{q['formula_cells']} cell(s) contained possible formulas; they were neutralized on export and "
                        "shown as text."))
    for r in no_eval:
        name = tx(r["name"], r.get("name_en", r["name"]))
        items.append(tx(f"Regla {r['id']} ({name}): no evaluable por falta de datos — faltan {', '.join(r['missing'])}.",
                        f"Rule {r['id']} ({name}): not evaluable due to missing data — missing {', '.join(r['missing'])}."))
    missing_fields = sorted(set(itertools.chain.from_iterable(r["missing"] for r in no_eval)))
    if missing_fields:
        items.append(tx(f"Campos ausentes en el archivo que limitaron el análisis: {', '.join(missing_fields)}.",
                        f"Fields missing from the file that limited the analysis: {', '.join(missing_fields)}."))
    sections.append({"id": "limitaciones", "number": "11", "title": tx("Limitaciones del análisis", "Limitations of the analysis"),
                     "blocks": [_list(ids("B"), items, kind="info")]})

    # Anexos -----------------------------------------------------------------------------------
    m = a["methodology"]
    blocks = [_p(ids("B"), m["formula"], kind="info"),
              _table(ids("T"), ["Factor", tx("Puntos", "Points"), tx("Detalle", "Detail")],
                     [[x["factor"], x["points"], x["detail"]] for x in m["factors"]], kind="info"),
              _table(ids("T"), [tx("Criticidad", "Severity"), tx("Rango", "Range")],
                     [[sev(b["severity"]), b["range"]] for b in m["bands"]], kind="info")]
    sections.append({"id": "anexo_a", "number": "A", "title": tx("Anexo A – Esquema de puntaje de riesgo",
                                                                 "Annex A – Risk scoring scheme"), "blocks": blocks})
    ioc_rows = [[i["id"], i["type"], i["value"][:160], i["context"], i["count"], ", ".join(i["finding_ids"][:6])] for i in a["iocs"]]
    sections.append({"id": "anexo_b", "number": "B", "title": tx("Anexo B – Indicadores de compromiso (IoCs)",
                                                                 "Annex B – Indicators of compromise (IoCs)"),
                     "blocks": [_table(ids("T"), ["ID", tx("Tipo", "Type"), tx("Valor", "Value"), tx("Contexto", "Context"),
                                                  tx("Frecuencia", "Frequency"), tx("Hallazgos", "Findings")], ioc_rows)]})
    rule_rows = [[r["id"], tx(r["name"], r.get("name_en", r["name"])), ", ".join(m_["id"] for m_ in r["mitre"]) or "—",
                  tx(*STATUS[r["status"]]), r["count"]] for r in rules]
    sections.append({"id": "anexo_c", "number": "C", "title": tx("Anexo C – Reglas evaluadas", "Annex C – Evaluated rules"),
                     "blocks": [_table(ids("T"), ["ID", tx("Regla", "Rule"), "MITRE", tx("Estado", "Status"),
                                                  tx("Hallazgos", "Findings")], rule_rows, kind="info")]})
    sections.append(_mitre_section(findings, ids))
    if intel_done:
        sections.append(_intel_section(intel, ids))

    return {
        "meta": {"kind": "tecnico", "title": tx("Informe técnico de análisis de incidente", "Technical incident analysis report"),
                 "client": client, "analyst": analyst, "lang": lang,
                 "generated_at": datetime.now().astimezone().isoformat(timespec="seconds"),
                 "version": session.report_versions.get("tecnico", 0) + 1,
                 "classification": tx("CONFIDENCIAL", "CONFIDENTIAL"),
                 "source_file": session.filename, "ai_used": False, "ai_model": None},
        "sections": sections,
        "ai_review": [],
    }


def find_block(report: dict, block_id: str) -> dict | None:
    for s in report["sections"]:
        for b in s["blocks"]:
            if b["id"] == block_id:
                return b
    return None


def tactic_label(t: str) -> str:
    entry = TACTICS.get(t, {})
    return tx(entry.get("es", t), entry.get("en", t))


def rule_name(rule_id: str) -> str:
    r = RULES_BY_ID.get(rule_id)
    return tx(r.name, r.name_en) if r else rule_id


VERDICT_LABEL = {"malicioso": ("Maliciosa", "Malicious"), "sospechoso": ("Sospechosa", "Suspicious"),
                 "limpio": ("Sin reportes", "No reports"), "sin_datos": ("Sin datos", "No data"), "error": ("Error", "Error")}


def _intel_section(intel: dict, ids) -> dict:
    """Anexo E: reputación externa de IPs públicas (contexto; no altera la criticidad del motor)."""
    from app.i18n import tr
    lang = current()
    sm = intel["summary"]
    blocks = [_p(ids("B"), tx(
        f"Se consultó la reputación de {sm['queried']} IP(s) pública(s) del archivo en AbuseIPDB "
        "(maliciosa: confianza de abuso ≥ 50/100; sospechosa: 25–49). "
        "Solo se enviaron las direcciones IP; ningún otro dato del cliente. La reputación externa es contexto adicional: "
        "una IP sin reportes no prueba que sea legítima y una IP reportada puede ser infraestructura compartida "
        "(VPN, proxy, nube).",
        f"The reputation of {sm['queried']} public IP(s) from the file was checked on AbuseIPDB "
        "(malicious: abuse confidence ≥ 50/100; suspicious: 25–49). "
        "Only the IP addresses were sent; no other client data. External reputation is extra context: an IP with no "
        "reports does not prove it is legitimate and a reported IP may be shared infrastructure (VPN, proxy, cloud)."),
        kind="info")]
    lists = [(tx("Mala reputación en AbuseIPDB", "Bad reputation in AbuseIPDB"), sm["bad_abuseipdb"]),
             (tx("Reputación sospechosa", "Suspicious reputation"), sm["suspicious"])]
    blocks.append(_list(ids("B"), [f"{t}: {', '.join(ips) if ips else tx('ninguna', 'none')}" for t, ips in lists],
                        kind="hecho_observado", title=tx("Resumen", "Summary")))
    rows = []
    for r in intel["results"].values() if isinstance(intel["results"], dict) else intel["results"]:
        def cell(p):
            x = r.get(p)
            if not x:
                return "—"
            label = tx(*VERDICT_LABEL[x["verdict"]]) if x["verdict"] in VERDICT_LABEL else x["verdict"]
            return f"{label} – {tr(x.get('summary', ''), lang)}"
        rows.append([r["ip"], r["events"], ", ".join(r["incident_ids"] + r["finding_ids"][:4]) or "—",
                     cell("abuseipdb")])
    blocks.append(_table(ids("T"), ["IP", tx("Eventos", "Events"), tx("Incidentes / hallazgos", "Incidents / findings"),
                                    "AbuseIPDB"], rows))
    errors = [f"{st['label']}: {tr(st['error'], lang)}" for st in intel["providers"].values() if st.get("error")]
    if errors or intel.get("not_queried"):
        n = len(intel.get("not_queried") or [])
        items = errors + ([tx(f"{n} IP(s) pública(s) no se consultaron por el límite configurado.",
                              f"{n} public IP(s) were not queried because of the configured limit.")] if n else [])
        blocks.append(_list(ids("B"), items, kind="info", title=tx("Limitaciones de la consulta", "Lookup limitations")))
    return {"id": "anexo_e", "number": "E", "title": tx("Anexo E – Reputación externa de IPs (AbuseIPDB)",
                                                        "Annex E – External IP reputation (AbuseIPDB)"),
            "blocks": blocks}


def _mitre_section(findings: list[dict], ids) -> dict:
    """Anexo D: técnicas MITRE ATT&CK observadas, ordenadas por táctica, con los hallazgos que las sustentan."""
    order = list(TACTICS)
    rows: dict[tuple[str, str], dict] = {}
    for f in findings:
        if f["is_anomaly"]:
            continue
        for m in f["mitre"]:
            key = (f["tactic"], m["id"])
            r = rows.setdefault(key, {"name": m["name"], "findings": [], "incidents": set()})
            r["findings"].append(f["id"])
            if f["incident_id"]:
                r["incidents"].add(f["incident_id"])
    table = [[tactic_label(t), TACTICS[t]["id"], tid, r["name"], ", ".join(r["findings"][:8]),
              ", ".join(sorted(r["incidents"])) or tx("aislado", "isolated")]
             for (t, tid), r in sorted(rows.items(), key=lambda kv: (order.index(kv[0][0]) if kv[0][0] in order else 99,
                                                                      kv[0][1]))]
    blocks = [_p(ids("B"), tx("Técnicas de MITRE ATT&CK con evidencia en los logs, agrupadas por táctica. Las anomalías "
                              "estadísticas no se mapean a técnicas.",
                              "MITRE ATT&CK techniques with evidence in the logs, grouped by tactic. Statistical "
                              "anomalies are not mapped to techniques."), kind="info"),
              _table(ids("T"), [tx("Táctica", "Tactic"), tx("ID táctica", "Tactic ID"), tx("Técnica", "Technique"),
                                tx("Nombre", "Name"), tx("Hallazgos", "Findings"), tx("Incidentes", "Incidents")], table,
                     kind="hecho_observado")]
    return {"id": "anexo_d", "number": "D", "title": tx("Anexo D – Mapeo MITRE ATT&CK", "Annex D – MITRE ATT&CK mapping"),
            "blocks": blocks}
