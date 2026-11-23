"""Clasificación de riesgo reproducible (0–100 → Crítico/Alto/Medio/Bajo)."""
from __future__ import annotations

import math

from app.detection.base import Context, Finding
from app.lang import tx

SEVERITIES = ["Crítico", "Alto", "Medio", "Bajo"]
SEVERITY_EN = {"Crítico": "Critical", "Alto": "High", "Medio": "Medium", "Bajo": "Low"}


def band(score: int, cfg: dict) -> str:
    b = cfg["scoring"]["bands"]
    if score >= b["critical"]:
        return "Crítico"
    if score >= b["high"]:
        return "Alto"
    if score >= b["medium"]:
        return "Medio"
    return "Bajo"


def score_finding(f: Finding, ctx: Context, cfg: dict, incident_tactics: int = 1) -> None:
    s = cfg["scoring"]
    factors: list[dict] = []
    base = int(s["base"].get(f.rule_id, 20))
    factors.append({"factor": tx(f"Base por técnica ({f.rule_id})", f"Technique base ({f.rule_id})"), "points": base})
    if f.auth_success is True:
        factors.append({"factor": tx("Autenticación exitosa (éxito, no solo intento)",
                                     "Successful authentication (success, not just an attempt)"), "points": s["success_bonus"]})
    elif f.auth_success is False:
        factors.append({"factor": tx("Solo intentos fallidos (sin éxito observado)",
                                     "Failed attempts only (no success observed)"), "points": 0})
    users = f.entities.get("user", [])
    priv = [u for u in users if ctx.is_privileged(u, at=f.end)]
    if priv:
        factors.append({"factor": tx(f"Cuenta privilegiada involucrada ({', '.join(priv[:3])})",
                                     f"Privileged account involved ({', '.join(priv[:3])})"), "points": s["privileged_bonus"]})
    hosts = [h for h in f.entities.get("host", []) if ctx.is_critical(h)]
    if hosts:
        factors.append({"factor": tx(f"Host crítico involucrado ({', '.join(hosts[:3])})",
                                     f"Critical host involved ({', '.join(hosts[:3])})"), "points": s["critical_host_bonus"]})
    n = len(f.rows)
    vol = min(int(s["volume_max"]), round(5 * math.log10(n))) if n > 1 else 0
    if vol:
        factors.append({"factor": tx(f"Volumen de evidencia ({n} filas)", f"Evidence volume ({n} rows)"), "points": vol})
    if not f.is_anomaly and incident_tactics > 1:
        corr = min(int(s["correlation_max"]), (incident_tactics - 1) * int(s["correlation_per_tactic"]))
        factors.append({"factor": tx(f"Correlación con otras fases del incidente ({incident_tactics} tácticas)",
                                     f"Correlation with other incident phases ({incident_tactics} tactics)"), "points": corr})
    total = sum(x["points"] for x in factors)
    if f.is_anomaly and total > s["anomaly_cap"]:
        factors.append({"factor": tx("Tope para anomalías (no es incidente confirmado)",
                                     "Anomaly cap (not a confirmed incident)"), "points": s["anomaly_cap"] - total})
        total = s["anomaly_cap"]
    total = max(0, min(100, total))
    f.score = int(total)
    f.severity = band(f.score, cfg)
    f.score_factors = factors


def score_incident(findings: list[Finding], n_tactics: int, cfg: dict) -> tuple[int, str, list[dict]]:
    s = cfg["scoring"]
    top = max(findings, key=lambda f: f.score)
    factors = [{"factor": tx(f"Hallazgo de mayor puntaje ({top.id} · {top.rule_id})",
                             f"Highest-scoring finding ({top.id} · {top.rule_id})"), "points": top.score}]
    breadth = (n_tactics - 1) * int(s["incident_breadth_per_tactic"])
    if breadth:
        factors.append({"factor": tx(f"Amplitud de la cadena de ataque ({n_tactics} tácticas)",
                                     f"Attack chain breadth ({n_tactics} tactics)"), "points": breadth})
    total = min(100, sum(x["points"] for x in factors))
    return total, band(total, cfg), factors


def methodology(cfg: dict) -> dict:
    s = cfg["scoring"]
    return {
        "formula": tx("puntaje = base(regla) + éxito + cuenta privilegiada + host crítico + volumen + correlación "
                      "(tope 100; anomalías con tope)",
                      "score = base(rule) + success + privileged account + critical host + volume + correlation "
                      "(max 100; anomalies capped)"),
        "factors": [
            {"factor": tx("Base por técnica", "Technique base"), "points": tx("según regla (10–60)", "per rule (10–60)"),
             "detail": tx("Refleja la gravedad intrínseca de la técnica MITRE.", "Reflects the intrinsic severity of the MITRE technique.")},
            {"factor": tx("Éxito vs intento", "Success vs attempt"), "points": f"+{s['success_bonus']} / 0",
             "detail": tx("Solo reglas de autenticación: hubo acceso efectivo.", "Authentication rules only: access actually happened.")},
            {"factor": tx("Cuenta privilegiada", "Privileged account"), "points": f"+{s['privileged_bonus']}",
             "detail": tx("Cuenta configurada como admin, con 4672 o agregada a grupo privilegiado.",
                          "Account configured as admin, with 4672 or added to a privileged group.")},
            {"factor": tx("Host crítico", "Critical host"), "points": f"+{s['critical_host_bonus']}",
             "detail": tx("Host que coincide con patrones de DC/servidor.", "Host matching DC/server patterns.")},
            {"factor": tx("Volumen", "Volume"), "points": f"0–{s['volume_max']}",
             "detail": tx("round(5·log10(filas de evidencia)).", "round(5·log10(evidence rows)).")},
            {"factor": tx("Correlación", "Correlation"),
             "points": tx(f"+{s['correlation_per_tactic']} por táctica adicional (máx. {s['correlation_max']})",
                          f"+{s['correlation_per_tactic']} per additional tactic (max {s['correlation_max']})"),
             "detail": tx("Otras fases del mismo incidente.", "Other phases of the same incident.")},
            {"factor": tx("Tope anomalías", "Anomaly cap"), "points": f"≤ {s['anomaly_cap']}",
             "detail": tx("Las anomalías nunca se clasifican por encima de Medio.", "Anomalies are never rated above Medium.")},
            {"factor": tx("Incidente", "Incident"),
             "points": tx(f"máx. hallazgo + {s['incident_breadth_per_tactic']} por táctica adicional",
                          f"max finding + {s['incident_breadth_per_tactic']} per additional tactic"),
             "detail": tx("Amplitud de la cadena de ataque.", "Attack chain breadth.")},
        ],
        "bands": [
            {"severity": "Crítico", "range": f"≥ {s['bands']['critical']}"},
            {"severity": "Alto", "range": f"{s['bands']['high']}–{s['bands']['critical'] - 1}"},
            {"severity": "Medio", "range": f"{s['bands']['medium']}–{s['bands']['high'] - 1}"},
            {"severity": "Bajo", "range": f"< {s['bands']['medium']}"},
        ],
        "base": s["base"],
    }
