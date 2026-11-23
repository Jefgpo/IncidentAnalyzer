"""Orquestador: evalúa reglas, correlaciona, puntúa y extrae IoCs."""
from __future__ import annotations

import logging
import math
import time
import warnings

import pandas as pd

from app import settings
from app.correlation.correlator import correlate
from app.detection.base import CATEGORIES, TACTICS, Context, Finding
from app.detection.rules import anomaly, auth, host, network
from app.iocs.extractor import extract_iocs
from app.lang import tx, using
from app.scoring.risk import methodology

log = logging.getLogger("soc.engine")
warnings.filterwarnings("ignore", message="This pattern is interpreted as a regular expression")


def json_safe(obj):
    """Convierte NaN/inf en None y tipos numpy en nativos: la respuesta debe ser JSON válido siempre."""
    if isinstance(obj, dict):
        return {k: json_safe(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [json_safe(v) for v in obj]
    if hasattr(obj, "item") and not isinstance(obj, (str, bytes)):
        obj = obj.item()
    if isinstance(obj, float) and not math.isfinite(obj):
        return None
    return obj


CORE_RULES = auth.RULES + host.RULES + network.RULES
ANOMALY_RULES = anomaly.RULES
ALL_RULES = CORE_RULES + ANOMALY_RULES
RULES_BY_ID = {r.id: r for r in ALL_RULES}


def catalog() -> list[dict]:
    return [r.meta() for r in ALL_RULES]


def run_analysis(events: pd.DataFrame, cfg: dict | None = None, lang: str = "es") -> dict:
    """Análisis completo. El idioma solo cambia los textos: hallazgos, IDs y puntajes son idénticos."""
    with using(lang):
        return _run_analysis(events, cfg)


def _run_analysis(events: pd.DataFrame, cfg: dict | None = None) -> dict:
    cfg = cfg or settings.rules_config()
    t0 = time.perf_counter()
    ctx = Context(events, cfg)
    statuses: list[dict] = []
    findings: list[Finding] = []

    def evaluate(rules):
        for rule in rules:
            meta = rule.meta()
            missing = rule.missing(ctx)
            if missing:
                statuses.append({**meta, "status": "no_evaluable", "missing": missing, "count": 0})
                continue
            params = (cfg.get("rules") or {}).get(rule.id) or {}
            try:
                produced = rule.fn(ctx, params)
            except Exception:  # una regla rota no debe tumbar el análisis
                log.exception("Error evaluando la regla %s", rule.id)
                statuses.append({**meta, "status": "error", "missing": [], "count": 0})
                continue
            for f in produced:
                f.rule_name = tx(rule.name, rule.name_en)
                f.category = rule.category
                f.tactic = rule.tactic
                f.mitre = meta["mitre"]
                f.is_anomaly = rule.category == "anomaly"
                if rule.fp_hint and rule.fp_hint not in f.fp_notes:
                    f.fp_notes.append(rule.fp_hint)
            findings.extend(produced)
            statuses.append({**meta, "status": "con_hallazgos" if produced else "sin_hallazgos",
                             "missing": [], "count": len(produced)})

    evaluate(CORE_RULES)
    ctx.covered_rows = {r for f in findings for r in f.rows}
    evaluate(ANOMALY_RULES)

    findings.sort(key=lambda f: (f.start or "", f.rule_id))
    for i, f in enumerate(findings, 1):
        f.id = f"F-{i:03d}"
    incidents, isolated, conclusion = correlate(findings, ctx, cfg)
    iocs = extract_iocs(ctx, findings)

    categories = []
    for key, label in CATEGORIES.items():
        rules = [s for s in statuses if s["category"] == key]
        count = sum(1 for f in findings if f.category == key)
        evaluable = [s for s in rules if s["status"] != "no_evaluable"]
        categories.append({"category": key, "label": tx(label["es"], label["en"]), "label_en": label["en"], "findings": count,
                           "rules_total": len(rules), "rules_evaluable": len(evaluable),
                           "status": ("con_hallazgos" if count else
                                      "sin_hallazgos" if evaluable else "no_evaluable")})
    log.info("Análisis: %d reglas, %d hallazgos, %d incidentes en %.2fs", len(statuses), len(findings),
             len(incidents), time.perf_counter() - t0)
    return json_safe({
        "findings": [f.to_dict() for f in findings],
        "incidents": incidents,
        "isolated": isolated,
        "conclusion": conclusion,
        "rules": statuses,
        "categories": categories,
        "iocs": iocs,
        "methodology": methodology(cfg),
        "tactics": TACTICS,
        "baseline_end": ctx.baseline_end.isoformat() if ctx.baseline_end is not None else None,
        "span_hours": round(ctx.span_hours, 1),
        "config": {"timezone": ctx.tz, "business_hours": cfg["general"]["business_hours"],
                   "allowed_countries": cfg["general"]["allowed_countries"],
                   "rules": cfg.get("rules", {}), "correlation": cfg["correlation"],
                   "min_baseline_hours": cfg["general"].get("min_baseline_hours", 48)},
        "elapsed_s": round(time.perf_counter() - t0, 2),
    })
