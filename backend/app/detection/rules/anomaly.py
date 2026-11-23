"""Anomalías estadísticas (AN-*). Se rotulan como ANOMALÍA, nunca como incidente confirmado."""
from __future__ import annotations

import pandas as pd

from app.detection.base import Context, Finding, Rule, make_finding, uniq
from app.lang import tx


def _anomaly_note() -> str:
    return tx("Anomalía estadística: requiere validación; no constituye por sí sola un incidente.",
              "Statistical anomaly: requires validation; it is not an incident on its own.")


def an001(ctx: Context, p: dict) -> list[Finding]:
    df = ctx.df
    if df.empty:
        return []
    local = df["ts"].dt.tz_convert("UTC").dt.floor("h").dt.tz_convert(ctx.tz)
    day = local.dt.strftime("%Y-%m-%d")
    hour = local.dt.hour
    grid = pd.crosstab(day, hour)
    all_days = pd.date_range(df["ts"].min().normalize(), df["ts"].max().normalize(), freq="D").strftime("%Y-%m-%d")
    grid = grid.reindex(index=all_days, columns=range(24), fill_value=0)
    out = []
    for d in grid.index:
        for h in grid.columns:
            c = int(grid.at[d, h])
            if c < p["min_events"]:
                continue
            others = grid[h].drop(d)
            if len(others) < 2:  # archivo de 1–2 días: no hay línea base para comparar esa hora
                continue
            mean, std = float(others.mean()), float(others.std(ddof=0))
            z = (c - mean) / (std + 1.0)
            if z < p["min_zscore"] or c < p["min_ratio"] * (mean + 1):
                continue
            part = df[(day == d) & (hour == h)]
            top_users = part["user"].value_counts().head(3)
            top_ips = part["src_ip"].value_counts().head(3)
            users_txt = ", ".join(f"{u} ({n})" for u, n in top_users.items()) or "—"
            ips_txt = ", ".join(f"{i} ({n})" for i, n in top_ips.items()) or "—"
            summary = tx(f"{c} eventos el {d} entre las {h:02d}:00 y {h:02d}:59 frente a una media de {mean:.1f} "
                         f"(σ={std:.1f}) para esa misma hora en los demás días (z={z:.1f}). "
                         f"Principales usuarios: {users_txt}; IPs: {ips_txt}.",
                         f"{c} events on {d} between {h:02d}:00 and {h:02d}:59 versus a mean of {mean:.1f} "
                         f"(σ={std:.1f}) for the same hour on other days (z={z:.1f}). "
                         f"Top users: {users_txt}; IPs: {ips_txt}.")
            title = tx(f"Pico de volumen: {c} eventos el {d} {h:02d}h", f"Volume spike: {c} events on {d} {h:02d}h")
            out.append(make_finding("AN-001", part, title, summary, ctx,
                                    entity_cols=(), related_cols=("user", "host", "src_ip"),
                                    metrics={"events": c, "mean": round(mean, 1), "std": round(std, 1), "z": round(z, 1)},
                                    confidence="baja", fp_notes=[_anomaly_note(), tx(
                                        "Procesos batch o despliegues masivos generan picos legítimos.",
                                        "Batch jobs or mass deployments produce legitimate spikes.")]))
    return out


def an002(ctx: Context, p: dict) -> list[Finding]:
    df = ctx.df
    if ctx.baseline_end is None:
        return []
    after = ctx.after_baseline(df["ts"])
    out = []
    labels = {"user": tx("usuario", "user"), "host": "host", "src_ip": tx("IP de origen", "source IP")}
    titles = {"user": tx("Usuario visto por primera vez", "User first seen"),
              "host": tx("Host visto por primera vez", "Host first seen"),
              "src_ip": tx("IP de origen vista por primera vez", "Source IP first seen")}
    for col in ("user", "host", "src_ip"):
        if not ctx.has(col):
            continue
        seen = set(df.loc[~after, col].dropna())
        if col == "user":
            seen |= set(df.loc[~after, "target_user"].dropna())
        new_rows = df[after & df[col].notna() & ~df[col].isin(seen) & ~df[col].map(ctx.is_ignored)]
        for value, part in new_rows.groupby(col, sort=False):
            first, base_end = f"{part['ts'].min():%d/%m %H:%M}", f"{ctx.baseline_end:%d/%m %H:%M}"
            summary = tx(f"El {labels[col]} «{value}» aparece por primera vez el {first}, después "
                         f"del período base (hasta {base_end}), en {len(part)} evento(s).",
                         f"The {labels[col]} “{value}” appears for the first time on {first}, after "
                         f"the baseline period (until {base_end}), in {len(part)} event(s).")
            out.append(make_finding("AN-002", part, f"{titles[col]}: {value}",
                                    summary, ctx, entity_cols=(col,), related_cols=("user", "host", "src_ip"),
                                    metrics={"events": len(part), "entity_type": col}, confidence="baja",
                                    fp_notes=[_anomaly_note(), tx("Altas de empleados o equipos nuevos aparecen así.",
                                                                  "New employees or new machines show up like this.")]))
    return out


def an003(ctx: Context, p: dict) -> list[Finding]:
    df = ctx.df
    out = []
    n = max(len(df), 1)
    specs = []
    if ctx.has("event_id"):
        specs.append(("event_id", df["event_id"], "EventID"))
    if ctx.has("process"):
        specs.append(("process", df["process"].fillna("").str.lower().str.split("\\").str[-1].replace("", None),
                      tx("proceso", "process")))
    for name, series, label in specs:
        counts = series.value_counts()
        rare = counts[(counts <= p["max_count"]) & (counts / n <= p["max_share"] * 10)]
        for value in rare.index:
            part = df[series == value]
            part = part[~part["row_id"].isin(ctx.covered_rows)]
            if part.empty:
                continue
            summary = tx(f"El {label} «{value}» aparece solo {int(counts[value])} vez/veces en {n} eventos y no está "
                         "cubierto por ninguna regla de detección.",
                         f"The {label} “{value}” appears only {int(counts[value])} time(s) in {n} events and is not "
                         "covered by any detection rule.")
            title = tx(f"{label[0].upper() + label[1:]} poco frecuente: {value}", f"Rare {label}: {value}")
            out.append(make_finding("AN-003", part, title, summary, ctx,
                                    entity_cols=(), related_cols=("user", "host"),
                                    metrics={"count": int(counts[value])}, confidence="baja",
                                    fp_notes=[_anomaly_note()]))
    return out


RULES = [
    Rule("AN-001", "Pico de volumen", "Volume spike", "anomaly", "anomaly", [],
         "Cantidad de eventos en una hora muy superior a la misma hora de los demás días (z-score).",
         "Hourly event count far above the same hour on other days (z-score).", ["timestamp"], an001),
    Rule("AN-002", "Entidad vista por primera vez", "First-seen entity", "anomaly", "anomaly", [],
         "Usuario, host o IP que no aparece en el período base y surge después.",
         "User, host or IP absent from the baseline period.", ["timestamp", "user|host|src_ip"], an002),
    Rule("AN-003", "Evento o proceso poco frecuente", "Rare event or process", "anomaly", "anomaly", [],
         "EventID o proceso de muy baja frecuencia no cubierto por otras reglas.",
         "Very rare EventID/process not covered by other rules.", ["timestamp", "event_id|process"], an003),
]
