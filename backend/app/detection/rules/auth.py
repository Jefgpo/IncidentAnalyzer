"""Reglas de autenticación: fuerza bruta (BF-*) e inicios de sesión sospechosos (LOG-*)."""
from __future__ import annotations

import math

import numpy as np
import pandas as pd

from app.detection.base import Context, Finding, Rule, clusters, distinct_bursts, bursts, make_finding, uniq
from app.lang import tx


def _auth(ctx: Context, kind: str) -> pd.DataFrame:
    return ctx.df[ctx.df["sem"] == kind]


def _fmt_list(values: list[str], limit: int = 6) -> str:
    shown = ", ".join(values[:limit])
    extra = len(values) - limit
    return shown + (tx(f" y {extra} más", f" and {extra} more") if extra > 0 else "")


def _unknown_src() -> str:
    return tx("origen no informado", "unreported source")


# ------------------------------------------------------------------------ BF-001
def bf001(ctx: Context, p: dict) -> list[Finding]:
    fails = _auth(ctx, "auth_fail")
    fails = fails[fails["user"].notna()]
    window = pd.Timedelta(minutes=p["window_minutes"])
    k = int(p["min_failures"])
    origin = "src_ip" if ctx.has("src_ip") else "host"
    oks = _auth(ctx, "auth_ok")
    out = []
    for (user, src), g in fails.groupby(["user", origin], dropna=False, sort=False):
        g = g.sort_values("ts")
        for a, b in bursts(g["ts"].values, window, k):
            part = g.iloc[a:b + 1]
            follow = oks[(oks["user"] == user) & (oks["ts"] > part["ts"].max()) &
                         (oks["ts"] <= part["ts"].max() + pd.Timedelta(minutes=30))]
            if isinstance(src, str):
                follow = follow[follow[origin] == src]
            success = not follow.empty
            src_txt = src if isinstance(src, str) else _unknown_src()
            t0, t1 = f"{part['ts'].min():%d/%m %H:%M}", f"{part['ts'].max():%d/%m %H:%M}"
            summary = tx(
                f"{len(part)} intentos de autenticación fallidos contra la cuenta «{user}» desde "
                f"{src_txt} entre {t0} y {t1} (umbral: {k} en {p['window_minutes']} min). "
                + ("Se observó un inicio de sesión exitoso posterior (ver BF-003)." if success else
                   "No se observó un inicio de sesión exitoso posterior desde el mismo origen."),
                f"{len(part)} failed authentication attempts against account “{user}” from "
                f"{src_txt} between {t0} and {t1} (threshold: {k} in {p['window_minutes']} min). "
                + ("A later successful logon was observed (see BF-003)." if success else
                   "No later successful logon was observed from the same source."))
            title = tx(f"Fuerza bruta contra «{user}» desde {src_txt}", f"Brute force against “{user}” from {src_txt}")
            out.append(make_finding("BF-001", part, title, summary, ctx,
                                    entity_cols=("user", origin), related_cols=("host",),
                                    metrics={"failures": len(part)}, auth_success=success,
                                    confidence="alta",
                                    fp_notes=[tx("Puede tratarse de un servicio con credenciales vencidas que reintenta "
                                                 "automáticamente; validar con el dueño de la cuenta.",
                                                 "It may be a service with expired credentials retrying automatically; "
                                                 "validate with the account owner.")]))
    return out


# ------------------------------------------------------------------------ BF-002
def bf002(ctx: Context, p: dict) -> list[Finding]:
    fails = _auth(ctx, "auth_fail")
    fails = fails[fails["src_ip"].notna() & fails["user"].notna()]
    window = pd.Timedelta(minutes=p["window_minutes"])
    k = int(p["min_distinct_users"])
    out = []
    for src, g in fails.groupby("src_ip", sort=False):
        g = g.sort_values("ts")
        for a, b in distinct_bursts(g["ts"].values, list(g["user"]), window, k):
            part = g.iloc[a:b + 1]
            users = uniq(part["user"])
            t0, t1 = f"{part['ts'].min():%d/%m %H:%M}", f"{part['ts'].max():%d/%m %H:%M}"
            summary = tx(
                f"La IP {src} falló la autenticación contra {len(users)} cuentas distintas "
                f"({_fmt_list(users)}) en {len(part)} intentos entre {t0} y {t1}; patrón compatible con "
                f"password spraying (umbral: {k} usuarios en {p['window_minutes']} min).",
                f"IP {src} failed authentication against {len(users)} distinct accounts "
                f"({_fmt_list(users)}) in {len(part)} attempts between {t0} and {t1}; pattern consistent with "
                f"password spraying (threshold: {k} users in {p['window_minutes']} min).")
            title = tx(f"Password spraying desde {src} ({len(users)} cuentas)",
                       f"Password spraying from {src} ({len(users)} accounts)")
            out.append(make_finding("BF-002", part, title, summary,
                                    ctx, entity_cols=("src_ip",), related_cols=("user", "host"),
                                    metrics={"failures": len(part), "distinct_users": len(users)},
                                    auth_success=False, confidence="alta",
                                    fp_notes=[tx("Un proxy/NAT corporativo compartido puede concentrar fallos legítimos "
                                                 "de muchos usuarios; verificar la naturaleza de la IP.",
                                                 "A shared corporate proxy/NAT can concentrate legitimate failures "
                                                 "from many users; verify what the IP is.")]))
    return out


# ------------------------------------------------------------------------ BF-003
def bf003(ctx: Context, p: dict) -> list[Finding]:
    fails = _auth(ctx, "auth_fail")
    oks = _auth(ctx, "auth_ok")
    look = pd.Timedelta(minutes=p["lookback_minutes"])
    k = int(p["min_failures"])
    use_ip = ctx.has("src_ip")
    out = []
    by_user = {u: g for u, g in fails.groupby("user", sort=False)}
    seen: set[str] = set()
    for _, ok in oks[oks["user"].isin(by_user.keys())].iterrows():
        g = by_user[ok["user"]]
        prior = g[(g["ts"] < ok["ts"]) & (g["ts"] >= ok["ts"] - look)]
        same_origin = prior[prior["src_ip"] == ok["src_ip"]] if use_ip and isinstance(ok["src_ip"], str) else prior
        # desde una IP externa bastan menos fallos: un usuario legítimo no suele equivocarse desde Internet
        needed = int(p.get("min_failures_external", k)) if ctx.is_external(ok["src_ip"]) else k
        if len(same_origin) < needed:
            continue
        key = f"{ok['user']}|{ok['src_ip']}|{prior['ts'].min()}"
        if key in seen:
            continue
        seen.add(key)
        part = pd.concat([same_origin, ok.to_frame().T]).sort_values("ts")
        part["ts"] = pd.to_datetime(part["ts"], utc=True).dt.tz_convert(ctx.tz)
        src_txt = ok["src_ip"] if isinstance(ok["src_ip"], str) else _unknown_src()
        when = f"{ok['ts']:%d/%m %H:%M:%S}"
        summary = tx(
            f"Tras {len(same_origin)} fallos consecutivos para «{ok['user']}» desde {src_txt}, se registró un "
            f"inicio de sesión EXITOSO a las {when} (fila {ok['row_id']}). Indica que la "
            "credencial pudo haber sido adivinada o comprometida.",
            f"After {len(same_origin)} consecutive failures for “{ok['user']}” from {src_txt}, a SUCCESSFUL "
            f"logon was recorded at {when} (row {ok['row_id']}). The credential may have been guessed or "
            "compromised.")
        title = tx(f"Éxito tras racha de fallos: «{ok['user']}»", f"Success after failure streak: “{ok['user']}”")
        out.append(make_finding("BF-003", part, title, summary, ctx,
                                entity_cols=("user", "src_ip"), related_cols=("host",),
                                metrics={"failures_before": len(same_origin)}, auth_success=True,
                                confidence="alta",
                                fp_notes=[tx("El usuario legítimo pudo recordar la contraseña tras varios intentos; "
                                             "confirmar con el usuario y revisar el origen.",
                                             "The legitimate user may have remembered the password after several "
                                             "attempts; confirm with the user and review the source.")]))
    return out


# ------------------------------------------------------------------------ LOG-001
def log001(ctx: Context, p: dict) -> list[Finding]:
    oks = _auth(ctx, "auth_ok")
    oks = oks[oks["src_ip"].map(ctx.is_external).astype(bool) & ~oks["src_ip"].map(ctx.is_allowlisted).astype(bool)]
    allowed = {c.upper() for c in ctx.general.get("allowed_countries", [])}
    if ctx.has("country"):
        mask = oks["country"].notna() & ~oks["country"].isin(allowed)
        reason = tx("país fuera de la lista de países habituales (", "country outside the usual-country list (") \
            + ", ".join(sorted(allowed)) + ")"
        # sin país informado: IP externa no vista en el período base para esa cuenta
        no_geo = oks[oks["country"].isna()]
    else:
        mask = pd.Series(False, index=oks.index)
        no_geo = oks
        reason = ""
    if ctx.baseline_end is None:
        # sin línea base (archivo de pocas horas): todo logon exitoso desde IP pública sin geolocalización
        # se informa; las IPs legítimas (VPN, NAT) se excluyen con external_ip_allowlist
        unseen = no_geo
    else:
        base = ctx.df[~ctx.after_baseline(ctx.df["ts"]) & (ctx.df["sem"] == "auth_ok")]
        seen_pairs = set(zip(base["user"], base["src_ip"]))
        unseen = no_geo[ctx.after_baseline(no_geo["ts"]) &
                        ~pd.Series([(u, i) in seen_pairs for u, i in zip(no_geo["user"], no_geo["src_ip"])],
                                   index=no_geo.index, dtype=bool)]
    hits = pd.concat([oks[mask], unseen]).drop_duplicates("row_id")
    out = []
    for (user, ip), part in clusters(hits, ["user", "src_ip"], pd.Timedelta(hours=24)):
        countries = uniq(part["country"]) if "country" in part else []
        if countries and not set(countries) <= allowed:
            why = reason
        elif ctx.baseline_end is None:
            why = tx("acceso exitoso desde una IP pública (el archivo no trae geolocalización ni cubre días "
                     "suficientes para una línea base)",
                     "successful access from a public IP (the file has no geolocation and does not cover enough "
                     "days for a baseline)")
        else:
            why = tx("IP externa no observada para esta cuenta durante el período base",
                     "external IP not seen for this account during the baseline period")
        geo = (tx(f" (geolocalización informada: {', '.join(countries)})",
                  f" (reported geolocation: {', '.join(countries)})") if countries else "")
        summary = tx(f"{len(part)} inicio(s) de sesión exitoso(s) de «{user}» desde la IP externa {ip}{geo}. "
                     f"Motivo: {why}.",
                     f"{len(part)} successful logon(s) by “{user}” from external IP {ip}{geo}. Reason: {why}.")
        title = tx(f"Logon desde origen inusual: «{user}» desde {ip}", f"Logon from unusual source: “{user}” from {ip}")
        out.append(make_finding("LOG-001", part, title, summary, ctx,
                                entity_cols=("user", "src_ip"), related_cols=("host", "country", "city"),
                                metrics={"logons": len(part)}, auth_success=True, confidence="media",
                                fp_notes=[tx("Viajes de negocio o VPN comerciales del propio usuario pueden explicar "
                                             "el origen; confirmar con el usuario.",
                                             "Business travel or the user's own commercial VPN may explain the "
                                             "source; confirm with the user.")]))
    return out


# ------------------------------------------------------------------------ LOG-002
def log002(ctx: Context, p: dict) -> list[Finding]:
    oks = _auth(ctx, "auth_ok")
    lt = oks["logon_type"]
    interactive = lt.isin(ctx.interactive_types) | (lt.isna() & oks["src_ip"].map(ctx.is_external).astype(bool))
    oks = oks[interactive & ~oks["user"].map(ctx.is_service).astype(bool) & oks["user"].notna()]
    hits = oks[ctx.off_hours(oks["ts"])]
    bh = ctx.general["business_hours"]
    out = []
    for (user,), part in clusters(hits, ["user"], pd.Timedelta(hours=2)):
        t0, t1 = f"{part['ts'].min():%d/%m %H:%M}", f"{part['ts'].max():%d/%m %H:%M}"
        hours = f"{bh['start']:02d}:00–{bh['end']:02d}:00, {ctx.tz}"
        summary = tx(f"{len(part)} inicio(s) de sesión interactivo(s)/remoto(s) de «{user}» fuera del horario laboral "
                     f"configurado (L–V {hours}), entre {t0} y {t1}.",
                     f"{len(part)} interactive/remote logon(s) by “{user}” outside the configured business hours "
                     f"(Mon–Fri {hours}), between {t0} and {t1}.")
        out.append(make_finding("LOG-002", part, tx(f"Logon fuera de horario: «{user}»", f"Off-hours logon: “{user}”"),
                                summary, ctx,
                                metrics={"logons": len(part)}, auth_success=True, confidence="baja",
                                fp_notes=[tx("El trabajo fuera de horario (guardias, teletrabajo) es habitual; por sí "
                                             "solo no indica compromiso.",
                                             "Off-hours work (on-call, remote work) is common; on its own it does "
                                             "not indicate compromise.")]))
    return out


# ------------------------------------------------------------------------ LOG-003
def log003(ctx: Context, p: dict) -> list[Finding]:
    oks = _auth(ctx, "auth_ok")
    hits = oks[oks["user"].map(ctx.is_service).astype(bool) & oks["logon_type"].isin(ctx.interactive_types)]
    out = []
    for (user,), part in clusters(hits, ["user"], pd.Timedelta(hours=12)):
        types = ", ".join(uniq(part["logon_type"]))
        hosts = ", ".join(uniq(part["host"]))
        srcs = ", ".join(uniq(part["src_ip"])) or _unknown_src()
        summary = tx(f"La cuenta de servicio «{user}» inició sesión de forma interactiva/remota (logon type {types}) "
                     f"en {hosts} desde {srcs}. Las cuentas de servicio no deberían usarse para sesiones interactivas.",
                     f"Service account “{user}” logged on interactively/remotely (logon type {types}) "
                     f"on {hosts} from {srcs}. Service accounts should not be used for interactive sessions.")
        title = tx(f"Cuenta de servicio con logon interactivo: «{user}»", f"Service account with interactive logon: “{user}”")
        out.append(make_finding("LOG-003", part, title, summary, ctx,
                                metrics={"logons": len(part)}, auth_success=True, confidence="alta",
                                fp_notes=[tx("Un administrador pudo usar la cuenta para una tarea de mantenimiento; "
                                             "verificar ticket de cambio.",
                                             "An administrator may have used the account for maintenance; check "
                                             "for a change ticket.")]))
    return out


# ------------------------------------------------------------------------ LOG-004
def _haversine(lat1, lon1, lat2, lon2) -> float:
    r = 6371.0
    p1, p2 = math.radians(lat1), math.radians(lat2)
    dp, dl = p2 - p1, math.radians(lon2 - lon1)
    a = math.sin(dp / 2) ** 2 + math.cos(p1) * math.cos(p2) * math.sin(dl / 2) ** 2
    return 2 * r * math.asin(math.sqrt(a))


def log004(ctx: Context, p: dict) -> list[Finding]:
    oks = _auth(ctx, "auth_ok")
    oks = oks[oks["lat"].notna() & oks["lon"].notna() & oks["user"].notna()]
    out = []
    for user, g in oks.groupby("user", sort=False):
        g = g.sort_values("ts")
        pairs = []
        rows = list(g.itertuples())
        for a, b in zip(rows, rows[1:]):
            dist = _haversine(a.lat, a.lon, b.lat, b.lon)
            hours = max((b.ts - a.ts).total_seconds() / 3600, 1 / 60)
            speed = dist / hours
            if dist >= p["min_distance_km"] and speed > p["max_speed_kmh"]:
                pairs.append((a, b, dist, speed))
        if not pairs:
            continue
        idx = sorted({x.Index for a, b, *_ in pairs for x in (a, b)})
        part = g.loc[idx]
        details = [f"{a.ts:%d/%m %H:%M} {a.city or a.country} ({a.row_id}) → {b.ts:%d/%m %H:%M} "
                   f"{b.city or b.country} ({b.row_id}): {dist:,.0f} km, {speed:,.0f} km/h"
                   for a, b, dist, speed in pairs]
        summary = tx(f"La cuenta «{user}» registró inicios de sesión exitosos desde ubicaciones separadas por distancias "
                     f"imposibles de recorrer en el tiempo transcurrido (velocidad > {p['max_speed_kmh']} km/h) en "
                     f"{len(pairs)} ocasión(es).",
                     f"Account “{user}” logged on successfully from locations whose distance cannot be covered in "
                     f"the elapsed time (speed > {p['max_speed_kmh']} km/h) on {len(pairs)} occasion(s).")
        out.append(make_finding("LOG-004", part, tx(f"Viaje imposible: «{user}»", f"Impossible travel: “{user}”"),
                                summary, ctx,
                                entity_cols=("user", "src_ip"), related_cols=("country", "city"),
                                metrics={"pairs": len(pairs), "max_speed_kmh": round(max(x[3] for x in pairs))},
                                auth_success=True, confidence="media", details=details,
                                fp_notes=[tx("La geolocalización por IP puede ser imprecisa (VPN, proxies móviles).",
                                             "IP geolocation can be inaccurate (VPNs, mobile proxies).")]))
    return out


# ------------------------------------------------------------------------ LOG-005
def log005(ctx: Context, p: dict) -> list[Finding]:
    oks = _auth(ctx, "auth_ok")
    oks = oks[oks["src_ip"].map(ctx.is_external).astype(bool) & oks["user"].notna()]
    window = pd.Timedelta(minutes=p["window_minutes"])
    out = []
    for user, g in oks.groupby("user", sort=False):
        g = g.sort_values("ts")
        for a, b in distinct_bursts(g["ts"].values, list(g["src_ip"]), window, 2):
            part = g.iloc[a:b + 1]
            ips = uniq(part["src_ip"])
            span = f"{part['ts'].min():%d/%m %H:%M}–{part['ts'].max():%H:%M}"
            summary = tx(f"La cuenta «{user}» tuvo sesiones exitosas desde {len(ips)} IPs externas distintas "
                         f"({', '.join(ips)}) en menos de {p['window_minutes']} minutos ({span}).",
                         f"Account “{user}” had successful sessions from {len(ips)} distinct external IPs "
                         f"({', '.join(ips)}) within {p['window_minutes']} minutes ({span}).")
            title = tx(f"Sesiones simultáneas: «{user}» desde {len(ips)} IPs", f"Concurrent sessions: “{user}” from {len(ips)} IPs")
            out.append(make_finding("LOG-005", part, title, summary,
                                    ctx, entity_cols=("user", "src_ip"), related_cols=("country",),
                                    metrics={"distinct_ips": len(ips)}, auth_success=True, confidence="media",
                                    fp_notes=[tx("Cambio de red del usuario (wifi → 4G) puede generar dos IPs en "
                                                 "minutos; contrastar con la geolocalización.",
                                                 "A network change by the user (wifi → 4G) can produce two IPs within "
                                                 "minutes; cross-check with geolocation.")]))
    return out


RULES = [
    Rule("BF-001", "Fuerza bruta por cuenta", "Brute force per account", "bruteforce", "credential_access",
         [("T1110.001", "Brute Force: Password Guessing")],
         "Muchos fallos de autenticación para una misma cuenta y origen dentro de una ventana corta.",
         "Many failed authentications for one account and source in a short window.",
         ["timestamp", "user", "auth"], bf001),
    Rule("BF-002", "Password spraying", "Password spraying", "bruteforce", "credential_access",
         [("T1110.003", "Brute Force: Password Spraying")],
         "Una misma IP falla la autenticación contra muchas cuentas distintas en poco tiempo.",
         "A single IP fails authentication against many distinct accounts.",
         ["timestamp", "user", "src_ip", "auth"], bf002),
    Rule("BF-003", "Éxito tras racha de fallos", "Success after failure streak", "bruteforce", "initial_access",
         [("T1110", "Brute Force"), ("T1078", "Valid Accounts")],
         "Inicio de sesión exitoso precedido por una racha de fallos para la misma cuenta y origen.",
         "Successful logon preceded by a streak of failures for the same account/source.",
         ["timestamp", "user", "auth"], bf003),
    Rule("LOG-001", "Logon desde origen inusual", "Logon from unusual source", "suspicious_logon", "initial_access",
         [("T1078", "Valid Accounts"), ("T1133", "External Remote Services")],
         "Inicio de sesión exitoso desde IP externa con país no habitual, o IP externa nunca vista para la cuenta.",
         "Successful logon from an external IP in an unusual country or never seen for the account.",
         ["timestamp", "user", "src_ip", "auth"], log001),
    Rule("LOG-002", "Logon fuera de horario", "Off-hours logon", "suspicious_logon", "initial_access",
         [("T1078", "Valid Accounts")],
         "Inicio de sesión interactivo/remoto fuera del horario laboral del cliente (zona horaria configurada).",
         "Interactive/remote logon outside client business hours.",
         ["timestamp", "user", "auth", "logon_type|src_ip"], log002),
    Rule("LOG-003", "Cuenta de servicio con logon interactivo", "Service account interactive logon",
         "suspicious_logon", "initial_access", [("T1078.002", "Valid Accounts: Domain Accounts")],
         "Cuenta de servicio (patrón configurable) con logon type interactivo o RDP.",
         "Service account with interactive/RDP logon type.",
         ["timestamp", "user", "auth", "logon_type"], log003),
    Rule("LOG-004", "Viaje imposible", "Impossible travel", "suspicious_logon", "initial_access",
         [("T1078", "Valid Accounts")],
         "Dos logons exitosos de la misma cuenta desde ubicaciones cuya distancia exige una velocidad imposible.",
         "Two successful logons whose distance implies an impossible travel speed.",
         ["timestamp", "user", "auth", "geo"], log004),
    Rule("LOG-005", "Sesiones simultáneas anómalas", "Anomalous concurrent sessions", "suspicious_logon",
         "initial_access", [("T1078", "Valid Accounts")],
         "Sesiones exitosas de la misma cuenta desde varias IPs externas en pocos minutos.",
         "Successful sessions of the same account from several external IPs within minutes.",
         ["timestamp", "user", "src_ip", "auth"], log005),
]
