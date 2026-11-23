"""Reglas de red, web y datos: C2 por intérpretes de scripts, web shells, acceso masivo a archivos y exfiltración."""
from __future__ import annotations

import re

import pandas as pd

from app.detection.base import Context, Finding, Rule, clusters, distinct_bursts, make_finding, uniq
from app.lang import tx

HOUR = pd.Timedelta(hours=1)
SCRIPT_HOSTS = {"powershell.exe", "pwsh.exe", "cmd.exe", "wscript.exe", "cscript.exe", "mshta.exe", "rundll32.exe",
                "regsvr32.exe", "certutil.exe", "bitsadmin.exe", "msbuild.exe", "installutil.exe"}
_PROC_IN_TEXT = re.compile(r"\b(?:process|proceso|application|app)\s*[=:]\s*\"?([\w.\\:-]+)", re.IGNORECASE)
_OBJECT_IN_TEXT = re.compile(r"(?:file access|object name|nombre del objeto|share access|file share access|objeto)\s*[:=]\s*(.+)",
                             re.IGNORECASE)
_WEBSHELL_URI = re.compile(r"\.(aspx?|ashx|php\d?|jspx?|cfm)\?[^\s]*\b(cmd|exec|command|execute|c)=", re.IGNORECASE)
_WEB_IDENTITY = re.compile(r"apppool|^iusr|www-data|^apache|^nginx|^tomcat|^w3wp|^httpd", re.IGNORECASE)
_SHELLISH = re.compile(r"\b(cmd(\.exe)?\s*/c|powershell|pwsh|whoami|net1?(\.exe)?\s|certutil|ipconfig|systeminfo|bitsadmin)",
                       re.IGNORECASE)


def _process_of(row) -> str | None:
    proc = row.get("process")
    if isinstance(proc, str) and proc:
        return proc.replace("/", "\\").split("\\")[-1].lower()
    text = " ".join(v for v in (row.get("message"), row.get("command_line")) if isinstance(v, str))
    m = _PROC_IN_TEXT.search(text)
    return m.group(1).replace("/", "\\").split("\\")[-1].lower() if m else None


# ------------------------------------------------------------------------ C2-001
def c2001(ctx: Context, p: dict) -> list[Finding]:
    df = ctx.df
    net = df[df["sem"].isin(["net_conn", "proxy_request"]) & df["dst_ip"].map(ctx.is_external).astype(bool)]
    if net.empty:
        return []
    procs = net.apply(_process_of, axis=1)
    hits = net[procs.isin(SCRIPT_HOSTS)].copy()
    hits["proc"] = procs[hits.index]
    out = []
    for (host,), part in clusters(hits, ["host"], HOUR):
        dsts = uniq(f"{ip}:{port}" if isinstance(port, str) else ip for ip, port in zip(part["dst_ip"], part["port"]))
        procs_txt = ", ".join(uniq(part["proc"]))
        summary = tx(f"{len(part)} conexión(es) saliente(s) desde {host} iniciadas por un intérprete de scripts/LOLBin "
                     f"({procs_txt}) hacia IP(s) pública(s) {', '.join(dsts[:5])}. Los intérpretes de "
                     "comandos no suelen conectarse directamente a Internet; es un patrón típico de descarga de "
                     "herramientas o de canal de comando y control.",
                     f"{len(part)} outbound connection(s) from {host} started by a script interpreter/LOLBin "
                     f"({procs_txt}) to public IP(s) {', '.join(dsts[:5])}. Command interpreters rarely connect "
                     "directly to the Internet; this is a typical tool-download or command-and-control pattern.")
        title = tx(f"Conexión externa de {procs_txt} desde {host}", f"External connection by {procs_txt} from {host}")
        f = make_finding("C2-001", part, title, summary,
                         ctx, related_cols=("dst_ip",), metrics={"connections": len(part)}, confidence="media",
                         fp_notes=[tx("Scripts de actualización o agentes de gestión pueden usar PowerShell contra servicios "
                                      "en la nube; verificar el destino.",
                                      "Update scripts or management agents may use PowerShell against cloud services; "
                                      "verify the destination.")])
        f.details = [f"{r.row_id}: {str(r.message or r.command_line)[:300]}" for r in part.itertuples()][:10]
        out.append(f)
    return out


# ------------------------------------------------------------------------ WEB-001
def web001(ctx: Context, p: dict) -> list[Finding]:
    df = ctx.df
    text = (df["command_line"].fillna("") + " " + df["domain"].fillna("") + " " + df["message"].fillna(""))
    uri_hit = text.str.contains(_WEBSHELL_URI)
    ident_hit = df["user"].fillna("").str.contains(_WEB_IDENTITY) & ctx.cmd_text.str.contains(_SHELLISH)
    parent_hit = df["parent_process"].fillna("").str.contains(r"w3wp|httpd|nginx|tomcat|php-cgi", case=False) & \
        ctx.cmd_text.str.contains(_SHELLISH)
    hits = df[uri_hit | ident_hit | parent_hit]
    out = []
    for (host,), part in clusters(hits, ["host"], HOUR):
        n_uri = int(uri_hit[part.index].sum())
        n_proc = len(part) - n_uri
        signals = []
        if n_uri:
            signals.append(tx(f"{n_uri} petición(es) HTTP a un script con parámetro de comando (p. ej. «?cmd=»)",
                              f"{n_uri} HTTP request(s) to a script with a command parameter (e.g. “?cmd=”)"))
        if n_proc:
            ident = ", ".join(uniq(part.loc[~uri_hit[part.index], "user"]))
            signals.append(tx(f"{n_proc} proceso(s) de shell lanzados por la identidad del servidor web ({ident})",
                              f"{n_proc} shell process(es) launched by the web server identity ({ident})"))
        srcs = ", ".join(uniq(part["src_ip"])) or tx("origen no informado", "unreported source")
        summary = tx(f"En {host}: {' y '.join(signals)}, desde {srcs}. "
                     "Es el patrón de una web shell: el atacante ejecuta comandos del sistema a través de la aplicación web.",
                     f"On {host}: {' and '.join(signals)}, from {srcs}. "
                     "This is a web shell pattern: the attacker runs system commands through the web application.")
        f = make_finding("WEB-001", part, tx(f"Posible web shell en {host}", f"Possible web shell on {host}"), summary, ctx,
                         metrics={"uri_hits": n_uri, "process_hits": n_proc},
                         auth_success=None, confidence="alta" if n_uri and n_proc else "media",
                         fp_notes=[tx("Un escáner de vulnerabilidades autorizado genera peticiones similares; si además hay "
                                      "procesos lanzados por el pool de la aplicación, la ejecución fue real.",
                                      "An authorized vulnerability scanner produces similar requests; if processes were "
                                      "also launched by the application pool, execution really happened.")])
        f.details = [f"{r.row_id}: {str(r.command_line or r.message)[:300]}" for r in part.itertuples()][:12]
        out.append(f)
    return out


# ------------------------------------------------------------------------ COL-001
def col001(ctx: Context, p: dict) -> list[Finding]:
    df = ctx.df
    acc = df[df["sem"].isin(["object_access", "share_access"]) & df["user"].notna()].copy()
    if acc.empty:
        return []
    # solo filas que identifican el objeto accedido (ruta de archivo); el texto genérico del evento no cuenta
    from_cmd = acc["command_line"].fillna("").str.extract(_OBJECT_IN_TEXT, expand=False)
    from_msg = acc["message"].fillna("").str.extract(_OBJECT_IN_TEXT, expand=False)
    acc["object"] = from_cmd.fillna(from_msg).str.strip()
    acc = acc[acc["object"].notna() & (acc["object"] != "")]
    window = pd.Timedelta(minutes=p["window_minutes"])
    k = int(p["min_objects"])
    out = []
    for (user, _host), g in acc.groupby(["user", "host"], sort=False, dropna=False):
        g = g.sort_values("ts")
        for a, b in distinct_bursts(g["ts"].values, list(g["object"]), window, k):
            part = g.iloc[a:b + 1]
            objs = uniq(part["object"])
            hosts = ", ".join(uniq(part["host"]))
            span = f"{part['ts'].min():%d/%m %H:%M}–{part['ts'].max():%H:%M}"
            srcs = ", ".join(uniq(part["src_ip"])) or tx("origen no informado", "unreported source")
            examples = "; ".join(o[:80] for o in objs[:3])
            summary = tx(f"«{user}» accedió a {len(objs)} archivos/objetos distintos en {hosts} en "
                         f"menos de {p['window_minutes']} minutos ({span}) desde {srcs}. Ejemplos: {examples}. "
                         "El acceso masivo y secuencial es típico de la recolección previa a una exfiltración o al "
                         "cifrado por ransomware.",
                         f"“{user}” accessed {len(objs)} distinct files/objects on {hosts} within "
                         f"{p['window_minutes']} minutes ({span}) from {srcs}. Examples: {examples}. "
                         "Massive sequential access is typical of collection before exfiltration or ransomware "
                         "encryption.")
            title = tx(f"Acceso masivo a archivos: «{user}» ({len(objs)} objetos)",
                       f"Mass file access: “{user}” ({len(objs)} objects)")
            out.append(make_finding("COL-001", part, title, summary,
                                    ctx, metrics={"objects": len(objs)}, confidence="media",
                                    fp_notes=[tx("Backups, antivirus e indexadores recorren muchos archivos; verificar el "
                                                 "proceso y la cuenta.",
                                                 "Backups, antivirus and indexers walk many files; verify the process "
                                                 "and the account.")]))
    return out


# ------------------------------------------------------------------------ EXF-001
def exf001(ctx: Context, p: dict) -> list[Finding]:
    df = ctx.df
    sent = df[df["bytes_out_n"].notna() & (df["bytes_out_n"] > 0)].copy()
    if sent.empty:
        return []
    sent["dest"] = sent["dst_ip"].fillna(sent["dst_host"]).fillna(sent["domain"])
    ext = sent["dst_ip"].map(ctx.is_external).astype(bool) | (sent["dst_ip"].isna() & sent["domain"].notna())
    sent = sent[ext & sent["dest"].notna()]
    sent["origin"] = sent["host"].fillna(sent["src_ip"])
    limit = float(p["min_megabytes"]) * 1_000_000
    out = []
    for (origin, dest), part in clusters(sent, ["origin", "dest"], pd.Timedelta(minutes=p["window_minutes"])):
        total = float(part["bytes_out_n"].sum())
        if total < limit:
            continue
        mb = total / 1_000_000
        t0, t1 = f"{part['ts'].min():%d/%m %H:%M}", f"{part['ts'].max():%H:%M}"
        summary = tx(f"{origin} envió {mb:,.1f} MB a {dest} en {len(part)} transferencia(s) entre {t0} y {t1} "
                     f"(umbral: {p['min_megabytes']} MB en {p['window_minutes']} min). Un volumen saliente sostenido "
                     "hacia un destino externo es compatible con exfiltración de datos.",
                     f"{origin} sent {mb:,.1f} MB to {dest} in {len(part)} transfer(s) between {t0} and {t1} "
                     f"(threshold: {p['min_megabytes']} MB in {p['window_minutes']} min). Sustained outbound volume "
                     "to an external destination is consistent with data exfiltration.")
        title = tx(f"Gran volumen saliente: {origin} → {dest} ({mb:,.0f} MB)",
                   f"Large outbound volume: {origin} → {dest} ({mb:,.0f} MB)")
        f = make_finding("EXF-001", part, title, summary, ctx,
                         related_cols=("dst_ip",), metrics={"megabytes": round(mb, 1), "transfers": len(part)},
                         confidence="media",
                         fp_notes=[tx("Copias a la nube corporativa o actualizaciones grandes generan tráfico similar; "
                                      "verificar si el destino es un servicio autorizado.",
                                      "Corporate cloud backups or large updates produce similar traffic; verify "
                                      "whether the destination is an authorized service.")])
        out.append(f)
    return out


RULES = [
    Rule("C2-001", "Intérprete de scripts con conexión externa", "Script interpreter outbound connection", "execution",
         "command_and_control", [("T1071.001", "Application Layer Protocol: Web Protocols"),
                                 ("T1059.001", "Command and Scripting Interpreter: PowerShell")],
         "PowerShell, cmd, mshta, rundll32 u otros LOLBins conectándose directamente a IPs públicas (firewall/proxy).",
         "Script interpreters or LOLBins connecting straight to public IPs.",
         ["timestamp", "dst_ip", "event_id|log_source"], c2001),
    Rule("WEB-001", "Web shell / ejecución de comandos vía web", "Web shell / web command execution", "web",
         "initial_access", [("T1190", "Exploit Public-Facing Application"),
                            ("T1505.003", "Server Software Component: Web Shell")],
         "Peticiones HTTP a scripts con parámetros de comando (?cmd=) o shells lanzadas por la identidad del servidor web.",
         "HTTP requests to scripts with command parameters or shells spawned by the web server identity.",
         ["timestamp", "command_line|domain|message"], web001),
    Rule("COL-001", "Acceso masivo a archivos", "Mass file access", "collection", "collection",
         [("T1039", "Data from Network Shared Drive"), ("T1005", "Data from Local System")],
         "Una cuenta accede a muchos archivos/objetos distintos (4663/5145) en una ventana corta.",
         "One account accessing many distinct files/objects in a short window.",
         ["timestamp", "user", "event_id"], col001),
    Rule("EXF-001", "Gran volumen de datos salientes", "Large outbound data volume", "collection", "exfiltration",
         [("T1048", "Exfiltration Over Alternative Protocol"), ("T1041", "Exfiltration Over C2 Channel")],
         "Suma de bytes enviados por un host hacia un destino externo por encima del umbral (proxy/firewall).",
         "Bytes sent from one host to an external destination above the threshold.",
         ["timestamp", "bytes_out"], exf001),
]
