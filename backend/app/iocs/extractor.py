"""Extracción de IoCs a partir de las filas de evidencia de los hallazgos."""
from __future__ import annotations

import re

import pandas as pd

from app.detection.base import Context, Finding
from app.lang import tx

URL_RX = re.compile(r"\b(?:https?|ftp)://[^\s'\"<>()]+", re.IGNORECASE)
DOMAIN_RX = re.compile(r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:[a-z]{2,24})\b", re.IGNORECASE)
IPV4_RX = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")
HASH_RX = re.compile(r"\b(?:[a-f0-9]{64}|[a-f0-9]{40}|[a-f0-9]{32})\b", re.IGNORECASE)
FILE_EXT = {"exe", "dll", "ps1", "bat", "cmd", "vbs", "js", "txt", "dmp", "7z", "zip", "rar", "log", "msi", "sys",
            "dat", "tmp", "csv", "xlsx", "docx", "hta", "scr", "lnk", "ini", "cpl", "xml", "json"}
MAX_ROWS_LISTED = 200


def _domains(text: str) -> set[str]:
    out = set()
    for url in URL_RX.findall(text):
        host = re.sub(r"^[a-z]+://", "", url, flags=re.IGNORECASE).split("/")[0].split(":")[0].lower()
        if host and not IPV4_RX.fullmatch(host):
            out.add(host)
    for d in DOMAIN_RX.findall(text):
        tld = d.rsplit(".", 1)[-1].lower()
        if tld not in FILE_EXT and not d.lower().endswith((".dll", ".exe")):
            out.add(d.lower())
    return out


def extract_iocs(ctx: Context, findings: list[Finding]) -> list[dict]:
    df = ctx.df
    core = [f for f in findings if not f.is_anomaly and f.incident_id]
    base = df[~ctx.after_baseline(df["ts"])]
    base_ips = set(base["src_ip"].dropna()) | set(base["assigned_ip"].dropna())
    evidence_ids = {r for f in core for r in f.rows}
    ev = df[df["row_id"].isin(evidence_ids)]
    row_findings: dict[str, list[str]] = {}
    for f in core:
        for r in f.rows:
            row_findings.setdefault(r, []).append(f.id)

    items: dict[tuple[str, str], dict] = {}

    def add(kind: str, value: str, context: str, rows_all: list[str]):
        key = (kind, value)
        if key in items or not value:
            return
        fids = sorted({x for r in rows_all if r in row_findings for x in row_findings[r]})
        items[key] = {"type": kind, "value": value, "context": context, "count": len(rows_all),
                      "rows": rows_all[:MAX_ROWS_LISTED], "rows_truncated": len(rows_all) > MAX_ROWS_LISTED,
                      "finding_ids": fids}

    # IPs (origen/destino/asignada)
    for col in ("src_ip", "dst_ip", "assigned_ip"):
        if col not in ev:
            continue
        for ip in ev[col].dropna().unique():
            kind = ctx.ip_kind(ip)
            if kind == "invalid":
                continue
            rows = df.loc[(df["src_ip"] == ip) | (df["dst_ip"] == ip) | (df["assigned_ip"] == ip), "row_id"].tolist()
            label = tx("externa", "external") if kind == "external" else tx("interna", "internal")
            if ip in base_ips:
                label += tx(" · vista en período base (posiblemente legítima)", " · seen in baseline period (possibly legitimate)")
            add("ip", ip, label, rows)
    # usuarios y hosts implicados (entidades de hallazgos)
    for f in core:
        for u in f.entities.get("user", []):
            if not ctx.is_ignored(u):
                rows = df.loc[(df["user"] == u) | (df["target_user"] == u), "row_id"].tolist()
                add("user", u, tx("cuenta privilegiada", "privileged account") if ctx.is_privileged(u) else tx("cuenta", "account"), rows)
        for h in f.entities.get("host", []):
            rows = df.loc[df["host"] == h, "row_id"].tolist()
            add("host", h, tx("host crítico", "critical host") if ctx.is_critical(h) else "host", rows)
    # hashes poco frecuentes en filas de procesos sospechosos
    hash_counts = df["hash"].value_counts()
    rule_of = {f.id: f.rule_id for f in core}
    proc_rows = ev[ev["hash"].notna() & ev["row_id"].map(
        lambda r: any(rule_of[fid].startswith(("EX", "LM")) for fid in row_findings.get(r, [])))]
    system_path = re.compile(r"^[a-z]:\\(windows|program files( \(x86\))?)\\", re.IGNORECASE)
    for h in proc_rows["hash"].unique():
        images = df.loc[df["hash"] == h, "process"].dropna()
        if hash_counts.get(h, 0) <= 3 and not all(system_path.match(p) for p in images):
            rows = df.loc[df["hash"] == h, "row_id"].tolist()
            proc = df.loc[df["hash"] == h, "process"].dropna()
            add("hash", h, tx("SHA/MD5 de ", "SHA/MD5 of ") + (proc.iloc[0] if len(proc) else tx("archivo", "file")), rows)
    # dominios / URLs en comandos y mensajes
    text_cols = ev[["row_id", "command_line", "message", "domain"]].fillna("")
    found: set[str] = set()
    for _, r in text_cols.iterrows():
        found |= _domains(f"{r['command_line']} {r['message']} {r['domain']}")
    searchable = (df["command_line"].fillna("") + " " + df["message"].fillna("") + " " + df["domain"].fillna("")).str.lower()
    for d in sorted(found):
        rows = df.loc[searchable.str.contains(d, regex=False), "row_id"].tolist()
        add("domain", d, tx("dominio en línea de comando", "domain in command line"), rows)
    for _, r in text_cols.iterrows():
        for url in URL_RX.findall(r["command_line"] + " " + r["message"]):
            rows = df.loc[searchable.str.contains(url.lower(), regex=False), "row_id"].tolist()
            add("url", url, tx("URL en línea de comando", "URL in command line"), rows)
    # líneas de comando sospechosas
    cmd_rows = ev[ev["command_line"].notna()]
    for _, r in cmd_rows.iterrows():
        fids = row_findings.get(r["row_id"], [])
        rules = {f.rule_id for f in core if f.id in fids}
        if any(x.startswith(("EX", "LM", "PE")) for x in rules):
            rows = df.loc[df["command_line"] == r["command_line"], "row_id"].tolist()
            add("command", r["command_line"], tx("comando sospechoso", "suspicious command"), rows)

    order = {"ip": 0, "user": 1, "host": 2, "hash": 3, "domain": 4, "url": 5, "command": 6}
    out = sorted(items.values(), key=lambda x: (order[x["type"]], -len(x["finding_ids"]), -x["count"]))
    for i, item in enumerate(out, 1):
        item["id"] = f"IOC-{i:03d}"
    return out
