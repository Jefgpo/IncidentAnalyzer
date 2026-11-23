"""Validación posterior de la salida de la IA contra los datos reales.

Regla de oro: una afirmación solo se acepta si cita IDs de fila existentes, esas filas
pertenecen a la evidencia de los hallazgos citados, y todas las IPs / hashes / usuarios /
hosts que menciona aparecen en esas filas o en las entidades de esos hallazgos.
"""
from __future__ import annotations

import re

import pandas as pd

from app.lang import tx

IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
HASH = re.compile(r"\b(?:[a-fA-F0-9]{64}|[a-fA-F0-9]{40}|[a-fA-F0-9]{32})\b")
FINDING_ID = re.compile(r"\bF-\d{3}\b")
ROW_ID = re.compile(r"\b[\w.-]+![0-9]+\b")
KINDS = {"hecho_observado", "inferencia", "hipotesis", "recomendacion"}
ENTITY_COLS = ("user", "target_user", "host", "src_ip", "dst_ip", "assigned_ip", "hash")


class Validator:
    def __init__(self, events: pd.DataFrame, analysis: dict):
        self.events = events
        self.rows = set(events["row_id"])
        self.findings = {f["id"]: f for f in analysis["findings"]}
        self.incidents = {i["id"]: i for i in analysis["incidents"]}
        self.evidence = {r for f in analysis["findings"] for r in f["rows"]}
        users = set(events["user"].dropna().str.lower()) | set(events["target_user"].dropna().str.lower())
        hosts = set(events["host"].dropna().str.lower())
        # solo nombres «distintivos» para evitar falsos rechazos con palabras comunes
        self.known_users = {u for u in users if re.search(r"[._\d]", u) or u in ("administrator", "administrador")}
        self.known_hosts = {h for h in hosts if "-" in h or any(c.isdigit() for c in h)}
        self.all_ips = set(events["src_ip"].dropna()) | set(events["dst_ip"].dropna()) | set(events["assigned_ip"].dropna())
        self._index = events.set_index("row_id")

    def _row_tokens(self, row_ids: list[str]) -> str:
        sub = self._index.loc[[r for r in row_ids if r in self.rows]]
        parts = []
        for col in sub.columns:
            if col in ("raw", "issues", "ts"):
                continue
            parts.extend(str(v) for v in sub[col].dropna())
        for raw in sub["raw"]:
            parts.extend(str(v) for v in (raw or {}).values() if v)
        return " ".join(parts).lower()

    def check(self, claim: dict, allowed_findings: set[str] | None = None) -> tuple[bool, str | None]:
        text = str(claim.get("text", "")).strip()
        kind = claim.get("kind")
        row_ids = [str(r).strip() for r in claim.get("row_ids") or []]
        fids = [str(f).strip() for f in claim.get("finding_ids") or []]
        if not text:
            return False, tx("afirmación vacía", "empty claim")
        if kind not in KINDS:
            return False, tx(f"tipo de afirmación desconocido: {kind}", f"unknown claim type: {kind}")
        bad_f = [f for f in fids if f not in self.findings and f not in self.incidents]
        if bad_f:
            return False, tx(f"hallazgo/incidente inexistente: {', '.join(bad_f)}", f"finding/incident does not exist: {', '.join(bad_f)}")
        mentioned_f = set(FINDING_ID.findall(text)) - set(self.findings)
        if mentioned_f:
            return False, tx(f"menciona hallazgos inexistentes: {', '.join(sorted(mentioned_f))}", f"mentions findings that do not exist: {', '.join(sorted(mentioned_f))}")
        if kind in ("hecho_observado", "inferencia") and not row_ids:
            return False, tx("afirmación factual sin IDs de fila", "factual claim without row IDs")
        if kind in ("hipotesis", "recomendacion") and not row_ids and not fids:
            return False, tx("sin referencia a hallazgos ni filas", "no reference to findings or rows")
        missing = [r for r in row_ids if r not in self.rows]
        if missing:
            return False, tx(f"ID de fila inexistente: {', '.join(missing[:5])}", f"row ID does not exist: {', '.join(missing[:5])}")
        # filas citadas en el texto también deben existir
        in_text = [r for r in ROW_ID.findall(text) if "!" in r and r.strip() not in self.rows]
        if in_text:
            return False, tx(f"cita en el texto filas inexistentes: {', '.join(in_text[:3])}", f"the text cites rows that do not exist: {', '.join(in_text[:3])}")
        scope_rows: set[str] = set()
        for f in fids:
            if f in self.findings:
                scope_rows |= set(self.findings[f]["rows"])
            elif f in self.incidents:
                for x in self.incidents[f]["finding_ids"]:
                    scope_rows |= set(self.findings[x]["rows"])
        if allowed_findings is not None and fids and not (set(fids) <= allowed_findings | set(self.incidents)):
            return False, tx("cita hallazgos fuera del contexto entregado", "cites findings outside the provided context")
        if row_ids:
            scope = scope_rows or self.evidence
            outside = [r for r in row_ids if r not in scope]
            if outside:
                return False, tx(f"filas que no pertenecen a la evidencia de los hallazgos citados: {', '.join(outside[:4])}", f"rows that are not evidence of the cited findings: {', '.join(outside[:4])}")
        # coincidencia de entidades mencionadas con los datos
        haystack = self._row_tokens(row_ids) if row_ids else ""
        ent_text = " ".join(" ".join(v) for f in fids if f in self.findings
                            for v in list(self.findings[f]["entities"].values()) + list(self.findings[f]["related"].values()))
        for f in fids:
            if f in self.incidents:
                ent_text += " " + " ".join(" ".join(v) for v in self.incidents[f]["entities"].values())
        haystack += " " + ent_text.lower()
        low = text.lower()
        for ip in IPV4.findall(text):
            if ip not in self.all_ips:
                return False, tx(f"la IP {ip} no aparece en los logs", f"IP {ip} does not appear in the logs")
            if ip.lower() not in haystack:
                return False, tx(f"la IP {ip} no aparece en las filas citadas", f"IP {ip} does not appear in the cited rows")
        for h in HASH.findall(text):
            if h.lower() not in haystack:
                return False, tx(f"el hash {h[:12]}… no aparece en las filas citadas", f"hash {h[:12]}… does not appear in the cited rows")
        for name in self.known_users | self.known_hosts:
            if re.search(rf"(?<![\w.-]){re.escape(name)}(?![\w-])", low) and name not in haystack:
                return False, tx(f"«{name}» no aparece en las filas ni hallazgos citados", f"“{name}” does not appear in the cited rows or findings")
        return True, None


def validate_claims(validator: Validator, claims: list[dict], section: str,
                    allowed_findings: set[str] | None = None) -> tuple[list[dict], list[dict]]:
    ok, rejected = [], []
    for c in claims or []:
        valid, reason = validator.check(c, allowed_findings)
        if valid:
            ok.append(c)
        else:
            rejected.append({"section": section, "text": str(c.get("text", ""))[:500], "reason": reason,
                             "row_ids": c.get("row_ids") or []})
    return ok, rejected
