"""Traducción de mensajes del backend según el idioma de la interfaz (cabecera Accept-Language).

Los mensajes se escriben en español en el código; esta tabla los traduce al inglés en el borde
de la API (errores HTTP y textos del job de reputación). Así ningún `raise` necesita conocer el idioma.
"""
from __future__ import annotations

import re
from typing import Any

from fastapi import Request

Lang = str  # "es" | "en"


def lang_of(value: str | None) -> Lang:
    """Primer idioma de una cabecera Accept-Language; solo se distingue inglés del español (por defecto)."""
    first = (value or "").split(",")[0].strip().lower()
    return "en" if first.startswith("en") else "es"


def request_lang(request: Request) -> Lang:
    return lang_of(request.headers.get("accept-language"))


# (patrón en español, plantilla en inglés). Los grupos capturados se reinsertan con \1, \2…
_MESSAGES: list[tuple[str, str]] = [
    # sesión y flujo
    (r"Sesión inexistente o expirada\. Volvé a cargar el archivo\.", "Session not found or expired. Upload the file again."),
    (r"Primero confirmá el mapeo de columnas\.", "Confirm the column mapping first."),
    (r"Primero ejecutá el análisis\.", "Run the analysis first."),
    (r"Primero generá los informes\.", "Generate the reports first."),
    (r"No se encontró el dataset sintético \(ejecutá sample_data/generate_synthetic\.py\)\.",
     "The synthetic dataset was not found (run sample_data/generate_synthetic.py)."),
    (r"Seleccioná al menos una hoja\.", "Select at least one sheet."),
    (r"Zona horaria desconocida: (.+)", r"Unknown timezone: \1"),
    (r"Hoja inexistente: (.+)", r"Sheet not found: \1"),
    (r"Columnas inexistentes en (.+?): (.+)", r"Columns not found in \1: \2"),
    (r"Campos desconocidos: (.+)", r"Unknown fields: \1"),
    (r"Error interno del servidor\. Revisá los logs del backend\.", "Internal server error. Check the backend logs."),
    # informes
    (r"Tipo de informe desconocido: (.+)\. Usá «ejecutivo» o «tecnico»\.", r"Unknown report type: \1. Use “ejecutivo” or “tecnico”."),
    (r"Bloque inexistente\.", "Block not found."),
    (r"Este bloque reproduce evidencia literal y no es editable\.", "This block reproduces literal evidence and cannot be edited."),
    (r"Contenido incompatible con el tipo de bloque\.", "Content is not compatible with the block type."),
    # carga del Excel
    (r"Solo se aceptan archivos \.xlsx \(Excel 2007\+\)\.", "Only .xlsx files are accepted (Excel 2007+)."),
    (r"El archivo pesa (.+) MB; el máximo permitido es (.+) MB\.", r"The file is \1 MB; the maximum allowed is \2 MB."),
    (r"El contenido no corresponde a un \.xlsx válido \(firma ZIP ausente\)\.", "The content is not a valid .xlsx (missing ZIP signature)."),
    (r"El ZIP no contiene la estructura de un libro de Excel\.", "The ZIP does not contain an Excel workbook structure."),
    (r"El libro contiene macros \(VBA\); no se procesa por seguridad\.", "The workbook contains macros (VBA); it is not processed for security reasons."),
    (r"El archivo descomprimido es anormalmente grande\.", "The decompressed file is abnormally large."),
    (r"El archivo está dañado o no es un \.xlsx\.", "The file is damaged or is not an .xlsx."),
    (r"No se pudo leer el libro de Excel\.", "The Excel workbook could not be read."),
    (r"El libro tiene (\d+) filas; el máximo es (\d+)\.", r"The workbook has \1 rows; the maximum is \2."),
    (r"El libro no contiene hojas con datos\.", "The workbook has no sheets with data."),
    # IA
    (r"IA deshabilitada: definí AI_API_KEY en el backend\.", "AI disabled: set AI_API_KEY on the backend."),
    (r"La API key de Anthropic es inválida\.", "The Anthropic API key is invalid."),
    (r"Límite de uso de la API alcanzado; reintentá en unos minutos\.", "API rate limit reached; retry in a few minutes."),
    (r"Solicitud rechazada por la API: (.+)", r"Request rejected by the API: \1"),
    (r"Error de la API de Anthropic \((.+)\)\.", r"Anthropic API error (\1)."),
    (r"No se pudo conectar con la API de Anthropic\.", "Could not connect to the Anthropic API."),
    (r"El modelo declinó la solicitud \(refusal\)\.", "The model declined the request (refusal)."),
    (r"La respuesta de la IA se truncó \(max_tokens\)\.", "The AI response was truncated (max_tokens)."),
    (r"La IA devolvió un JSON inválido\.", "The AI returned invalid JSON."),
    # reputación de IPs
    (r"Ya hay una consulta de reputación en curso para esta sesión\.", "A reputation lookup is already running for this session."),
    (r"No hay API key configurada: definí ABUSEIPDB_API_KEY o ingresalas en la pantalla\.",
     "No API key configured: set ABUSEIPDB_API_KEY or enter it on screen."),
    (r"no es una IP válida", "not a valid IP"),
    (r"rango de documentación \(RFC 5737/3849\), no enrutable", "documentation range (RFC 5737/3849), not routable"),
    (r"IP privada/interna", "private/internal IP"),
    (r"IP multicast/no especificada", "multicast/unspecified IP"),
    (r"rango reservado o de documentación \(no enrutable\)", "reserved or documentation range (not routable)"),
    (r"Límite de velocidad; reintentando en (\d+) s", r"Rate limited; retrying in \1 s"),
    (r"Error de consulta: (.+)", r"Lookup error: \1"),
    (r"(.+): límite de consultas alcanzado repetidamente \(¿cuota diaria agotada\?\)\.", r"\1: query limit reached repeatedly (daily quota exhausted?)."),
    (r"Confianza de abuso (\d+)/100 · (\d+) reportes", r"Abuse confidence \1/100 · \2 reports"),
    (r"pantalla", "screen"),
    (r"entorno", "environment"),
]
_COMPILED = [(re.compile(rf"^{p}$", re.S), en) for p, en in _MESSAGES]


def tr(text: str, lang: Lang) -> str:
    """Traduce un mensaje conocido; los desconocidos se devuelven sin cambios."""
    if lang != "en" or not isinstance(text, str):
        return text
    for pattern, template in _COMPILED:
        m = pattern.match(text)
        if m:
            return m.expand(template)
    return text


_TEXT_KEYS = {"reason", "note", "error", "summary", "key_source"}


def tr_deep(obj: Any, lang: Lang) -> Any:
    """Traduce los campos de texto conocidos (motivos, notas, errores) dentro de una respuesta JSON."""
    if lang != "en":
        return obj
    if isinstance(obj, dict):
        return {k: (tr(v, lang) if k in _TEXT_KEYS and isinstance(v, str) else tr_deep(v, lang)) for k, v in obj.items()}
    if isinstance(obj, list):
        return [tr_deep(v, lang) for v in obj]
    return obj


# Etiquetas de los campos canónicos en inglés (el español vive en ingest/mapper.py)
FIELD_LABELS_EN: dict[str, str] = {
    "timestamp": "Event date/time",
    "log_id": "SIEM event ID",
    "log_source": "Log source (Security, Proxy…)",
    "user": "User / account",
    "target_user": "Target account / member",
    "host": "Host / machine",
    "src_ip": "Source IP",
    "dst_ip": "Destination IP",
    "destination": "Destination (host, IP:port or path)",
    "dst_host": "Destination host",
    "src_host": "Source host",
    "event_id": "EventID",
    "action": "Action / event type",
    "outcome": "Outcome",
    "logon_type": "Logon type",
    "process": "Process / image",
    "parent_process": "Parent process",
    "command_line": "Command line",
    "hash": "Hash",
    "group": "Group",
    "privileges": "Privileges",
    "share": "Share",
    "service": "Service",
    "country": "Country (geo)",
    "city": "City (geo)",
    "lat": "Latitude",
    "lon": "Longitude",
    "domain": "Domain / URL",
    "port": "Port",
    "bytes_out": "Bytes sent",
    "siem_severity": "SIEM severity",
    "message": "Message",
    "assigned_ip": "Assigned IP (VPN)",
}
