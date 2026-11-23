"""Sanitización de contenido de celdas.

* Inyección de fórmulas (CSV/Excel injection): valores que empiezan con = + - @ TAB CR.
* Caracteres de control y longitud excesiva.
El escape HTML lo hace React al renderizar (nunca se usa dangerouslySetInnerHTML) y
ReportLab recibe el texto escapado con `escape_markup`.
"""
from __future__ import annotations

import html
import re

FORMULA_PREFIXES = ("=", "+", "-", "@", "\t", "\r")
_CONTROL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
MAX_CELL_LEN = 4000
NULL_TOKENS = {"", "-", "nan", "nat", "none", "null", "n/a", "na", "n/d"}


def clean_text(value) -> str | None:
    """Normaliza a texto, sin caracteres de control. Devuelve None para vacíos."""
    if value is None:
        return None
    text = str(value)
    if text.strip().lower() in NULL_TOKENS:
        return None
    text = _CONTROL.sub("", text).strip()
    if len(text) > MAX_CELL_LEN:
        text = text[:MAX_CELL_LEN] + "…[truncado]"
    return text or None


def looks_like_formula(text: str | None) -> bool:
    if not isinstance(text, str) or len(text) < 2:
        return False
    if text[0] == "-" and (text[1].isdigit() or text[1] == " "):
        return False  # números negativos / guiones de texto no son fórmulas
    return text.startswith(FORMULA_PREFIXES)


def neutralize_formula(text: str | None) -> str | None:
    """Prefija con apóstrofo para que hojas de cálculo no lo evalúen al exportar."""
    if looks_like_formula(text):
        return "'" + text
    return text


def escape_markup(text) -> str:
    """Escape para ReportLab Paragraph (mini-HTML)."""
    return html.escape("" if text is None else str(text), quote=False)
