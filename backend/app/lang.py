"""Idioma de los textos que genera el motor y los informes.

El motor es determinístico: el mismo análisis se puede producir en español (canónico) o en inglés
cambiando solo el idioma activo. Cada texto se escribe en ambos idiomas junto al código que lo genera
(`tx(es, en)`), de modo que la lógica de detección existe una sola vez.
"""
from __future__ import annotations

import contextvars
from contextlib import contextmanager

LANGS = ("es", "en")
_current: contextvars.ContextVar[str] = contextvars.ContextVar("soc_lang", default="es")


def current() -> str:
    return _current.get()


def tx(es: str, en: str) -> str:
    """Devuelve el texto en el idioma activo."""
    return en if _current.get() == "en" else es


@contextmanager
def using(lang: str):
    """Activa un idioma mientras dura el bloque (por hilo/tarea: seguro con peticiones concurrentes)."""
    token = _current.set("en" if lang == "en" else "es")
    try:
        yield
    finally:
        _current.reset(token)


SEVERITY_EN = {"Crítico": "Critical", "Alto": "High", "Medio": "Medium", "Bajo": "Low"}
CONFIDENCE_EN = {"alta": "high", "media": "medium", "baja": "low"}


def sev(s: str) -> str:
    """Etiqueta visible de una criticidad (los valores internos siguen siendo «Crítico», «Alto»…)."""
    return SEVERITY_EN.get(s, s) if current() == "en" else s


def conf(c: str) -> str:
    return CONFIDENCE_EN.get(c, c) if current() == "en" else c
