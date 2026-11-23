"""Configuración de la aplicación (variables de entorno + archivos YAML)."""
from __future__ import annotations

import os
from functools import lru_cache
from pathlib import Path

import yaml

CONFIG_DIR = Path(__file__).parent / "config"


def _load_dotenv() -> None:
    """Carga un .env de la raíz del proyecto o de backend/ sin dependencias externas."""
    for candidate in (Path(__file__).resolve().parents[2] / ".env", Path(__file__).resolve().parents[1] / ".env"):
        if candidate.is_file():
            for line in candidate.read_text(encoding="utf-8").splitlines():
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                key, _, value = line.partition("=")
                os.environ.setdefault(key.strip(), value.strip().strip('"').strip("'"))


_load_dotenv()

MAX_UPLOAD_MB = float(os.getenv("MAX_UPLOAD_MB", "25"))
MAX_ROWS = int(os.getenv("MAX_ROWS", "500000"))
# Sesiones: "disk" (cifradas en disco, sobreviven a reinicios) o "memory" (nada toca el disco).
SESSION_STORE = os.getenv("SESSION_STORE", "disk").strip().lower()
SESSION_DIR = os.getenv("SESSION_DIR", str(Path(__file__).resolve().parents[1] / ".sessions"))
SESSION_ENCRYPTION_KEY = os.getenv("SESSION_ENCRYPTION_KEY", "").strip() or None
# Vencimiento por inactividad (deslizante). SESSION_TTL_MINUTES se acepta por compatibilidad.
SESSION_TTL_HOURS = (float(os.getenv("SESSION_TTL_MINUTES")) / 60 if os.getenv("SESSION_TTL_MINUTES")
                     else float(os.getenv("SESSION_TTL_HOURS", "24")))
CORS_ORIGINS = [o.strip() for o in os.getenv(
    "CORS_ORIGINS", "http://localhost:5173,http://127.0.0.1:5173,http://localhost:8080").split(",") if o.strip()]
SAMPLE_FILE = Path(os.getenv("SAMPLE_FILE", str(Path(__file__).resolve().parents[2] / "sample_data" / "SINTETICO_logs_cliente.xlsx")))
# IA opcional. Nombres genéricos (AI_*); ANTHROPIC_* se acepta como alias por compatibilidad.
AI_MODEL = os.getenv("AI_MODEL") or os.getenv("ANTHROPIC_MODEL") or "claude-opus-5-5"
# Inteligencia de amenazas (la clave se lee en tiempo de ejecución: ABUSEIPDB_API_KEY)
INTEL_MAX_IPS = int(os.getenv("INTEL_MAX_IPS", "25"))
INTEL_CACHE_TTL_S = int(os.getenv("INTEL_CACHE_TTL_S", "86400"))
AI_MAX_EVIDENCE_ROWS = int(os.getenv("AI_MAX_EVIDENCE_ROWS", "12"))


def ai_key() -> str | None:
    """Clave del proveedor de IA (hoy Anthropic/Claude). Sin clave, la IA queda deshabilitada."""
    key = (os.getenv("AI_API_KEY") or os.getenv("ANTHROPIC_API_KEY") or "").strip()
    return key or None


def load_yaml(name: str) -> dict:
    with open(CONFIG_DIR / name, encoding="utf-8") as fh:
        return yaml.safe_load(fh) or {}


def rules_config() -> dict:
    """Se relee en cada análisis para que los cambios de umbrales apliquen sin reiniciar."""
    return load_yaml("rules.yaml")


@lru_cache
def synonyms() -> dict[str, list[str]]:
    return load_yaml("synonyms.yaml")


@lru_cache
def event_semantics() -> dict:
    return load_yaml("event_semantics.yaml")
