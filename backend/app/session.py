"""Almacén de sesiones de análisis.

Dos modos (variable SESSION_STORE):

* ``disk`` (por defecto): la sesión vive en memoria y además se guarda CIFRADA en disco
  (Fernet = AES-128-CBC + HMAC-SHA256) para sobrevivir a recargas del navegador y a reinicios
  del backend o del contenedor. El archivo original del cliente no se guarda: solo las hojas
  leídas, los eventos normalizados y los resultados.
* ``memory``: nada toca el disco; la sesión se pierde al reiniciar el backend.

Toda sesión expira tras SESSION_TTL_HOURS sin uso (vencimiento deslizante) y puede borrarse
explícitamente; al borrarla se elimina también su archivo.
"""
from __future__ import annotations

import logging
import os
import pickle
import secrets
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path

import pandas as pd
from cryptography.fernet import Fernet, InvalidToken

from app import settings

log = logging.getLogger("soc.session")
_SID_CHARS = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_")


@dataclass
class Session:
    id: str
    filename: str
    size: int
    sheets: dict[str, pd.DataFrame]
    created: float = field(default_factory=time.time)
    touched: float = field(default_factory=time.time)
    events: pd.DataFrame | None = None
    quality: dict | None = None
    analysis: dict | None = None
    analysis_en: dict | None = None  # misma corrida en inglés (se calcula al pedirla; mismos IDs y puntajes)
    reports: dict[str, dict] = field(default_factory=dict)          # {"ejecutivo": {...}, "tecnico": {...}}
    report_versions: dict[str, int] = field(default_factory=dict)   # última versión exportada por tipo
    chat: list[dict] = field(default_factory=list)
    intel: dict | None = None  # job de reputación de IPs (sin API keys)
    default_timezone: str | None = None

    def analysis_in(self, lang: str) -> dict | None:
        """Análisis en el idioma pedido. El español es el canónico; el inglés se calcula una sola vez.

        El motor es determinístico: la corrida en inglés produce los mismos hallazgos, IDs y puntajes,
        solo cambian los textos.
        """
        if lang != "en" or self.analysis is None or self.events is None:
            return self.analysis
        if self.analysis_en is None:
            from app.detection.engine import run_analysis
            self.analysis_en = run_analysis(self.events, lang="en")
        return self.analysis_en

    def expires_at(self) -> float:
        return self.touched + settings.SESSION_TTL_HOURS * 3600


class SessionStore:
    def __init__(self, mode: str | None = None, directory: str | Path | None = None, key: bytes | str | None = None):
        self.mode = (mode or settings.SESSION_STORE).lower()
        self._items: dict[str, Session] = {}
        self._lock = threading.RLock()
        self._dir: Path | None = None
        self._fernet: Fernet | None = None
        if self.mode == "disk":
            self._dir = Path(directory or settings.SESSION_DIR)
            self._dir.mkdir(parents=True, exist_ok=True)
            self._fernet = Fernet(key or self._load_or_create_key())

    # ------------------------------------------------------------------ clave de cifrado
    def _load_or_create_key(self) -> bytes:
        env_key = settings.SESSION_ENCRYPTION_KEY
        if env_key:
            return env_key.encode()
        key_file = self._dir / ".key"
        if key_file.is_file():
            return key_file.read_bytes().strip()
        key = Fernet.generate_key()
        key_file.write_bytes(key)
        try:
            os.chmod(key_file, 0o600)
        except OSError:
            pass
        log.warning("Se generó una clave de cifrado de sesiones en %s; para datos reales definí "
                    "SESSION_ENCRYPTION_KEY fuera del volumen de datos.", key_file)
        return key

    def _path(self, sid: str) -> Path | None:
        if self._dir is None or not sid or not set(sid) <= _SID_CHARS:
            return None  # evita rutas arbitrarias a partir del ID recibido
        return self._dir / f"{sid}.session"

    # ------------------------------------------------------------------ API
    def create(self, filename: str, size: int, sheets: dict[str, pd.DataFrame]) -> Session:
        self.purge_expired()
        s = Session(id=secrets.token_urlsafe(18), filename=filename, size=size, sheets=sheets)
        with self._lock:
            self._items[s.id] = s
        self.persist(s)
        return s

    def get(self, sid: str) -> Session | None:
        self.purge_expired()
        with self._lock:
            s = self._items.get(sid)
            if s is None:
                s = self._load(sid)
                if s is not None:
                    self._items[sid] = s
            if s is not None:
                s.touched = time.time()
                self._touch_file(sid)
            return s

    def persist(self, s: Session | None) -> None:
        """Guarda la sesión cifrada (modo disk). Escritura atómica: archivo temporal + rename."""
        if s is None or self._fernet is None:
            return
        path = self._path(s.id)
        if path is None:
            return
        with self._lock:
            state = dict(s.__dict__)
            intel = state.get("intel")
            if intel:  # el lock y los hilos de un job en curso no se guardan
                state["intel"] = {k: v for k, v in intel.items() if k != "cancel"}
            blob = self._fernet.encrypt(pickle.dumps(state, protocol=pickle.HIGHEST_PROTOCOL))
        tmp = path.with_suffix(".tmp")
        tmp.write_bytes(blob)
        os.replace(tmp, path)

    def persist_id(self, sid: str) -> None:
        with self._lock:
            s = self._items.get(sid)
        self.persist(s)

    def delete(self, sid: str) -> bool:
        with self._lock:
            existed = self._items.pop(sid, None) is not None
            path = self._path(sid)
            if path is not None and path.exists():
                path.unlink()
                existed = True
        return existed

    def purge_expired(self) -> None:
        limit = time.time() - settings.SESSION_TTL_HOURS * 3600
        with self._lock:
            for sid in [k for k, v in self._items.items() if v.touched < limit]:
                del self._items[sid]
            if self._dir is not None:
                for f in self._dir.glob("*.session"):
                    try:
                        if f.stat().st_mtime < limit:
                            f.unlink()
                    except OSError:
                        pass

    # ------------------------------------------------------------------ internos
    def _touch_file(self, sid: str) -> None:
        path = self._path(sid)
        if path is not None and path.exists():
            try:
                os.utime(path, None)
            except OSError:
                pass

    def _load(self, sid: str) -> Session | None:
        path = self._path(sid)
        if path is None or self._fernet is None or not path.is_file():
            return None
        try:
            # El HMAC de Fernet garantiza que el contenido lo escribió este backend antes de deserializarlo.
            state = pickle.loads(self._fernet.decrypt(path.read_bytes()))
        except (InvalidToken, pickle.UnpicklingError, EOFError, AttributeError, TypeError):
            log.warning("Sesión ilegible (clave distinta o archivo dañado); se descarta.")
            path.unlink(missing_ok=True)
            return None
        s = Session(id=state["id"], filename=state["filename"], size=state["size"], sheets=state["sheets"])
        for k, v in state.items():
            if hasattr(s, k):
                setattr(s, k, v)
        if s.intel and s.intel.get("status") == "en_curso":
            s.intel["status"] = "cancelado"  # el hilo de consulta no sobrevive a un reinicio
            s.intel["interrupted"] = True
        return s


store = SessionStore()
