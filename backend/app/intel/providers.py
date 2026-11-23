"""Proveedor de inteligencia de amenazas: AbuseIPDB.

El proveedor consulta UNA IP y devuelve un resultado normalizado con su veredicto
(malicioso / sospechoso / limpio / sin_datos). Solo se envía la dirección IP al
servicio externo: nunca otros datos del archivo del cliente.
"""
from __future__ import annotations

from dataclasses import dataclass

import httpx


class ProviderError(Exception):
    """Error recuperable de una consulta puntual (se registra en esa IP)."""


class ProviderFatal(Exception):
    """Error que invalida al proveedor para el resto del job (clave inválida, cuota agotada)."""


class RateLimited(Exception):
    def __init__(self, retry_after: float):
        super().__init__(f"rate limited, retry after {retry_after}s")
        self.retry_after = retry_after


def _retry_after(resp: httpx.Response, default: float) -> float:
    try:
        return max(1.0, float(resp.headers.get("Retry-After", default)))
    except ValueError:
        return default


@dataclass
class Provider:
    name: str
    label: str
    env_key: str
    min_interval_s: float

    def check(self, client: httpx.Client, ip: str, key: str, cfg: dict) -> dict:  # pragma: no cover - interfaz
        raise NotImplementedError

    def link(self, ip: str) -> str:  # pragma: no cover - interfaz
        raise NotImplementedError


class AbuseIPDB(Provider):
    URL = "https://api.abuseipdb.com/api/v2/check"

    def link(self, ip: str) -> str:
        return f"https://www.abuseipdb.com/check/{ip}"

    def check(self, client: httpx.Client, ip: str, key: str, cfg: dict) -> dict:
        resp = client.get(self.URL, params={"ipAddress": ip, "maxAgeInDays": int(cfg.get("max_age_days", 90))},
                          headers={"Key": key, "Accept": "application/json"})
        if resp.status_code in (401, 403):
            raise ProviderFatal("AbuseIPDB rechazó la API key (401/403). Revisá ABUSEIPDB_API_KEY.")
        if resp.status_code == 429:
            # AbuseIPDB devuelve 429 tanto por ráfaga como por cuota diaria agotada
            remaining = resp.headers.get("X-RateLimit-Remaining")
            if remaining == "0":
                raise ProviderFatal("Se agotó la cuota diaria de AbuseIPDB para esta API key.")
            raise RateLimited(_retry_after(resp, 5))
        if resp.status_code >= 400:
            raise ProviderError(f"HTTP {resp.status_code}")
        d = (resp.json() or {}).get("data") or {}
        score = int(d.get("abuseConfidenceScore") or 0)
        bad, sus = int(cfg.get("malicious_score", 50)), int(cfg.get("suspicious_score", 25))
        if d.get("isWhitelisted"):
            verdict = "limpio"
        elif score >= bad:
            verdict = "malicioso"
        elif score >= sus:
            verdict = "sospechoso"
        else:
            verdict = "limpio"
        return {
            "verdict": verdict,
            "score": score,
            "summary": f"Confianza de abuso {score}/100 · {int(d.get('totalReports') or 0)} reportes",
            "country": d.get("countryCode"),
            "isp": d.get("isp"),
            "domain": d.get("domain"),
            "usage_type": d.get("usageType"),
            "total_reports": int(d.get("totalReports") or 0),
            "distinct_users": int(d.get("numDistinctUsers") or 0),
            "last_reported_at": d.get("lastReportedAt"),
            "is_tor": bool(d.get("isTor")),
            "link": self.link(ip),
        }


PROVIDERS: dict[str, Provider] = {
    "abuseipdb": AbuseIPDB("abuseipdb", "AbuseIPDB", "ABUSEIPDB_API_KEY", min_interval_s=0.2),
}
