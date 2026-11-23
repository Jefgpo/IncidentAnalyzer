"""Enriquecimiento de IPs públicas con AbuseIPDB.

* Las API keys salen de variables de entorno (ABUSEIPDB_API_KEY) o se
  ingresan en la UI solo para la sesión: viven en memoria durante el job y nunca se devuelven,
  se registran ni se escriben a disco.
* Solo se consultan IPs globalmente enrutables (se excluyen privadas, loopback, reservadas y
  rangos de documentación).
* Cada proveedor corre en su propio hilo respetando su límite de velocidad; el frontend consulta
  el progreso. Los resultados se cachean en memoria por (proveedor, IP) para no gastar cuota.
"""
from __future__ import annotations

import copy
import ipaddress
import logging
import threading
import time
from collections import Counter
from typing import Callable

import httpx

from app import settings
from app.intel.providers import PROVIDERS, ProviderError, ProviderFatal, RateLimited

log = logging.getLogger("soc.intel")

MAX_RATE_RETRIES = 3
_DOC_NETS = [ipaddress.ip_network(n) for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "2001:db8::/32")]
_cache: dict[tuple[str, str], tuple[float, dict]] = {}
_cache_lock = threading.Lock()
_job_lock = threading.Lock()  # protege los resultados que escriben los hilos de cada proveedor

# Puntos de inyección para tests
client_factory: Callable[[], httpx.Client] = lambda: httpx.Client(timeout=20, headers={"User-Agent": "incidentanalyzer"})
sleep: Callable[[float], None] = time.sleep


def env_key(provider: str) -> str | None:
    import os
    v = os.getenv(PROVIDERS[provider].env_key, "").strip()
    return v or None


def status() -> dict:
    return {name: {"label": p.label, "configured": env_key(name) is not None, "env_var": p.env_key,
                   "min_interval_s": _interval(name)} for name, p in PROVIDERS.items()}


def _interval(provider: str) -> float:
    return PROVIDERS[provider].min_interval_s


def ip_scope(ip: str) -> str | None:
    """Devuelve el motivo por el que NO se consulta la IP, o None si es pública."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return "no es una IP válida"
    if any(addr in net for net in _DOC_NETS if addr.version == net.version):
        return "rango de documentación (RFC 5737/3849), no enrutable"
    if addr.is_private or addr.is_loopback or addr.is_link_local:
        return "IP privada/interna"
    if addr.is_multicast or addr.is_unspecified:
        return "IP multicast/no especificada"
    if not addr.is_global:
        return "rango reservado o de documentación (no enrutable)"
    return None


def candidate_ips(session) -> tuple[list[dict], list[dict]]:
    """IPs del archivo ordenadas por relevancia: primero las de incidentes, luego hallazgos, luego frecuencia."""
    df = session.events
    counts: Counter = Counter()
    for col in ("src_ip", "dst_ip", "assigned_ip"):
        if col in df:
            counts.update(df[col].dropna().tolist())
    findings_of: dict[str, set[str]] = {}
    incident_of: dict[str, set[str]] = {}
    for f in (session.analysis or {}).get("findings", []):
        ips = set(f["entities"].get("src_ip", [])) | set(f["related"].get("src_ip", []))
        for ip in ips:
            findings_of.setdefault(ip, set()).add(f["id"])
            if f.get("incident_id"):
                incident_of.setdefault(ip, set()).add(f["incident_id"])
    public, skipped = [], []
    for ip, n in counts.items():
        item = {"ip": ip, "events": n, "finding_ids": sorted(findings_of.get(ip, [])),
                "incident_ids": sorted(incident_of.get(ip, []))}
        reason = ip_scope(ip)
        if reason:
            if ip in findings_of:  # solo se listan las omitidas que importan para el análisis
                skipped.append({**item, "reason": reason})
        else:
            public.append(item)
    public.sort(key=lambda x: (-len(x["incident_ids"]), -len(x["finding_ids"]), -x["events"], x["ip"]))
    return public, skipped


def _cached(provider: str, ip: str) -> dict | None:
    with _cache_lock:
        hit = _cache.get((provider, ip))
        if hit and time.time() - hit[0] < settings.INTEL_CACHE_TTL_S:
            return {**hit[1], "cached": True}
    return None


def _store(provider: str, ip: str, result: dict) -> None:
    with _cache_lock:
        _cache[(provider, ip)] = (time.time(), result)


def _run_provider(job: dict, name: str, key: str, ips: list[str], cfg: dict) -> None:
    prov = PROVIDERS[name]
    st = job["providers"][name]
    interval = _interval(name)
    with client_factory() as client:
        for i, ip in enumerate(ips):
            if job.get("cancel"):
                st["state"] = "cancelado"
                return
            hit = _cached(name, ip)
            if hit is not None:
                with _job_lock:
                    job["results"][ip][name] = hit
                st["done"] += 1
                continue
            retries = 0
            while True:
                try:
                    res = prov.check(client, ip, key, cfg)
                    _store(name, ip, res)
                    with _job_lock:
                        job["results"][ip][name] = res
                    break
                except RateLimited as rl:
                    retries += 1
                    if retries > MAX_RATE_RETRIES:
                        st["state"] = "error"
                        st["error"] = f"{prov.label}: límite de consultas alcanzado repetidamente (¿cuota diaria agotada?)."
                        return
                    st["note"] = f"Límite de velocidad; reintentando en {int(rl.retry_after)} s"
                    sleep(rl.retry_after)
                except ProviderFatal as exc:
                    st["state"] = "error"
                    st["error"] = str(exc)
                    return
                except (ProviderError, httpx.HTTPError, ValueError) as exc:
                    detail = str(exc) if isinstance(exc, ProviderError) else type(exc).__name__
                    with _job_lock:
                        job["results"][ip][name] = {"verdict": "error", "summary": f"Error de consulta: {detail}",
                                                    "link": prov.link(ip)}
                    break
            st["note"] = None
            st["done"] += 1
            if i < len(ips) - 1:
                sleep(interval)
    st["state"] = "completado"


def _summarize(job: dict) -> None:
    rows = list(job["results"].values())
    active = [n for n, st in job["providers"].items() if st["state"] != "omitido"]

    def bad(r, n):
        return (r.get(n) or {}).get("verdict") == "malicioso"

    job["summary"] = {
        "queried": len(rows),
        "bad_abuseipdb": [r["ip"] for r in rows if bad(r, "abuseipdb")],
        "suspicious": [r["ip"] for r in rows if any((r.get(n) or {}).get("verdict") == "sospechoso" for n in active)
                       and not any(bad(r, n) for n in active)],
        "providers_used": active,
    }


def start_job(session, keys: dict[str, str | None], max_ips: int) -> dict:
    """Arranca el enriquecimiento en segundo plano. `keys` = claves ingresadas en la UI (opcionales)."""
    if session.intel and session.intel.get("status") == "en_curso":
        raise RuntimeError("Ya hay una consulta de reputación en curso para esta sesión.")
    resolved = {n: (keys.get(n) or "").strip() or env_key(n) for n in PROVIDERS}
    if not any(resolved.values()):
        raise ValueError("No hay API key configurada: definí ABUSEIPDB_API_KEY "
                         "o ingresalas en la pantalla.")
    public, skipped = candidate_ips(session)
    selected = public[:max_ips]
    cfg = settings.rules_config().get("threat_intel", {})
    job = {
        "status": "en_curso", "started_at": time.time(), "finished_at": None,
        "total_public": len(public), "selected": len(selected), "max_ips": max_ips,
        "skipped": skipped, "not_queried": [p["ip"] for p in public[max_ips:]],
        "providers": {n: {"label": p.label, "state": "en_curso" if resolved[n] else "omitido",
                          "key_source": ("pantalla" if (keys.get(n) or "").strip() else "entorno") if resolved[n] else None,
                          "done": 0, "total": len(selected) if resolved[n] else 0, "error": None, "note": None,
                          "eta_s": round(len(selected) * _interval(n)) if resolved[n] else 0}
                      for n, p in PROVIDERS.items()},
        "results": {p["ip"]: {**p} for p in selected},
        "summary": None,
    }
    session.intel = job
    ips = [p["ip"] for p in selected]
    threads = [threading.Thread(target=_run_provider, args=(job, n, resolved[n], ips, cfg.get(n, {})), daemon=True)
               for n in PROVIDERS if resolved[n]]

    def supervise():
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        _summarize(job)
        job["status"] = "cancelado" if job.get("cancel") else "completado"
        job["finished_at"] = time.time()
        from app.session import store
        store.persist(session)  # el resultado de la consulta queda guardado con la sesión
        log.info("Reputación de IPs: %d IPs consultadas, %d maliciosas en AbuseIPDB",
                 len(ips), len(job["summary"]["bad_abuseipdb"]))

    if not ips:
        _summarize(job)
        job["status"] = "completado"
        job["finished_at"] = time.time()
        for st in job["providers"].values():
            if st["state"] == "en_curso":
                st["state"] = "completado"
    else:
        threading.Thread(target=supervise, daemon=True).start()
    return public_view(job)


def public_view(job: dict | None) -> dict | None:
    """Vista serializable del job (sin claves; resultados como lista ordenada)."""
    if job is None:
        return None
    with _job_lock:
        snap = copy.deepcopy({k: v for k, v in job.items() if k != "cancel"})
    if snap["status"] == "en_curso":
        _summarize(snap)
    snap["results"] = list(snap["results"].values())
    return snap
