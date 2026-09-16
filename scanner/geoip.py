from __future__ import annotations

import json
import threading
import unicodedata
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Optional, Tuple

try:
    import requests
except ImportError:
    requests = None

from scanner.models import ScanResult

_GEOIP_CACHE: Dict[str, Tuple[Optional[str], Optional[str], Optional[str]]] = {}
_CACHE_LOCK = threading.Lock()


def _sanitize_string(val: Optional[str], max_len: int = 20) -> str:
    """Normalize string to safe terminal ASCII/clean unicode and truncate."""
    if not val:
        return ""
    norm = unicodedata.normalize("NFKD", val)
    clean = "".join(c for c in norm if not unicodedata.combining(c))
    clean = clean.encode("ascii", errors="ignore").decode("ascii").strip()
    return clean[:max_len]


def resolve_ip_location(
    ip: str,
    timeout: float = 4.0,
) -> Tuple[Optional[str], Optional[str], Optional[str]]:
    """
    Resolve the physical / ISP geographic location of an IP address.
    Returns: (country_code, city, org)
    Example: ('IR', 'Tehran', 'FanAvaran Mihan Mizban')
    """
    with _CACHE_LOCK:
        if ip in _GEOIP_CACHE:
            return _GEOIP_CACHE[ip]

    country: Optional[str] = None
    city: Optional[str] = None
    org: Optional[str] = None

    # Primary provider: ipinfo.io
    headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"}
    try:
        if requests is not None:
            r = requests.get(f"https://ipinfo.io/{ip}/json", headers=headers, timeout=timeout)
            if r.status_code == 200:
                data = r.json()
                raw_country = data.get("country")
                if raw_country and len(raw_country) == 2:
                    country = raw_country.upper()
                raw_city = data.get("city")
                if raw_city:
                    city = _sanitize_string(raw_city, max_len=14)
                if data.get("anycast") or (data.get("org") and "cloudflare" in data.get("org", "").lower()):
                    if not city or city.lower() in ("san francisco", "chicago", "ashburn"):
                        city = "Anycast"
                raw_org = data.get("org")
                if raw_org:
                    org = _sanitize_string(raw_org, max_len=30)
        else:
            req = urllib.request.Request(f"https://ipinfo.io/{ip}/json", headers=headers)
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                data = json.loads(resp.read().decode("utf-8", errors="ignore"))
                raw_country = data.get("country")
                if raw_country and len(raw_country) == 2:
                    country = raw_country.upper()
                raw_city = data.get("city")
                if raw_city:
                    city = _sanitize_string(raw_city, max_len=14)
                if data.get("anycast") or (data.get("org") and "cloudflare" in data.get("org", "").lower()):
                    if not city or city.lower() in ("san francisco", "chicago", "ashburn"):
                        city = "Anycast"
                raw_org = data.get("org")
                if raw_org:
                    org = _sanitize_string(raw_org, max_len=30)
    except Exception:
        pass

    # Secondary provider: freeipapi.com
    if not country:
        try:
            if requests is not None:
                r = requests.get(f"https://freeipapi.com/api/json/{ip}", headers=headers, timeout=timeout)
                if r.status_code == 200:
                    data = r.json()
                    raw_country = data.get("countryCode")
                    if raw_country and len(raw_country) == 2:
                        country = raw_country.upper()
                    raw_city = data.get("cityName")
                    if raw_city:
                        city = _sanitize_string(raw_city, max_len=14)
            else:
                req = urllib.request.Request(f"https://freeipapi.com/api/json/{ip}", headers=headers)
                with urllib.request.urlopen(req, timeout=timeout) as resp:
                    data = json.loads(resp.read().decode("utf-8", errors="ignore"))
                    raw_country = data.get("countryCode")
                    if raw_country and len(raw_country) == 2:
                        country = raw_country.upper()
                    raw_city = data.get("cityName")
                    if raw_city:
                        city = _sanitize_string(raw_city, max_len=14)
        except Exception:
            pass

    res = (country, city, org)
    # Only cache successful lookups
    if country:
        with _CACHE_LOCK:
            _GEOIP_CACHE[ip] = res
    return res


def format_ip_location(
    country: Optional[str],
    city: Optional[str],
    short: bool = True,
) -> str:
    """Format IP country and city into a clean badge, e.g. '[IR] Tehran' or '[US]'."""
    if not country:
        return "-"
    c_code = country.upper()
    if city and city.lower() != "unknown" and city != "-":
        return f"[{c_code}] {city}"
    return f"[{c_code}]"


def enrich_results_with_geoip(
    results: List[ScanResult],
    workers: int = 10,
    timeout: float = 4.0,
) -> None:
    """Concurrently resolve IP physical location for working results."""
    targets = [r for r in results if r.ok and not r.ip_country]
    if not targets:
        return

    unique_ips = list({r.ip for r in targets})
    ip_to_geo: Dict[str, Tuple[Optional[str], Optional[str], Optional[str]]] = {}

    worker_count = min(workers, max(1, len(unique_ips)))
    with ThreadPoolExecutor(max_workers=worker_count) as ex:
        futures = {ex.submit(resolve_ip_location, ip, timeout): ip for ip in unique_ips}
        for fut in as_completed(futures):
            ip = futures[fut]
            try:
                ip_to_geo[ip] = fut.result()
            except Exception:
                ip_to_geo[ip] = (None, None, None)

    for r in targets:
        geo = ip_to_geo.get(r.ip)
        if geo and geo[0]:
            r.ip_country, r.ip_city, r.ip_org = geo
