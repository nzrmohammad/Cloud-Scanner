import bisect
import json
import socket
import struct
import threading
import time
import unicodedata
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Optional, Tuple

from scanner.constants import app_dir
from scanner.logger import get_logger
from scanner.models import ScanResult

logger = get_logger("geoip")

try:
    import requests
except ImportError:
    requests = None

_GEOIP_CACHE_FILE = app_dir() / "results" / "geoip_cache.json"
_GEOIP_CACHE: Dict[str, Tuple[Optional[str], Optional[str], Optional[str]]] = {}
_CACHE_LOADED = False
_CACHE_LOCK = threading.Lock()

_LOCAL_GEOIP_LOADED = False
_LOCAL_GEOIP_RANGES: List[Tuple[int, int, str]] = []
_LOCAL_GEOIP_STARTS: List[int] = []


def _decode_varint(data: bytes, pos: int) -> Tuple[int, int]:
    res, shift = 0, 0
    while True:
        b = data[pos]
        pos += 1
        res |= (b & 0x7F) << shift
        shift += 7
        if not (b & 0x80):
            break
    return res, pos


def _load_local_geoip_dat() -> None:
    global _LOCAL_GEOIP_LOADED, _LOCAL_GEOIP_RANGES, _LOCAL_GEOIP_STARTS
    if _LOCAL_GEOIP_LOADED:
        return
    _LOCAL_GEOIP_LOADED = True

    try:
        from scanner.xray import find_asset

        dat_path = find_asset("geoip.dat")
        if not dat_path or not dat_path.exists():
            return

        buf = dat_path.read_bytes()
        pos, total_len = 0, len(buf)
        ranges = []
        while pos < total_len:
            tag, pos = _decode_varint(buf, pos)
            wire = tag & 0x7
            fnum = tag >> 3
            if wire == 2:
                length, pos = _decode_varint(buf, pos)
                entry_end = pos + length
                if fnum == 1:
                    cc = ""
                    while pos < entry_end:
                        stag, pos = _decode_varint(buf, pos)
                        swire = stag & 0x7
                        snum = stag >> 3
                        if swire == 2:
                            slen, pos = _decode_varint(buf, pos)
                            if snum == 1:
                                cc = buf[pos : pos + slen].decode("latin1", errors="ignore").upper()
                            elif snum == 2 and cc:
                                cpos, cend = pos, pos + slen
                                ip_bytes, prefix = None, 32
                                while cpos < cend:
                                    ctag, cpos = _decode_varint(buf, cpos)
                                    cwire = ctag & 0x7
                                    cnum = ctag >> 3
                                    if cwire == 2:
                                        clen, cpos = _decode_varint(buf, cpos)
                                        if cnum == 1:
                                            ip_bytes = buf[cpos : cpos + clen]
                                        cpos += clen
                                    elif cwire == 0:
                                        val, cpos = _decode_varint(buf, cpos)
                                        if cnum == 2:
                                            prefix = val
                                if ip_bytes and len(ip_bytes) == 4:
                                    net = struct.unpack("!I", ip_bytes)[0]
                                    mask = (
                                        ((1 << 32) - 1) ^ ((1 << (32 - prefix)) - 1)
                                        if prefix < 32
                                        else 0xFFFFFFFF
                                    )
                                    start = net & mask
                                    end = start | ((1 << (32 - prefix)) - 1) if prefix < 32 else start
                                    ranges.append((start, end, cc))
                            pos += slen
                        elif swire == 0:
                            _, pos = _decode_varint(buf, pos)
            else:
                break

        ranges.sort()
        _LOCAL_GEOIP_RANGES = ranges
        _LOCAL_GEOIP_STARTS = [r[0] for r in ranges]
        logger.debug("Loaded %d IP ranges from local geoip.dat", len(ranges))
    except Exception as exc:
        logger.debug("Failed to parse local geoip.dat: %s", exc)


def lookup_local_geoip(ip: str) -> Optional[str]:
    """Look up country code for an IPv4 address from local geoip.dat."""
    try:
        ip_bytes = socket.inet_aton(ip)
    except OSError:
        return None

    with _CACHE_LOCK:
        _load_local_geoip_dat()
        if not _LOCAL_GEOIP_RANGES:
            return None
        ip_int = struct.unpack("!I", ip_bytes)[0]
        idx = bisect.bisect_right(_LOCAL_GEOIP_STARTS, ip_int) - 1
        if 0 <= idx < len(_LOCAL_GEOIP_RANGES):
            r = _LOCAL_GEOIP_RANGES[idx]
            if r[0] <= ip_int <= r[1]:
                return r[2]
    return None


def _load_cache() -> None:
    global _CACHE_LOADED
    if _CACHE_LOADED:
        return
    try:
        if _GEOIP_CACHE_FILE.exists():
            data = json.loads(_GEOIP_CACHE_FILE.read_text(encoding="utf-8"))
            now = time.time()
            ttl = 30 * 86400  # 30-day cache TTL
            for ip, val in data.items():
                if isinstance(val, dict) and (now - val.get("ts", 0)) < ttl:
                    _GEOIP_CACHE[ip] = (val.get("country"), val.get("city"), val.get("org"))
    except Exception as exc:
        logger.debug("Failed to load geoip cache: %s", exc)
    _CACHE_LOADED = True


def _save_cache_entry(ip: str, res: Tuple[Optional[str], Optional[str], Optional[str]]) -> None:
    try:
        _GEOIP_CACHE_FILE.parent.mkdir(parents=True, exist_ok=True)
        data = {}
        if _GEOIP_CACHE_FILE.exists():
            try:
                data = json.loads(_GEOIP_CACHE_FILE.read_text(encoding="utf-8"))
            except Exception:
                data = {}
        data[ip] = {"country": res[0], "city": res[1], "org": res[2], "ts": time.time()}
        tmp = _GEOIP_CACHE_FILE.with_suffix(".tmp")
        tmp.write_text(json.dumps(data, indent=2), encoding="utf-8")
        tmp.replace(_GEOIP_CACHE_FILE)
    except Exception as exc:
        logger.debug("Failed to save geoip cache entry: %s", exc)


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
        _load_cache()
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
    except Exception as exc:
        logger.debug("ipinfo lookup failed for %s: %s", ip, exc)

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
        except Exception as exc:
            logger.debug("freeipapi lookup failed for %s: %s", ip, exc)

    # Tertiary provider: Local geoip.dat database fallback
    if not country:
        local_cc = lookup_local_geoip(ip)
        if local_cc:
            if local_cc == "CLOUDFLARE":
                country = "US"
                city = "Anycast"
                org = "Cloudflare, Inc."
            elif len(local_cc) == 2:
                country = local_cc
                city = "Local DB"
            logger.debug("Resolved %s from local geoip.dat: country=%s", ip, country)

    res = (country, city, org)
    # Only cache successful lookups
    if country:
        with _CACHE_LOCK:
            _GEOIP_CACHE[ip] = res
            _save_cache_entry(ip, res)
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
            except Exception as exc:
                logger.debug("enrich_results_with_geoip worker failed for %s: %s", ip, exc)
                ip_to_geo[ip] = (None, None, None)

    for r in targets:
        geo = ip_to_geo.get(r.ip)
        if geo and geo[0]:
            r.ip_country, r.ip_city, r.ip_org = geo
