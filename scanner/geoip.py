import bisect
import ipaddress
import json
import threading
import time
import unicodedata
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Dict, List, Optional, Tuple

from scanner.constants import app_dir
from scanner.logger import get_logger
from scanner.models import ScanResult

logger = get_logger("geoip")

try:
    import requests
except ImportError:
    requests = None  # type: ignore[assignment]

_GEOIP_CACHE_FILE = app_dir() / "results" / "geoip_cache.json"
_GEOIP_CACHE: Dict[str, Tuple[Optional[str], Optional[str], Optional[str]]] = {}
_GEOIP_CACHE_TS: Dict[str, float] = {}
_CACHE_LOADED = False
_CACHE_LOCK = threading.Lock()

_LOCAL_GEOIP_LOADED = False
_LOCAL_GEOIP_RANGES: List[Tuple[int, int, str]] = []
_LOCAL_GEOIP_STARTS: List[int] = []
_LOCAL_GEOIP_MAX_ENDS: List[int] = []
_LOCAL_GEOIP_V6_RANGES: List[Tuple[int, int, str]] = []
_LOCAL_GEOIP_V6_STARTS: List[int] = []
_LOCAL_GEOIP_V6_MAX_ENDS: List[int] = []

# Circuit-breaker state for remote HTTP GeoIP providers when offline/blocked/rate-limited
_REMOTE_LOCK = threading.Lock()
_REMOTE_FAIL_STREAK: Dict[str, int] = {"ipinfo": 0, "freeipapi": 0}
_REMOTE_COOLDOWN_UNTIL: Dict[str, float] = {"ipinfo": 0.0, "freeipapi": 0.0}
_DEFAULT_HEADERS = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"}
_CACHE_TTL_SECONDS = 30 * 86400


def _decode_varint(data: bytes, pos: int) -> Tuple[int, int]:
    res, shift = 0, 0
    while True:
        b = data[pos]
        pos += 1
        res |= (b & 0x7F) << shift
        if not (b & 0x80):
            return res, pos
        shift += 7


def _skip_protobuf_field(data: bytes, pos: int, wire: int) -> Optional[int]:
    if wire == 0:
        _, pos = _decode_varint(data, pos)
        return pos
    if wire == 1:
        return pos + 8
    if wire == 2:
        length, pos = _decode_varint(data, pos)
        return pos + length
    if wire == 5:
        return pos + 4
    return None


def _build_interval_index(raw: List[Tuple[int, int, str]]) -> Tuple[List[Tuple[int, int, str]], List[int], List[int]]:
    """Sort CIDR ranges outermost-first per start and precompute prefix max-ends for exact overlap search."""
    if not raw:
        return [], [], []
    # Outermost first at identical start; if identical bounds, prefer CLOUDFLARE/specific tag last so backward scan hits it first
    raw.sort(key=lambda r: (r[0], -(r[1] - r[0]), 1 if r[2] == "CLOUDFLARE" else 0, r[2]))
    starts: List[int] = []
    max_ends: List[int] = []
    cur_max = -1
    for start, end, _ in raw:
        starts.append(start)
        if end > cur_max:
            cur_max = end
        max_ends.append(cur_max)
    return raw, starts, max_ends


def _lookup_interval_index(
    ip_int: int,
    ranges: List[Tuple[int, int, str]],
    starts: List[int],
    max_ends: List[int],
) -> Optional[str]:
    if not ranges:
        return None
    idx = bisect.bisect_right(starts, ip_int) - 1
    while idx >= 0 and max_ends[idx] >= ip_int:
        start, end, cc = ranges[idx]
        if start <= ip_int <= end:
            return cc
        idx -= 1
    return None


def _load_local_geoip_dat() -> None:
    global _LOCAL_GEOIP_LOADED
    global _LOCAL_GEOIP_RANGES, _LOCAL_GEOIP_STARTS, _LOCAL_GEOIP_MAX_ENDS
    global _LOCAL_GEOIP_V6_RANGES, _LOCAL_GEOIP_V6_STARTS, _LOCAL_GEOIP_V6_MAX_ENDS
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
        v4_ranges: List[Tuple[int, int, str]] = []
        v6_ranges: List[Tuple[int, int, str]] = []
        v4_mask_all = 0xFFFFFFFF
        v6_mask_all = (1 << 128) - 1

        while pos < total_len:
            tag, pos = _decode_varint(buf, pos)
            wire = tag & 0x7
            fnum = tag >> 3
            if wire == 2:
                length, pos = _decode_varint(buf, pos)
                entry_end = min(total_len, pos + length)
                if fnum == 1:
                    cc = ""
                    while pos < entry_end:
                        stag, pos = _decode_varint(buf, pos)
                        swire = stag & 0x7
                        snum = stag >> 3
                        if swire == 2:
                            slen, pos = _decode_varint(buf, pos)
                            sub_end = min(entry_end, pos + slen)
                            if snum == 1:
                                cc = buf[pos:sub_end].decode("latin1", errors="ignore").upper()
                            elif snum == 2 and cc:
                                cpos = pos
                                ip_bytes: Optional[bytes] = None
                                prefix = 32
                                has_prefix = False
                                while cpos < sub_end:
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
                                            has_prefix = True
                                    else:
                                        nxt = _skip_protobuf_field(buf, cpos, cwire)
                                        if nxt is None:
                                            break
                                        cpos = nxt
                                if ip_bytes:
                                    blen = len(ip_bytes)
                                    if blen == 4:
                                        p = prefix if has_prefix else 32
                                        if 0 <= p <= 32:
                                            net = int.from_bytes(ip_bytes, "big")
                                            host_bits = 32 - p
                                            mask = (v4_mask_all ^ ((1 << host_bits) - 1)) if host_bits else v4_mask_all
                                            start = net & mask
                                            end = start | ((1 << host_bits) - 1) if host_bits else start
                                            v4_ranges.append((start, end, cc))
                                    elif blen == 16:
                                        p = prefix if has_prefix else 128
                                        if 0 <= p <= 128:
                                            net = int.from_bytes(ip_bytes, "big")
                                            host_bits = 128 - p
                                            mask = (v6_mask_all ^ ((1 << host_bits) - 1)) if host_bits else v6_mask_all
                                            start = net & mask
                                            end = start | ((1 << host_bits) - 1) if host_bits else start
                                            v6_ranges.append((start, end, cc))
                            pos = sub_end
                        else:
                            nxt = _skip_protobuf_field(buf, pos, swire)
                            if nxt is None:
                                pos = entry_end
                                break
                            pos = nxt
                else:
                    pos = entry_end
            else:
                nxt = _skip_protobuf_field(buf, pos, wire)
                if nxt is None:
                    break
                pos = nxt

        _LOCAL_GEOIP_RANGES, _LOCAL_GEOIP_STARTS, _LOCAL_GEOIP_MAX_ENDS = _build_interval_index(v4_ranges)
        _LOCAL_GEOIP_V6_RANGES, _LOCAL_GEOIP_V6_STARTS, _LOCAL_GEOIP_V6_MAX_ENDS = _build_interval_index(v6_ranges)
        logger.debug(
            "Loaded %d IPv4 and %d IPv6 ranges from local geoip.dat",
            len(_LOCAL_GEOIP_RANGES),
            len(_LOCAL_GEOIP_V6_RANGES),
        )
    except Exception as exc:
        logger.debug("Failed to parse local geoip.dat: %s", exc)


def lookup_local_geoip(ip: str) -> Optional[str]:
    """Look up country code for an IPv4 or IPv6 address from local geoip.dat."""
    try:
        ip_obj = ipaddress.ip_address(ip.strip())
    except ValueError:
        return None

    with _CACHE_LOCK:
        _load_local_geoip_dat()
        ip_int = int(ip_obj)
        if ip_obj.version == 4:
            return _lookup_interval_index(ip_int, _LOCAL_GEOIP_RANGES, _LOCAL_GEOIP_STARTS, _LOCAL_GEOIP_MAX_ENDS)
        return _lookup_interval_index(ip_int, _LOCAL_GEOIP_V6_RANGES, _LOCAL_GEOIP_V6_STARTS, _LOCAL_GEOIP_V6_MAX_ENDS)


def _load_cache() -> None:
    global _CACHE_LOADED
    if _CACHE_LOADED:
        return
    try:
        if _GEOIP_CACHE_FILE.exists():
            data = json.loads(_GEOIP_CACHE_FILE.read_text(encoding="utf-8"))
            now = time.time()
            for ip, val in data.items():
                if isinstance(val, dict) and (now - val.get("ts", 0)) < _CACHE_TTL_SECONDS:
                    _GEOIP_CACHE[ip] = (val.get("country"), val.get("city"), val.get("org"))
                    _GEOIP_CACHE_TS[ip] = float(val.get("ts", now))
    except Exception as exc:
        logger.debug("Failed to load geoip cache: %s", exc)
    _CACHE_LOADED = True


def _flush_cache() -> None:
    """Persist all in-memory cache entries to disk atomically in one write."""
    try:
        _GEOIP_CACHE_FILE.parent.mkdir(parents=True, exist_ok=True)
        now = time.time()
        data: Dict[str, Dict[str, Any]] = {}
        if _GEOIP_CACHE_FILE.exists():
            try:
                existing = json.loads(_GEOIP_CACHE_FILE.read_text(encoding="utf-8"))
                if isinstance(existing, dict):
                    for k, v in existing.items():
                        if isinstance(v, dict) and (now - v.get("ts", 0)) < _CACHE_TTL_SECONDS:
                            data[k] = v
            except Exception:
                pass
        for ip, res in _GEOIP_CACHE.items():
            data[ip] = {
                "country": res[0],
                "city": res[1],
                "org": res[2],
                "ts": _GEOIP_CACHE_TS.get(ip, now),
            }
        tmp = _GEOIP_CACHE_FILE.with_suffix(".tmp")
        tmp.write_text(json.dumps(data, indent=2), encoding="utf-8")
        tmp.replace(_GEOIP_CACHE_FILE)
    except Exception as exc:
        logger.debug("Failed to flush geoip cache: %s", exc)


def _save_cache_entry(ip: str, res: Tuple[Optional[str], Optional[str], Optional[str]]) -> None:
    _GEOIP_CACHE[ip] = res
    _GEOIP_CACHE_TS[ip] = time.time()
    _flush_cache()


def _sanitize_string(val: Optional[str], max_len: int = 20) -> str:
    """Normalize string to safe terminal ASCII/clean unicode and truncate."""
    if not val:
        return ""
    norm = unicodedata.normalize("NFKD", val)
    clean = "".join(c for c in norm if not unicodedata.combining(c))
    clean = clean.encode("ascii", errors="ignore").decode("ascii").strip()
    return clean[:max_len]


def _provider_available(provider: str) -> bool:
    with _REMOTE_LOCK:
        return time.monotonic() >= _REMOTE_COOLDOWN_UNTIL.get(provider, 0.0)


def _record_provider_outcome(provider: str, success: bool, rate_limited: bool = False) -> None:
    with _REMOTE_LOCK:
        if success:
            _REMOTE_FAIL_STREAK[provider] = 0
            return
        streak = _REMOTE_FAIL_STREAK.get(provider, 0) + 1
        _REMOTE_FAIL_STREAK[provider] = streak
        if rate_limited or streak >= 3:
            cooldown = min(60.0, 5.0 * (2 ** min(streak - 1, 3)))
            _REMOTE_COOLDOWN_UNTIL[provider] = time.monotonic() + cooldown


def _fetch_json(url: str, timeout: float, session: Optional[Any] = None) -> Tuple[Optional[Dict[str, Any]], int]:
    """Unified JSON HTTP helper supporting pooled requests.Session and urllib fallback."""
    if requests is not None:
        client = session or requests
        r = client.get(url, headers=_DEFAULT_HEADERS, timeout=timeout)
        if r.status_code == 200:
            data = r.json()
            return (data if isinstance(data, dict) else None), 200
        return None, r.status_code

    req = urllib.request.Request(url, headers=_DEFAULT_HEADERS)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read().decode("utf-8", errors="ignore"))
            return (data if isinstance(data, dict) else None), int(getattr(resp, "status", 200))
    except urllib.error.HTTPError as err:
        return None, int(err.code)


def _extract_ipinfo(data: Dict[str, Any]) -> Tuple[Optional[str], Optional[str], Optional[str]]:
    country: Optional[str] = None
    city: Optional[str] = None
    org: Optional[str] = None
    raw_country = data.get("country")
    if isinstance(raw_country, str) and len(raw_country) == 2:
        country = raw_country.upper()
    raw_city = data.get("city")
    if isinstance(raw_city, str) and raw_city:
        city = _sanitize_string(raw_city, max_len=14)
    raw_org = data.get("org")
    if data.get("anycast") or (isinstance(raw_org, str) and "cloudflare" in raw_org.lower()):
        if not city or city.lower() in ("san francisco", "chicago", "ashburn"):
            city = "Anycast"
    if isinstance(raw_org, str) and raw_org:
        org = _sanitize_string(raw_org, max_len=30)
    return country, city, org


def _extract_freeipapi(data: Dict[str, Any]) -> Tuple[Optional[str], Optional[str]]:
    country: Optional[str] = None
    city: Optional[str] = None
    raw_country = data.get("countryCode")
    if isinstance(raw_country, str) and len(raw_country) == 2:
        country = raw_country.upper()
    raw_city = data.get("cityName")
    if isinstance(raw_city, str) and raw_city:
        city = _sanitize_string(raw_city, max_len=14)
    return country, city


def resolve_ip_location(
    ip: str,
    timeout: float = 4.0,
    save_immediately: bool = True,
    session: Optional[Any] = None,
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
    if _provider_available("ipinfo"):
        try:
            data, status = _fetch_json(f"https://ipinfo.io/{ip}/json", timeout=timeout, session=session)
            if data:
                country, city, org = _extract_ipinfo(data)
                _record_provider_outcome("ipinfo", success=bool(country))
            else:
                _record_provider_outcome("ipinfo", success=False, rate_limited=(status == 429))
        except Exception as exc:
            _record_provider_outcome("ipinfo", success=False)
            logger.debug("ipinfo lookup failed for %s: %s", ip, exc)

    # Secondary provider: freeipapi.com
    if not country and _provider_available("freeipapi"):
        try:
            data, status = _fetch_json(f"https://freeipapi.com/api/json/{ip}", timeout=timeout, session=session)
            if data:
                country, city = _extract_freeipapi(data)
                _record_provider_outcome("freeipapi", success=bool(country))
            else:
                _record_provider_outcome("freeipapi", success=False, rate_limited=(status == 429))
        except Exception as exc:
            _record_provider_outcome("freeipapi", success=False)
            logger.debug("freeipapi lookup failed for %s: %s", ip, exc)

    # Tertiary provider: Local geoip.dat database fallback (instant offline/blocked fallback)
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
    if country:
        with _CACHE_LOCK:
            _GEOIP_CACHE[ip] = res
            _GEOIP_CACHE_TS[ip] = time.time()
            if save_immediately:
                _flush_cache()
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
    if not short:
        return f"[{c_code}]"
    if city and city.lower() != "unknown" and city != "-":
        return f"[{c_code}] {city}"
    return f"[{c_code}]"


def enrich_results_with_geoip(
    results: List[ScanResult],
    workers: int = 10,
    timeout: float = 2.5,
) -> None:
    """Concurrently resolve IP physical location for working results."""
    targets = [r for r in results if r.ok and not r.ip_country]
    if not targets:
        return

    with _CACHE_LOCK:
        _load_cache()

    unique_ips = list({r.ip for r in targets})
    ip_to_geo: Dict[str, Tuple[Optional[str], Optional[str], Optional[str]]] = {}

    thread_local = threading.local()

    def _resolve_one(ip: str) -> Tuple[Optional[str], Optional[str], Optional[str]]:
        sess = getattr(thread_local, "session", None)
        if sess is None and requests is not None:
            sess = requests.Session()
            thread_local.session = sess
        return resolve_ip_location(ip, timeout=timeout, save_immediately=False, session=sess)

    worker_count = min(workers, max(1, len(unique_ips)))
    with ThreadPoolExecutor(max_workers=worker_count) as ex:
        futures = {ex.submit(_resolve_one, ip): ip for ip in unique_ips}
        for fut in as_completed(futures):
            ip = futures[fut]
            try:
                ip_to_geo[ip] = fut.result()
            except Exception as exc:
                logger.debug("enrich_results_with_geoip worker failed for %s: %s", ip, exc)
                ip_to_geo[ip] = (None, None, None)

    with _CACHE_LOCK:
        _flush_cache()

    for r in targets:
        geo = ip_to_geo.get(r.ip)
        if geo and geo[0]:
            r.ip_country, r.ip_city, r.ip_org = geo
