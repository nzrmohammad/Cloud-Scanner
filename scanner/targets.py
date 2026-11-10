import ipaddress
import re
from bisect import bisect_right
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Set, Tuple

from scanner.constants import (
    MAX_DEFAULT_HOSTS,
    SAFE_AUTO_EXPAND_LIMIT,
    SAFE_IPV6_AUTO_EXPAND_LIMIT,
    app_dir,
    format_host_port,
    isp_root,
)
from scanner.logger import get_logger
from scanner.models import TargetSource

logger = get_logger("targets")

_IP_SYNTAX_RE = re.compile(r"^[\da-fA-F:\.\[\]/\-]+$")


def clean_target_token(item: str) -> str:
    """Return the first valid-looking token from a target line."""
    item = item.strip().strip(",;")
    if not item or item.startswith("#") or item.startswith("//"):
        return ""
    for marker in ("#", "//"):
        if marker in item:
            item = item.split(marker, 1)[0].strip()
    item = re.sub(r"\s*-\s*", "-", item)
    item = item.replace("*", " ")
    parts = re.split(r"[\s,;]+", item)
    return parts[0].strip() if parts else ""


def _network_host_bounds(net: ipaddress._BaseNetwork) -> Tuple[int, int]:
    """Return usable host bounds. For /31, /32 and IPv6 tiny nets keep all."""
    start = int(net.network_address)
    end = int(net.broadcast_address)
    if net.version == 4 and net.num_addresses > 2:
        start += 1
        end -= 1
    return start, end


def parse_ip_and_port(token: str) -> Tuple[str, Optional[int]]:
    """Extract host IP string and optional port from a token.
    Supports IPv4, [IPv6]:port, bare IPv6, and IPv4:port.
    """
    token = token.strip()
    if token.startswith("[") and "]:" in token:
        bracket_idx = token.index("]:")
        host = token[1:bracket_idx]
        port_s = token[bracket_idx + 2:]
        try:
            p = int(port_s)
            if 1 <= p <= 65535:
                return host, p
        except ValueError:
            pass
        return host, None
    if token.startswith("[") and token.endswith("]"):
        return token[1:-1], None
    if ":" in token and "/" not in token and "-" not in token:
        try:
            ipaddress.IPv6Address(token)
            return token, None
        except ValueError:
            host, sep, port_s = token.rpartition(":")
            if host:
                try:
                    p = int(port_s)
                    if 1 <= p <= 65535:
                        return host, p
                except ValueError:
                    pass
    return token, None


def _build_isp_file_index(root: Path) -> List[Path]:
    """Return all packaged ISP txt files once for fast in-memory matching."""
    if not root.exists():
        return []
    return [p for p in root.rglob("*.txt") if p.is_file()]


def _resolve_target_file(raw_item: str, token: str, isp_index: Optional[List[Path]] = None) -> Optional[Path]:
    """Look for an existing file directly, in app_dir, or matching in ip-ranges."""
    p = Path(raw_item)
    try:
        if p.is_file():
            return p
    except OSError:
        pass
    alt = app_dir() / raw_item
    try:
        if alt.is_file():
            return alt
    except OSError:
        pass

    # Skip slow catalog searches when the token already looks like an IP/CIDR/range literal
    if token and _IP_SYNTAX_RE.match(token) and ("." in token or ":" in token):
        return None

    files = isp_index if isp_index is not None else _build_isp_file_index(isp_root())
    if not files:
        return None

    candidates = {c.lower() for c in (raw_item, f"{raw_item}.txt", token, f"{token}.txt") if c}
    for f in files:
        if f.name.lower() in candidates or f.stem.lower() in candidates:
            return f

    m = re.match(r"^(?:as|asn)?(\d{2,7})$", token, re.IGNORECASE)
    if m:
        num = m.group(1)
        non_v6 = [f for f in files if num in f.name and "ipv6" not in f.name.lower()]
        if non_v6:
            return non_v6[0]
        any_match = [f for f in files if num in f.name]
        if any_match:
            return any_match[0]
    return None


def _fetch_asn_prefixes(token: str) -> List[str]:
    """Attempt to fetch announced prefixes for an ASN (e.g. AS42337) from RIPE stat API."""
    m = re.match(r"^(?:as|asn)(\d{2,7})$", token, re.IGNORECASE)
    if not m:
        return []
    asn_num = m.group(1)
    try:
        import json
        import urllib.request
        url = f"https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS{asn_num}"
        req = urllib.request.Request(url, headers={"User-Agent": "CloudScanner/1.0"})
        with urllib.request.urlopen(req, timeout=5) as resp:
            data = json.loads(resp.read().decode("utf-8", errors="ignore"))
            return [p["prefix"] for p in data.get("data", {}).get("prefixes", [])]
    except Exception as exc:
        logger.warning("Failed to fetch announced prefixes for ASN%s from RIPE NCC: %s", asn_num, exc)
        return []


def _parse_single_target_source(token: str) -> Optional[TargetSource]:
    """Parse a single CIDR, range (A.B.C.D-W.X.Y.Z or A.B.C.D-E), or IP[:port] into a TargetSource."""
    if "/" in token:
        net = ipaddress.ip_network(token, strict=False)
        start, end = _network_host_bounds(net)
        return TargetSource(start=start, end=end, version=net.version, label=token) if end >= start else None

    if "-" in token:
        start_s, end_s = [x.strip() for x in token.split("-", 1)]
        start_ip = ipaddress.ip_address(start_s)
        if end_s.isdigit() and start_ip.version == 4:
            last_octet = int(end_s)
            if not 0 <= last_octet <= 255:
                raise ValueError(f"Invalid IP range: {token}")
            end_s = f"{start_s.rsplit('.', 1)[0]}.{last_octet}"
        end_ip = ipaddress.ip_address(end_s)
        if start_ip.version != end_ip.version or int(end_ip) < int(start_ip):
            raise ValueError(f"Invalid IP range: {token}")
        return TargetSource(start=int(start_ip), end=int(end_ip), version=start_ip.version, label=token)

    host_str, port = parse_ip_and_port(token)
    ip = ipaddress.ip_address(host_str)
    return TargetSource(start=int(ip), end=int(ip), version=ip.version, label=token, port=port)


def _target_sources(
    items: Iterable[str],
    allow_file_lookup: bool = True,
    _visited_files: Optional[Set[Path]] = None,
    _isp_index: Optional[List[Path]] = None,
) -> List[TargetSource]:
    sources: List[TargetSource] = []
    visited = _visited_files if _visited_files is not None else set()
    isp_index = _isp_index

    for item in items:
        raw_item = str(item).strip().strip('"').strip("'")
        if not raw_item:
            continue
        token = clean_target_token(raw_item)

        if allow_file_lookup:
            if isp_index is None and not (token and _IP_SYNTAX_RE.match(token) and ("." in token or ":" in token)):
                isp_index = _build_isp_file_index(isp_root())
            matched_file = _resolve_target_file(raw_item, token, isp_index=isp_index)
            if matched_file and matched_file.is_file():
                resolved = matched_file.resolve()
                if resolved in visited:
                    continue
                visited.add(resolved)
                lines = matched_file.read_text(encoding="utf-8", errors="ignore").splitlines()
                sources.extend(_target_sources(lines, allow_file_lookup=False, _visited_files=visited, _isp_index=isp_index))
                continue

        if not token:
            continue

        # Fast-path IP / CIDR / range parsing before external ASN HTTP calls
        try:
            src = _parse_single_target_source(token)
            if src is not None:
                sources.append(src)
            continue
        except ValueError:
            pass

        asn_prefixes = _fetch_asn_prefixes(token)
        if asn_prefixes:
            sources.extend(_target_sources(asn_prefixes, allow_file_lookup=False, _visited_files=visited, _isp_index=isp_index))
            continue

        # Re-raise descriptive ValueError on invalid target token
        _parse_single_target_source(token)

    return sources


def _format_target_item(ip_int: int, port: Optional[int]) -> str:
    ip_str = str(ipaddress.ip_address(ip_int))
    return format_host_port(ip_str, port) if port is not None else ip_str


def _expand_sources_exact(sources: List[TargetSource], max_hosts: Optional[int] = None) -> List[str]:
    out: List[str] = []
    seen = set()
    for src in sources:
        for n in range(src.start, src.end + 1):
            item_str = _format_target_item(n, src.port)
            if item_str in seen:
                continue
            seen.add(item_str)
            out.append(item_str)
            if max_hosts is not None and max_hosts > 0 and len(out) > max_hosts:
                raise ValueError(
                    f"Too many targets. Current limit is {max_hosts}. Use max_targets in config.txt to raise it."
                )
    return out


def _sample_sources_evenly(sources: List[TargetSource], max_hosts: int) -> List[str]:
    """Sample targets evenly across all selected ranges without enumerating them."""
    sources = [s for s in sources if s.size > 0]
    if not sources or max_hosts <= 0:
        return []
    totals: Dict[int, int] = {}
    weights: Dict[int, int] = {}
    by_version: Dict[int, List[TargetSource]] = {}
    for src in sources:
        totals[src.version] = totals.get(src.version, 0) + src.size
        # Cap per-range weight when splitting budget between IPv4 and IPv6 so huge IPv6 subnets do not starve IPv4
        weights[src.version] = weights.get(src.version, 0) + min(src.size, 256)
        by_version.setdefault(src.version, []).append(src)
    grand_weight = sum(weights.values())
    allocations: Dict[int, int] = {}
    used = 0
    remainders: List[Tuple[float, int]] = []
    for version, weight in weights.items():
        raw = (max_hosts * weight) / grand_weight
        alloc = min(totals[version], max(1, int(raw)))
        allocations[version] = alloc
        used += alloc
        remainders.append((raw - int(raw), version))
    while used > max_hosts:
        cand_v: Optional[int] = max((v for v, a in allocations.items() if a > 1), key=lambda v: allocations[v], default=None)
        if cand_v is None:
            cand_v = max((v for v, a in allocations.items() if a > 0), key=lambda v: allocations[v], default=None)
        if cand_v is None:
            break
        allocations[cand_v] -= 1
        used -= 1
    for _, version in sorted(remainders, reverse=True):
        if used >= max_hosts:
            break
        if allocations[version] < totals[version]:
            allocations[version] += 1
            used += 1

    out: List[str] = []
    seen = set()
    for version, version_sources in by_version.items():
        total = sum(src.size for src in version_sources)
        count = min(allocations.get(version, 0), total)
        if count <= 0:
            continue
        cumulative: List[int] = []
        run = 0
        for src in version_sources:
            run += src.size
            cumulative.append(run)
        if count == 1:
            positions = [total // 2]
        else:
            positions = [(i * (total - 1)) // (count - 1) for i in range(count)]
        for pos in positions:
            idx = bisect_right(cumulative, pos)
            prev = cumulative[idx - 1] if idx > 0 else 0
            src = version_sources[idx]
            n = src.start + (pos - prev)
            item_str = _format_target_item(n, src.port)
            if item_str not in seen:
                seen.add(item_str)
                out.append(item_str)
    return out[:max_hosts]


def expand_targets(
    items: Iterable[str],
    max_hosts: Optional[int] = MAX_DEFAULT_HOSTS,
    sample_if_too_many: bool = False,
) -> List[str]:
    """Parse, expand, and sample IP targets from strings, CIDRs, ranges or file paths."""
    sources = _target_sources(items)
    total = sum(src.size for src in sources)
    limit = None if max_hosts is None or max_hosts <= 0 else int(max_hosts)
    if limit is None:
        v4_sources = [s for s in sources if s.version == 4]
        v6_sources = [s for s in sources if s.version == 6]
        v4_total = sum(s.size for s in v4_sources)
        v6_total = sum(s.size for s in v6_sources)
        if v4_total <= SAFE_AUTO_EXPAND_LIMIT and v6_total <= SAFE_IPV6_AUTO_EXPAND_LIMIT:
            return _expand_sources_exact(sources, None)
        if not sample_if_too_many:
            raise ValueError(
                f"Target range is too large ({total} addresses). Specify a positive max_targets or enable sampling."
            )
        out: List[str] = []
        if v4_sources:
            out.extend(
                _expand_sources_exact(v4_sources, None)
                if v4_total <= SAFE_AUTO_EXPAND_LIMIT
                else _sample_sources_evenly(v4_sources, SAFE_AUTO_EXPAND_LIMIT)
            )
        if v6_sources:
            out.extend(
                _expand_sources_exact(v6_sources, None)
                if v6_total <= SAFE_IPV6_AUTO_EXPAND_LIMIT
                else _sample_sources_evenly(v6_sources, SAFE_IPV6_AUTO_EXPAND_LIMIT)
            )
        return out
    if total <= limit:
        return _expand_sources_exact(sources, limit)
    if not sample_if_too_many:
        raise ValueError(f"Too many targets. Current limit is {limit}.")
    return _sample_sources_evenly(sources, limit)


def count_target_sources(items: Iterable[str]) -> Tuple[int, int]:
    sources = _target_sources(items)
    return len(sources), sum(src.size for src in sources)


def list_isp_files(category: str) -> List[Path]:
    root = isp_root() / category
    if not root.exists():
        return []
    return sorted([p for p in root.glob("*.txt") if p.is_file()], key=lambda p: p.stem.lower())


def isp_display_name(path: Path) -> str:
    return path.stem.replace("_", " ").strip()


def read_isp_stats(path: Path) -> Tuple[int, str]:
    try:
        lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()
        valid = [clean_target_token(line) for line in lines]
        valid = [x for x in valid if x]
        preview = ", ".join(valid[:2]) + (" ..." if len(valid) > 2 else "")
        return len(valid), preview
    except Exception:
        return 0, ""


def resolve_isp_files(category: str, names: Optional[List[str]]) -> List[Path]:
    files = list_isp_files(category)
    if not names or any(n.lower() == "all" for n in names):
        return files
    by_key = {p.stem.lower(): p for p in files}
    by_name = {isp_display_name(p).lower(): p for p in files}
    selected: List[Path] = []
    for name in names:
        key = name.lower().strip()
        match = by_key.get(key) or by_name.get(key)
        if not match:
            partial = [p for p in files if key in p.stem.lower() or key in isp_display_name(p).lower()]
            if len(partial) == 1:
                match = partial[0]
        if not match:
            raise ValueError(f"ISP not found in {category}: {name}")
        if match not in selected:
            selected.append(match)
    return selected


def print_isp_catalog_cli() -> None:
    from scanner.constants import ISP_CATEGORIES
    from scanner.ui.terminal import cprint

    for category, label in ISP_CATEGORIES.items():
        files = list_isp_files(category)
        cprint(f"\n{label}:", "bold cyan")
        for path in files:
            count, preview = read_isp_stats(path)
            cprint(f"  - {isp_display_name(path)} ({count} lines) {preview}")
