import ipaddress
import re
from bisect import bisect_right
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple

from scanner.constants import MAX_DEFAULT_HOSTS, app_dir, isp_root
from scanner.models import TargetSource


def clean_target_token(item: str) -> str:
    """Return the first valid-looking token from a target line."""
    item = item.strip().strip(",;")
    if not item or item.startswith("#") or item.startswith("//"):
        return ""
    for marker in ("#", "//"):
        if marker in item:
            item = item.split(marker, 1)[0].strip()
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


def _target_sources(items: Iterable[str]) -> List[TargetSource]:
    sources: List[TargetSource] = []
    for item in items:
        raw_item = str(item).strip().strip('"').strip("'")
        if not raw_item:
            continue
        p = Path(raw_item)
        if not p.is_absolute():
            if not (p.exists() and p.is_file()):
                alt_p = app_dir() / raw_item
                if alt_p.exists() and alt_p.is_file():
                    p = alt_p
        if p.exists() and p.is_file():
            lines = p.read_text(encoding="utf-8", errors="ignore").splitlines()
            sources.extend(_target_sources(lines))
            continue
        token = clean_target_token(raw_item)
        if not token:
            continue
        if "/" in token:
            net = ipaddress.ip_network(token, strict=False)
            start, end = _network_host_bounds(net)
            if end >= start:
                sources.append(TargetSource(start=start, end=end, version=net.version, label=token))
            continue
        if "-" in token:
            start_s, end_s = [x.strip() for x in token.split("-", 1)]
            start_ip, end_ip = ipaddress.ip_address(start_s), ipaddress.ip_address(end_s)
            if start_ip.version != end_ip.version or int(end_ip) < int(start_ip):
                raise ValueError(f"Invalid IP range: {token}")
            sources.append(TargetSource(start=int(start_ip), end=int(end_ip), version=start_ip.version, label=token))
            continue

        host_str, port = parse_ip_and_port(token)
        ip = ipaddress.ip_address(host_str)
        sources.append(TargetSource(start=int(ip), end=int(ip), version=ip.version, label=token, port=port))
    return sources


def _expand_sources_exact(sources: List[TargetSource], max_hosts: Optional[int] = None) -> List[str]:
    out: List[str] = []
    seen = set()
    limited = max_hosts is not None and max_hosts > 0
    for src in sources:
        for n in range(src.start, src.end + 1):
            ip_obj = ipaddress.ip_address(n)
            ip_str = str(ip_obj)
            if src.port is not None:
                item_str = f"[{ip_str}]:{src.port}" if ip_obj.version == 6 else f"{ip_str}:{src.port}"
            else:
                item_str = ip_str
            if item_str in seen:
                continue
            seen.add(item_str)
            out.append(item_str)
            if limited and len(out) > int(max_hosts):
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
    by_version: Dict[int, List[TargetSource]] = {}
    for src in sources:
        totals[src.version] = totals.get(src.version, 0) + src.size
        by_version.setdefault(src.version, []).append(src)
    grand_total = sum(totals.values())
    allocations: Dict[int, int] = {}
    used = 0
    remainders: List[Tuple[float, int]] = []
    for version, total in totals.items():
        raw = (max_hosts * total) / grand_total
        alloc = max(1, int(raw))
        allocations[version] = alloc
        used += alloc
        remainders.append((raw - int(raw), version))
    while used > max_hosts:
        version = max((v for v, a in allocations.items() if a > 1), key=lambda v: allocations[v], default=None)
        if version is None:
            break
        allocations[version] -= 1
        used -= 1
    for _, version in sorted(remainders, reverse=True):
        if used >= max_hosts:
            break
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
            ip_obj = ipaddress.ip_address(n)
            ip_str = str(ip_obj)
            if src.port is not None:
                item_str = f"[{ip_str}]:{src.port}" if ip_obj.version == 6 else f"{ip_str}:{src.port}"
            else:
                item_str = ip_str
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
        return _expand_sources_exact(sources, None)
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


class TargetResolver:
    """Class wrapper for IP range and ISP catalog resolution."""

    @staticmethod
    def expand(items: Iterable[str], max_hosts: Optional[int] = 0, sample: bool = True) -> List[str]:
        return expand_targets(items, max_hosts=max_hosts, sample_if_too_many=sample)

    @staticmethod
    def get_isps(category: str) -> List[Path]:
        return list_isp_files(category)

    @staticmethod
    def resolve_isps(category: str, names: Optional[List[str]]) -> List[Path]:
        return resolve_isp_files(category, names)
