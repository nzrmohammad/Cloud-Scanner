import ipaddress
from collections import Counter
from typing import Callable, List, Optional, Set, Tuple

from scanner.config import make_vless_link
from scanner.constants import (
    STREAMING_LOW_JITTER_MS,
    STREAMING_LOW_LOSS_PCT,
    STREAMING_MID_JITTER_MS,
    STREAMING_MID_LOSS_PCT,
    STREAMING_MID_SPEED_MBPS,
    STREAMING_MIN_SPEED_MBPS,
)
from scanner.models import ScanResult, SmartRecommendation, VlessConfig


def _sustained_rank(sustained: Optional[bool]) -> float:
    """Sort score for sustained status: True (0.0) < None (1.0) < False (2.0)."""
    if sustained is True:
        return 0.0
    if sustained is None:
        return 1.0
    return 2.0


def _fmt_ms(val: Optional[float], default: str = "-") -> str:
    """Safely format millisecond values without crashing on None."""
    return f"{val:.0f}" if val is not None else default


def _fmt_loss(val: Optional[float], default: str = "-") -> str:
    """Safely format packet loss percentage without crashing on None."""
    return f"{val:.0f}" if val is not None else default


def _loss_score(loss: Optional[float]) -> float:
    """Sort score for packet loss: tested 0-100% loss preserved; untested (None) mapped to 50.0% penalty."""
    return loss if loss is not None else 50.0


def _usable_speed_score(speed: Optional[float], loss: Optional[float], jitter: Optional[float]) -> float:
    """Calculate continuous usable throughput penalized smoothly by packet loss and jitter.

    When stability metrics are unmeasured (None), default baseline penalties (STREAMING_MID_LOSS_PCT, STREAMING_MID_JITTER_MS)
    are applied so tested ultra-clean endpoints are preferred over unverified burst throughput.
    """
    if speed is None or speed <= 0:
        return -1.0
    loss_val = loss if loss is not None else STREAMING_MID_LOSS_PCT
    jitter_val = jitter if jitter is not None else STREAMING_MID_JITTER_MS
    loss_penalty = 1.0 + (loss_val / STREAMING_LOW_LOSS_PCT) ** 2
    jitter_penalty = 1.0 + max(0.0, jitter_val - STREAMING_LOW_JITTER_MS) / STREAMING_MID_JITTER_MS
    return speed / (loss_penalty * jitter_penalty)


def latency_sort_key(r: ScanResult) -> Tuple[float, str, int]:
    """Initial scan output: sort only by latency, low to high."""
    latency = r.latency_ms if r.latency_ms is not None else 10**12
    return (latency, r.ip, r.port)


def recheck_sort_key(r: ScanResult) -> Tuple[float, float, float, float, str, int]:
    """Re-check output: sustained first, lowest packet loss first, then lowest jitter, then lowest latency."""
    sustained_score = _sustained_rank(r.sustained)
    loss = _loss_score(r.packet_loss)
    jitter = r.jitter_ms if r.jitter_ms is not None else 10**6
    latency = r.latency_ms if r.latency_ms is not None else 10**12
    return (sustained_score, loss, jitter, latency, r.ip, r.port)


def full_sort_key(r: ScanResult) -> Tuple[float, float, float, float, float, float, str, int]:
    """Full-test output:
    - Sustained status first: True (0.0) < None (1.0) < False (2.0).
    - For sustained (True/None): highest usable speed (loss/jitter penalized), highest upload, lowest latency, lowest jitter.
    - For dropped (False): lowest longevity loss first, lowest packet loss, lowest jitter, lowest latency, highest usable speed.
    """
    sustained_score = _sustained_rank(r.sustained)
    usable_speed = _usable_speed_score(r.speed_mbps, r.packet_loss, r.jitter_ms)
    upload = r.upload_mbps if r.upload_mbps is not None else -1.0
    latency = r.latency_ms if r.latency_ms is not None else 10**12
    jitter = r.jitter_ms if r.jitter_ms is not None else 10**6

    if r.sustained is False:
        long_loss = r.longevity_loss if r.longevity_loss is not None else 100.0
        pkt_loss = _loss_score(r.packet_loss)
        return (sustained_score, long_loss, pkt_loss, jitter, latency, -usable_speed, r.ip, r.port)

    return (sustained_score, 0.0, -usable_speed, -upload, latency, jitter, r.ip, r.port)


def longevity_sort_key(r: ScanResult) -> Tuple[float, float, float, str, int]:
    """Longevity test output: sustained first, lowest longevity loss, then lowest latency."""
    sustained_score = _sustained_rank(r.sustained)
    loss = r.longevity_loss if r.longevity_loss is not None else (0.0 if r.sustained is True else 100.0)
    latency = r.latency_ms if r.latency_ms is not None else 10**12
    return (sustained_score, loss, latency, r.ip, r.port)


def speed_sort_key(r: ScanResult) -> Tuple[float, float, float, str, int]:
    """Speed-test output: sort by download speed (descending), then upload speed (descending)."""
    speed = r.speed_mbps if r.speed_mbps is not None else -1.0
    upload = r.upload_mbps if r.upload_mbps is not None else -1.0
    latency = r.latency_ms if r.latency_ms is not None else 10**12
    return (-speed, -upload, latency, r.ip, r.port)


def result_sort_key(r: ScanResult) -> Tuple[float, str, int]:
    """Default/live scan ordering: latency only."""
    return latency_sort_key(r)


def output_sort_key(filename_prefix: str, ok: Optional[List[ScanResult]] = None) -> Callable[[ScanResult], Tuple]:
    """Pick the output order for each independent result file based on stage detection."""
    is_full, is_speed, is_recheck, is_longevity = detect_stage_flags(filename_prefix, ok or [])
    if is_full:
        return full_sort_key
    if is_speed:
        return speed_sort_key
    if is_longevity:
        return longevity_sort_key
    if is_recheck:
        return recheck_sort_key
    return latency_sort_key


def extract_subnet_prefix(ip: str) -> str:
    """Extract /24 subnet for IPv4 or /64 prefix for IPv6."""
    try:
        addr = ipaddress.ip_address(ip)
        if addr.version == 4:
            return ".".join(ip.split(".")[:3]) + ".0/24"
        else:
            exploded = addr.exploded
            return ":".join(exploded.split(":")[:4]) + "::/64"
    except Exception:
        return ip


def filter_diverse_endpoints(
    candidates: List[ScanResult],
    max_targets: int = 30,
    max_per_subnet: int = 2,
) -> List[ScanResult]:
    """Filter and trim endpoints to ensure IP deduplication and subnet diversity.

    1. Deduplicates multiple ports on the same IP (keeping the highest-ranking port).
    2. Distributes selections across /24 (IPv4) or /64 (IPv6) subnets up to max_per_subnet.
    3. Backfills from remaining candidates if diverse subnets are fewer than max_targets.
    """
    if max_targets <= 0 or not candidates:
        return candidates

    seen_ips: Set[str] = set()
    deduped: List[ScanResult] = []
    for r in candidates:
        if r.ip not in seen_ips:
            seen_ips.add(r.ip)
            deduped.append(r)

    if len(deduped) <= max_targets:
        return deduped

    selected: List[ScanResult] = []
    deferred: List[ScanResult] = []
    subnet_counts: Counter = Counter()

    for r in deduped:
        subnet = extract_subnet_prefix(r.ip)
        if subnet_counts[subnet] < max_per_subnet:
            subnet_counts[subnet] += 1
            selected.append(r)
            if len(selected) >= max_targets:
                break
        else:
            deferred.append(r)

    if len(selected) < max_targets and deferred:
        needed = max_targets - len(selected)
        selected.extend(deferred[:needed])

    return selected


def apply_result_filters(
    results: List[ScanResult],
    max_latency_ms: float = 0,
    min_speed_mbps: float = 0,
) -> List[ScanResult]:
    filtered: List[ScanResult] = []
    for r in results:
        if not r.ok:
            continue
        if max_latency_ms > 0 and (r.latency_ms is None or r.latency_ms > max_latency_ms):
            continue
        if min_speed_mbps > 0 and (r.speed_mbps is None or r.speed_mbps < min_speed_mbps):
            continue
        filtered.append(r)
    return sorted(filtered, key=result_sort_key)


def _make_rec_link(vless_config: Optional[VlessConfig], r: ScanResult, category: str) -> str:
    """Generate a tagged VLESS link for a recommendation."""
    if not vless_config:
        return ""
    loc_tag = f"_{r.ip_country}" if r.ip_country else ""
    colo_tag = f"_{r.colo}" if r.colo else ""
    return make_vless_link(vless_config, r.ip, r.port, f"{category}{loc_tag}{colo_tag}")


def get_smart_recommendations(
    results: List[ScanResult],
    vless_config: Optional[VlessConfig] = None,
) -> List[SmartRecommendation]:
    """Analyze working results and select the best endpoints tailored for specific use cases."""
    ok = [r for r in results if r.ok]
    if not ok:
        return []

    ok_sorted = sorted(
        ok,
        key=lambda r: (
            _sustained_rank(r.sustained),
            _loss_score(r.packet_loss),
            r.latency_ms if r.latency_ms is not None else 9999.0,
        ),
    )

    recs: List[SmartRecommendation] = []

    # 1. Best for Gaming:
    # Primary criteria: sustained connection, minimum packet loss, lowest jitter, lowest latency
    has_stability = any(r.jitter_ms is not None or r.recheck_total > 0 for r in ok_sorted)
    if has_stability:
        gaming_sorted = sorted(
            ok_sorted,
            key=lambda r: (
                _sustained_rank(r.sustained),
                _loss_score(r.packet_loss),
                r.jitter_ms if r.jitter_ms is not None else 9999.0,
                r.latency_ms if r.latency_ms is not None else 9999.0,
            ),
        )
        best_g = gaming_sorted[0]
        jit_txt = f" | Jitter: {best_g.jitter_ms:.1f}ms" if best_g.jitter_ms is not None else ""
        up_txt = f" | Up: {best_g.upload_mbps:.1f}M" if best_g.upload_mbps is not None else ""
        drop_g = " | Anti-Drop" if best_g.sustained is True else ""
        recs.append(
            SmartRecommendation(
                category="Gaming",
                icon="🎮",
                result=best_g,
                reason=f"Ping: {_fmt_ms(best_g.latency_ms)}ms | Loss: {_fmt_loss(best_g.packet_loss)}%{jit_txt}{up_txt}{drop_g}",
                vless_link=_make_rec_link(vless_config, best_g, "Gaming"),
            )
        )
    else:
        best_g = ok_sorted[0]
        up_txt = f" | Up: {best_g.upload_mbps:.1f}M" if best_g.upload_mbps is not None else ""
        drop_g = " | Anti-Drop" if best_g.sustained is True else ""
        recs.append(
            SmartRecommendation(
                category="Gaming",
                icon="🎮",
                result=best_g,
                reason=f"Ping: {_fmt_ms(best_g.latency_ms)}ms{up_txt}{drop_g}",
                vless_link=_make_rec_link(vless_config, best_g, "Gaming"),
            )
        )

    # 2. Best for Instagram, YouTube & Video Streaming:
    # Primary criteria: Sustained connection against DPI, high usable speed (loss/jitter penalized), low TTFB & ping
    has_speed = any(r.speed_mbps is not None and r.speed_mbps > 0 for r in ok_sorted)
    if has_speed:
        insta_candidates = [r for r in ok_sorted if r.speed_mbps is not None and r.speed_mbps > 0]
        insta_sorted = sorted(
            insta_candidates,
            key=lambda r: (
                _sustained_rank(r.sustained),
                -_usable_speed_score(r.speed_mbps, r.packet_loss, r.jitter_ms),
                -(r.upload_mbps or 0.0),
                r.ttfb_ms if r.ttfb_ms is not None else (r.latency_ms if r.latency_ms is not None else 999.0),
                r.latency_ms if r.latency_ms is not None else 9999.0,
            ),
        )
        best_i = insta_sorted[0]
        tier_txt = ""
        if best_i.speed_mbps is not None:
            if best_i.speed_mbps >= STREAMING_MIN_SPEED_MBPS and (best_i.packet_loss is None or best_i.packet_loss <= STREAMING_LOW_LOSS_PCT):
                tier_txt = " (4K)"
            elif best_i.speed_mbps >= STREAMING_MID_SPEED_MBPS:
                tier_txt = " (HD)"
        speed_txt = f"Down: {best_i.speed_mbps:.2f} Mbps{tier_txt}"
        if best_i.upload_mbps is not None:
            speed_txt += f" | Up: {best_i.upload_mbps:.2f} Mbps"
        jit_txt = f" | Jitter: {best_i.jitter_ms:.0f}ms" if best_i.jitter_ms is not None else ""
        drop_i = " | Anti-Drop" if best_i.sustained is True else ""
        recs.append(
            SmartRecommendation(
                category="Streaming",
                icon="📱",
                result=best_i,
                reason=f"{speed_txt}{drop_i}{jit_txt} | Ping: {_fmt_ms(best_i.latency_ms)}ms",
                vless_link=_make_rec_link(vless_config, best_i, "Streaming"),
            )
        )
    elif len(ok_sorted) > 1:
        alt = ok_sorted[1]
        st_reason = f"Ping: {_fmt_ms(alt.latency_ms)}ms"
        if alt.sustained is True:
            st_reason += " | Anti-Drop (High stability)"
        elif alt.jitter_ms is not None:
            if alt.jitter_ms <= STREAMING_LOW_JITTER_MS:
                st_reason += f" | Jitter: {alt.jitter_ms:.1f}ms (Stable stream)"
            else:
                st_reason += f" | Jitter: {alt.jitter_ms:.1f}ms"
        else:
            st_reason += " (Low latency)"
        recs.append(
            SmartRecommendation(
                category="Streaming",
                icon="📱",
                result=alt,
                reason=st_reason,
                vless_link=_make_rec_link(vless_config, alt, "Streaming"),
            )
        )

    # 3. Best for General Browsing / Telegram:
    if len(ok_sorted) >= 3:
        chosen_endpoints = {r.result.endpoint for r in recs}
        remaining = [r for r in ok_sorted if r.endpoint not in chosen_endpoints]
        best_gen = remaining[0] if remaining else ok_sorted[0]
        drop_badge = " | Anti-Drop" if best_gen.sustained is True else ""
        recs.append(
            SmartRecommendation(
                category="General Web",
                icon="🌐",
                result=best_gen,
                reason=f"Ping: {_fmt_ms(best_gen.latency_ms)}ms | Port: {best_gen.port}{drop_badge}",
                vless_link=_make_rec_link(vless_config, best_gen, "General"),
            )
        )

    # 4. Best Anti-Drop / DPI Endurance:
    has_longevity = any(r.sustained is not None for r in ok_sorted)
    if has_longevity:
        sustained_candidates = [r for r in ok_sorted if r.sustained is True]
        if sustained_candidates:
            best_anti = sorted(
                sustained_candidates,
                key=lambda r: (
                    r.longevity_loss if r.longevity_loss is not None else 999.0,
                    _loss_score(r.packet_loss),
                    -(r.speed_mbps or 0.0),
                    r.latency_ms if r.latency_ms is not None else 9999.0,
                ),
            )[0]
            spd = f" | {best_anti.speed_mbps:.1f} Mbps" if best_anti.speed_mbps is not None else ""
            drop_txt = f"{best_anti.longevity_loss:.0f}% drop" if best_anti.longevity_loss is not None else "DPI Resistant"
            recs.append(
                SmartRecommendation(
                    category="Anti-Drop",
                    icon="🛡",
                    result=best_anti,
                    reason=f"Sustained ({drop_txt}){spd} | Ping: {_fmt_ms(best_anti.latency_ms)}ms",
                    vless_link=_make_rec_link(vless_config, best_anti, "AntiDrop"),
                )
            )

    return recs


def _classify_scan_error(error: str) -> str:
    """Group verbose urllib3/requests/Xray/Windows error strings into clear diagnostic buckets."""
    err = (error or "").strip()
    if not err:
        return "Unknown failure"
    low = err.lower()
    if "xray did not open" in low or "failed to start" in low:
        return "Xray failed to start (check VLESS params / Xray version)"
    if "403 forbidden" in low or "bad handshake" in low:
        return "WebSocket handshake rejected (403 / bad handshake)"
    if "certificate_verify_failed" in low or "failed to verify certificate" in low:
        return "TLS certificate mismatch (IP not serving your SNI)"
    if any(k in low for k in ("unexpected_eof", "ssleoferror", "sslerror", "violation of protocol")):
        return "TLS/Proxy stream closed unexpectedly (SSLEOFError)"
    if any(k in low for k in ("read timed out", "timed out", "timeout", "10060")):
        return "Timed out waiting for response"
    if any(
        k in low
        for k in (
            "10061",
            "actively refused",
            "connection refused",
            "connectionrefused",
            "10054",
            "forcibly closed",
            "connection reset",
            "connection aborted",
            "remotedisconnected",
            "remote end closed",
            "broken pipe",
        )
    ):
        return "Connection reset / aborted by remote host"
    return err.splitlines()[0][:80]


def summarize_failure_diagnostics(results: List[ScanResult]) -> Tuple[List[Tuple[str, int]], List[str]]:
    """Summarize dominant failure causes and actionable troubleshooting hints for failed scans."""
    failed = [r for r in results if not r.ok]
    if not failed:
        return [], []

    counts: Counter[str] = Counter(_classify_scan_error(r.error) for r in failed)
    top_reasons = counts.most_common(5)
    labels_joined = " ".join(label.lower() for label, _ in top_reasons)

    hints: List[str] = []
    if any(k in labels_joined for k in ("ssleoferror", "connection reset", "timed out")):
        hints.append("Verify your base VLESS URI/UUID is active in a VPN client (expired/blocked accounts fail all IPs).")
        hints.append("Disable any active VPN / TUN adapter (Fake-IP DNS) before scanning so traffic uses your ISP.")
    if any(k in labels_joined for k in ("certificate mismatch", "403", "ssleoferror")):
        hints.append("Confirm the scanned IP/CIDR belongs to Cloudflare/your CDN and check SNI / Host parameters.")
    if "xray failed to start" in labels_joined:
        hints.append("Check results/scanner.log and VLESS parameters (Xray >= 26.1.31 removed allowInsecure=1).")
    if not hints:
        hints.append("Inspect results/scanner.log for detailed per-endpoint error messages.")

    return top_reasons, hints


def detect_stage_flags(filename_prefix: str, ok: List[ScanResult]) -> Tuple[bool, bool, bool, bool]:
    """Determine (is_full, is_speed, is_recheck, is_longevity) display/export mode flags."""
    has_jitter = any(r.jitter_ms is not None for r in ok)
    has_speed = any(r.speed_mbps is not None or r.upload_mbps is not None for r in ok)
    has_longevity = any(r.sustained is not None for r in ok)

    if "full" in filename_prefix:
        return True, False, False, False
    if "longevity" in filename_prefix:
        return False, False, False, True
    if "speed" in filename_prefix:
        return False, True, False, False
    if "rechecked" in filename_prefix:
        return False, False, True, False

    # Fallback to result data inspection when filename prefix is generic (e.g. "clean_ips")
    if has_jitter and has_speed and has_longevity:
        return True, False, False, False
    if has_speed:
        return False, True, False, False
    if has_longevity:
        return False, False, False, True
    if has_jitter:
        return False, False, True, False

    return False, False, False, False
