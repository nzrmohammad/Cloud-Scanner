from typing import Callable, List, Optional, Tuple

from scanner.config import make_vless_link
from scanner.constants import format_cf_colo
from scanner.models import ScanResult, SmartRecommendation, VlessConfig


def latency_sort_key(r: ScanResult) -> Tuple[float, str, int]:
    """Initial scan output: sort only by latency, low to high."""
    latency = r.latency_ms if r.latency_ms is not None else 10**12
    return (latency, r.ip, r.port)


def recheck_sort_key(r: ScanResult) -> Tuple[float, float, float, float, str, int]:
    """Re-check output: sustained first, lowest packet loss first, then lowest latency, then lowest jitter."""
    sustained_score = 0.0 if (r.sustained is True or r.sustained is None) else 1.0
    loss = r.packet_loss
    latency = r.latency_ms if r.latency_ms is not None else 10**12
    jitter = r.jitter_ms if r.jitter_ms is not None else 10**6
    return (sustained_score, loss, latency, jitter, r.ip, r.port)


def full_sort_key(r: ScanResult) -> Tuple[float, float, float, float, float, float, str, int]:
    """Full-test output: sustained first, highest download speed, highest upload speed, lowest loss, lowest latency."""
    sustained_score = 0.0 if (r.sustained is True or r.sustained is None) else 1.0
    speed = r.speed_mbps if r.speed_mbps is not None else -1.0
    upload = r.upload_mbps if r.upload_mbps is not None else -1.0
    loss = r.packet_loss
    latency = r.latency_ms if r.latency_ms is not None else 10**12
    jitter = r.jitter_ms if r.jitter_ms is not None else 10**6
    return (sustained_score, -speed, -upload, loss, latency, jitter, r.ip, r.port)


def longevity_sort_key(r: ScanResult) -> Tuple[float, float, float, str, int]:
    """Longevity test output: sustained first, lowest longevity loss, then lowest latency."""
    sustained_score = 0.0 if (r.sustained is True or r.sustained is None) else 1.0
    loss = r.longevity_loss if r.longevity_loss is not None else 0.0
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


def output_sort_key(filename_prefix: str) -> Callable[[ScanResult], Tuple]:
    """Pick the output order for each independent result file."""
    if "full" in filename_prefix:
        return full_sort_key
    if "speed" in filename_prefix:
        return speed_sort_key
    if "longevity" in filename_prefix:
        return longevity_sort_key
    if "rechecked" in filename_prefix:
        return recheck_sort_key
    return latency_sort_key


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


def get_smart_recommendations(
    results: List[ScanResult],
    vless_config: Optional[VlessConfig] = None,
) -> List[SmartRecommendation]:
    """Analyze working results and select the best endpoints tailored for specific use cases."""
    ok = [r for r in results if r.ok]
    if not ok:
        return []

    recs: List[SmartRecommendation] = []

    # 1. Best for Gaming:
    # Primary criteria: 0% packet loss (or minimum possible), lowest jitter, lowest latency
    has_stability = any(r.jitter_ms is not None or r.recheck_total > 0 for r in ok)
    if has_stability:
        gaming_sorted = sorted(
            ok,
            key=lambda r: (
                r.packet_loss,
                r.jitter_ms if r.jitter_ms is not None else 9999.0,
                r.latency_ms if r.latency_ms is not None else 9999.0,
            ),
        )
        best_g = gaming_sorted[0]
        jit_txt = f" | Jitter: {best_g.jitter_ms:.1f}ms" if best_g.jitter_ms is not None else ""
        up_txt = f" | Up: {best_g.upload_mbps:.1f}M" if best_g.upload_mbps is not None else ""
        drop_g = " | Anti-Drop" if best_g.sustained is True else ""
        loc_tag_g = f"_{best_g.ip_country}" if best_g.ip_country else ""
        colo_tag_g = f"_{best_g.colo}" if best_g.colo else ""
        link_g = make_vless_link(vless_config, best_g.ip, best_g.port, f"Gaming{loc_tag_g}{colo_tag_g}") if vless_config else ""
        recs.append(
            SmartRecommendation(
                category="Gaming",
                icon="🎮",
                result=best_g,
                reason=f"Ping: {best_g.latency_ms:.0f}ms | Loss: {best_g.packet_loss:.0f}%{jit_txt}{up_txt}{drop_g}",
                vless_link=link_g,
            )
        )
    else:
        gaming_sorted = sorted(ok, key=lambda r: r.latency_ms if r.latency_ms is not None else 9999.0)
        best_g = gaming_sorted[0]
        up_txt = f" | Up: {best_g.upload_mbps:.1f}M" if best_g.upload_mbps is not None else ""
        drop_g = " | Anti-Drop" if best_g.sustained is True else ""
        loc_tag_g = f"_{best_g.ip_country}" if best_g.ip_country else ""
        colo_tag_g = f"_{best_g.colo}" if best_g.colo else ""
        link_g = make_vless_link(vless_config, best_g.ip, best_g.port, f"Gaming{loc_tag_g}{colo_tag_g}") if vless_config else ""
        recs.append(
            SmartRecommendation(
                category="Gaming",
                icon="🎮",
                result=best_g,
                reason=f"Ping: {best_g.latency_ms:.0f}ms{up_txt}{drop_g}",
                vless_link=link_g,
            )
        )

    # 2. Best for Instagram, YouTube & Video Streaming:
    # Primary criteria: Highest download speed (Mbps) + upload speed for stories
    has_speed = any(r.speed_mbps is not None and r.speed_mbps > 0 for r in ok)
    if has_speed:
        insta_candidates = [r for r in ok if r.speed_mbps is not None and r.speed_mbps > 0]
        insta_sorted = sorted(
            insta_candidates,
            key=lambda r: (
                -r.speed_mbps,
                -(r.upload_mbps or 0.0),
                r.packet_loss,
                r.latency_ms if r.latency_ms is not None else 9999.0,
            ),
        )
        best_i = insta_sorted[0]
        loc_tag_i = f"_{best_i.ip_country}" if best_i.ip_country else ""
        colo_tag_i = f"_{best_i.colo}" if best_i.colo else ""
        link_i = make_vless_link(vless_config, best_i.ip, best_i.port, f"Streaming{loc_tag_i}{colo_tag_i}") if vless_config else ""
        speed_txt = f"Down: {best_i.speed_mbps:.2f} Mbps"
        if best_i.upload_mbps is not None:
            speed_txt += f" | Up: {best_i.upload_mbps:.2f} Mbps"
        drop_i = " | Anti-Drop" if best_i.sustained is True else ""
        recs.append(
            SmartRecommendation(
                category="Streaming",
                icon="📱",
                result=best_i,
                reason=f"{speed_txt}{drop_i} | Ping: {best_i.latency_ms:.0f}ms",
                vless_link=link_i,
            )
        )
    else:
        alt = ok[1] if len(ok) > 1 else ok[0]
        loc_tag_alt = f"_{alt.ip_country}" if alt.ip_country else ""
        colo_tag_alt = f"_{alt.colo}" if alt.colo else ""
        link_i = make_vless_link(vless_config, alt.ip, alt.port, f"Streaming{loc_tag_alt}{colo_tag_alt}") if vless_config else ""
        recs.append(
            SmartRecommendation(
                category="Streaming",
                icon="📱",
                result=alt,
                reason=f"Ping: {alt.latency_ms:.0f}ms (Fast loading)",
                vless_link=link_i,
            )
        )

    # 3. Best for General Browsing / Telegram:
    if len(ok) >= 3:
        chosen_endpoints = {r.result.endpoint for r in recs}
        remaining = [r for r in ok if r.endpoint not in chosen_endpoints]
        best_gen = remaining[0] if remaining else ok[0]
        loc_tag_gen = f"_{best_gen.ip_country}" if best_gen.ip_country else ""
        colo_tag_gen = f"_{best_gen.colo}" if best_gen.colo else ""
        link_gen = make_vless_link(vless_config, best_gen.ip, best_gen.port, f"General{loc_tag_gen}{colo_tag_gen}") if vless_config else ""
        drop_badge = " | Anti-Drop" if best_gen.sustained is True else ""
        recs.append(
            SmartRecommendation(
                category="General Web",
                icon="🌐",
                result=best_gen,
                reason=f"Ping: {best_gen.latency_ms:.0f}ms | Port: {best_gen.port}{drop_badge}",
                vless_link=link_gen,
            )
        )

    # 4. Best Anti-Drop / DPI Endurance:
    has_longevity = any(r.sustained is not None for r in ok)
    if has_longevity:
        sustained_candidates = [r for r in ok if r.sustained is True]
        if sustained_candidates:
            best_anti = sorted(
                sustained_candidates,
                key=lambda r: (
                    -(r.speed_mbps or 0.0),
                    r.packet_loss,
                    r.latency_ms if r.latency_ms is not None else 9999.0,
                ),
            )[0]
            loc_tag_anti = f"_{best_anti.ip_country}" if best_anti.ip_country else ""
            colo_tag_anti = f"_{best_anti.colo}" if best_anti.colo else ""
            link_anti = make_vless_link(vless_config, best_anti.ip, best_anti.port, f"AntiDrop{loc_tag_anti}{colo_tag_anti}") if vless_config else ""
            spd = f" | {best_anti.speed_mbps:.1f} Mbps" if best_anti.speed_mbps else ""
            recs.append(
                SmartRecommendation(
                    category="Anti-Drop",
                    icon="🛡",
                    result=best_anti,
                    reason=f"Sustained (0% drop){spd} | Ping: {best_anti.latency_ms:.0f}ms",
                    vless_link=link_anti,
                )
            )

    return recs


class RecommendationEngine:
    """Intelligent recommendation engine for ranking clean IP scan results."""

    @staticmethod
    def recommend(results: List[ScanResult], vless_config: Optional[VlessConfig] = None) -> List[SmartRecommendation]:
        return get_smart_recommendations(results, vless_config)

    @staticmethod
    def filter_and_sort(
        results: List[ScanResult],
        max_latency_ms: float = 0,
        min_speed_mbps: float = 0,
        sort_mode: str = "latency",
    ) -> List[ScanResult]:
        filtered = apply_result_filters(results, max_latency_ms, min_speed_mbps)
        return sorted(filtered, key=output_sort_key(sort_mode))
