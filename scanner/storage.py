import csv
from datetime import datetime
from pathlib import Path
from typing import List, Optional, Tuple

from scanner.analytics import apply_result_filters, output_sort_key
from scanner.config import make_vless_link
from scanner.constants import format_cf_colo
from scanner.geoip import format_ip_location
from scanner.models import ScanResult, SmartRecommendation, VlessConfig


def save_results(
    results: List[ScanResult],
    output_dir: Path,
    filename_prefix: str = "clean_ips",
    max_latency_ms: float = 0,
    min_speed_mbps: float = 0,
    include_speed_errors: bool = False,
    vless_config: Optional[VlessConfig] = None,
) -> Tuple[Path, Path]:
    """Save results with independent ordering per stage and support per-port separation.

    - clean_ips.*: sorted by latency only.
    - clean_ips_rechecked.*: sorted by lowest loss, latency, and jitter.
    - clean_ips_speed_tested.*: sorted by download and upload speed.
    - clean_ips_vless.txt: ready-to-use VLESS links.
    - by_port/: per-port separated TXT and VLESS files.
    """
    output_dir.mkdir(parents=True, exist_ok=True)
    ok = apply_result_filters(results, max_latency_ms=max_latency_ms, min_speed_mbps=min_speed_mbps)
    ok = sorted(ok, key=output_sort_key(filename_prefix))
    txt_path = output_dir / f"{filename_prefix}.txt"
    csv_path = output_dir / f"{filename_prefix}.csv"
    now = datetime.now().isoformat(timespec="seconds")

    is_full = "full" in filename_prefix or any(r.jitter_ms is not None and r.speed_mbps is not None for r in ok)
    is_speed = "speed" in filename_prefix and not is_full
    is_recheck = "rechecked" in filename_prefix and not is_full
    is_longevity = "longevity" in filename_prefix and not is_full

    lines: List[str] = []
    if not ok:
        lines.append("No results matched the selected filters.")
        if max_latency_ms > 0:
            lines.append(f"Max latency filter: {max_latency_ms} ms")
        if min_speed_mbps > 0:
            lines.append(f"Min speed filter: {min_speed_mbps} Mbps")
    else:
        for r in ok:
            latency = f"{r.latency_ms:.1f} ms" if r.latency_ms is not None else "-"
            down = f"{r.speed_mbps:.2f} Mbps" if r.speed_mbps is not None else "-"
            up = f"{r.upload_mbps:.2f} Mbps" if r.upload_mbps is not None else "-"
            jitter = f"{r.jitter_ms:.1f} ms" if r.jitter_ms is not None else "-"
            loss = f"{r.packet_loss:.0f}%"
            anti_drop = ""
            if r.sustained is not None:
                anti_drop = " | anti_drop: " + ("SUSTAINED" if r.sustained else f"DROPPED({r.longevity_loss:.0f}%)")
            loc_str = f" | loc: {format_ip_location(r.ip_country, r.ip_city)}" if r.ip_country else ""
            colo_str = f" | colo: {format_cf_colo(r.colo)}" if r.colo else ""
            extra_errs = []
            if include_speed_errors and r.speed_error:
                extra_errs.append(f"down_err: {r.speed_error}")
            if include_speed_errors and r.upload_error:
                extra_errs.append(f"up_err: {r.upload_error}")
            extra = (" | " + ", ".join(extra_errs)) if extra_errs else ""
            if is_full:
                lines.append(
                    f"{r.ip}:{r.port} | down: {down} | up: {up} | latency: {latency} | jitter: {jitter} | loss: {loss} | pass: {r.recheck_passed}/{r.recheck_total}{anti_drop}{loc_str}{colo_str} | HTTP {r.status_code}{extra}"
                )
            elif is_speed:
                lines.append(
                    f"{r.ip}:{r.port} | down: {down} | up: {up} | downloaded: {r.speed_bytes} bytes | uploaded: {r.upload_bytes} bytes{loc_str}{colo_str}{extra}"
                )
            elif is_longevity:
                drop_status = "SUSTAINED" if r.sustained else f"DROPPED({r.longevity_loss:.0f}%)"
                lines.append(
                    f"{r.ip}:{r.port} | anti_drop: {drop_status} | latency: {latency}{loc_str}{colo_str} | HTTP {r.status_code}"
                )
            elif is_recheck:
                lines.append(
                    f"{r.ip}:{r.port} | latency_avg: {latency} | jitter: {jitter} | loss: {loss} | pass: {r.recheck_passed}/{r.recheck_total}{anti_drop}{loc_str}{colo_str} | HTTP {r.status_code}"
                )
            else:
                lines.append(f"{r.ip}:{r.port} | latency: {latency}{loc_str}{colo_str} | HTTP {r.status_code}")
    txt_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    with csv_path.open("w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        if is_full:
            w.writerow([
                "ip",
                "port",
                "ip_country",
                "ip_city",
                "ip_org",
                "ip_location",
                "download_mbps",
                "upload_mbps",
                "avg_latency_ms",
                "jitter_ms",
                "packet_loss_pct",
                "anti_drop_sustained",
                "anti_drop_loss_pct",
                "colo_code",
                "colo_location",
                "speed_bytes",
                "upload_bytes",
                "recheck_passed",
                "recheck_total",
                "status_code",
                "tested_at",
            ])
            for r in ok:
                w.writerow([
                    r.ip,
                    r.port,
                    r.ip_country or "",
                    r.ip_city or "",
                    r.ip_org or "",
                    format_ip_location(r.ip_country, r.ip_city) if r.ip_country else "",
                    f"{r.speed_mbps:.2f}" if r.speed_mbps is not None else "",
                    f"{r.upload_mbps:.2f}" if r.upload_mbps is not None else "",
                    f"{r.latency_ms:.1f}" if r.latency_ms is not None else "",
                    f"{r.jitter_ms:.1f}" if r.jitter_ms is not None else "",
                    f"{r.packet_loss:.0f}",
                    str(r.sustained) if r.sustained is not None else "",
                    f"{r.longevity_loss:.0f}" if r.longevity_loss is not None else "",
                    r.colo or "",
                    format_cf_colo(r.colo) if r.colo else "",
                    r.speed_bytes or "",
                    r.upload_bytes or "",
                    r.recheck_passed or "",
                    r.recheck_total or "",
                    r.status_code or "",
                    now,
                ])
        elif is_longevity:
            w.writerow([
                "ip",
                "port",
                "ip_country",
                "ip_city",
                "ip_org",
                "ip_location",
                "anti_drop_sustained",
                "anti_drop_loss_pct",
                "avg_latency_ms",
                "colo_code",
                "colo_location",
                "status_code",
                "tested_at",
            ])
            for r in ok:
                w.writerow([
                    r.ip,
                    r.port,
                    r.ip_country or "",
                    r.ip_city or "",
                    r.ip_org or "",
                    format_ip_location(r.ip_country, r.ip_city) if r.ip_country else "",
                    str(r.sustained) if r.sustained is not None else "",
                    f"{r.longevity_loss:.0f}" if r.longevity_loss is not None else "",
                    f"{r.latency_ms:.1f}" if r.latency_ms is not None else "",
                    r.colo or "",
                    format_cf_colo(r.colo) if r.colo else "",
                    r.status_code or "",
                    now,
                ])
        elif is_speed:
            w.writerow([
                "ip",
                "port",
                "ip_country",
                "ip_city",
                "ip_org",
                "ip_location",
                "download_mbps",
                "upload_mbps",
                "colo_code",
                "colo_location",
                "speed_bytes",
                "upload_bytes",
                "speed_error",
                "upload_error",
                "tested_at",
            ])
            for r in ok:
                w.writerow([
                    r.ip,
                    r.port,
                    r.ip_country or "",
                    r.ip_city or "",
                    r.ip_org or "",
                    format_ip_location(r.ip_country, r.ip_city) if r.ip_country else "",
                    f"{r.speed_mbps:.2f}" if r.speed_mbps is not None else "",
                    f"{r.upload_mbps:.2f}" if r.upload_mbps is not None else "",
                    r.colo or "",
                    format_cf_colo(r.colo) if r.colo else "",
                    r.speed_bytes or "",
                    r.upload_bytes or "",
                    r.speed_error or "",
                    r.upload_error or "",
                    now,
                ])
        elif is_recheck:
            w.writerow([
                "ip",
                "port",
                "ip_country",
                "ip_city",
                "ip_org",
                "ip_location",
                "avg_latency_ms",
                "jitter_ms",
                "packet_loss_pct",
                "anti_drop_sustained",
                "anti_drop_loss_pct",
                "colo_code",
                "colo_location",
                "recheck_passed",
                "recheck_total",
                "status_code",
                "tested_at",
            ])
            for r in ok:
                w.writerow([
                    r.ip,
                    r.port,
                    r.ip_country or "",
                    r.ip_city or "",
                    r.ip_org or "",
                    format_ip_location(r.ip_country, r.ip_city) if r.ip_country else "",
                    f"{r.latency_ms:.1f}" if r.latency_ms is not None else "",
                    f"{r.jitter_ms:.1f}" if r.jitter_ms is not None else "",
                    f"{r.packet_loss:.0f}",
                    str(r.sustained) if r.sustained is not None else "",
                    f"{r.longevity_loss:.0f}" if r.longevity_loss is not None else "",
                    r.colo or "",
                    format_cf_colo(r.colo) if r.colo else "",
                    r.recheck_passed or "",
                    r.recheck_total or "",
                    r.status_code,
                    now,
                ])
        else:
            w.writerow([
                "ip",
                "port",
                "ip_country",
                "ip_city",
                "ip_org",
                "ip_location",
                "latency_ms",
                "colo_code",
                "colo_location",
                "status_code",
                "tested_at",
            ])
            for r in ok:
                w.writerow([
                    r.ip,
                    r.port,
                    r.ip_country or "",
                    r.ip_city or "",
                    r.ip_org or "",
                    format_ip_location(r.ip_country, r.ip_city) if r.ip_country else "",
                    f"{r.latency_ms:.1f}" if r.latency_ms is not None else "",
                    r.colo or "",
                    format_cf_colo(r.colo) if r.colo else "",
                    r.status_code,
                    now,
                ])

    # Save ready-to-import VLESS links
    if vless_config and ok:
        vless_path = output_dir / f"{filename_prefix}_vless.txt"
        vless_lines = []
        for r in ok:
            anti_tag = "_AntiDrop" if r.sustained is True else ""
            colo_tag = f"{r.colo}_" if r.colo else ""
            if (is_speed or is_full) and r.speed_mbps is not None:
                if r.upload_mbps is not None:
                    metric = f"{colo_tag}{r.speed_mbps:.1f}D_{r.upload_mbps:.1f}U{anti_tag}"
                else:
                    metric = f"{colo_tag}{r.speed_mbps:.2f}Mbps{anti_tag}"
            elif is_longevity and r.sustained is not None:
                metric = f"{colo_tag}AntiDrop" if r.sustained else f"{colo_tag}Drop{r.longevity_loss:.0f}pct"
            elif r.latency_ms:
                metric = f"{colo_tag}{r.latency_ms:.0f}ms{anti_tag}"
            else:
                metric = colo_tag.rstrip("_")
            vless_lines.append(make_vless_link(vless_config, r.ip, r.port, metric))
        vless_path.write_text("\n".join(vless_lines) + "\n", encoding="utf-8")

    # Save per-port separated output files
    ports_found = sorted(set(r.port for r in ok))
    if len(ports_found) > 1:
        by_port_dir = output_dir / "by_port"
        by_port_dir.mkdir(parents=True, exist_ok=True)
        for p in ports_found:
            port_results = [r for r in ok if r.port == p]
            port_txt = by_port_dir / f"{filename_prefix}_port_{p}.txt"
            port_lines = []
            for r in port_results:
                latency = f"{r.latency_ms:.1f} ms" if r.latency_ms is not None else "-"
                down = f"{r.speed_mbps:.2f} Mbps" if r.speed_mbps is not None else "-"
                up = f"{r.upload_mbps:.2f} Mbps" if r.upload_mbps is not None else "-"
                jitter = f"{r.jitter_ms:.1f} ms" if r.jitter_ms is not None else "-"
                loss = f"{r.packet_loss:.0f}%"
                port_colo_str = f" | colo: {format_cf_colo(r.colo)}" if r.colo else ""
                if is_full:
                    port_lines.append(
                        f"{r.ip} | down: {down} | up: {up} | latency: {latency} | jitter: {jitter} | loss: {loss} | pass: {r.recheck_passed}/{r.recheck_total}{port_colo_str} | HTTP {r.status_code}"
                    )
                elif is_speed:
                    port_lines.append(
                        f"{r.ip} | down: {down} | up: {up} | downloaded: {r.speed_bytes} bytes | uploaded: {r.upload_bytes} bytes{port_colo_str}"
                    )
                elif is_recheck:
                    port_lines.append(
                        f"{r.ip} | latency_avg: {latency} | jitter: {jitter} | loss: {loss} | pass: {r.recheck_passed}/{r.recheck_total}{port_colo_str} | HTTP {r.status_code}"
                    )
                else:
                    port_lines.append(f"{r.ip} | latency: {latency}{port_colo_str} | HTTP {r.status_code}")
            port_txt.write_text("\n".join(port_lines) + "\n", encoding="utf-8")

            if vless_config:
                port_vless = by_port_dir / f"{filename_prefix}_vless_port_{p}.txt"
                port_vless_lines = []
                for r in port_results:
                    port_colo_tag = f"{r.colo}_" if r.colo else ""
                    if (is_speed or is_full) and r.speed_mbps is not None:
                        if r.upload_mbps is not None:
                            metric = f"{port_colo_tag}{r.speed_mbps:.1f}D_{r.upload_mbps:.1f}U"
                        else:
                            metric = f"{port_colo_tag}{r.speed_mbps:.2f}Mbps"
                    elif r.latency_ms:
                        metric = f"{port_colo_tag}{r.latency_ms:.0f}ms"
                    else:
                        metric = port_colo_tag.rstrip("_")
                    port_vless_lines.append(make_vless_link(vless_config, r.ip, r.port, metric))
                port_vless.write_text("\n".join(port_vless_lines) + "\n", encoding="utf-8")

    return txt_path, csv_path


def save_recommended_configs(
    recs: List[SmartRecommendation],
    output_dir: Path,
) -> Optional[Path]:
    """Save smart recommendations to recommended_configs.txt."""
    if not recs:
        return None
    try:
        output_dir.mkdir(parents=True, exist_ok=True)
        rec_path = output_dir / "recommended_configs.txt"
        lines = [
            f"=== Cloudflare Clean-IP Smart Recommendations - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} ===",
            "Recommended endpoints ranked by stability, jitter, and download speed:\n",
        ]
        for rec in recs:
            lines.append(f"{rec.icon} {rec.category}")
            lines.append(f"   Endpoint: {rec.result.endpoint}")
            if rec.result.colo:
                lines.append(f"   Edge PoP: {format_cf_colo(rec.result.colo)}")
            lines.append(f"   Metrics:  {rec.reason}")
            if rec.vless_link:
                lines.append(f"   VLESS Link:\n   {rec.vless_link}\n")
            else:
                lines.append("")
        rec_path.write_text("\n".join(lines), encoding="utf-8")
        return rec_path
    except Exception:
        return None


class ResultExporter:
    """Class responsible for formatting and persisting scan results to disk."""

    def __init__(self, output_dir: Path):
        self.output_dir = output_dir

    def export(
        self,
        results: List[ScanResult],
        prefix: str = "clean_ips",
        max_latency_ms: float = 0,
        min_speed_mbps: float = 0,
        include_speed_errors: bool = False,
        vless_config: Optional[VlessConfig] = None,
    ) -> Tuple[Path, Path]:
        return save_results(
            results,
            self.output_dir,
            filename_prefix=prefix,
            max_latency_ms=max_latency_ms,
            min_speed_mbps=min_speed_mbps,
            include_speed_errors=include_speed_errors,
            vless_config=vless_config,
        )

    def export_recommendations(self, recs: List[SmartRecommendation]) -> Optional[Path]:
        return save_recommended_configs(recs, self.output_dir)
