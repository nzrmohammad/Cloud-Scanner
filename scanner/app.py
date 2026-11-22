import argparse
import sys
from pathlib import Path
from typing import List, Optional, Set, Tuple

from scanner.analytics import (
    apply_result_filters,
    filter_diverse_endpoints,
    get_smart_recommendations,
    recheck_sort_key,
)
from scanner.config import ConfigManager, load_saved_vless_config, parse_vless, save_vless_config
from scanner.constants import (
    APP_HEADER,
    DEFAULT_CF_TLS_PORTS,
    DEFAULT_CONCURRENCY,
    DEFAULT_LONGEVITY_DURATION,
    DEFAULT_SPEED_URL,
    DEFAULT_TIMEOUT,
    DEFAULT_TRIES,
    DEFAULT_URL,
    MAX_DEFAULT_HOSTS,
    app_dir,
)
from scanner.engine import (
    build_target_pairs,
    enrich_results_with_colo,
    run_longevity_stage,
    run_scan,
    run_speed_stage,
    run_stability_stage,
)
from scanner.geoip import set_geoip_cache_dir
from scanner.logger import get_logger, setup_logging
from scanner.models import (
    NavigationBack,
    NavigationExit,
    ScanInterrupted,
    ScanResult,
    VlessConfig,
)
from scanner.storage import (
    save_recommended_configs,
    save_results,
    save_scan_summary_report,
)
from scanner.targets import expand_targets, print_isp_catalog_cli, resolve_isp_files
from scanner.ui import (
    check_and_prompt_xray_update,
    cprint,
    handle_post_scan_testing_tui,
    pause,
    post_scan_actions_menu,
    progress_reporter,
    prompt_continue_nav,
    prompt_str,
    render_stage,
    render_welcome_config_screen,
    select_targets_tui,
    show_final_results,
    tcp_prefilter_reporter,
    tui_screen,
)
from scanner.xray import find_xray

try:
    import requests
except ImportError:
    requests = None  # type: ignore[assignment]

logger = get_logger("app")


def build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description=f"{APP_HEADER} - Cloudflare Clean-IP scanner for VLESS + Xray")
    p.add_argument("-c", "--config", help="VLESS URI or text file containing a VLESS URI")
    p.add_argument("-t", "--targets", nargs="*", help="IP, CIDR, range, or file path")
    p.add_argument("--ports", help="Comma-separated ports to scan (e.g. 443,8443,2053,2083,2087,2096). Default: config port")
    p.add_argument("--all-cf-tls-ports", action="store_true", help="Scan all 6 Cloudflare TLS ports: 443, 8443, 2053, 2083, 2087, 2096")
    p.add_argument("--skip-tcp-prefilter", action="store_true", help="Disable the fast TCP pre-filter")
    p.add_argument("--xray", help="Path to xray executable. Default: xray.exe/xray beside script")
    p.add_argument("-o", "--output-dir", default=str(app_dir() / "results"), help="Output folder")
    p.add_argument("--concurrency", type=int, default=DEFAULT_CONCURRENCY)
    p.add_argument("--tries", type=int, default=DEFAULT_TRIES)
    p.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT)
    p.add_argument("--max-hosts", type=int, default=MAX_DEFAULT_HOSTS, help="Maximum targets to load. 0/default = unlimited; positive numbers cap and sample large ISP ranges.")
    p.add_argument("--url", default=DEFAULT_URL)
    p.add_argument("--loglevel", choices=["debug", "info", "warning", "error", "none"], default="warning")
    p.add_argument("--recheck", action="store_true", help="After the first scan, re-test working IPs and save updated results")
    p.add_argument("--recheck-samples", type=int, default=8, help="Latency tests per working IP during --recheck")
    p.add_argument("--recheck-workers", type=int, default=None, help="Workers for --recheck. Default: same as --concurrency")
    p.add_argument("--top-targets", type=int, default=None, help="Maximum endpoints to benchmark in post-scan stages (default: 30, 0=all)")
    p.add_argument("--longevity-test", action="store_true", help="Run Anti-Drop endurance test against DPI throttling for working endpoints")
    p.add_argument("--longevity-duration", type=int, default=DEFAULT_LONGEVITY_DURATION, help=f"Duration in seconds for Anti-Drop test (default: {DEFAULT_LONGEVITY_DURATION})")
    p.add_argument("--speed-test", action="store_true", help="Run a download speed test for working IPs after scanning/recheck")
    p.add_argument("--speed-workers", type=int, default=6, help="Workers for speed testing")
    p.add_argument("--speed-mb", type=int, default=3, help="Download size per IP in MB")
    p.add_argument("--speed-upload-mb", type=int, default=1, help="Upload size per IP in MB (default: 1, set 0 to disable)")
    p.add_argument("--skip-upload-test", action="store_true", help="Skip upload speed testing during speed test")
    p.add_argument("--speed-duration", type=int, default=5, help="Duration limit for each speed test in seconds")
    p.add_argument("--speed-timeout", type=int, default=20, help="Timeout for each speed test")
    p.add_argument("--speed-url", default=DEFAULT_SPEED_URL, help="Speed test URL. Use {bytes} placeholder for download size")
    p.add_argument("--min-speed", type=float, default=0, help="Filter final output by minimum Mbps")
    p.add_argument("--max-latency", type=float, default=0, help="Filter final output by maximum latency in ms")
    p.add_argument("--list-isps", action="store_true", help="List packaged ISP range files and exit")
    p.add_argument("--isp-category", choices=["iran", "international", "ipv6"], help="Use packaged ISP ranges from this category")
    p.add_argument("--isp", nargs="*", help="ISP names/stems to use from --isp-category, or all")
    p.add_argument("--sample-large-ranges", action="store_true", help="Evenly sample ranges when selected targets exceed a positive --max-hosts value")
    return p


def get_explicit_cli_keys(parser: argparse.ArgumentParser, argv: Optional[List[str]]) -> Set[str]:
    """Identify which CLI arguments were explicitly provided on the command line (resolves abbreviations)."""
    import copy

    shadow_parser = copy.deepcopy(parser)
    for action in shadow_parser._actions:
        action.default = argparse.SUPPRESS
    try:
        ns = shadow_parser.parse_args(argv if argv is not None else sys.argv[1:])
        return set(vars(ns).keys())
    except Exception:
        return set()


def _run_scan_with_tracking(
    v: VlessConfig,
    targets: List[str],
    ports: List[int],
    xray: Path,
    concurrency: int,
    timeout: int,
    tries: int,
    url: str,
    loglevel: str,
    use_tcp_prefilter: bool,
    output_dir: Path,
    total_endpoints: int,
) -> Tuple[List[ScanResult], int]:
    """Run initial scan with decoupled stage reporters while tracking TCP-alive count."""
    tcp_alive_count = total_endpoints if (not use_tcp_prefilter or total_endpoints <= 1) else 0

    def _track_tcp_alive(_done: int, _total_items: int, alive_count: int) -> None:
        nonlocal tcp_alive_count
        tcp_alive_count = alive_count

    results = run_scan(
        v,
        targets,
        ports,
        xray,
        concurrency,
        timeout,
        tries,
        url,
        loglevel,
        use_tcp_prefilter=use_tcp_prefilter,
        output_dir=output_dir,
        on_stage=render_stage,
        on_message=cprint,
        make_reporter=progress_reporter,
        on_prefilter_progress=_track_tcp_alive,
        make_tcp_reporter=tcp_prefilter_reporter,
    )
    return results, tcp_alive_count


class CloudScannerApp:
    """Main application coordinator for Cloudflare Clean-IP Scanner."""

    def __init__(self, argv: Optional[List[str]] = None):
        self.argv = argv if argv is not None else sys.argv[1:]
        self.parser = build_arg_parser()
        self.config_manager = ConfigManager()
        self.last_results: List[ScanResult] = []
        self.last_txt: Optional[Path] = None
        self.last_csv: Optional[Path] = None
        self.last_prefix: str = "clean_ips"
        self.last_vless: Optional[VlessConfig] = None
        self.last_output_dir: Path = app_dir() / "results"

    def interactive(self) -> int:
        """Run interactive TUI mode in the normal scrollable terminal buffer."""
        xray = find_xray()

        with tui_screen():
            xray = check_and_prompt_xray_update(xray)
            if not xray:
                cprint("xray.exe/xray not found. Place it beside the script or run scripts/download_core.py.", "red")
                pause("Press Enter to exit...")
                return 1
            ret = self._run_interactive_tui(xray)

        if self.last_results:
            cprint("\n[bold green]Cloud Scanner finished.[/bold green] Summary of top clean endpoints:")
            show_final_results(
                self.last_results,
                self.last_txt or (self.last_output_dir / "clean_ips.txt"),
                self.last_csv or (self.last_output_dir / "clean_ips.csv"),
                filename_prefix=self.last_prefix or "clean_ips",
                vless_config=self.last_vless,
                save_recommendations=False,
            )
        else:
            clean_file = self.last_output_dir / "clean_ips.txt"
            if clean_file.exists():
                cprint(f"\n[bold green]Cloud Scanner finished.[/bold green] Output saved to: [cyan]{clean_file}[/cyan]")
        return ret

    def _run_interactive_tui(self, xray: Path) -> int:
        while True:
            settings = self.config_manager.load_settings()
            v: Optional[VlessConfig] = None
            if settings.vless_raw:
                try:
                    v = parse_vless(settings.vless_raw)
                except Exception as exc:
                    logger.warning("Saved configuration in config.txt was invalid: %s", exc)
                    cprint("\n[yellow]Saved configuration was invalid, please enter a new one.[/yellow]")
                    v = None

            if v is None:
                try:
                    from scanner.ui import read_vless_tui
                    v = read_vless_tui(xray)
                    settings = self.config_manager.load_settings()
                except NavigationExit:
                    render_stage("Exited", "No scan was started.", "yellow")
                    return 0
            else:
                # Startup check & welcome screen
                error = ""
                while True:
                    if not render_welcome_config_screen(xray, error=error, saved_config=settings.vless_raw, settings=settings):
                        cprint("\nMissing required runtime files/dependencies. Fix them and run again.", "yellow")
                        pause("Press Enter to exit...")
                        return 1

                    raw = prompt_str("Press Enter to start (or paste new VLESS)", default="").strip()
                    if raw.lower() in {"q", "quit", "exit"}:
                        render_stage("Exited", "No scan was started.", "yellow")
                        return 0
                    if not raw:
                        break
                    if raw.startswith("vless://"):
                        try:
                            v = parse_vless(raw)
                            save_vless_config(raw)
                            settings = self.config_manager.load_settings()
                            break
                        except Exception as e:
                            error = f"Invalid configuration: {e}"
                            continue
                    else:
                        try:
                            p = Path(raw)
                            if p.exists() and p.is_file():
                                content = p.read_text(encoding="utf-8").strip()
                                v = parse_vless(content)
                                save_vless_config(content)
                                settings = self.config_manager.load_settings()
                                break
                        except Exception as e:
                            error = f"Could not read config file: {e}"
                            continue
                        error = "Invalid VLESS URI. Press Enter to use saved config, or type q to exit."

            while True:
                try:
                    targets, target_label = select_targets_tui(v=v, settings=settings)
                except NavigationBack:
                    break
                except NavigationExit:
                    render_stage("Exited", "No scan was started.", "yellow")
                    return 0

                ports = settings.ports if settings.ports else [v.port]
                output_dir = settings.output_dir
                output_dir.mkdir(parents=True, exist_ok=True)
                self.last_output_dir = output_dir
                setup_logging(output_dir)
                set_geoip_cache_dir(output_dir)

                while True:
                    self.last_results = []
                    self.last_txt = None
                    self.last_csv = None
                    self.last_prefix = "clean_ips"
                    total_endpoints = len(build_target_pairs(targets, ports))
                    est_time = max(3, int(total_endpoints / max(1, settings.workers * 2)))

                    render_stage(
                        "Scan Plan & Dry-Run",
                        f"Source: {target_label} | IPs: {len(targets)} | Ports: {len(ports)} | Total Endpoints: {total_endpoints} | Workers: {settings.workers}\n"
                        f"Estimated duration: ~{est_time}s (with TCP prefilter).",
                        "cyan",
                    )
                    try:
                        prompt_continue_nav("Press Enter to begin scan", allow_back=True)
                    except NavigationBack:
                        break

                    try:
                        results, tcp_alive_count = _run_scan_with_tracking(
                            v=v,
                            targets=targets,
                            ports=ports,
                            xray=xray,
                            concurrency=settings.workers,
                            timeout=settings.timeout,
                            tries=1,
                            url=settings.test_url,
                            loglevel="warning",
                            use_tcp_prefilter=settings.tcp_prefilter,
                            output_dir=output_dir,
                            total_endpoints=total_endpoints,
                        )
                        txt, csvp = save_results(results, output_dir, "clean_ips", vless_config=v)
                        render_stage("Scan Results", "Latency scan finished. Results are saved below.", "green")
                    except ScanInterrupted as interrupted:
                        results = interrupted.results
                        txt, csvp = save_results(results, output_dir, "clean_ips_interrupted", vless_config=v)
                        render_stage("Scan Interrupted", "Ctrl+C detected. Partial results up to this point were saved.", "yellow")
                        show_final_results(results, txt, csvp, vless_config=v)
                        pause("\nPress Enter to exit...")
                        return 130

                    show_final_results(results, txt, csvp, vless_config=v)

                    working_results = [r for r in results if r.ok]
                    final_results = working_results
                    prefix = "clean_ips"
                    final_txt, final_csv = txt, csvp

                    if working_results:
                        cprint(f"\n[bold green]Success![/bold green] Found [bold cyan]{len(working_results)}[/bold cyan] responsive clean IP(s).")
                        prompt_continue_nav("Press Enter to continue to Quality & Speed Testing", allow_back=False)
                        final_results, final_txt, final_csv, prefix = handle_post_scan_testing_tui(
                            v,
                            working_results,
                            xray,
                            settings.workers,
                            settings.timeout,
                            settings.test_url,
                            output_dir,
                            settings=settings,
                        )
                        render_stage("Final Results", "Testing complete. Summary of best results below.", "green")
                        show_final_results(final_results, final_txt, final_csv, filename_prefix=prefix, vless_config=v)

                    recs = get_smart_recommendations(final_results, v) if final_results else []
                    save_scan_summary_report(
                        final_results,
                        output_dir,
                        vless_config=v,
                        settings=settings,
                        total_targets_count=total_endpoints,
                        tcp_alive_count=tcp_alive_count,
                        recommendations=recs,
                        initial_ok_count=len(working_results),
                    )

                    self.last_results = final_results
                    self.last_txt = final_txt
                    self.last_csv = final_csv
                    self.last_prefix = prefix
                    self.last_vless = v

                    if len(final_results) > 50:
                        view_choice = prompt_str(
                            f"\n> Press Enter for action options, or type 'v' to view all {len(final_results)} results",
                            default="",
                        ).lower()
                        if view_choice in {"v", "view", "all"}:
                            render_stage(
                                "All Working Results",
                                f"Showing all {len(final_results)} endpoints. Use your terminal scrollbar / mouse wheel to scroll.",
                                "green",
                            )
                            show_final_results(
                                final_results,
                                final_txt,
                                final_csv,
                                filename_prefix=prefix,
                                vless_config=v,
                                display_limit=None,
                            )
                            pause("\n> Press Enter to view action options (Scan Again / Retest / Exit)...")
                    else:
                        pause("\n> Press Enter to view action options (Scan Again / Retest / Exit)...")
                    action = post_scan_actions_menu(v, final_results, prefix)
                    if action == "retest_same":
                        continue
                    elif action == "rescan_all":
                        self.last_results = []
                        self.last_txt = None
                        self.last_csv = None
                        self.last_prefix = "clean_ips"
                        break
                    else:
                        render_stage("Scanner Finished", "Thank you for using Cloud Scanner!", "green")
                        return 0

    def run_cli(self, args: argparse.Namespace) -> int:
        """Run non-interactive CLI mode."""
        if args.list_isps:
            print_isp_catalog_cli(cprint)
            return 0

        is_config_file = not args.config or not args.config.startswith("vless://")
        cfg_mgr = ConfigManager(args.config) if (args.config and not args.config.startswith("vless://")) else self.config_manager
        settings = cfg_mgr.load_settings()

        using_isp_cli = bool(args.isp_category)
        cfg_val = args.config if (args.config and args.config.startswith("vless://")) else (settings.vless_raw or load_saved_vless_config())

        if not cfg_val or (not args.targets and not using_isp_cli):
            self.parser.error(
                "CLI mode requires -c/--config (or saved config.txt) and either -t/--targets or --isp-category. "
                "Run without arguments for interactive mode."
            )

        xray = find_xray(args.xray)
        if not xray:
            cprint("xray.exe/xray not found. Place it beside the script or pass --xray.", "red")
            return 2
        if requests is None:
            cprint("Missing dependency: pip install requests[socks] rich", "red")
            return 2

        explicit_keys = get_explicit_cli_keys(self.parser, self.argv)

        out_dir = Path(args.output_dir) if "output_dir" in explicit_keys else settings.output_dir
        setup_logging(out_dir)
        set_geoip_cache_dir(out_dir)

        try:
            v = parse_vless(cfg_val)
            if not load_saved_vless_config():
                save_vless_config(v.raw)
            if args.all_cf_tls_ports:
                ports = list(DEFAULT_CF_TLS_PORTS)
            elif args.ports:
                if args.ports.strip().lower() == "config":
                    if is_config_file and settings.ports:
                        ports = [p for p in settings.ports if 1 <= p <= 65535]
                    else:
                        ports = [v.port]
                else:
                    ports = [int(p.strip()) for p in args.ports.split(",") if p.strip()]
                    for p in ports:
                        if not (1 <= p <= 65535):
                            raise ValueError(f"Port must be between 1 and 65535: {p}")
            elif is_config_file and settings.ports:
                ports = [p for p in settings.ports if 1 <= p <= 65535]
                if not ports:
                    ports = [v.port]
            else:
                ports = [v.port]

            # Recheck / longevity / speed flags
            recheck_enabled = bool(args.recheck)
            longevity_enabled = bool(args.longevity_test)
            speed_enabled = bool(args.speed_test)
            if args.min_speed > 0:
                speed_enabled = True

            has_explicit_post = bool(
                "recheck" in explicit_keys
                or "longevity_test" in explicit_keys
                or "speed_test" in explicit_keys
                or "min_speed" in explicit_keys
            )
            if is_config_file and not has_explicit_post:
                mode = (settings.post_scan_mode or "none").lower()
                if mode == "full":
                    recheck_enabled = True
                    longevity_enabled = True
                    speed_enabled = True
                elif mode == "stability":
                    recheck_enabled = True
                elif mode == "longevity":
                    recheck_enabled = True
                    longevity_enabled = True
                elif mode == "speed":
                    speed_enabled = True

                if mode == "none" and settings.longevity_test:
                    longevity_enabled = True

            concurrency: int = (
                max(1, int(args.concurrency))
                if "concurrency" in explicit_keys
                else (max(1, int(settings.workers)) if settings.workers else DEFAULT_CONCURRENCY)
            )
            timeout: int = (
                max(1, int(args.timeout))
                if "timeout" in explicit_keys
                else (max(1, int(settings.timeout)) if settings.timeout else DEFAULT_TIMEOUT)
            )
            max_hosts: int = (
                max(0, int(args.max_hosts))
                if "max_hosts" in explicit_keys
                else (max(0, int(settings.max_targets)) if settings.max_targets != MAX_DEFAULT_HOSTS else MAX_DEFAULT_HOSTS)
            )
            speed_workers: int = (
                max(1, int(args.speed_workers))
                if "speed_workers" in explicit_keys
                else (max(1, int(settings.speed_workers)) if settings.speed_workers else 6)
            )
            download_mb: int = (
                int(args.speed_mb)
                if "speed_mb" in explicit_keys
                else (int(settings.download_mb) if settings.download_mb is not None else 3)
            )
            upload_mb: int = (
                0 if args.skip_upload_test else (
                    int(args.speed_upload_mb)
                    if "speed_upload_mb" in explicit_keys
                    else (int(settings.upload_mb) if settings.upload_mb is not None else 1)
                )
            )
            longevity_duration: int = (
                max(1, int(args.longevity_duration))
                if "longevity_duration" in explicit_keys
                else (max(1, int(settings.longevity_duration)) if settings.longevity_duration is not None else DEFAULT_LONGEVITY_DURATION)
            )
            speed_duration: int = (
                max(1, int(args.speed_duration))
                if "speed_duration" in explicit_keys
                else (max(1, int(settings.speed_duration)) if settings.speed_duration is not None else 5)
            )
            recheck_samples: int = (
                max(1, int(args.recheck_samples))
                if "recheck_samples" in explicit_keys
                else (max(1, int(settings.ping_samples)) if settings.ping_samples else 8)
            )
            test_url: str = (
                str(args.url)
                if "url" in explicit_keys
                else (str(settings.test_url) if settings.test_url else DEFAULT_URL)
            )
            use_tcp_prefilter: bool = (
                False
                if "skip_tcp_prefilter" in explicit_keys and args.skip_tcp_prefilter
                else (bool(settings.tcp_prefilter) if is_config_file else not args.skip_tcp_prefilter)
            )
            recheck_workers: int = args.recheck_workers if args.recheck_workers is not None else concurrency

            if using_isp_cli:
                isp_files = resolve_isp_files(args.isp_category, args.isp)
                if not isp_files:
                    raise ValueError(f"No ISP files found for category: {args.isp_category}")
                targets = expand_targets([str(p) for p in isp_files], max_hosts, sample_if_too_many=True)
                cprint(f"Loaded {len(targets)} target(s) from {args.isp_category} ISP list.", "green")
            else:
                targets = expand_targets(args.targets, max_hosts, sample_if_too_many=args.sample_large_ranges)
        except Exception as e:
            cprint(str(e), "red")
            return 2

        total_prefilter = len(build_target_pairs(targets, ports))
        try:
            results, tcp_alive_count = _run_scan_with_tracking(
                v=v,
                targets=targets,
                ports=ports,
                xray=xray,
                concurrency=concurrency,
                timeout=timeout,
                tries=args.tries,
                url=test_url,
                loglevel=args.loglevel,
                use_tcp_prefilter=use_tcp_prefilter,
                output_dir=out_dir,
                total_endpoints=total_prefilter,
            )
            has_post_scan = bool(recheck_enabled or longevity_enabled or speed_enabled)
            final_results = [r for r in results if r.ok]
            initial_ok_count = len(final_results)
            final_prefix = "clean_ips"
            if not has_post_scan and final_results:
                enrich_results_with_colo(v, final_results, xray, workers=min(concurrency, 20), timeout=timeout)
            txt, csvp = save_results(results, out_dir, "clean_ips", vless_config=v)
        except ScanInterrupted as interrupted:
            results = interrupted.results
            txt, csvp = save_results(results, out_dir, "clean_ips_interrupted", vless_config=v)
            cprint("Ctrl+C detected. Partial scan results were saved.", "yellow")
            show_final_results(results, txt, csvp, vless_config=v, save_recommendations=False)
            return 130

        show_final_results(results, txt, csvp, vless_config=v, save_recommendations=False)

        top_limit: int = (
            max(0, int(args.top_targets))
            if "top_targets" in explicit_keys and args.top_targets is not None
            else (max(0, int(settings.top_targets)) if settings.top_targets is not None else 30)
        )
        if has_post_scan and top_limit > 0 and len(final_results) > top_limit:
            if longevity_enabled or speed_enabled:
                screen_cap = max(top_limit * 3, 60)
                if len(final_results) > screen_cap:
                    final_results = sorted(final_results, key=lambda r: (r.latency_ms if r.latency_ms is not None else 10**12))[:screen_cap]
            else:
                final_results = filter_diverse_endpoints(
                    sorted(final_results, key=lambda r: (r.latency_ms if r.latency_ms is not None else 10**12)),
                    max_targets=top_limit,
                    max_per_subnet=2,
                )

        if recheck_enabled and final_results:
            final_results = [r for r in final_results if r.ok]
            try:
                final_results = run_stability_stage(
                    v,
                    final_results,
                    xray,
                    recheck_workers,
                    timeout,
                    recheck_samples,
                    test_url,
                    args.loglevel,
                    on_stage=render_stage,
                    make_reporter=progress_reporter,
                )
                if not longevity_enabled and not speed_enabled:
                    enrich_results_with_colo(v, final_results, xray, workers=recheck_workers, timeout=timeout)
                final_prefix = "clean_ips_rechecked"
                txt, csvp = save_results(final_results, out_dir, final_prefix, vless_config=v)
            except ScanInterrupted as interrupted:
                final_results = interrupted.results
                txt, csvp = save_results(final_results, out_dir, "clean_ips_rechecked_interrupted", vless_config=v)
                cprint("Ctrl+C detected. Partial re-check results were saved.", "yellow")
                show_final_results(final_results, txt, csvp, filename_prefix="clean_ips_rechecked", vless_config=v, save_recommendations=False)
                return 130
            show_final_results(final_results, txt, csvp, filename_prefix=final_prefix, vless_config=v, save_recommendations=False)

        if longevity_enabled and final_results:
            final_results = [r for r in final_results if r.ok]
            if top_limit > 0 and len(final_results) > top_limit:
                final_results = filter_diverse_endpoints(
                    sorted(final_results, key=recheck_sort_key if recheck_enabled else lambda r: (r.latency_ms if r.latency_ms is not None else 10**12)),
                    max_targets=top_limit,
                    max_per_subnet=2,
                )
            try:
                final_results = run_longevity_stage(
                    v,
                    final_results,
                    xray,
                    speed_workers,
                    longevity_duration,
                    timeout,
                    args.loglevel,
                    on_stage=render_stage,
                    make_reporter=progress_reporter,
                )
                if not speed_enabled:
                    enrich_results_with_colo(v, final_results, xray, workers=speed_workers, timeout=timeout)
                final_prefix = "clean_ips_longevity"
                txt, csvp = save_results(final_results, out_dir, final_prefix, vless_config=v)
            except ScanInterrupted as interrupted:
                final_results = interrupted.results
                txt, csvp = save_results(final_results, out_dir, "clean_ips_longevity_interrupted", vless_config=v)
                cprint("Ctrl+C detected. Partial anti-drop results were saved.", "yellow")
                show_final_results(final_results, txt, csvp, filename_prefix="clean_ips_longevity", vless_config=v, save_recommendations=False)
                return 130
            show_final_results(final_results, txt, csvp, filename_prefix=final_prefix, vless_config=v, save_recommendations=False)

        if speed_enabled and final_results:
            final_results = [r for r in final_results if r.ok]
            if top_limit > 0 and len(final_results) > top_limit:
                final_results = filter_diverse_endpoints(
                    sorted(final_results, key=recheck_sort_key if recheck_enabled else lambda r: (r.latency_ms if r.latency_ms is not None else 10**12)),
                    max_targets=top_limit,
                    max_per_subnet=2,
                )
            try:
                final_results = run_speed_stage(
                    v,
                    final_results,
                    xray,
                    speed_workers,
                    speed_duration,
                    args.speed_timeout,
                    download_mb,
                    upload_mb=upload_mb,
                    speed_url=args.speed_url,
                    loglevel=args.loglevel,
                    on_stage=render_stage,
                    make_reporter=progress_reporter,
                )
                enrich_results_with_colo(v, final_results, xray, workers=speed_workers, timeout=timeout)
                if recheck_enabled and longevity_enabled:
                    final_prefix = "clean_ips_full_tested"
                else:
                    final_prefix = "clean_ips_speed_tested"
                txt, csvp = save_results(final_results, out_dir, final_prefix, include_speed_errors=True, vless_config=v)
            except ScanInterrupted as interrupted:
                final_results = interrupted.results
                interrupted_prefix = "clean_ips_full_interrupted" if (recheck_enabled and longevity_enabled) else "clean_ips_speed_tested_interrupted"
                txt, csvp = save_results(final_results, out_dir, interrupted_prefix, include_speed_errors=True, vless_config=v)
                cprint("Ctrl+C detected. Partial speed-test results were saved.", "yellow")
                show_final_results(final_results, txt, csvp, filename_prefix=interrupted_prefix, vless_config=v, save_recommendations=False)
                return 130
            show_final_results(final_results, txt, csvp, filename_prefix=final_prefix, vless_config=v, save_recommendations=False)

        summary_results = [r for r in final_results if r.ok] if final_results else []
        if summary_results and (args.max_latency > 0 or args.min_speed > 0):
            filtered_prefix = f"{final_prefix}_filtered" if final_prefix != "clean_ips" else "clean_ips_filtered"
            txt, csvp = save_results(
                summary_results,
                out_dir,
                filtered_prefix,
                max_latency_ms=args.max_latency,
                min_speed_mbps=args.min_speed,
                include_speed_errors=speed_enabled,
                vless_config=v,
            )
            show_final_results(
                summary_results,
                txt,
                csvp,
                max_latency_ms=args.max_latency,
                min_speed_mbps=args.min_speed,
                filename_prefix=filtered_prefix,
                vless_config=v,
                save_recommendations=False,
            )
            summary_results = apply_result_filters(
                summary_results, max_latency_ms=args.max_latency, min_speed_mbps=args.min_speed
            )

        recs = get_smart_recommendations(summary_results, v) if summary_results else []
        save_recommended_configs(recs, out_dir)
        save_scan_summary_report(
            summary_results,
            out_dir,
            settings=settings if is_config_file else None,
            vless_config=v,
            total_targets_count=total_prefilter,
            tcp_alive_count=tcp_alive_count,
            recommendations=recs,
            initial_ok_count=initial_ok_count,
        )
        return 0

    def run(self) -> int:
        """Parse arguments and branch into interactive or CLI mode."""
        if not self.argv:
            try:
                return self.interactive()
            except KeyboardInterrupt:
                cprint("\nCanceled by user.", "yellow")
                return 130

        args = self.parser.parse_args(self.argv)
        return self.run_cli(args)
