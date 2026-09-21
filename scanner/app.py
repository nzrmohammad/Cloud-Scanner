import argparse
import sys
from pathlib import Path
from typing import List, Optional

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
    execute_configured_post_scan_tests,
    run_latency_recheck,
    run_longevity_tests,
    run_scan,
    run_speed_tests,
)
from scanner.models import (
    AppSettings,
    NavigationBack,
    NavigationExit,
    ScanInterrupted,
    ScanResult,
    VlessConfig,
)
from scanner.storage import save_results
from scanner.targets import expand_targets, print_isp_catalog_cli, resolve_isp_files
from scanner.ui import (
    cprint,
    pause,
    post_scan_actions_menu,
    prompt_str,
    render_stage,
    render_welcome_config_screen,
    select_targets_tui,
    show_final_results,
)
from scanner.xray import find_xray

try:
    import requests
except ImportError:
    requests = None


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
    p.add_argument("--keep-configs", action="store_true")
    p.add_argument("--recheck", action="store_true", help="After the first scan, re-test working IPs and save updated results")
    p.add_argument("--recheck-samples", type=int, default=5, help="Latency tests per working IP during --recheck")
    p.add_argument("--recheck-workers", type=int, default=None, help="Workers for --recheck. Default: same as --concurrency")
    p.add_argument("--longevity-test", action="store_true", help="Run Anti-Drop endurance test against DPI throttling for working endpoints")
    p.add_argument("--longevity-duration", type=int, default=DEFAULT_LONGEVITY_DURATION, help=f"Duration in seconds for Anti-Drop test (default: {DEFAULT_LONGEVITY_DURATION})")
    p.add_argument("--speed-test", action="store_true", help="Run a download speed test for working IPs after scanning/recheck")
    p.add_argument("--speed-workers", type=int, default=5, help="Workers for speed testing")
    p.add_argument("--speed-mb", type=int, default=5, help="Download size per IP in MB")
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


class CloudScannerApp:
    """Main application coordinator for Cloudflare Clean-IP Scanner."""

    def __init__(self, argv: Optional[List[str]] = None):
        self.argv = argv if argv is not None else sys.argv[1:]
        self.parser = build_arg_parser()
        self.config_manager = ConfigManager()

    def interactive(self) -> int:
        """Run interactive TUI mode."""
        xray = find_xray()
        if not xray:
            cprint("xray.exe/xray not found. Place it beside the script or pass --xray.", "red")
            pause("Press Enter to exit...")
            return 1

        while True:
            settings = self.config_manager.load_settings()
            v: Optional[VlessConfig] = None
            if settings.vless_raw:
                try:
                    v = parse_vless(settings.vless_raw)
                except Exception:
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
                        except Exception:
                            pass
                        error = "Invalid VLESS URI. Press Enter to use saved config, or type q to exit."

            while True:
                try:
                    targets, target_label = select_targets_tui(v=v, settings=settings)
                except (NavigationBack, NavigationExit):
                    render_stage("Exited", "No scan was started.", "yellow")
                    return 0

                ports = settings.ports if settings.ports else [v.port]
                output_dir = settings.output_dir
                output_dir.mkdir(parents=True, exist_ok=True)

                action = None
                while True:
                    total_endpoints = len(targets) * len(ports)
                    render_stage(
                        "Scanning",
                        f"Source: {target_label} | IPs: {len(targets)} | Ports: {len(ports)} | Total: {total_endpoints} | Workers: {settings.workers}",
                        "cyan",
                    )
                    try:
                        results = run_scan(
                            v,
                            targets,
                            ports,
                            xray,
                            settings.workers,
                            settings.timeout,
                            1,
                            settings.test_url,
                            "warning",
                            False,
                            use_tcp_prefilter=settings.tcp_prefilter,
                            output_dir=output_dir,
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

                    if working_results and settings.post_scan_mode != "none":
                        final_results, final_txt, final_csv, prefix = execute_configured_post_scan_tests(
                            settings, v, working_results, xray, output_dir
                        )
                        render_stage("Final Results", "Testing complete. Summary of best results below.", "green")
                        show_final_results(final_results, final_txt, final_csv, filename_prefix=prefix, vless_config=v)

                    pause("\n› Press Enter to view action options (Scan Again / Retest / Exit)...")
                    action = post_scan_actions_menu(v, final_results, prefix)
                    if action == "retest_same":
                        continue
                    elif action == "rescan_all":
                        break
                    else:
                        render_stage("Scanner Finished", "Thank you for using Cloud Scanner!", "green")
                        return 0

                if action == "rescan_all":
                    break

    def run_cli(self, args: argparse.Namespace) -> int:
        """Run non-interactive CLI mode."""
        if args.list_isps:
            print_isp_catalog_cli()
            return 0

        using_isp_cli = bool(args.isp_category)
        cfg_val = args.config or load_saved_vless_config()

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

        try:
            v = parse_vless(cfg_val)
            save_vless_config(cfg_val)
            if args.all_cf_tls_ports:
                ports = list(DEFAULT_CF_TLS_PORTS)
            elif args.ports:
                ports = [int(p.strip()) for p in args.ports.split(",") if p.strip()]
            else:
                ports = [v.port]

            use_tcp_prefilter = not args.skip_tcp_prefilter

            if using_isp_cli:
                isp_files = resolve_isp_files(args.isp_category, args.isp)
                if not isp_files:
                    raise ValueError(f"No ISP files found for category: {args.isp_category}")
                targets = expand_targets([str(p) for p in isp_files], args.max_hosts, sample_if_too_many=True)
                cprint(f"Loaded {len(targets)} target(s) from {args.isp_category} ISP list.", "green")
            else:
                targets = expand_targets(args.targets, args.max_hosts, sample_if_too_many=args.sample_large_ranges)
        except Exception as e:
            cprint(str(e), "red")
            return 2

        try:
            results = run_scan(
                v,
                targets,
                ports,
                xray,
                args.concurrency,
                args.timeout,
                args.tries,
                args.url,
                args.loglevel,
                args.keep_configs,
                use_tcp_prefilter=use_tcp_prefilter,
                output_dir=Path(args.output_dir),
            )
            txt, csvp = save_results(results, Path(args.output_dir), "clean_ips", vless_config=v)
        except ScanInterrupted as interrupted:
            results = interrupted.results
            txt, csvp = save_results(results, Path(args.output_dir), "clean_ips_interrupted", vless_config=v)
            cprint("Ctrl+C detected. Partial scan results were saved.", "yellow")
            show_final_results(results, txt, csvp, vless_config=v)
            return 130

        show_final_results(results, txt, csvp, vless_config=v)
        final_results = [r for r in results if r.ok]

        if args.recheck:
            try:
                final_results = run_latency_recheck(
                    v,
                    final_results,
                    xray,
                    args.recheck_workers or args.concurrency,
                    args.timeout,
                    args.recheck_samples,
                    args.url,
                    args.loglevel,
                )
                txt, csvp = save_results(final_results, Path(args.output_dir), "clean_ips_rechecked", vless_config=v)
            except ScanInterrupted as interrupted:
                final_results = interrupted.results
                txt, csvp = save_results(final_results, Path(args.output_dir), "clean_ips_rechecked_interrupted", vless_config=v)
                cprint("Ctrl+C detected. Partial re-check results were saved.", "yellow")
                show_final_results(final_results, txt, csvp, filename_prefix="clean_ips_rechecked", vless_config=v)
                return 130
            show_final_results(final_results, txt, csvp, filename_prefix="clean_ips_rechecked", vless_config=v)

        if args.longevity_test:
            try:
                final_results = run_longevity_tests(
                    v,
                    final_results,
                    xray,
                    workers=args.speed_workers,
                    duration=args.longevity_duration,
                    timeout=args.timeout,
                    url=args.url,
                    loglevel=args.loglevel,
                )
                txt, csvp = save_results(final_results, Path(args.output_dir), "clean_ips_longevity", vless_config=v)
            except ScanInterrupted as interrupted:
                final_results = interrupted.results
                txt, csvp = save_results(final_results, Path(args.output_dir), "clean_ips_longevity_interrupted", vless_config=v)
                cprint("Ctrl+C detected. Partial anti-drop results were saved.", "yellow")
                show_final_results(final_results, txt, csvp, filename_prefix="clean_ips_longevity", vless_config=v)
                return 130
            show_final_results(final_results, txt, csvp, filename_prefix="clean_ips_longevity", vless_config=v)

        if args.speed_test:
            try:
                test_upload = not args.skip_upload_test and args.speed_upload_mb > 0
                final_results = run_speed_tests(
                    v,
                    final_results,
                    xray,
                    args.speed_workers,
                    args.speed_timeout,
                    args.speed_mb * 1024 * 1024,
                    args.speed_duration,
                    args.speed_url,
                    args.loglevel,
                    test_upload=test_upload,
                    upload_bytes=args.speed_upload_mb * 1024 * 1024,
                )
                txt, csvp = save_results(final_results, Path(args.output_dir), "clean_ips_speed_tested", include_speed_errors=True, vless_config=v)
            except ScanInterrupted as interrupted:
                final_results = interrupted.results
                txt, csvp = save_results(final_results, Path(args.output_dir), "clean_ips_speed_tested_interrupted", include_speed_errors=True, vless_config=v)
                cprint("Ctrl+C detected. Partial speed-test results were saved.", "yellow")
                show_final_results(final_results, txt, csvp, filename_prefix="clean_ips_speed_tested", vless_config=v)
                return 130
            show_final_results(final_results, txt, csvp, filename_prefix="clean_ips_speed_tested", vless_config=v)
            if args.max_latency > 0 or args.min_speed > 0:
                txt, csvp = save_results(
                    final_results,
                    Path(args.output_dir),
                    "clean_ips_speed_filtered",
                    max_latency_ms=args.max_latency,
                    min_speed_mbps=args.min_speed,
                    include_speed_errors=True,
                    vless_config=v,
                )
                show_final_results(
                    final_results,
                    txt,
                    csvp,
                    max_latency_ms=args.max_latency,
                    min_speed_mbps=args.min_speed,
                    filename_prefix="clean_ips_speed_filtered",
                    vless_config=v,
                )
        return 0

    def run(self) -> int:
        """Parse arguments and branch into interactive or CLI mode."""
        args = self.parser.parse_args(self.argv)
        using_isp_cli = bool(args.isp_category)

        if not args.config and not args.targets and not using_isp_cli and not args.list_isps:
            try:
                return self.interactive()
            except KeyboardInterrupt:
                cprint("\nCanceled by user.", "yellow")
                return 130

        return self.run_cli(args)
