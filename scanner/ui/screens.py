import re
from pathlib import Path
from typing import Any, List, Optional, Tuple

from scanner.analytics import (
    apply_result_filters,
    detect_stage_flags,
    full_sort_key,
    get_smart_recommendations,
    output_sort_key,
    summarize_failure_diagnostics,
)
from scanner.config import load_saved_vless_config, parse_vless, save_vless_config
from scanner.constants import (
    ISP_CATEGORIES,
    LATENCY_TEST_URLS,
    MAX_DEFAULT_HOSTS,
    app_dir,
    format_cf_colo,
)
from scanner.geoip import format_ip_location
from scanner.logger import get_logger
from scanner.models import (
    AppSettings,
    NavigationBack,
    NavigationExit,
    ScanResult,
    SmartRecommendation,
    VlessConfig,
)
from scanner.targets import (
    expand_targets,
    isp_display_name,
    isp_root,
    list_isp_files,
    read_isp_stats,
)
from scanner.ui.menus import key_multi_select_menu, key_select_menu
from scanner.ui.terminal import (
    RICH,
    box,
    clear_screen,
    console,
    cprint,
    is_back_value,
    pause,
    prompt_confirm,
    prompt_confirm_nav,
    prompt_continue_nav,
    prompt_int_nav,
    prompt_str,
    render_fixed_header,
    render_stage,
    show_banner,
)
from scanner.xray import (
    download_xray_release,
    fetch_latest_xray_tag,
    find_xray,
    get_environment_status,
    get_xray_version,
    is_newer_version,
)

try:
    from rich.panel import Panel
    from rich.prompt import Prompt
    from rich.table import Table
except ImportError:
    Panel = None  # type: ignore
    Prompt = None  # type: ignore
    Table = None  # type: ignore

try:
    import requests
except ImportError:
    requests = None  # type: ignore[assignment]

logger = get_logger("ui.screens")


def _format_settings_lines(fallback_port: int, settings: AppSettings) -> Tuple[str, str, str, str]:
    """Build shared formatted strings describing active AppSettings."""
    ports_str = ", ".join(str(p) for p in (settings.ports if settings.ports else [fallback_port]))
    mode_str = settings.post_scan_mode.upper()
    max_t_str = "Unlimited" if settings.max_targets == 0 else str(settings.max_targets)
    top_t_desc = "All working IPs" if settings.top_targets == 0 else f"Top {settings.top_targets}"
    return ports_str, mode_str, max_t_str, top_t_desc


def _run_xray_download_flow(target_dir: Path, tag: Optional[str] = None) -> bool:
    """Download/update Xray-core interactively with progress bar and optional proxy retry."""
    proxies: Optional[dict] = None
    while True:
        cprint(f"\n[cyan]Downloading Xray-core into {target_dir}...[/cyan]")
        if RICH and console is not None:
            try:
                from rich.progress import (
                    BarColumn,
                    DownloadColumn,
                    Progress,
                    TextColumn,
                    TimeRemainingColumn,
                    TransferSpeedColumn,
                )

                with Progress(
                    TextColumn("[bold cyan]{task.description}"),
                    BarColumn(),
                    DownloadColumn(),
                    TransferSpeedColumn(),
                    TimeRemainingColumn(),
                    console=console,
                ) as progress:
                    task_id = progress.add_task("Xray-core", total=None)

                    def _on_prog(dl: int, total: int, tid: Any = task_id, prog: Any = progress) -> None:
                        if total > 0:
                            prog.update(tid, total=total, completed=dl)
                        else:
                            prog.update(tid, completed=dl)

                    ok, msg = download_xray_release(target_dir, tag=tag, proxies=proxies, on_progress=_on_prog)
            except Exception as exc:
                logger.debug("Rich progress download UI fallback triggered: %s", exc)
                ok, msg = download_xray_release(target_dir, tag=tag, proxies=proxies)
        else:
            ok, msg = download_xray_release(target_dir, tag=tag, proxies=proxies)

        if ok:
            cprint(f"\n[bold green]Xray-core v{msg} installed successfully![/bold green]")
            pause("Press Enter to continue...")
            return True

        cprint(f"\n[red]Download failed:[/red] {msg}")
        proxy_in = prompt_str("Optional proxy URL to retry (e.g. http://127.0.0.1:10808, Enter to skip)", default="").strip()
        if not proxy_in:
            return False
        proxies = {"http": proxy_in, "https": proxy_in}


def check_and_prompt_xray_update(xray: Optional[Path]) -> Optional[Path]:
    """Check if Xray-core is missing or has a newer GitHub release, and prompt user to update."""
    if xray is None:
        render_stage("Xray-core Not Found", "Official Xray-core binary is required to run scans.", "yellow")
        if prompt_confirm("Download latest official Xray-core into core/ now?", default=True):
            if _run_xray_download_flow(app_dir() / "core"):
                clear_screen()
                return find_xray()
        clear_screen()
        return None

    local_ver = get_xray_version(xray)
    if not local_ver:
        return xray

    latest_tag = fetch_latest_xray_tag(timeout=2.0)
    if latest_tag and is_newer_version(latest_tag, local_ver):
        render_stage(
            "Xray-core Update Available",
            f"Installed version: v{local_ver}   |   Latest release: {latest_tag}",
            "cyan",
        )
        if prompt_confirm(f"A newer Xray-core ({latest_tag}) is available. Update now?", default=True):
            _run_xray_download_flow(xray.parent, tag=latest_tag)
            updated = find_xray(str(xray)) or find_xray()
            clear_screen()
            return updated or xray
        clear_screen()

    return xray


def make_active_settings_panel(v: Optional[VlessConfig], settings: Optional[AppSettings]) -> Optional[Any]:
    """Create a concise, elegant summary panel of settings loaded from config.txt."""
    if not v or not settings or not RICH or Panel is None:
        return None
    ports_str, mode_str, max_t_str, top_t_desc = _format_settings_lines(v.port, settings)
    details = (
        f"[bold cyan]Config Remark:[/bold cyan] {v.remark} ([green]{v.host}:{v.port}[/green])\n"
        f"[bold cyan]Target Ports:[/bold cyan]  {ports_str}\n"
        f"[bold cyan]Scan Workers:[/bold cyan]  {settings.workers}  |  [bold cyan]Timeout:[/bold cyan] {settings.timeout}s  |  [bold cyan]TCP Pre-filter:[/bold cyan] {'[green]Enabled[/green]' if settings.tcp_prefilter else '[red]Disabled[/red]'}\n"
        f"[bold cyan]Max Targets:[/bold cyan]   {max_t_str}  |  [bold cyan]Post-Scan Mode:[/bold cyan] [yellow]{mode_str}[/yellow] ({top_t_desc}, {settings.download_mb}MB down, {settings.upload_mb}MB up)\n"
        f"[dim]Loaded directly from config.txt. Modify config.txt to customize any parameter.[/dim]"
    )
    return Panel(details, title="[bold green]Loaded from config.txt[/bold green]", border_style="cyan", box=box.ROUNDED, expand=False)


def render_active_settings_panel(v: VlessConfig, settings: AppSettings) -> None:
    """Display a concise, elegant banner and summary of settings loaded from config.txt."""
    if RICH and console is not None:
        panel = make_active_settings_panel(v, settings)
        if panel:
            clear_screen()
            render_fixed_header(compact=True, show_controls=False)
            console.print(panel)
    else:
        ports_str, mode_str, max_t_str, top_t_desc = _format_settings_lines(v.port, settings)
        print("=== Loaded from config.txt ===")
        print(f"Config: {v.remark} ({v.host}:{v.port}) | Ports: {ports_str} | Workers: {settings.workers} | Max Targets: {max_t_str} | Mode: {mode_str} ({top_t_desc})")


def render_startup_check(xray_path: Optional[Path]) -> bool:
    """Render startup environment table with dependency status in the terminal."""
    env = get_environment_status(xray_path)
    rows = []

    if env["xray_ok"]:
        ver = env["xray_version"]
        xray_status = f"[green]FOUND (v{ver})[/green]" if ver else "[green]FOUND[/green]"
    else:
        xray_status = "[red]MISSING[/red]"

    rows.append(("xray.exe / xray", xray_status))
    rows.append(("geoip.dat", "[green]FOUND[/green]" if env["geoip_ok"] else "[red]MISSING[/red]"))
    rows.append(("geosite.dat", "[green]FOUND[/green]" if env["geosite_ok"] else "[red]MISSING[/red]"))
    rows.append(("requests[socks]", "[green]FOUND[/green]" if env["requests_ok"] else "[red]MISSING[/red]"))

    if RICH and console is not None and Table is not None:
        table = Table(title="Startup Check", box=box.ROUNDED, border_style="cyan", expand=False)
        table.add_column("Component", style="white")
        table.add_column("Status")
        for name, status in rows:
            table.add_row(name, status)
        console.print(table)
    else:
        for name, status in rows:
            print(f"{name}: {status}")

    return bool(env["ok"])


def render_welcome_config_screen(
    xray: Optional[Path],
    error: str = "",
    saved_config: str = "",
    settings: Optional[AppSettings] = None,
) -> bool:
    """One combined first page: big logo, startup check, and config entry prompt."""
    clear_screen()
    show_banner(clear=False)
    env_ok = render_startup_check(xray)
    if RICH and console is not None and Panel is not None:
        if saved_config:
            fallback_port = 443
            try:
                parsed_saved = parse_vless(saved_config)
                fallback_port = parsed_saved.port
                info = f"[cyan]{parsed_saved.remark}[/cyan] ([green]{parsed_saved.host}:{parsed_saved.port}[/green])"
            except Exception:
                info = saved_config[:40] + ("..." if len(saved_config) > 40 else "")

            if settings:
                ports_str, mode_str, max_t_str, top_t_desc = _format_settings_lines(fallback_port, settings)
                help_text = (
                    f"[bold green]Saved VLESS config found in config.txt[/bold green] -> {info}\n"
                    f"[bold cyan]Target Ports:[/bold cyan]  {ports_str}\n"
                    f"[bold cyan]Scan Workers:[/bold cyan]  {settings.workers}  |  [bold cyan]Timeout:[/bold cyan] {settings.timeout}s  |  [bold cyan]TCP Pre-filter:[/bold cyan] {'[green]Enabled[/green]' if settings.tcp_prefilter else '[red]Disabled[/red]'}\n"
                    f"[bold cyan]Max Targets:[/bold cyan]   {max_t_str}  |  [bold cyan]Post-Scan Mode:[/bold cyan] [yellow]{mode_str}[/yellow] ({top_t_desc}, {settings.download_mb}MB down, {settings.upload_mb}MB up)\n\n"
                    f"[bold white]Press Enter[/bold white] to use saved config & start, or paste a new VLESS link.\n"
                    f"[dim]q/exit = quit.[/dim]"
                )
            else:
                help_text = (
                    f"[bold green]Saved VLESS config found in config.txt[/bold green] -> {info}\n"
                    f"[bold white]Press Enter[/bold white] to use saved config, or paste a new one.\n"
                    f"[dim]q/exit = quit.[/dim]"
                )
        else:
            help_text = (
                "[bold]Paste your VLESS config below[/bold] (it will be saved to config.txt for next time)\n"
                "[dim]q/exit = quit.[/dim]"
            )
        if error:
            help_text += f"\n[red]{error}[/red]"
        console.print(Panel(help_text, border_style="cyan", box=box.ROUNDED, expand=False))
    else:
        if saved_config:
            print("Saved VLESS config found in config.txt. Press Enter to use it, or paste a new one:")
        else:
            print("Paste your VLESS config below, or enter a file path containing one. q/exit = quit.")
        if error:
            print(f"ERROR: {error}")
    return bool(env_ok and xray and requests is not None)


def show_config_summary(v: VlessConfig) -> None:
    q = v.query
    if RICH and console is not None and Table is not None:
        table = Table(title="Configuration Summary", box=box.ROUNDED, border_style="green", expand=False)
        table.add_column("Property", style="bold cyan")
        table.add_column("Value", style="bold white")
        table.add_row("Remark", v.remark or "(empty)")
        table.add_row("Host / Server", v.host)
        table.add_row("Port", str(v.port))
        table.add_row("UUID", v.uuid)
        table.add_row("Network / Type", q.get("type") or q.get("network") or "tcp")
        table.add_row("Security", q.get("security", "none"))
        table.add_row("SNI", q.get("sni") or q.get("servername") or "(none)")
        table.add_row("Path", q.get("path") or "(none)")
        console.print(table)
    else:
        print(f"Remark: {v.remark} | Host: {v.host} | Port: {v.port} | Network: {q.get('type') or 'tcp'} | Security: {q.get('security', 'none')}")


def read_vless_tui(xray: Optional[Path]) -> VlessConfig:
    error = ""
    while True:
        saved_config = load_saved_vless_config()
        valid_default: Optional[str] = None
        if saved_config:
            try:
                parse_vless(saved_config)
                valid_default = saved_config
            except Exception:
                valid_default = None
        if not render_welcome_config_screen(xray, error, saved_config=valid_default or ""):
            cprint("\nMissing required runtime files/dependencies. Fix them and run again.", "yellow")
            pause("Press Enter to exit")
            raise NavigationExit
        try:
            raw = prompt_str("VLESS config", default=valid_default)
        except EOFError:
            raise NavigationExit from None
        if not raw and valid_default:
            raw = valid_default
        if raw.strip().lower() in {"q", "quit", "exit", "b", "back"}:
            raise NavigationExit
        try:
            v = parse_vless(raw)
            save_vless_config(v.raw)
            cprint("Configuration loaded successfully.", "green")
            show_config_summary(v)
            prompt_continue_nav("Press Enter to continue to target selection", allow_back=False)
            return v
        except Exception as e:
            error = f"Invalid configuration: {e}"


def show_main_target_menu(top_panel: Optional[Any] = None) -> str:
    rows = [
        ("Manual IP ranges", "Enter one or more IP/CIDR/range values yourself"),
        ("ISP range list", "Pick from packaged Iranian or international ISP files"),
    ]
    idx = key_select_menu("Target Source", rows, default_index=0, allow_back=True, top_panel=top_panel)
    return str(idx + 1)


def ask_max_targets(default: int = MAX_DEFAULT_HOSTS) -> int:
    render_stage("Target Limit", "Choose how many targets to load before scanning.  B/back returns to the previous step.", "yellow")
    cprint("Press Enter to use the default: unlimited. That means every IP in the selected ranges will be expanded and scanned; large ranges can take a long time.", "dim")
    cprint("Enter a number only if you want to cap the scan and sample large ranges evenly.", "dim")
    while True:
        try:
            if RICH and Prompt is not None:
                raw = Prompt.ask(
                    "[bold yellow]Maximum targets to load/scan[/bold yellow] [dim](default unlimited, b=back)[/dim]",
                    default="",
                    show_default=False,
                )
            else:
                raw = input("Maximum targets to load/scan (default unlimited, b=back): ").strip()
            raw = (raw or "").strip().lower()
            if not raw or raw == "0":
                return 0
            if is_back_value(raw):
                raise NavigationBack
            value = int(raw)
            if value < 1:
                raise ValueError
            return value
        except NavigationBack:
            raise
        except EOFError:
            raise NavigationBack from None
        except Exception:
            cprint("Enter a positive number, press Enter for unlimited, or type b to go back.", "yellow")


def select_manual_targets_tui() -> Tuple[List[str], str]:
    render_stage(
        "Manual Scan",
        "Paste IPs, CIDRs, or IP ranges in one batch.  b/back returns.",
        "cyan",
    )
    cprint("Paste multiple targets at once; one item per line is recommended.", "dim")
    cprint("Spaces, commas, and semicolons are also accepted.", "dim")
    cprint("After the last line, press Enter on an empty line to continue.", "dim")
    cprint("Usually this means pressing Enter twice after your pasted text.", "dim")
    cprint("")

    lines: List[str] = []
    while True:
        try:
            raw = input("> ").strip()
        except EOFError:
            if lines:
                break
            raise NavigationBack from None
        if not raw:
            if lines:
                break
            cprint("Enter at least one target, or type b/back to return.", "yellow")
            continue
        if not lines and is_back_value(raw):
            raise NavigationBack
        lines.append(raw)

    blob = re.sub(r"\s*-\s*", "-", "\n".join(lines))
    items = [x.strip() for x in re.split(r"[\s,;]+", blob) if x.strip()]
    if not items:
        raise NavigationBack
    return items, "Manual IP ranges"


def choose_isp_category_tui() -> str:
    categories = [
        ("iran", ISP_CATEGORIES.get("iran", "Iranian ISPs & Datacenters")),
        ("international", ISP_CATEGORIES.get("international", "International ISPs & Clouds")),
        ("ipv6", ISP_CATEGORIES.get("ipv6", "IPv6 Ranges (Cloudflare & Clouds)")),
    ]
    rows = []
    for cat_id, label in categories:
        count = len(list_isp_files(cat_id))
        rows.append((label, f"{count} packaged range file(s)"))
    idx = key_select_menu("Target Categories", rows, default_index=0, allow_back=True)
    return categories[idx][0]


def select_isp_targets_tui() -> Tuple[List[str], str]:
    while True:
        category = choose_isp_category_tui()
        files = list_isp_files(category)
        if not files:
            raise ValueError(f"No ISP files found in {isp_root() / category}")
        label = ISP_CATEGORIES.get(category, category)
        rows: List[Tuple[str, str]] = []
        for path in files:
            count, preview = read_isp_stats(path)
            rows.append((isp_display_name(path), f"{count} range line(s)  {preview}".strip()))
        try:
            idxs = key_multi_select_menu(f"{label} Range Files", rows, allow_back=True)
        except NavigationBack:
            continue
        selected_files = [files[i] for i in idxs]
        selected_names = ", ".join(isp_display_name(p) for p in selected_files[:5])
        if len(selected_files) > 5:
            selected_names += f", +{len(selected_files)-5} more"
        return [str(p) for p in selected_files], f"{label}: {selected_names}"


def select_targets_tui(v: Optional[VlessConfig] = None, settings: Optional[Any] = None) -> Tuple[List[str], str]:
    """Select target sources, using max_targets from settings if available."""
    while True:
        mode = show_main_target_menu()
        try:
            while True:
                if mode == "1":
                    items, target_label = select_manual_targets_tui()
                else:
                    items, target_label = select_isp_targets_tui()
                try:
                    if settings is not None and hasattr(settings, "max_targets"):
                        max_hosts = settings.max_targets
                    else:
                        max_hosts = ask_max_targets(MAX_DEFAULT_HOSTS)
                    targets = expand_targets(items, max_hosts=max_hosts, sample_if_too_many=True)
                    return targets, target_label
                except NavigationBack:
                    continue
        except NavigationBack:
            continue
        except Exception as exc:
            cprint(f"Target selection failed: {exc}", "red")
            try:
                retry = prompt_confirm_nav("Try target selection again?", True, allow_back=True)
            except NavigationBack:
                retry = True
            if not retry:
                raise NavigationBack from None


def choose_latency_test_url_tui() -> str:
    rows = [(name, url) for name, url, _detail in LATENCY_TEST_URLS]
    idx = key_select_menu("Latency Test URL", rows, default_index=0, allow_back=True)
    return LATENCY_TEST_URLS[idx][1]




def render_smart_recommendations(
    recs: List[SmartRecommendation],
    output_dir: Path,
    save_to_disk: bool = True,
) -> None:
    if not recs:
        return

    if RICH and console is not None and Table is not None:
        table = Table(
            title="Smart Recommendations (Best Endpoints per Use-Case)",
            box=box.ROUNDED,
            border_style="green",
            expand=False,
        )
        table.add_column("Use Case", style="bold white", no_wrap=True)
        table.add_column("Endpoint", style="bold cyan", no_wrap=True)
        table.add_column("Edge PoP", justify="center", style="bold yellow", no_wrap=True)
        table.add_column("Highlights & Performance", style="bright_white")
        for rec in recs:
            colo_str = format_cf_colo(rec.result.colo, short=True) if rec.result.colo else "-"
            table.add_row(rec.category, rec.result.endpoint, colo_str, rec.reason)
        console.print(table)
    else:
        print("\n=======================================================")
        print("Smart Recommendations (Best Endpoints per Use-Case):")
        for rec in recs:
            colo_str = f" [{format_cf_colo(rec.result.colo, short=True)}]" if rec.result.colo else ""
            print(f"  {rec.category:<12} -> {rec.result.endpoint:<20}{colo_str} ({rec.reason})")
        print("=======================================================\n")

    if save_to_disk:
        from scanner.storage import save_recommended_configs
        save_recommended_configs(recs, output_dir)


def _rich_drop_badge(r: ScanResult) -> str:
    if r.sustained is True:
        return "[green]Pass[/green]"
    if r.sustained is False:
        return "[red]Drop[/red]"
    return "-"


def show_final_results(
    results: List[ScanResult],
    txt_path: Path,
    csv_path: Path,
    max_latency_ms: float = 0,
    min_speed_mbps: float = 0,
    filename_prefix: str = "clean_ips",
    vless_config: Optional[VlessConfig] = None,
    display_limit: Optional[int] = 50,
    save_recommendations: bool = True,
) -> None:
    ok = apply_result_filters(results, max_latency_ms=max_latency_ms, min_speed_mbps=min_speed_mbps)
    is_full, is_speed, is_recheck, is_longevity = detect_stage_flags(filename_prefix, ok)
    sort_fn = full_sort_key if is_full else output_sort_key(filename_prefix)
    ok = sorted(ok, key=sort_fn)
    failed = len([r for r in results if not r.ok])
    filtered_out = len([r for r in results if r.ok]) - len(ok)

    output_dir = txt_path.parent
    display_items = ok if display_limit is None else ok[:display_limit]

    if RICH and console is not None and Panel is not None and Table is not None:
        has_longevity = any(r.sustained is not None for r in ok)
        has_colo = any(bool(r.colo) for r in ok)
        has_loc = any(bool(r.ip_country) for r in ok)
        has_upload = any(r.upload_mbps is not None for r in ok)

        filter_line = ""
        if max_latency_ms > 0 or min_speed_mbps > 0:
            filter_line = f"\nFiltered out: [bold yellow]{filtered_out}[/bold yellow]"
        console.print(Panel(f"[bold green]Scan Finished[/bold green]\n\nWorking Endpoints: [bold green]{len(ok)}[/bold green]\nFailed Endpoints: [bold red]{failed}[/bold red]{filter_line}", border_style="green", expand=False))
        if not ok and failed > 0:
            reasons, hints = summarize_failure_diagnostics(results)
            reason_lines = "\n".join(f"- [red]{count}x[/red] {label}" for label, count in reasons)
            hint_lines = "\n".join(f"• {hint}" for hint in hints)
            console.print(
                Panel(
                    f"[bold yellow]No working endpoints found.[/bold yellow]\n\n[bold]Top failure reasons:[/bold]\n{reason_lines}\n\n[bold]Troubleshooting:[/bold]\n{hint_lines}",
                    title="Failure Breakdown",
                    border_style="yellow",
                    expand=False,
                )
            )
            return
        if not ok:
            console.print(Panel("[bold yellow]No endpoints matched the active filters.[/bold yellow]", border_style="yellow", expand=False))
            return
        shown_count = len(display_items)
        title_txt = f"Best Results (Showing {shown_count} of {len(ok)})" if len(ok) > shown_count else "Best Results"
        table = Table(title=title_txt, box=box.ROUNDED, border_style="cyan", expand=False, pad_edge=False)
        if len(ok) > shown_count:
            table.caption = f"[dim]Showing top {shown_count} of {len(ok)} endpoints. Full results saved to {txt_path.name}[/dim]"
        table.add_column("#", justify="right", style="dim", no_wrap=True)
        table.add_column("IP", style="bold white", no_wrap=True)
        table.add_column("Port", justify="center", style="bold cyan", no_wrap=True)
        if has_loc:
            table.add_column("IP Loc", justify="center", style="bright_blue", no_wrap=True)
        if has_colo:
            table.add_column("Colo", justify="center", style="bright_cyan", no_wrap=True)
        if is_full:
            table.add_column("Down", justify="right", style="yellow", no_wrap=True)
            if has_upload:
                table.add_column("Up", justify="right", style="bright_magenta", no_wrap=True)
            table.add_column("Ping", justify="right", style="green", no_wrap=True)
            table.add_column("Jitter", justify="right", style="cyan", no_wrap=True)
            table.add_column("Loss", justify="right", style="magenta", no_wrap=True)
            if has_longevity:
                table.add_column("Drop", justify="center", no_wrap=True)
            table.add_column("Pass", justify="right", no_wrap=True)
            table.add_column("HTTP", justify="right", no_wrap=True, min_width=4)
            for i, r in enumerate(display_items, 1):
                down = f"{r.speed_mbps:.1f}M" if r.speed_mbps is not None else "-"
                up = f"{r.upload_mbps:.1f}M" if r.upload_mbps is not None else "-"
                latency = f"{r.latency_ms:.0f}ms" if r.latency_ms is not None else "-"
                jitter = f"{r.jitter_ms:.0f}ms" if r.jitter_ms is not None else "-"
                loss = f"{r.packet_loss:.0f}%"
                recheck = f"{r.recheck_passed}/{r.recheck_total}" if r.recheck_total else "-"
                row = [str(i), r.ip, str(r.port)]
                if has_loc:
                    row.append(format_ip_location(r.ip_country, r.ip_city) if r.ip_country else "-")
                if has_colo:
                    row.append(format_cf_colo(r.colo, short=True) if r.colo else "-")
                row.append(down)
                if has_upload:
                    row.append(up)
                row.extend([latency, jitter, loss])
                if has_longevity:
                    row.append(_rich_drop_badge(r))
                row.extend([recheck, str(r.status_code or "")])
                table.add_row(*row)
        elif is_longevity:
            table.add_column("Drop", justify="center", no_wrap=True)
            table.add_column("DPI Loss", justify="right", style="magenta", no_wrap=True)
            table.add_column("Ping", justify="right", style="green", no_wrap=True)
            table.add_column("HTTP", justify="right", no_wrap=True, min_width=4)
            for i, r in enumerate(display_items, 1):
                drop_badge = _rich_drop_badge(r)
                loss = f"{r.longevity_loss:.0f}%" if r.longevity_loss is not None else "-"
                latency = f"{r.latency_ms:.0f}ms" if r.latency_ms is not None else "-"
                row = [str(i), r.ip, str(r.port)]
                if has_loc:
                    row.append(format_ip_location(r.ip_country, r.ip_city) if r.ip_country else "-")
                if has_colo:
                    row.append(format_cf_colo(r.colo, short=True) if r.colo else "-")
                row.extend([drop_badge, loss, latency, str(r.status_code or "")])
                table.add_row(*row)
        elif is_speed:
            table.add_column("Down", justify="right", style="yellow", no_wrap=True)
            if has_upload:
                table.add_column("Up", justify="right", style="bright_magenta", no_wrap=True)
            table.add_column("Downloaded", justify="right", style="cyan", no_wrap=True)
            for i, r in enumerate(display_items, 1):
                down = f"{r.speed_mbps:.2f} Mbps" if r.speed_mbps is not None else "-"
                up = f"{r.upload_mbps:.2f} Mbps" if r.upload_mbps is not None else "-"
                row = [str(i), r.ip, str(r.port)]
                if has_loc:
                    row.append(format_ip_location(r.ip_country, r.ip_city) if r.ip_country else "-")
                if has_colo:
                    row.append(format_cf_colo(r.colo, short=True) if r.colo else "-")
                row.append(down)
                if has_upload:
                    row.append(up)
                row.append(str(r.download_bytes or "-"))
                table.add_row(*row)
        elif is_recheck:
            table.add_column("Ping", justify="right", style="green", no_wrap=True)
            table.add_column("Jitter", justify="right", style="cyan", no_wrap=True)
            table.add_column("Loss", justify="right", style="magenta", no_wrap=True)
            if has_longevity:
                table.add_column("Drop", justify="center", no_wrap=True)
            table.add_column("Pass", justify="right", no_wrap=True)
            table.add_column("HTTP", justify="right", no_wrap=True, min_width=4)
            for i, r in enumerate(display_items, 1):
                latency = f"{r.latency_ms:.0f}ms" if r.latency_ms is not None else "-"
                jitter = f"{r.jitter_ms:.0f}ms" if r.jitter_ms is not None else "-"
                loss = f"{r.packet_loss:.0f}%"
                recheck = f"{r.recheck_passed}/{r.recheck_total}" if r.recheck_total else "-"
                row = [str(i), r.ip, str(r.port)]
                if has_loc:
                    row.append(format_ip_location(r.ip_country, r.ip_city) if r.ip_country else "-")
                if has_colo:
                    row.append(format_cf_colo(r.colo, short=True) if r.colo else "-")
                row.extend([latency, jitter, loss])
                if has_longevity:
                    row.append(_rich_drop_badge(r))
                row.extend([recheck, str(r.status_code or "")])
                table.add_row(*row)
        else:
            table.add_column("Ping", justify="right", style="green", no_wrap=True)
            table.add_column("HTTP", justify="right", no_wrap=True, min_width=4)
            for i, r in enumerate(display_items, 1):
                latency = f"{r.latency_ms:.0f}ms" if r.latency_ms is not None else "-"
                row = [str(i), r.ip, str(r.port)]
                if has_loc:
                    row.append(format_ip_location(r.ip_country, r.ip_city) if r.ip_country else "-")
                if has_colo:
                    row.append(format_cf_colo(r.colo, short=True) if r.colo else "-")
                row.extend([latency, str(r.status_code or "")])
                table.add_row(*row)
        console.print(table)

        recs = get_smart_recommendations(ok, vless_config=vless_config)
        render_smart_recommendations(recs, output_dir, save_to_disk=save_recommendations)
    else:
        print(f"\nScan Finished | Working: {len(ok)} | Failed: {failed} | Filtered: {filtered_out}")
        if not ok and failed > 0:
            reasons, hints = summarize_failure_diagnostics(results)
            print("Failure Breakdown:")
            for label, count in reasons:
                print(f"  - {count}x {label}")
            for hint in hints:
                print(f"  * {hint}")
            return
        if not ok:
            print("No endpoints matched the active filters.")
            return
        for i, r in enumerate(display_items, 1):
            loc_str = f" loc={format_ip_location(r.ip_country, r.ip_city)}" if r.ip_country else ""
            colo_str = f" colo={format_cf_colo(r.colo, short=True)}" if r.colo else ""
            http_str = str(r.status_code) if r.status_code is not None else "-"
            if is_full:
                down = f"{r.speed_mbps:.2f} Mbps" if r.speed_mbps is not None else "-"
                up = f"{r.upload_mbps:.2f} Mbps" if r.upload_mbps is not None else "-"
                latency = f"{r.latency_ms:.1f} ms" if r.latency_ms is not None else "-"
                jitter = f"{r.jitter_ms:.1f} ms" if r.jitter_ms is not None else "-"
                loss = f"{r.packet_loss:.0f}%"
                recheck = f"{r.recheck_passed}/{r.recheck_total}" if r.recheck_total else "-"
                drop_txt = f" anti_drop={'OK' if r.sustained else 'DROP'}" if r.sustained is not None else ""
                print(f"{i}. {r.endpoint}{loc_str}{colo_str} down={down} up={up} latency={latency} jitter={jitter} loss={loss}{drop_txt} pass={recheck} HTTP {http_str}")
            elif is_longevity:
                drop_txt = "SUSTAINED" if r.sustained is True else ("DROPPED" if r.sustained is False else "-")
                loss = f"{r.longevity_loss:.0f}%" if r.longevity_loss is not None else "-"
                latency = f"{r.latency_ms:.1f} ms" if r.latency_ms is not None else "-"
                print(f"{i}. {r.endpoint}{loc_str}{colo_str} anti_drop={drop_txt} loss={loss} latency={latency} HTTP {http_str}")
            elif is_speed:
                down = f"{r.speed_mbps:.2f} Mbps" if r.speed_mbps is not None else "-"
                up = f"{r.upload_mbps:.2f} Mbps" if r.upload_mbps is not None else "-"
                print(f"{i}. {r.endpoint}{loc_str}{colo_str} down={down} up={up} downloaded={r.download_bytes or '-'}")
            elif is_recheck:
                latency = f"{r.latency_ms:.1f} ms" if r.latency_ms is not None else "-"
                jitter = f"{r.jitter_ms:.1f} ms" if r.jitter_ms is not None else "-"
                loss = f"{r.packet_loss:.0f}%"
                recheck = f"{r.recheck_passed}/{r.recheck_total}" if r.recheck_total else "-"
                drop_txt = f" anti_drop={'OK' if r.sustained else 'DROP'}" if r.sustained is not None else ""
                print(f"{i}. {r.endpoint}{loc_str}{colo_str} latency_avg={latency} jitter={jitter} loss={loss}{drop_txt} pass={recheck} HTTP {http_str}")
            else:
                latency = f"{r.latency_ms:.1f} ms" if r.latency_ms is not None else "-"
                print(f"{i}. {r.endpoint}{loc_str}{colo_str} latency={latency} HTTP {http_str}")
        if len(ok) > len(display_items):
            print(f"... and {len(ok) - len(display_items)} more endpoints (full list saved to {txt_path.name})")

        recs = get_smart_recommendations(ok, vless_config=vless_config)
        render_smart_recommendations(recs, output_dir, save_to_disk=save_recommendations)


def handle_post_scan_testing_tui(
    v: VlessConfig,
    working_results: List[ScanResult],
    xray: Path,
    concurrency: int,
    timeout: int,
    test_url: str,
    output_dir: Path,
    settings: Optional[AppSettings] = None,
) -> Tuple[List[ScanResult], Path, Path, str]:
    """Unified post-scan testing menu pre-populated from config.txt AppSettings."""
    if not working_results:
        return working_results, output_dir / "clean_ips.txt", output_dir / "clean_ips.csv", "clean_ips"

    cfg = settings or AppSettings()
    def_samples = max(2, min(20, cfg.ping_samples))
    def_longevity = max(0, min(60, cfg.longevity_duration if cfg.longevity_test else 0))
    def_dl = max(0, min(100, cfg.download_mb))
    def_ul = max(0, min(50, cfg.upload_mb))
    def_speed_dur = max(1, min(60, cfg.speed_duration))
    def_workers = max(1, min(30, cfg.speed_workers or min(concurrency, 5)))
    mode_to_idx = {"full": 0, "stability": 1, "longevity": 2, "speed": 3, "none": 4}
    default_menu_idx = mode_to_idx.get(cfg.post_scan_mode, 0)

    menu_rows = [
        ("Full Quality Test (Recommended)", "Stability (Loss% + Jitter) + Anti-Drop + Download & Upload Speed"),
        ("Stability & Jitter Test only", "Measure Packet Loss% and Latency Jitter across multiple pings"),
        ("Anti-Drop / DPI Endurance only", f"Test connection endurance ({max(5, def_longevity or 30)}s) against DPI throttling & drops"),
        ("Speed Test (Download & Upload)", "Measure download and upload speed (Mbps) for working endpoints"),
        ("Skip Post-Scan Testing", "Keep initial scan results and proceed to final menu"),
    ]
    try:
        choice = key_select_menu(
            "Quality & Speed Testing (Step 5)", menu_rows, default_index=default_menu_idx, allow_back=True
        )
    except NavigationBack:
        return working_results, output_dir / "clean_ips.txt", output_dir / "clean_ips.csv", "clean_ips"

    if choice == 4:
        return working_results, output_dir / "clean_ips.txt", output_dir / "clean_ips.csv", "clean_ips"

    max_candidates = len(working_results)
    cfg_top = cfg.top_targets if cfg.top_targets > 0 else max_candidates
    default_test_count = max(1, min(cfg_top, max_candidates))

    try:
        test_count = prompt_int_nav("Number of top endpoints to test", default_test_count, 1, max_candidates, allow_back=True)
        mode_map = {0: "full", 1: "stability", 2: "longevity", 3: "speed"}
        mode = mode_map[choice]
        sample_count = 0
        longevity_duration = 0
        speed_mb, upload_mb, speed_duration = 0, 0, 0

        if mode in ("full", "stability"):
            sample_count = prompt_int_nav("Ping samples per IP for jitter & loss", def_samples, 2, 20, allow_back=True)
        if mode == "full":
            longevity_duration = prompt_int_nav(
                "Anti-Drop endurance duration (seconds, 0 to skip)", def_longevity, 0, 60, allow_back=True
            )
        elif mode == "longevity":
            longevity_duration = prompt_int_nav(
                "Anti-Drop endurance duration (seconds)", max(5, def_longevity or 30), 5, 60, allow_back=True
            )
        if mode in ("full", "speed"):
            speed_mb = prompt_int_nav("Download size per IP (MB, 0 to skip)", def_dl, 0, 100, allow_back=True)
            upload_mb = prompt_int_nav("Upload size per IP (MB, 0 to skip)", def_ul, 0, 50, allow_back=True)
            speed_duration = prompt_int_nav("Speed test duration limit (seconds)", def_speed_dur, 1, 60, allow_back=True)

        w_default = min(concurrency, 10) if mode == "stability" and settings is None else def_workers
        w_max = 50 if mode == "stability" else 30
        workers = prompt_int_nav("Testing workers", max(1, min(w_default, w_max)), 1, w_max, allow_back=True)
    except NavigationBack:
        return working_results, output_dir / "clean_ips.txt", output_dir / "clean_ips.csv", "clean_ips"

    from scanner.engine import execute_configured_post_scan_tests
    from scanner.ui.terminal import cprint, progress_reporter, render_stage

    post_settings = AppSettings(
        post_scan_mode=mode,
        top_targets=test_count,
        ping_samples=sample_count,
        longevity_test=(longevity_duration > 0),
        longevity_duration=longevity_duration,
        download_mb=speed_mb,
        upload_mb=upload_mb,
        speed_duration=speed_duration,
        speed_workers=workers,
        timeout=timeout,
        test_url=test_url,
    )

    return execute_configured_post_scan_tests(
        post_settings,
        v,
        working_results,
        xray,
        output_dir,
        on_stage=render_stage,
        on_message=cprint,
        make_reporter=progress_reporter,
        strict_top_targets=True,
    )

