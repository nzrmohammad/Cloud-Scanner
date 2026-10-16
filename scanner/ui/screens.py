import re
from pathlib import Path
from typing import Any, List, Optional, Tuple

from scanner.analytics import (
    apply_result_filters,
    get_smart_recommendations,
    output_sort_key,
)
from scanner.config import load_saved_vless_config, parse_vless, save_vless_config
from scanner.constants import (
    ISP_CATEGORIES,
    LATENCY_TEST_URLS,
    MAX_DEFAULT_HOSTS,
    format_cf_colo,
)
from scanner.geoip import format_ip_location
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
    prompt_confirm_nav,
    prompt_continue_nav,
    prompt_int_nav,
    prompt_str,
    render_fixed_header,
    render_stage,
    show_banner,
)
from scanner.xray import get_environment_status

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


def make_active_settings_panel(v: Optional[VlessConfig], settings: Optional[AppSettings]) -> Optional[Any]:
    """Create a concise, elegant summary panel of settings loaded from config.txt."""
    if not v or not settings or not RICH or Panel is None:
        return None
    ports_str = ", ".join(str(p) for p in (settings.ports if settings.ports else [v.port]))
    mode_str = settings.post_scan_mode.upper()
    max_t_str = "Unlimited" if settings.max_targets == 0 else str(settings.max_targets)
    top_t_desc = "All working IPs" if settings.top_targets == 0 else f"Top {settings.top_targets}"
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
        ports_str = ", ".join(str(p) for p in (settings.ports if settings.ports else [v.port]))
        mode_str = settings.post_scan_mode.upper()
        max_t_str = "Unlimited" if settings.max_targets == 0 else str(settings.max_targets)
        top_t_desc = "All working IPs" if settings.top_targets == 0 else f"Top {settings.top_targets}"
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
        table = Table(title="Startup Check", box=box.ROUNDED, border_style="cyan")
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
            try:
                parsed_saved = parse_vless(saved_config)
                info = f"[cyan]{parsed_saved.remark}[/cyan] ([green]{parsed_saved.host}:{parsed_saved.port}[/green])"
            except Exception:
                info = saved_config[:40] + "..."

            if settings:
                ports_str = ", ".join(str(p) for p in (settings.ports if settings.ports else [parsed_saved.port]))
                mode_str = settings.post_scan_mode.upper()
                max_t_str = "Unlimited" if settings.max_targets == 0 else str(settings.max_targets)
                top_t_desc = "All working IPs" if settings.top_targets == 0 else f"Top {settings.top_targets}"
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
                "[dim]q/exit = quit. This first page replaces the old separate startup screen.[/dim]"
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
        table = Table(title="Configuration Summary", box=box.ROUNDED, border_style="green")
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
        if not render_welcome_config_screen(xray, error, saved_config=saved_config):
            cprint("\nMissing required runtime files/dependencies. Fix them and run again.", "yellow")
            pause("Press Enter to exit")
            raise NavigationExit
        raw = prompt_str("VLESS config", default=saved_config if saved_config else None)
        if not raw and saved_config:
            raw = saved_config
        if raw.strip().lower() in {"q", "quit", "exit", "b", "back"}:
            raise NavigationExit
        try:
            v = parse_vless(raw)
            save_vless_config(raw)
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
                raw = Prompt.ask("[bold yellow]Maximum targets to load/scan[/bold yellow] [dim](default unlimited, b=back)[/dim]", default="")
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
            raw = ""
        if not raw:
            if lines:
                break
            cprint("Enter at least one target, or type b/back to return.", "yellow")
            continue
        if not lines and is_back_value(raw):
            raise NavigationBack
        lines.append(raw)

    blob = "\n".join(lines)
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
                raise


def choose_latency_test_url_tui() -> str:
    rows = [(name, url) for name, url, _detail in LATENCY_TEST_URLS]
    idx = key_select_menu("Latency Test URL", rows, default_index=0, allow_back=True)
    return LATENCY_TEST_URLS[idx][1]




def render_smart_recommendations(recs: List[SmartRecommendation], output_dir: Path) -> None:
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

    from scanner.storage import save_recommended_configs
    save_recommended_configs(recs, output_dir)


def show_final_results(
    results: List[ScanResult],
    txt_path: Path,
    csv_path: Path,
    max_latency_ms: float = 0,
    min_speed_mbps: float = 0,
    filename_prefix: str = "clean_ips",
    vless_config: Optional[VlessConfig] = None,
) -> None:
    ok = apply_result_filters(results, max_latency_ms=max_latency_ms, min_speed_mbps=min_speed_mbps)
    ok = sorted(ok, key=output_sort_key(filename_prefix))
    failed = len([r for r in results if not r.ok])
    filtered_out = len([r for r in results if r.ok]) - len(ok)
    is_full = "full" in filename_prefix or any(r.jitter_ms is not None and r.speed_mbps is not None for r in ok)
    is_speed = "speed" in filename_prefix and not is_full
    is_recheck = "rechecked" in filename_prefix and not is_full

    output_dir = txt_path.parent
    display_limit = 25
    display_items = ok[:display_limit]

    if RICH and console is not None and Panel is not None and Table is not None:
        has_longevity = any(r.sustained is not None for r in ok)
        has_colo = any(bool(r.colo) for r in ok)
        has_loc = any(bool(r.ip_country) for r in ok)
        has_upload = any(r.upload_mbps is not None for r in ok)
        is_longevity = "longevity" in filename_prefix and not is_full

        filter_line = ""
        if max_latency_ms > 0 or min_speed_mbps > 0:
            filter_line = f"\nFiltered out: [bold yellow]{filtered_out}[/bold yellow]"
        console.print(Panel(f"[bold green]Scan Finished[/bold green]\n\nWorking Endpoints: [bold green]{len(ok)}[/bold green]\nFailed Endpoints: [bold red]{failed}[/bold red]{filter_line}", border_style="green", expand=False))
        title_txt = f"Best Results (Showing {min(len(ok), display_limit)} of {len(ok)})" if len(ok) > display_limit else "Best Results"
        table = Table(title=title_txt, box=box.ROUNDED, border_style="cyan", expand=False, pad_edge=False)
        if len(ok) > display_limit:
            table.caption = f"[dim]Showing top {display_limit} of {len(ok)} endpoints. Full results saved to {txt_path.name}[/dim]"
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
                    if r.sustained is True:
                        row.append("[green]Pass[/green]")
                    elif r.sustained is False:
                        row.append("[red]Drop[/red]")
                    else:
                        row.append("-")
                row.extend([recheck, str(r.status_code or "")])
                table.add_row(*row)
        elif is_longevity:
            table.add_column("Drop", justify="center", no_wrap=True)
            table.add_column("DPI Loss", justify="right", style="magenta", no_wrap=True)
            table.add_column("Ping", justify="right", style="green", no_wrap=True)
            table.add_column("HTTP", justify="right", no_wrap=True, min_width=4)
            for i, r in enumerate(display_items, 1):
                drop_badge = "[green]Pass[/green]" if r.sustained else "[red]Drop[/red]"
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
                    if r.sustained is True:
                        row.append("[green]Pass[/green]")
                    elif r.sustained is False:
                        row.append("[red]Drop[/red]")
                    else:
                        row.append("-")
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
        render_smart_recommendations(recs, output_dir)
    else:
        has_longevity = any(r.sustained is not None for r in ok)
        has_colo = any(bool(r.colo) for r in ok)
        has_loc = any(bool(r.ip_country) for r in ok)
        is_longevity = "longevity" in filename_prefix and not is_full
        print(f"\nScan Finished | Working: {len(ok)} | Failed: {failed} | Filtered: {filtered_out}")
        for i, r in enumerate(display_items, 1):
            loc_str = f" loc={format_ip_location(r.ip_country, r.ip_city)}" if r.ip_country else ""
            colo_str = f" colo={format_cf_colo(r.colo, short=True)}" if r.colo else ""
            if is_full:
                down = f"{r.speed_mbps:.2f} Mbps" if r.speed_mbps is not None else "-"
                up = f"{r.upload_mbps:.2f} Mbps" if r.upload_mbps is not None else "-"
                latency = f"{r.latency_ms:.1f} ms" if r.latency_ms is not None else "-"
                jitter = f"{r.jitter_ms:.1f} ms" if r.jitter_ms is not None else "-"
                loss = f"{r.packet_loss:.0f}%"
                recheck = f"{r.recheck_passed}/{r.recheck_total}" if r.recheck_total else "-"
                drop_txt = f" anti_drop={'OK' if r.sustained else 'DROP'}" if r.sustained is not None else ""
                print(f"{i}. {r.ip}:{r.port}{loc_str}{colo_str} down={down} up={up} latency={latency} jitter={jitter} loss={loss}{drop_txt} pass={recheck} HTTP {r.status_code}")
            elif is_longevity:
                drop_txt = "SUSTAINED" if r.sustained else "DROPPED"
                loss = f"{r.longevity_loss:.0f}%" if r.longevity_loss is not None else "-"
                latency = f"{r.latency_ms:.1f} ms" if r.latency_ms is not None else "-"
                print(f"{i}. {r.ip}:{r.port}{loc_str}{colo_str} anti_drop={drop_txt} loss={loss} latency={latency} HTTP {r.status_code}")
            elif is_speed:
                down = f"{r.speed_mbps:.2f} Mbps" if r.speed_mbps is not None else "-"
                up = f"{r.upload_mbps:.2f} Mbps" if r.upload_mbps is not None else "-"
                print(f"{i}. {r.ip}:{r.port}{loc_str}{colo_str} down={down} up={up} downloaded={r.download_bytes or '-'}")
            elif is_recheck:
                latency = f"{r.latency_ms:.1f} ms" if r.latency_ms is not None else "-"
                jitter = f"{r.jitter_ms:.1f} ms" if r.jitter_ms is not None else "-"
                loss = f"{r.packet_loss:.0f}%"
                recheck = f"{r.recheck_passed}/{r.recheck_total}" if r.recheck_total else "-"
                drop_txt = f" anti_drop={'OK' if r.sustained else 'DROP'}" if r.sustained is not None else ""
                print(f"{i}. {r.ip}:{r.port}{loc_str}{colo_str} latency_avg={latency} jitter={jitter} loss={loss}{drop_txt} pass={recheck} HTTP {r.status_code}")
            else:
                latency = f"{r.latency_ms:.1f} ms" if r.latency_ms is not None else "-"
                print(f"{i}. {r.ip}:{r.port}{loc_str}{colo_str} latency={latency} HTTP {r.status_code}")
        if len(ok) > display_limit:
            print(f"... and {len(ok) - display_limit} more endpoints (full list saved to {txt_path.name})")

        recs = get_smart_recommendations(ok, vless_config=vless_config)
        render_smart_recommendations(recs, output_dir)


def handle_post_scan_testing_tui(
    v: VlessConfig,
    working_results: List[ScanResult],
    xray: Path,
    concurrency: int,
    timeout: int,
    test_url: str,
    output_dir: Path,
) -> Tuple[List[ScanResult], Path, Path, str]:
    """Unified post-scan testing menu: combines Stability/Jitter, Anti-Drop, and Speed Test."""
    if not working_results:

        return working_results, output_dir / "clean_ips.txt", output_dir / "clean_ips.csv", "clean_ips"

    menu_rows = [
        ("Full Quality Test (Recommended)", "Stability (Loss% + Jitter) + Anti-Drop + Download & Upload Speed"),
        ("Stability & Jitter Test only", "Measure Packet Loss% and Latency Jitter across multiple pings"),
        ("Anti-Drop / DPI Endurance only", "Test connection endurance (15s) against DPI throttling & drops"),
        ("Speed Test (Download & Upload)", "Measure download and upload speed (Mbps) for working endpoints"),
        ("Skip Post-Scan Testing", "Keep initial scan results and proceed to final menu"),
    ]
    try:
        choice = key_select_menu("Quality & Speed Testing (Step 5)", menu_rows, default_index=0, allow_back=True)
    except NavigationBack:
        return working_results, output_dir / "clean_ips.txt", output_dir / "clean_ips.csv", "clean_ips"

    if choice == 4:
        return working_results, output_dir / "clean_ips.txt", output_dir / "clean_ips.csv", "clean_ips"

    max_candidates = len(working_results)
    default_test_count = min(10, max_candidates)

    try:
        test_count = prompt_int_nav("Number of top endpoints to test", default_test_count, 1, max_candidates, allow_back=True)
    except NavigationBack:
        return working_results, output_dir / "clean_ips.txt", output_dir / "clean_ips.csv", "clean_ips"

    # Mode 0: Full Quality Test

    if choice == 0:
        try:
            sample_count = prompt_int_nav("Ping samples per IP for jitter & loss", 8, 2, 20, allow_back=True)
            longevity_duration = prompt_int_nav("Anti-Drop endurance duration (seconds, 0 to skip)", 30, 0, 60, allow_back=True)
            speed_mb = prompt_int_nav("Download size per IP (MB)", 5, 1, 100, allow_back=True)
            upload_mb = prompt_int_nav("Upload size per IP (MB, 0 to skip)", 1, 0, 50, allow_back=True)
            speed_duration = prompt_int_nav("Speed test duration limit (seconds)", 5, 1, 60, allow_back=True)
            workers = prompt_int_nav("Testing workers", min(concurrency, 5), 1, 30, allow_back=True)
        except NavigationBack:
            return working_results, output_dir / "clean_ips.txt", output_dir / "clean_ips.csv", "clean_ips"
        mode = "full"
    # Mode 1: Stability & Jitter only
    elif choice == 1:
        try:
            sample_count = prompt_int_nav("Ping samples per IP for jitter & loss", 8, 2, 20, allow_back=True)
            workers = prompt_int_nav("Testing workers", min(concurrency, 10), 1, 50, allow_back=True)
        except NavigationBack:
            return working_results, output_dir / "clean_ips.txt", output_dir / "clean_ips.csv", "clean_ips"
        mode = "stability"
        longevity_duration = 0
        speed_mb, upload_mb, speed_duration = 0, 0, 0
    # Mode 2: Anti-Drop / DPI Endurance only
    elif choice == 2:
        try:
            longevity_duration = prompt_int_nav("Anti-Drop endurance duration (seconds)", 30, 5, 60, allow_back=True)
            workers = prompt_int_nav("Testing workers", min(concurrency, 5), 1, 30, allow_back=True)
        except NavigationBack:
            return working_results, output_dir / "clean_ips.txt", output_dir / "clean_ips.csv", "clean_ips"
        mode = "longevity"
        sample_count = 0
        speed_mb, upload_mb, speed_duration = 0, 0, 0
    # Mode 3: Speed Test only
    else:
        try:
            speed_mb = prompt_int_nav("Download size per IP (MB)", 5, 1, 100, allow_back=True)
            upload_mb = prompt_int_nav("Upload size per IP (MB, 0 to skip)", 1, 0, 50, allow_back=True)
            speed_duration = prompt_int_nav("Speed test duration limit (seconds)", 5, 1, 60, allow_back=True)
            workers = prompt_int_nav("Testing workers", min(concurrency, 5), 1, 30, allow_back=True)
        except NavigationBack:
            return working_results, output_dir / "clean_ips.txt", output_dir / "clean_ips.csv", "clean_ips"
        mode = "speed"
        sample_count = 0
        longevity_duration = 0

    from scanner.engine import execute_configured_post_scan_tests
    from scanner.models import AppSettings
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
    )

