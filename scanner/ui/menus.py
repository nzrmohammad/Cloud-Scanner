import re
from typing import Any, List, Optional, Set, Tuple

from scanner.models import NavigationBack, ScanResult, VlessConfig
from scanner.ui.keys import read_key, terminal_supports_keys
from scanner.ui.terminal import (
    RICH,
    box,
    clear_screen,
    console,
    cprint,
    make_fixed_header_panel,
    prompt_str,
    render_stage,
)

try:
    from rich.console import Group
    from rich.live import Live
    from rich.panel import Panel
    from rich.table import Table
except ImportError:
    Group = None  # type: ignore
    Live = None  # type: ignore
    Panel = None  # type: ignore
    Table = None  # type: ignore


def parse_multi_select(raw: str, total: int) -> List[int]:
    """Parse selection string like '1,3,5' or '1-4' or 'all' into a list of 0-based indices."""
    raw = raw.strip().lower()
    if raw in {"all", "a", "*"}:
        return list(range(total))
    selected: Set[int] = set()
    for part in re.split(r"[\s,]+", raw):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            a, b = part.split("-", 1)
            if not a.isdigit() or not b.isdigit():
                raise ValueError("Invalid range selection")
            start, end = int(a), int(b)
            if start > end:
                start, end = end, start
            for n in range(start, end + 1):
                if not 1 <= n <= total:
                    raise ValueError("Selection out of range")
                selected.add(n - 1)
        else:
            if not part.isdigit():
                raise ValueError("Invalid selection")
            n = int(part)
            if not 1 <= n <= total:
                raise ValueError("Selection out of range")
            selected.add(n - 1)
    if not selected:
        raise ValueError("No item selected")
    return sorted(selected)


def build_menu_renderable(
    title: str,
    rows: List[Tuple[str, str]],
    cursor: int,
    selected: Optional[Set[int]] = None,
    typed: str = "",
    multi: bool = False,
    allow_back: bool = True,
    top_panel: Optional[Any] = None,
    error_msg: str = "",
) -> Any:
    selected = selected or set()
    total_items = len(rows)

    import shutil

    if RICH and console is not None:
        term_cols, term_lines = console.size.width, console.size.height
    else:
        ts = shutil.get_terminal_size((80, 25))
        term_cols, term_lines = ts.columns, ts.lines

    overhead = 14 + (1 if multi else 0) + (1 if typed else 0) + (1 if error_msg else 0)
    if term_cols < 80:
        overhead += 2
    if top_panel is not None:
        raw_top = getattr(top_panel, "renderable", "")
        top_lines = (str(raw_top).count("\n") + 1) if isinstance(raw_top, str) and raw_top else 5
        overhead += max(5, top_lines + 3)
    available_lines = max(3, term_lines - overhead)
    max_visible = min(total_items, available_lines)

    if total_items <= max_visible:
        start_idx = 0
        end_idx = total_items
    else:
        half = max_visible // 2
        if cursor < half:
            start_idx = 0
        elif cursor >= total_items - (max_visible - half):
            start_idx = total_items - max_visible
        else:
            start_idx = cursor - half
        end_idx = min(total_items, start_idx + max_visible)

    if not (RICH and Table is not None and Panel is not None):
        return None

    elements = []
    header = make_fixed_header_panel(compact=True, show_controls=False)
    if header is not None:
        elements.append(header)
    if top_panel is not None:
        elements.append(top_panel)

    raw_title = f"{title} [{cursor + 1}/{total_items}]" if total_items > (end_idx - start_idx) else title
    max_title_len = max(20, term_cols - 4)
    title_display = raw_title if len(raw_title) <= max_title_len else (raw_title[: max_title_len - 3] + "...")

    item_w = max(14, min(38, (term_cols - 26) // 2))
    info_w = max(12, min(52, term_cols - item_w - 26))

    table = Table(title=title_display, box=box.ROUNDED, border_style="bright_blue", expand=False)
    table.add_column("", justify="center", width=3, no_wrap=True)
    table.add_column("#", justify="right", width=4, style="cyan", no_wrap=True)
    table.add_column("Item", style="bold white", width=item_w, max_width=item_w, no_wrap=True, overflow="ellipsis")
    table.add_column("Info", style="dim", width=info_w, max_width=info_w, no_wrap=True, overflow="ellipsis")

    visible_count = end_idx - start_idx
    for i in range(start_idx, end_idx):
        name, detail = rows[i]
        marker = ">" if i == cursor else " "
        check = "[x]" if i in selected else "[ ]"
        icon = check if multi else marker
        row_style = "bold black on cyan" if i == cursor else ("green" if i in selected else "")
        table.add_row(icon, str(i + 1), name, detail, style=row_style)

    # Pad empty rows to maintain fixed table height when scrolling paginated lists
    if total_items > max_visible and visible_count < max_visible:
        for _ in range(max_visible - visible_count):
            table.add_row("", "", "", "")

    elements.append(table)

    help_lines = [
        "[bold]Up/Down[/bold]=move  [bold]PgUp/PgDn[/bold]=±10  [bold]Enter[/bold]=confirm"
        + ("  [bold]B/Esc[/bold]=back" if allow_back else "")
    ]
    if multi:
        help_lines.append(
            f"[bold]Space[/bold]=toggle  [bold]A[/bold]=all  [bold]N[/bold]=none  | Selected: [cyan]{len(selected)}/{total_items}[/cyan]"
        )
        help_lines.append("[dim]Type # (1 | 1,3,5 | 1-20) then Enter[/dim]")
    else:
        help_lines.append("[dim]Numeric shortcut: type item # then Enter[/dim]")
    if typed:
        help_lines.append(f"[yellow]Typed:[/yellow] {typed[:40]}")
    if error_msg:
        help_lines.append(f"[bold red]Error:[/bold red] {error_msg[:60]}")

    elements.append(Panel("\n".join(help_lines), border_style="magenta", expand=False))
    if Group is not None:
        return Group(*elements)
    return elements


def render_key_menu(
    title: str,
    rows: List[Tuple[str, str]],
    cursor: int,
    selected: Optional[Set[int]] = None,
    typed: str = "",
    multi: bool = False,
    allow_back: bool = True,
    top_panel: Optional[Any] = None,
    error_msg: str = "",
) -> None:
    clear_screen()
    if RICH and console is not None and Table is not None and Panel is not None:
        renderable = build_menu_renderable(
            title,
            rows,
            cursor,
            selected=selected,
            typed=typed,
            multi=multi,
            allow_back=allow_back,
            top_panel=top_panel,
            error_msg=error_msg,
        )
        if renderable is not None:
            console.print(renderable)
            return

    selected = selected or set()
    total_items = len(rows)
    print(title)
    for i in range(total_items):
        name, detail = rows[i]
        prefix = ">" if i == cursor else " "
        check = "[x]" if i in selected else "[ ]"
        print(f"{prefix} {check if multi else ''} {i+1}) {name} {detail}")
    print("Use arrows/Enter, or type numbers. B/Esc = back.")
    if typed:
        print(f"Typed: {typed}")
    if error_msg:
        print(f"Error: {error_msg}")


def _render_non_tty_fallback_menu(
    title: str,
    rows: List[Tuple[str, str]],
    *,
    multi: bool,
    allow_back: bool,
    top_panel: Optional[Any] = None,
) -> None:
    """Render static numbered table for non-TTY / fallback input."""
    subtitle = (
        "Select one or more items by number, range, or all. Type b/back to return."
        if multi
        else ("Select with number. Type b/back to return." if allow_back else "Select with number.")
    )
    color = "green" if multi else "cyan"
    render_stage(title, subtitle, color)
    if top_panel is not None and RICH and console is not None:
        console.print(top_panel)
        console.print()
    if RICH and console is not None and Table is not None:
        table = Table(title=title, box=box.ROUNDED, border_style=color)
        table.add_column("#", justify="right", style=f"bold {color}")
        table.add_column("Item", style="bold white")
        table.add_column("Info", style="dim")
        for i, (name, detail) in enumerate(rows, 1):
            table.add_row(str(i), name, detail)
        console.print(table)
    else:
        for i, (name, detail) in enumerate(rows, 1):
            print(f"{i}) {name} {detail}")


def _run_interactive_menu_loop(
    title: str,
    rows: List[Tuple[str, str]],
    *,
    cursor: int = 0,
    multi: bool = False,
    allow_back: bool = True,
    top_panel: Optional[Any] = None,
) -> List[int]:
    """Unified Live/fallback raw-keyboard menu loop for single-select and multi-select."""
    selected: Set[int] = set()
    typed = ""
    error_msg = ""
    total = len(rows)

    def _make_renderable():
        return build_menu_renderable(
            title,
            rows,
            cursor,
            selected=selected if multi else None,
            typed=typed,
            multi=multi,
            allow_back=allow_back,
            top_panel=top_panel,
            error_msg=error_msg,
        )

    def _process_key(key: str) -> Optional[List[int]]:
        nonlocal cursor, typed, error_msg, selected
        if error_msg:
            error_msg = ""

        if key == "up":
            cursor = (cursor - 1) % total
        elif key == "down":
            cursor = (cursor + 1) % total
        elif key == "page_up":
            cursor = max(0, cursor - 10)
        elif key == "page_down":
            cursor = min(total - 1, cursor + 10)
        elif key == "home":
            cursor = 0
        elif key == "end":
            cursor = total - 1
        elif key == "esc":
            if allow_back:
                raise NavigationBack
        elif key == "backspace":
            typed = typed[:-1]
        elif key == "space":
            if multi:
                if typed:
                    typed += " "
                elif cursor in selected:
                    selected.remove(cursor)
                else:
                    selected.add(cursor)
        elif key == "enter":
            if typed:
                raw = typed.strip().lower()
                typed = ""
                if allow_back and raw in {"b", "back", "0", "q", "quit", "exit"}:
                    raise NavigationBack
                if multi:
                    try:
                        return parse_multi_select(raw, total)
                    except Exception as exc:
                        error_msg = f"Invalid selection: {exc}"
                        return None
                if raw.isdigit() and 1 <= int(raw) <= total:
                    return [int(raw) - 1]
                error_msg = f"Invalid selection: {raw}. Choose 1-{total}."
                return None

            if not multi:
                return [cursor]
            if selected:
                return sorted(selected)
            selected.add(cursor)
            return sorted(selected)
        elif len(key) == 1:
            low = key.lower()
            if allow_back and low in {"b", "q"} and not typed:
                raise NavigationBack
            if multi:
                if low == "a" and not typed:
                    selected = set(range(total))
                elif low == "n" and not typed:
                    selected.clear()
                elif key in "0123456789,-*":
                    typed += key
            else:
                if key in "0123456789":
                    candidate = int(key)
                    if not typed and 1 <= candidate <= total <= 9:
                        return [candidate - 1]
                    typed += key
        return None

    clear_screen()
    if RICH and console is not None and Live is not None:
        try:
            with Live(
                _make_renderable(),
                console=console,
                auto_refresh=False,
                transient=True,
                vertical_overflow="crop",
            ) as live:
                while True:
                    key = read_key()
                    res = _process_key(key)
                    if res is not None:
                        return res
                    live.update(_make_renderable(), refresh=True)
        finally:
            clear_screen()
    else:
        while True:
            render_key_menu(
                title,
                rows,
                cursor,
                selected=selected if multi else None,
                typed=typed,
                multi=multi,
                allow_back=allow_back,
                top_panel=top_panel,
                error_msg=error_msg,
            )
            key = read_key()
            res = _process_key(key)
            if res is not None:
                return res


def key_select_menu(
    title: str,
    rows: List[Tuple[str, str]],
    default_index: int = 0,
    allow_back: bool = True,
    top_panel: Optional[Any] = None,
) -> int:
    """Single-select menu with arrows plus numeric fallback."""
    if not rows:
        raise ValueError("Menu has no items")
    if not terminal_supports_keys():
        _render_non_tty_fallback_menu(title, rows, multi=False, allow_back=allow_back, top_panel=top_panel)
        while True:
            raw = prompt_str("Select item" + (" / b=back" if allow_back else ""), str(default_index + 1)).strip().lower()
            if allow_back and raw in {"b", "back", "0", "q", "quit", "exit"}:
                raise NavigationBack
            if raw.isdigit() and 1 <= int(raw) <= len(rows):
                return int(raw) - 1
            cprint(f"Please choose 1-{len(rows)}.", "yellow")

    cursor = max(0, min(default_index, len(rows) - 1))
    return _run_interactive_menu_loop(
        title, rows, cursor=cursor, multi=False, allow_back=allow_back, top_panel=top_panel
    )[0]


def key_multi_select_menu(title: str, rows: List[Tuple[str, str]], allow_back: bool = True) -> List[int]:
    """Multi-select menu with arrows/space plus numeric range syntax."""
    if not rows:
        raise ValueError("Menu has no items")
    if not terminal_supports_keys():
        _render_non_tty_fallback_menu(title, rows, multi=True, allow_back=allow_back)
        cprint("Select one or more items. Examples: 1 | 1,3,5 | 2-6 | all | b=back", "dim")
        while True:
            raw = prompt_str("Selection", "all")
            if allow_back and raw.strip().lower() in {"b", "back", "0", "q", "quit", "exit"}:
                raise NavigationBack
            try:
                return parse_multi_select(raw, len(rows))
            except Exception as exc:
                cprint(f"Invalid selection: {exc}", "red")

    return _run_interactive_menu_loop(title, rows, cursor=0, multi=True, allow_back=allow_back)


def post_scan_actions_menu(
    v: VlessConfig,
    final_results: List[ScanResult],
    filename_prefix: str = "",
) -> str:
    """Action menu after scan and tests complete:
    - 'rescan_all': Start a fresh scan with target selection
    - 'retest_same': Retest the exact same targets again immediately
    - 'exit': Exit program
    """
    from scanner.analytics import get_smart_recommendations

    recs = get_smart_recommendations(final_results, vless_config=v)
    info_parts = []
    for rec in recs[:2]:
        info_parts.append(f"{rec.icon} {rec.category.split('/')[0].strip()}: {rec.result.endpoint}")
    summary = " | ".join(info_parts) if info_parts else "Scan finished"

    menu_rows = [
        ("Scan Again / New Targets", "Start a new scan with new or existing targets/ports"),
        ("Retest Same Targets", "Immediately run scan on the same targets again"),
        ("Exit", "Finish and close the scanner"),
    ]
    top_panel: Optional[Any] = (
        Panel(f"[bold green]Top Highlights:[/bold green] {summary}", border_style="green", box=box.ROUNDED, expand=False)
        if (info_parts and RICH and Panel is not None and box is not None)
        else None
    )
    choice = key_select_menu("Next Action", menu_rows, default_index=0, allow_back=False, top_panel=top_panel)

    if choice == 0:
        return "rescan_all"
    elif choice == 1:
        return "retest_same"
    else:
        return "exit"


build_key_menu_renderable = build_menu_renderable
