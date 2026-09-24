import re
import sys
import time
from typing import Any, List, Optional, Set, Tuple

from scanner.models import NavigationBack, ScanResult, VlessConfig
from scanner.ui.keys import read_key, terminal_supports_keys
from scanner.ui.terminal import (
    RICH,
    box,
    clear_screen,
    console,
    cprint,
    prompt_str,
    render_fixed_header,
    render_stage,
)

try:
    from rich.panel import Panel
    from rich.table import Table
except ImportError:
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


def render_key_menu(
    title: str,
    rows: List[Tuple[str, str]],
    cursor: int,
    selected: Optional[Set[int]] = None,
    typed: str = "",
    multi: bool = False,
    allow_back: bool = True,
    top_panel: Optional[Any] = None,
) -> None:
    clear_screen()
    selected = selected or set()
    total_items = len(rows)

    import shutil
    term_lines = shutil.get_terminal_size((80, 25)).lines
    overhead = 18 if top_panel is not None else 12
    max_visible = max(6, min(total_items, term_lines - overhead))

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

    if RICH and console is not None and Table is not None and Panel is not None:
        render_fixed_header(compact=True, show_controls=True)
        if top_panel is not None:
            console.print(top_panel)
            console.print()

        title_display = f"{title} [{cursor + 1}/{total_items}]" if total_items > (end_idx - start_idx) else title
        table = Table(title=title_display, box=box.ROUNDED, border_style="bright_blue")
        table.add_column("", justify="center", width=4)
        table.add_column("#", justify="right", width=4, style="cyan")
        table.add_column("Item", style="bold white")
        table.add_column("Info", style="dim")

        for i in range(start_idx, end_idx):
            name, detail = rows[i]
            marker = ">" if i == cursor else " "
            check = "[x]" if i in selected else "[ ]"
            icon = check if multi else marker
            row_style = "bold black on cyan" if i == cursor else ("green" if i in selected else "")
            table.add_row(icon, str(i + 1), name, detail, style=row_style)

        console.print(table)
        help_text = "[bold]Enter[/bold]=confirm/select   [bold]Up/Down[/bold]=move   [bold]PgUp/PgDn[/bold]=jump 10"
        if multi:
            help_text += "   [bold]Space[/bold]=toggle   [bold]A[/bold]=all   [bold]N[/bold]=none"
        if allow_back:
            help_text += "   [bold]B/Esc[/bold]=back"
        help_text += (
            f"\n[dim]Selected: {len(selected)}/{total_items} items | Numbers: type item # then Enter | Examples: 1 | 1,3,5 | 1-20 | all[/dim]"
            if multi
            else "\n[dim]Numeric input: type item number then Enter[/dim]"
        )
        if typed:
            help_text += f"\n[yellow]Typed:[/yellow] {typed}"
        console.print(Panel(help_text, border_style="magenta", expand=False))
    else:
        print(title)
        for i in range(start_idx, end_idx):
            name, detail = rows[i]
            prefix = ">" if i == cursor else " "
            check = "[x]" if i in selected else "[ ]"
            print(f"{prefix} {check if multi else ''} {i+1}) {name} {detail}")
        print("Use arrows/Enter, or type numbers. B/Esc = back.")
        if typed:
            print(f"Typed: {typed}")


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
        render_stage(title, "Select with number. Type b/back to return." if allow_back else "Select with number.", "cyan")
        if top_panel is not None and RICH and console is not None:
            console.print(top_panel)
            console.print()
        if RICH and console is not None and Table is not None:
            table = Table(title=title, box=box.ROUNDED, border_style="cyan")
            table.add_column("#", justify="right", style="bold cyan")
            table.add_column("Item", style="bold white")
            table.add_column("Info", style="dim")
            for i, (name, detail) in enumerate(rows, 1):
                table.add_row(str(i), name, detail)
            console.print(table)
        else:
            for i, (name, detail) in enumerate(rows, 1):
                print(f"{i}) {name} {detail}")
        while True:
            raw = prompt_str("Select item" + (" / b=back" if allow_back else ""), str(default_index + 1)).strip().lower()
            if allow_back and raw in {"b", "back", "0", "q", "quit", "exit"}:
                raise NavigationBack
            if raw.isdigit() and 1 <= int(raw) <= len(rows):
                return int(raw) - 1
            cprint(f"Please choose 1-{len(rows)}.", "yellow")

    cursor = max(0, min(default_index, len(rows) - 1))
    typed = ""
    while True:
        render_key_menu(title, rows, cursor, typed=typed, multi=False, allow_back=allow_back, top_panel=top_panel)
        key = read_key()
        if key == "up":
            cursor = (cursor - 1) % len(rows)
            continue
        if key == "down":
            cursor = (cursor + 1) % len(rows)
            continue
        if key == "page_up":
            cursor = max(0, cursor - 10)
            continue
        if key == "page_down":
            cursor = min(len(rows) - 1, cursor + 10)
            continue
        if key == "enter":
            if typed:
                raw = typed.strip().lower()
                typed = ""
                if allow_back and raw in {"b", "back", "0", "q", "quit", "exit"}:
                    raise NavigationBack
                if raw.isdigit() and 1 <= int(raw) <= len(rows):
                    return int(raw) - 1
                cprint("Invalid numeric selection.", "yellow")
                time.sleep(0.8)
                continue
            return cursor
        if key in {"esc"}:
            if allow_back:
                raise NavigationBack
        if key == "backspace":
            typed = typed[:-1]
            continue
        if len(key) == 1:
            if allow_back and key.lower() in {"b", "q"} and not typed:
                raise NavigationBack
            if key.isdigit():
                candidate = int(key)
                if 1 <= candidate <= len(rows) and len(rows) <= 9:
                    return candidate - 1
            if key.isprintable():
                typed += key


def key_multi_select_menu(title: str, rows: List[Tuple[str, str]], allow_back: bool = True) -> List[int]:
    """Multi-select menu with arrows/space plus old numeric syntax."""
    if not rows:
        raise ValueError("Menu has no items")
    if not terminal_supports_keys():
        render_stage(title, "Select one or more items by number, range, or all. Type b/back to return.", "green")
        if RICH and console is not None and Table is not None:
            table = Table(title=title, box=box.ROUNDED, border_style="green")
            table.add_column("#", justify="right", style="bold green")
            table.add_column("Item", style="bold white")
            table.add_column("Info", style="dim")
            for i, (name, detail) in enumerate(rows, 1):
                table.add_row(str(i), name, detail)
            console.print(table)
        else:
            for i, (name, detail) in enumerate(rows, 1):
                print(f"{i}) {name} {detail}")
        cprint("Select one or more items. Examples: 1 | 1,3,5 | 2-6 | all | b=back", "dim")
        while True:
            raw = prompt_str("Selection", "all")
            if allow_back and raw.strip().lower() in {"b", "back", "0", "q", "quit", "exit"}:
                raise NavigationBack
            try:
                return parse_multi_select(raw, len(rows))
            except Exception as exc:
                cprint(f"Invalid selection: {exc}", "red")

    cursor = 0
    selected: Set[int] = set()
    typed = ""
    while True:
        render_key_menu(title, rows, cursor, selected=selected, typed=typed, multi=True, allow_back=allow_back)
        key = read_key()
        if key == "up":
            cursor = (cursor - 1) % len(rows)
            continue
        if key == "down":
            cursor = (cursor + 1) % len(rows)
            continue
        if key == "page_up":
            cursor = max(0, cursor - 10)
            continue
        if key == "page_down":
            cursor = min(len(rows) - 1, cursor + 10)
            continue
        if key == "space":
            if cursor in selected:
                selected.remove(cursor)
            else:
                selected.add(cursor)
            continue
        if key == "enter":
            if typed:
                raw = typed.strip().lower()
                typed = ""
                if allow_back and raw in {"b", "back", "0", "q", "quit", "exit"}:
                    raise NavigationBack
                try:
                    return parse_multi_select(raw, len(rows))
                except Exception as exc:
                    cprint(f"Invalid selection: {exc}", "red")
                    time.sleep(0.9)
                    continue
            if selected:
                return sorted(selected)
            selected.add(cursor)
            return sorted(selected)
        if key in {"esc"}:
            if allow_back:
                raise NavigationBack
        if key == "backspace":
            typed = typed[:-1]
            continue
        if len(key) == 1:
            low = key.lower()
            if allow_back and low in {"b", "q"} and not typed:
                raise NavigationBack
            if low == "a" and not typed:
                selected = set(range(len(rows)))
                continue
            if low == "n" and not typed:
                selected.clear()
            if key.isprintable():
                typed += key


def post_scan_actions_menu(
    v: VlessConfig,
    final_results: List[ScanResult],
    filename_prefix: str,
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
    choice = key_select_menu(f"Next Action [{summary}]", menu_rows, default_index=0, allow_back=False)

    if choice == 0:
        return "rescan_all"
    elif choice == 1:
        return "retest_same"
    else:
        return "exit"
