import os
import sys
from typing import Optional

if sys.platform == "win32":
    try:
        if hasattr(sys.stdout, "reconfigure"):
            sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        if hasattr(sys.stderr, "reconfigure"):
            sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

from scanner.constants import APP_NAME, APP_VERSION, APP_HEADER, APP_CHANNEL
from scanner.models import NavigationBack

try:
    from rich import box
    from rich.align import Align
    from rich.console import Console
    from rich.panel import Panel
    from rich.prompt import Confirm, IntPrompt, Prompt
    from rich.text import Text

    console = Console()
    RICH = True
except ImportError:
    box = None  # type: ignore
    Align = None  # type: ignore
    Console = None  # type: ignore
    Panel = None  # type: ignore
    Confirm = None  # type: ignore
    IntPrompt = None  # type: ignore
    Prompt = None  # type: ignore
    Text = None  # type: ignore
    console = None  # type: ignore
    RICH = False

BACK_WORDS = {"b", "back", "q", "quit", "exit"}


def is_back_value(value: str) -> bool:
    return value.strip().lower() in BACK_WORDS


def cprint(text: str = "", style: Optional[str] = None) -> None:
    if RICH and console is not None:
        console.print(text, style=style)
    else:
        print(text)


def clear_screen() -> None:
    if sys.stdout.isatty():
        try:
            if os.name == "nt":
                os.system("cls")
            else:
                sys.stdout.write("\033[2J\033[H\033[3J")
                sys.stdout.flush()
        except Exception:
            pass
    if RICH and console is not None:
        try:
            console.clear()
            return
        except Exception:
            pass
    if not sys.stdout.isatty():
        print("\n" * 2, end="")


def render_fixed_header(compact: bool = True, show_controls: bool = True) -> None:
    """Render the fixed boxed header for post-login TUI screens."""
    if RICH and console is not None:
        content = Text()
        content.append(APP_NAME, style="bold cyan")
        content.append(f" {APP_VERSION}", style="bold magenta")
        content.append("  |  Telegram: ", style="dim white")
        content.append(APP_CHANNEL, style="bold green")
        if not compact:
            content.append("\nClean-IP Scanner for VLESS + Xray", style="white")
        if show_controls:
            content.append("\n\nUp/Down move   Space toggle   Enter confirm   Numbers still work", style="dim")
        console.print(Panel(content, border_style="cyan", box=box.ROUNDED, expand=False))
        console.print()
    else:
        print(f"==== {APP_HEADER} ====")
        if show_controls:
            print("Up/Down move   Space toggle   Enter confirm   Numbers still work")
        print()


def show_banner(clear: bool = True) -> None:
    if clear:
        clear_screen()
    if RICH and console is not None:
        logo = Text()
        logo.append("\n  ██████╗ ██╗  ██╗██╗  ██╗      ██████╗███████╗███████╗\n", style="bold cyan")
        logo.append("  ██╔══██╗██║ ██╔╝██║  ██║     ██╔════╝██╔════╝██╔════╝\n", style="bold cyan")
        logo.append("  ██████╔╝█████╔╝ ███████║     ██║     █████╗  ███████╗\n", style="bold cyan")
        logo.append("  ██╔══██╗██╔═██╗ ██╔══██║     ██║     ██╔══╝  ╚════██║\n", style="bold cyan")
        logo.append("  ██║  ██║██║  ██╗██║  ██║     ╚██████╗██║     ███████║\n", style="bold cyan")
        logo.append("  ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝      ╚═════╝╚═╝     ╚══════╝\n", style="bold cyan")
        subtitle = Text("Cloudflare Clean-IP Scanner for VLESS + Xray Core", style="white")
        version = Text(f"{APP_HEADER}", style="bold magenta")
        console.print(Panel(Align.center(logo + Text("\n") + version + Text("\n") + subtitle), border_style="cyan", box=box.DOUBLE))
    else:
        print(f"==== {APP_HEADER} - Cloudflare Clean-IP Scanner ====")


def render_stage(title: str, subtitle: str = "", border_style: str = "cyan", clear: bool = True) -> None:
    """Render the current TUI stage box. If clear is True, clears the screen first."""
    if clear:
        clear_screen()
        render_fixed_header(compact=True, show_controls=True)
    if RICH and console is not None:
        content = f"[bold]{title}[/bold]"
        if subtitle:
            content += f"\n[dim]{subtitle}[/dim]"
        console.print(Panel(content, border_style=border_style, box=box.ROUNDED, expand=False))
    else:
        print(title)
        if subtitle:
            print(subtitle)
        print()


def pause(message: str = "Press Enter to continue") -> None:
    try:
        if RICH and Prompt is not None:
            Prompt.ask(f"[dim]{message}[/dim]", default="")
        else:
            input(message)
    except KeyboardInterrupt:
        raise


def prompt_str(message: str, default: Optional[str] = None, password: bool = False) -> str:
    if RICH and Prompt is not None:
        return Prompt.ask(message, default=default, password=password).strip()
    suffix = f" [{default}]" if default else ""
    val = input(f"{message}{suffix}: ").strip()
    return val or (default or "")


def prompt_int(message: str, default: int, min_value: int = 1, max_value: Optional[int] = None) -> int:
    while True:
        try:
            if RICH and IntPrompt is not None:
                value = IntPrompt.ask(message, default=default)
            else:
                raw = input(f"{message} [{default}]: ").strip()
                value = int(raw or default)
            if value < min_value or (max_value is not None and value > max_value):
                raise ValueError
            return value
        except Exception:
            cprint(f"Please enter a number between {min_value} and {max_value or '∞'}.", "yellow")


def prompt_confirm(message: str, default: bool = True) -> bool:
    if RICH and Confirm is not None:
        return Confirm.ask(message, default=default)
    raw = input(f"{message} [{'Y/n' if default else 'y/N'}]: ").strip().lower()
    if not raw:
        return default
    return raw in {"y", "yes", "1", "true"}


def prompt_str_nav(message: str, default: Optional[str] = None, password: bool = False, allow_back: bool = True) -> str:
    """Prompt for text and allow b/back to navigate to the previous TUI stage."""
    raw = prompt_str(message, default=default, password=password)
    if allow_back and is_back_value(raw):
        raise NavigationBack
    return raw


def prompt_int_nav(message: str, default: int, min_value: int = 1, max_value: Optional[int] = None, allow_back: bool = True) -> int:
    """Integer prompt that supports b/back in both Rich and plain terminals."""
    while True:
        try:
            label = message + (" [dim](b=back)[/dim]" if RICH and allow_back else "")
            if RICH and Prompt is not None:
                raw = Prompt.ask(label, default=str(default))
            else:
                raw = input(f"{message} [{default}]" + (" / b=back" if allow_back else "") + ": ").strip() or str(default)
            if allow_back and is_back_value(raw):
                raise NavigationBack
            value = int(str(raw).strip())
            if value < min_value or (max_value is not None and value > max_value):
                raise ValueError
            return value
        except NavigationBack:
            raise
        except Exception:
            cprint(f"Please enter a number between {min_value} and {max_value or '∞'}, or type b to go back.", "yellow")


def prompt_confirm_nav(message: str, default: bool = True, allow_back: bool = True) -> bool:
    """Yes/no prompt that supports b/back. Returns True/False, raises NavigationBack on back."""
    while True:
        if RICH and Prompt is not None:
            suffix = "Y/n" if default else "y/N"
            raw = Prompt.ask(f"{message} [dim]({suffix}, b=back)[/dim]", default="y" if default else "n")
        else:
            raw = input(f"{message} [{'Y/n' if default else 'y/N'} / b=back]: ").strip().lower()
            if not raw:
                raw = "y" if default else "n"
        raw = str(raw).strip().lower()
        if allow_back and is_back_value(raw):
            raise NavigationBack
        if raw in {"y", "yes", "1", "true"}:
            return True
        if raw in {"n", "no", "0", "false"}:
            return False
        cprint("Please answer y/n, or type b to go back.", "yellow")


def prompt_continue_nav(message: str = "Press Enter to continue", allow_back: bool = True) -> None:
    """Enter continues; b/back returns to the previous step."""
    if RICH and Prompt is not None:
        label = message + (" [dim](b=back)[/dim]" if allow_back else "")
        raw = Prompt.ask(label, default="")
    else:
        raw = input(message + (" / b=back" if allow_back else "") + ": ").strip()
    if allow_back and is_back_value(str(raw)):
        raise NavigationBack
