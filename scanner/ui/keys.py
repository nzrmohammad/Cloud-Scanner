import os
import sys

from scanner.ui.terminal import RICH


def read_key() -> str:
    """Read one key press and normalize arrows/enter/backspace.

    Works on Windows through msvcrt and on Unix-like terminals through termios.
    If the terminal does not support raw key reading, callers should fall back
    to normal numeric prompts.
    """
    if os.name == "nt":
        import msvcrt

        ch = msvcrt.getwch()  # type: ignore[attr-defined]
        if ch in {"\x00", "\xe0"}:
            ch2 = msvcrt.getwch()  # type: ignore[attr-defined]
            return {"H": "up", "P": "down", "K": "left", "M": "right", "I": "page_up", "Q": "page_down"}.get(ch2, "")
        if ch == "\x03":
            raise KeyboardInterrupt
        if ch == "\r":
            return "enter"
        if ch == "\x1b":
            return "esc"
        if ch == "\b":
            return "backspace"
        if ch == " ":
            return "space"
        return ch

    import select
    import termios
    import tty

    fd = sys.stdin.fileno()
    old = termios.tcgetattr(fd)  # type: ignore[attr-defined]
    try:
        tty.setraw(fd)  # type: ignore[attr-defined]
        ch = sys.stdin.read(1)
        if ch == "\x1b":
            seq = ""
            # Read full CSI/SS3 escape sequence (up to 4 bytes, e.g. '[5~' for PgUp)
            for _ in range(4):
                r, _, _ = select.select([sys.stdin], [], [], 0.03)
                if not r:
                    break
                nxt = sys.stdin.read(1)
                seq += nxt
                if nxt.isalpha() or nxt == "~":
                    break
            return {
                "[A": "up",
                "[B": "down",
                "[D": "left",
                "[C": "right",
                "[5~": "page_up",
                "[6~": "page_down",
                "[H": "home",
                "[1~": "home",
                "[F": "end",
                "[4~": "end",
                "[3~": "delete",
            }.get(seq, "esc" if not seq else "")
        if ch in {"\r", "\n"}:
            return "enter"
        if ch in {"\x7f", "\b"}:
            return "backspace"
        if ch == " ":
            return "space"
        if ch == "\x03":
            raise KeyboardInterrupt
        return ch
    finally:
        termios.tcsetattr(fd, termios.TCSADRAIN, old)  # type: ignore[attr-defined]


def terminal_supports_keys() -> bool:
    """Check if the current terminal environment supports raw keyboard navigation."""
    return bool(RICH and sys.stdin.isatty() and sys.stdout.isatty())
