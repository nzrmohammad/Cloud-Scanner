import pytest
from rich.console import Group
from rich.table import Table

from scanner.ui.menus import (
    build_key_menu_renderable,
    build_menu_renderable,
    parse_multi_select,
)


def test_parse_multi_select():
    assert parse_multi_select("1", 5) == [0]
    assert parse_multi_select("1, 3, 5", 5) == [0, 2, 4]
    assert parse_multi_select("2-4", 5) == [1, 2, 3]
    assert parse_multi_select("all", 3) == [0, 1, 2]
    assert parse_multi_select("a", 3) == [0, 1, 2]
    assert parse_multi_select("*", 3) == [0, 1, 2]

    with pytest.raises(ValueError):
        parse_multi_select("0", 5)

    with pytest.raises(ValueError):
        parse_multi_select("6", 5)

    with pytest.raises(ValueError):
        parse_multi_select("invalid", 5)


def test_build_menu_renderable_structure():
    rows = [("Option A", "Detail A"), ("Option B", "Detail B"), ("Option C", "Detail C")]
    renderable = build_menu_renderable("Test Title", rows, cursor=1, multi=False)

    assert isinstance(renderable, Group)
    # Group should contain: header panel, table, help panel
    assert len(renderable.renderables) >= 2

    # Find Table in group renderables
    table = next(r for r in renderable.renderables if isinstance(r, Table))
    assert table is not None
    # 3 options in rows
    assert table.row_count == 3


def test_build_menu_renderable_multi_select():
    rows = [("Option A", "Detail A"), ("Option B", "Detail B")]
    selected = {0}
    renderable = build_key_menu_renderable(
        "Multi Menu",
        rows,
        cursor=1,
        selected=selected,
        multi=True,
        error_msg="Test Error",
    )

    assert isinstance(renderable, Group)
    table = next(r for r in renderable.renderables if isinstance(r, Table))
    assert table.row_count == 2


def test_build_menu_renderable_long_rows_no_wrap():
    rows = [
        ("Very Long Iranian Provider Name With Many Words", "192.168.1.0/24, 192.168.2.0/24, 192.168.3.0/24 ..."),
        ("Short", "Detail"),
    ]
    renderable = build_menu_renderable(
        "Long Title",
        rows,
        cursor=0,
        typed="1",
        multi=True,
        error_msg="Test error",
    )
    assert isinstance(renderable, Group)
    table = next(r for r in renderable.renderables if isinstance(r, Table))
    assert all(col.no_wrap for col in table.columns)


def test_build_menu_renderable_fits_compact_terminal_with_top_panel(monkeypatch):
    from types import SimpleNamespace

    from rich.panel import Panel

    from scanner.ui import menus

    fake_console = SimpleNamespace(size=SimpleNamespace(width=78, height=24))
    monkeypatch.setattr(menus, "console", fake_console)
    rows = [(f"Item {i}", f"Detail {i}") for i in range(30)]
    top = Panel("Line 1\nLine 2\nLine 3\nLine 4", expand=False)
    renderable = build_menu_renderable("Compact Menu", rows, cursor=10, multi=True, top_panel=top)
    table = next(r for r in renderable.renderables if isinstance(r, Table))
    assert table.row_count < 10
    assert table.expand is False


def test_windows_keys_map_home_end_delete(monkeypatch):
    import sys
    from types import ModuleType

    from scanner.ui import keys

    seq = iter(["\xe0", "G", "\xe0", "O", "\xe0", "S"])
    fake_msvcrt = ModuleType("msvcrt")
    fake_msvcrt.getwch = lambda: next(seq)  # type: ignore[attr-defined]
    prev_msvcrt = sys.modules.get("msvcrt")
    monkeypatch.setattr(keys.os, "name", "nt")
    sys.modules["msvcrt"] = fake_msvcrt
    try:
        assert keys.read_key() == "home"
        assert keys.read_key() == "end"
        assert keys.read_key() == "delete"
    finally:
        if prev_msvcrt is None:
            sys.modules.pop("msvcrt", None)
        else:
            sys.modules["msvcrt"] = prev_msvcrt
