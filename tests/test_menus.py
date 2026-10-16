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
