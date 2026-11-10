import sys
from contextlib import contextmanager
from pathlib import Path

from scanner.config import parse_vless
from scanner.engine import run_scan
from scanner.models import ScanResult
from scanner.ui import terminal


def test_run_scan_stage_and_reporter_lifecycle_non_overlapping(monkeypatch, tmp_path):
    """Ensure TCP prefilter reporter exits completely before Xray stage clears screen and starts latency reporter."""
    events = []

    def fake_stage(title, subtitle="", color="cyan"):
        events.append(("stage", title))

    @contextmanager
    def fake_tcp_reporter(total):
        events.append(("tcp_enter", total))
        try:
            yield lambda done, total_items, alive: events.append(("tcp_tick", done, total_items, alive))
        finally:
            events.append(("tcp_exit", total))

    @contextmanager
    def fake_latency_reporter(title, total, mode="latency"):
        events.append(("latency_enter", title, total, mode))
        try:
            yield lambda r, d, t: events.append(("latency_tick", r.ip, d, t))
        finally:
            events.append(("latency_exit", title))

    def fake_fast_tcp_filter(pairs, timeout=1.5, workers=30, on_progress=None):
        if on_progress:
            on_progress(len(pairs), len(pairs), 1)
        return [pairs[0]]

    def fake_latency_scan(v, pairs, xray, concurrency=1, timeout=3, tries=1, url="", loglevel="warning", on_result=None):
        res = [ScanResult(ip=ip, port=p, ok=True, latency_ms=25.0) for ip, p in pairs]
        if on_result:
            for idx, r in enumerate(res, 1):
                on_result(r, idx, len(res))
        return res

    monkeypatch.setattr("scanner.engine.fast_tcp_filter", fake_fast_tcp_filter)
    monkeypatch.setattr("scanner.engine.run_latency_scan", fake_latency_scan)

    tracked_counts = []
    v = parse_vless("vless://11111111-2222-3333-4444-555555555555@example.com:443?security=tls&type=ws#Test")
    results = run_scan(
        v,
        ["1.1.1.1", "1.0.0.1"],
        [443],
        Path("xray.exe"),
        concurrency=2,
        timeout=2,
        use_tcp_prefilter=True,
        output_dir=tmp_path,
        on_stage=fake_stage,
        make_reporter=fake_latency_reporter,
        make_tcp_reporter=fake_tcp_reporter,
        on_prefilter_progress=lambda d, t, a: tracked_counts.append(a),
    )

    assert len(results) == 1
    assert tracked_counts == [1]

    # Exact ordering guarantees Fast TCP Pre-filter stage clears BEFORE tcp_enter,
    # and tcp_exit completes BEFORE Xray Latency Scan clears screen and enters latency reporter.
    stage_indices = {
        "prefilter_stage": events.index(("stage", "Fast TCP Pre-filter")),
        "tcp_enter": events.index(("tcp_enter", 2)),
        "tcp_exit": events.index(("tcp_exit", 2)),
        "latency_stage": events.index(("stage", "Xray Latency Scan")),
        "latency_enter": events.index(("latency_enter", "Scanning", 1, "latency")),
        "latency_exit": events.index(("latency_exit", "Scanning")),
    }
    assert stage_indices["prefilter_stage"] < stage_indices["tcp_enter"] < stage_indices["tcp_exit"]
    assert stage_indices["tcp_exit"] < stage_indices["latency_stage"] < stage_indices["latency_enter"] < stage_indices["latency_exit"]


def test_clear_screen_works_when_stdout_proxied_by_rich(monkeypatch):
    writes = []

    class FakeRealTTY:
        def isatty(self):
            return True

        def write(self, data):
            writes.append(data)
            return len(data)

        def flush(self):
            pass

    class FakeRichProxy:
        rich_proxied_file = object()

        def isatty(self):
            return False

        def flush(self):
            pass

    monkeypatch.setattr(sys, "__stdout__", FakeRealTTY())
    monkeypatch.setattr(sys, "stdout", FakeRichProxy())
    monkeypatch.setattr(terminal, "console", None)
    monkeypatch.setattr(terminal.os, "name", "posix")

    terminal.clear_screen()
    assert "\033[2J\033[3J\033[H" in "".join(writes)


def test_tui_screen_does_not_lock_alternate_buffer(monkeypatch):
    """Ensure tui_screen() avoids console.screen() so terminal scrollback remains active."""
    entered = []

    class FakeConsole:
        is_terminal = True

        def screen(self, **kwargs):
            raise AssertionError("console.screen() alternate buffer must not be called")

        def show_cursor(self, show=True):
            entered.append(("cursor", show))

    monkeypatch.setattr(terminal, "console", FakeConsole())
    with terminal.tui_screen():
        entered.append(("body", True))
    assert ("body", True) in entered
    assert ("cursor", True) in entered


def test_show_final_results_28_endpoints_and_display_limit_none(monkeypatch, tmp_path):
    from scanner.ui import screens

    results = [
        ScanResult(ip=f"104.16.1.{i}", port=443, ok=True, latency_ms=20.0 + i, status_code=204)
        for i in range(1, 29)
    ]
    out_lines = []
    monkeypatch.setattr(screens, "RICH", False)
    monkeypatch.setattr(screens, "console", None)
    monkeypatch.setattr("builtins.print", lambda *a, **k: out_lines.append(" ".join(str(x) for x in a)))

    screens.show_final_results(results, tmp_path / "clean_ips.txt", tmp_path / "clean_ips.csv")
    joined = "\n".join(out_lines)
    assert "104.16.1.28:443" in joined

    out_lines.clear()
    screens.show_final_results(results, tmp_path / "clean_ips.txt", tmp_path / "clean_ips.csv", display_limit=None)
    assert "104.16.1.28:443" in "\n".join(out_lines)


def test_show_final_results_save_recommendations_false_skips_write(monkeypatch, tmp_path):
    from scanner.ui import screens

    results = [
        ScanResult(ip="104.16.1.1", port=443, ok=True, latency_ms=25.0, status_code=204),
    ]
    monkeypatch.setattr(screens, "RICH", False)
    monkeypatch.setattr(screens, "console", None)
    monkeypatch.setattr("builtins.print", lambda *a, **k: None)

    screens.show_final_results(
        results,
        tmp_path / "clean_ips.txt",
        tmp_path / "clean_ips.csv",
        save_recommendations=False,
    )
    assert not (tmp_path / "recommended_configs.txt").exists()
