from contextlib import contextmanager

from scanner.analytics import detect_stage_flags
from scanner.app import CloudScannerApp
from scanner.constants import app_dir
from scanner.geoip import set_geoip_cache_dir
from scanner.logger import close_logging
from scanner.models import AppSettings, ScanResult


def test_run_cli_applies_max_latency_without_speed_test(monkeypatch, tmp_path):
    xray_bin = tmp_path / "xray.exe"
    xray_bin.write_text("dummy", encoding="utf-8")
    out_dir = tmp_path / "out"

    fake_results = [
        ScanResult(ip="104.16.1.1", port=443, ok=True, latency_ms=45.0, status_code=204),
        ScanResult(ip="104.16.1.2", port=443, ok=True, latency_ms=350.0, status_code=204),
    ]

    monkeypatch.setattr("scanner.app._run_scan_with_tracking", lambda **kw: (fake_results, 2))
    monkeypatch.setattr("scanner.app.enrich_results_with_colo", lambda *a, **kw: None)
    monkeypatch.setattr("scanner.app.show_final_results", lambda *a, **kw: None)

    app = CloudScannerApp(
        [
            "-c",
            "vless://11111111-2222-3333-4444-555555555555@example.com:443?security=tls&type=ws#CLI",
            "-t",
            "104.16.1.1",
            "104.16.1.2",
            "--xray",
            str(xray_bin),
            "-o",
            str(out_dir),
            "--max-latency",
            "100",
        ]
    )
    try:
        rc = app.run()
        assert rc == 0

        filtered_txt = out_dir / "clean_ips_filtered.txt"
        assert filtered_txt.exists()
        filtered_content = filtered_txt.read_text(encoding="utf-8")
        assert "104.16.1.1:443" in filtered_content
        assert "104.16.1.2:443" not in filtered_content

        report_content = (out_dir / "scan_summary_report.txt").read_text(encoding="utf-8")
        assert "104.16.1.1:443" in report_content
        assert "104.16.1.2:443" not in report_content
    finally:
        close_logging()
        set_geoip_cache_dir(app_dir() / "results")


def test_run_cli_explicit_port_target_count_and_all_filtered_summary(monkeypatch, tmp_path):
    xray_bin = tmp_path / "xray.exe"
    xray_bin.write_text("dummy", encoding="utf-8")
    out_dir = tmp_path / "out"

    fake_results = [
        ScanResult(ip="104.16.1.1", port=443, ok=True, latency_ms=250.0, status_code=204),
    ]
    monkeypatch.setattr("scanner.app._run_scan_with_tracking", lambda **kw: (fake_results, 1))
    monkeypatch.setattr("scanner.app.enrich_results_with_colo", lambda *a, **kw: None)
    monkeypatch.setattr("scanner.app.show_final_results", lambda *a, **kw: None)

    app = CloudScannerApp(
        [
            "-c",
            "vless://11111111-2222-3333-4444-555555555555@example.com:443?security=tls&type=ws#CLI2",
            "-t",
            "104.16.1.1:443",
            "--all-cf-tls-ports",
            "--xray",
            str(xray_bin),
            "-o",
            str(out_dir),
            "--max-latency",
            "50",
        ]
    )
    try:
        rc = app.run()
        assert rc == 0
        report = (out_dir / "scan_summary_report.txt").read_text(encoding="utf-8")
        assert "Total candidate targets expanded   : 1" in report
        assert "1 endpoints (filtered to 0)" in report
    finally:
        close_logging()
        set_geoip_cache_dir(app_dir() / "results")


def test_detect_stage_flags_variants():
    basic = [ScanResult(ip="104.16.1.1", port=443, ok=True, latency_ms=100.0)]
    assert detect_stage_flags("clean_ips", basic) == (False, False, False, False)

    rechecked = [
        ScanResult(ip="104.16.1.1", port=443, ok=True, latency_ms=100.0, jitter_ms=5.0)
    ]
    assert detect_stage_flags("clean_ips_rechecked", rechecked) == (
        False,
        False,
        True,
        False,
    )

    upload_only = [
        ScanResult(ip="104.16.1.1", port=443, ok=True, latency_ms=100.0, upload_mbps=12.0)
    ]
    assert detect_stage_flags("clean_ips_speed_tested", upload_only) == (
        False,
        True,
        False,
        False,
    )

    longevity_only = [
        ScanResult(ip="104.16.1.1", port=443, ok=True, latency_ms=100.0, sustained=True)
    ]
    assert detect_stage_flags("clean_ips_longevity", longevity_only) == (
        False,
        False,
        False,
        True,
    )

    recheck_longevity = [
        ScanResult(
            ip="104.16.1.1",
            port=443,
            ok=True,
            latency_ms=100.0,
            jitter_ms=5.0,
            sustained=True,
        )
    ]
    assert detect_stage_flags("clean_ips_longevity", recheck_longevity) == (
        True,
        False,
        False,
        False,
    )

    recheck_upload_only = [
        ScanResult(
            ip="104.16.1.1",
            port=443,
            ok=True,
            latency_ms=100.0,
            jitter_ms=5.0,
            upload_mbps=12.0,
        )
    ]
    assert detect_stage_flags("clean_ips_speed_tested", recheck_upload_only) == (
        True,
        False,
        False,
        False,
    )

    assert detect_stage_flags("clean_ips_full", basic)[0] is True


def test_interactive_tui_passes_initial_ok_count_and_no_duplicate_recs(
    tmp_path, monkeypatch
):
    vless_uri = "vless://11111111-1111-1111-1111-111111111111@example.com:443?security=tls&type=ws#test"
    out_dir = tmp_path / "out"
    xray_bin = tmp_path / "xray.exe"
    xray_bin.write_bytes(b"")

    targets = [f"104.16.1.{i}" for i in range(1, 41)]
    initial_working = [
        ScanResult(ip=ip, port=443, ok=True, latency_ms=100.0 + i)
        for i, ip in enumerate(targets, start=1)
    ]
    trimmed_final = [
        ScanResult(
            ip=r.ip,
            port=r.port,
            ok=True,
            latency_ms=r.latency_ms,
            jitter_ms=4.0,
            speed_mbps=20.0,
        )
        for r in initial_working[:30]
    ]

    @contextmanager
    def _noop_tui_screen():
        yield

    import scanner.app as app_mod

    monkeypatch.setattr(app_mod, "tui_screen", _noop_tui_screen)
    monkeypatch.setattr(app_mod, "find_xray", lambda *a, **kw: xray_bin)
    monkeypatch.setattr(app_mod, "check_and_prompt_xray_update", lambda x: x)
    monkeypatch.setattr(app_mod, "render_welcome_config_screen", lambda *a, **kw: True)
    monkeypatch.setattr(app_mod, "prompt_str", lambda *a, **kw: "")
    monkeypatch.setattr(
        app_mod, "select_targets_tui", lambda *a, **kw: (targets, "Custom")
    )
    monkeypatch.setattr(app_mod, "prompt_continue_nav", lambda *a, **kw: True)
    monkeypatch.setattr(app_mod, "render_stage", lambda *a, **kw: None)
    monkeypatch.setattr(app_mod, "pause", lambda *a, **kw: None)
    monkeypatch.setattr(
        app_mod,
        "_run_scan_with_tracking",
        lambda *a, **kw: (initial_working, len(initial_working)),
    )

    def _fake_handle_post(*a, **kw):
        return (
            trimmed_final,
            out_dir / "clean_ips_full.txt",
            out_dir / "clean_ips_full.csv",
            "clean_ips_full",
        )

    monkeypatch.setattr(app_mod, "handle_post_scan_testing_tui", _fake_handle_post)

    menu_calls = {"n": 0}

    def _fake_actions_menu(*a, **kw):
        menu_calls["n"] += 1
        assert menu_calls["n"] == 1
        return "exit"

    monkeypatch.setattr(app_mod, "post_scan_actions_menu", _fake_actions_menu)

    show_calls = []

    def _spy_show_final(*a, **kw):
        show_calls.append((a, kw))

    monkeypatch.setattr(app_mod, "show_final_results", _spy_show_final)

    real_save_summary = app_mod.save_scan_summary_report

    def _spy_save_summary(*args, **kwargs):
        out_arg = kwargs.get("output_dir") if "output_dir" in kwargs else args[1]
        assert out_arg == out_dir
        return real_save_summary(*args, **kwargs)

    monkeypatch.setattr(app_mod, "save_scan_summary_report", _spy_save_summary)

    app = CloudScannerApp([])
    monkeypatch.setattr(
        app.config_manager,
        "load_settings",
        lambda: AppSettings(vless_raw=vless_uri, ports=[443], output_dir=out_dir),
    )

    try:
        rc = app.interactive()
        assert rc == 0
        report = (out_dir / "scan_summary_report.txt").read_text(encoding="utf-8")
        assert "40 endpoints (filtered to 30)" in report
        assert len(show_calls) == 3
        assert show_calls[-1][1].get("save_recommendations") is False
    finally:
        close_logging()
        set_geoip_cache_dir(app_dir() / "results")

