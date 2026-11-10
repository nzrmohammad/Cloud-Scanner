from scanner.app import CloudScannerApp
from scanner.constants import app_dir
from scanner.geoip import set_geoip_cache_dir
from scanner.logger import close_logging
from scanner.models import ScanResult


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
