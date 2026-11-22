import csv
import tempfile
from pathlib import Path

from scanner.models import ScanResult, SmartRecommendation, VlessConfig
from scanner.storage import (
    save_recommended_configs,
    save_results,
    save_scan_summary_report,
)


def test_save_results_initial_scan():
    with tempfile.TemporaryDirectory() as td:
        out_dir = Path(td)
        v = VlessConfig(uuid="test-uuid", host="test.com", port=443)
        results = [
            ScanResult(ip="104.16.1.1", port=443, ok=True, latency_ms=85.2, status_code=204, colo="FRA"),
            ScanResult(ip="104.16.1.2", port=443, ok=True, latency_ms=92.4, status_code=204, colo="AMS"),
            ScanResult(ip="104.16.1.3", port=443, ok=False, error="Timeout"),
        ]

        txt, csv_path = save_results(results, out_dir, "clean_ips", vless_config=v)

        assert txt.exists()
        assert csv_path.exists()

        # Check TXT content
        txt_content = txt.read_text(encoding="utf-8")
        assert "104.16.1.1:443" in txt_content
        assert "latency: 85.2 ms" in txt_content
        assert "FRA" in txt_content

        # Check CSV content
        with csv_path.open("r", encoding="utf-8") as f:
            reader = list(csv.reader(f))
            headers = reader[0]
            assert "ip" in headers
            assert "latency_ms" in headers
            assert "colo_code" in headers
            assert len(reader) == 3  # 1 header + 2 ok results

        # Check VLESS link file
        vless_txt = out_dir / "clean_ips_vless.txt"
        assert vless_txt.exists()
        vless_content = vless_txt.read_text(encoding="utf-8")
        assert "vless://" in vless_content
        assert "104.16.1.1:443" in vless_content


def test_save_results_speed_stage_and_download_bytes():
    with tempfile.TemporaryDirectory() as td:
        out_dir = Path(td)
        v = VlessConfig(uuid="test-uuid", host="test.com", port=443)
        results = [
            ScanResult(
                ip="104.16.1.1",
                port=443,
                ok=True,
                speed_mbps=45.67,
                upload_mbps=12.34,
                download_bytes=5242880,  # 5 MB
                upload_bytes=1048576,    # 1 MB
                ttfb_ms=65.2,
                colo="FRA",
            ),
        ]

        txt, csv_path = save_results(results, out_dir, "clean_ips_speed_tested", vless_config=v)

        # Verify TXT output reads download_bytes
        txt_content = txt.read_text(encoding="utf-8")
        assert "downloaded: 5242880 bytes" in txt_content
        assert "uploaded: 1048576 bytes" in txt_content

        # Verify CSV output has speed_bytes header but reads download_bytes value
        with csv_path.open("r", encoding="utf-8") as f:
            reader = list(csv.reader(f))
            headers = reader[0]
            assert "speed_bytes" in headers
            idx = headers.index("speed_bytes")
            data_row = reader[1]
            assert data_row[idx] == "5242880"


def test_save_results_full_recheck_and_longevity():
    with tempfile.TemporaryDirectory() as td:
        out_dir = Path(td)
        v = VlessConfig(uuid="test-uuid", host="test.com", port=443)
        results = [
            ScanResult(
                ip="104.16.1.1",
                port=443,
                ok=True,
                latency_ms=78.5,
                jitter_ms=4.2,
                packet_loss=0.0,
                recheck_passed=8,
                recheck_total=8,
                sustained=True,
                longevity_loss=0.0,
                speed_mbps=62.5,
                upload_mbps=15.0,
                download_bytes=10000000,
                upload_bytes=2000000,
                colo="LHR",
            ),
        ]

        txt, csv_path = save_results(results, out_dir, "clean_ips_full_tested", vless_config=v)

        txt_content = txt.read_text(encoding="utf-8")
        assert "pass: 8/8" in txt_content
        assert "anti_drop: SUSTAINED" in txt_content
        assert "down: 62.50 Mbps" in txt_content

        vless_txt = out_dir / "clean_ips_full_tested_vless.txt"
        vless_content = vless_txt.read_text(encoding="utf-8")
        assert "_AntiDrop" in vless_content
        assert "LHR_" in vless_content


def test_save_results_interrupted_and_per_port():
    with tempfile.TemporaryDirectory() as td:
        out_dir = Path(td)
        v = VlessConfig(uuid="test-uuid", host="test.com", port=443)
        results = [
            ScanResult(ip="104.16.1.1", port=443, ok=True, latency_ms=80.0),
            ScanResult(ip="104.16.1.2", port=8443, ok=True, latency_ms=85.0),
        ]

        txt, csv_path = save_results(results, out_dir, "clean_ips_interrupted", vless_config=v)

        assert txt.name == "clean_ips_interrupted.txt"
        assert csv_path.name == "clean_ips_interrupted.csv"

        # Check per-port directory
        by_port = out_dir / "by_port"
        assert by_port.exists()
        assert (by_port / "clean_ips_interrupted_port_443.txt").exists()
        assert (by_port / "clean_ips_interrupted_port_8443.txt").exists()


def test_save_recommendations():
    with tempfile.TemporaryDirectory() as td:
        out_dir = Path(td)
        base = ScanResult(ip="104.16.1.1", port=443, ok=True, latency_ms=60.0, speed_mbps=50.0, colo="FRA")
        recs = [
            SmartRecommendation(
                category="Balanced (Fast & Stable)",
                icon="⚖️",
                result=base,
                reason="60ms, 50.0 Mbps",
                vless_link="vless://test-link#Balanced",
            )
        ]

        rec_file = save_recommended_configs(recs, out_dir)
        assert rec_file is not None
        assert rec_file.exists()
        content = rec_file.read_text(encoding="utf-8")
        assert "Balanced (Fast & Stable)" in content
        assert "104.16.1.1:443" in content
        assert "vless://test-link#Balanced" in content


def test_save_scan_summary_report():
    with tempfile.TemporaryDirectory() as td:
        out_dir = Path(td)
        v = VlessConfig(uuid="test-uuid", host="example.com", port=443, remark="TestServer")
        r1 = ScanResult(
            ip="104.16.1.1",
            port=443,
            ok=True,
            latency_ms=45.0,
            jitter_ms=2.1,
            sustained=True,
            speed_mbps=85.5,
            upload_mbps=22.3,
            colo="FRA",
        )
        r2 = ScanResult(
            ip="104.16.1.2",
            port=8443,
            ok=False,
            error="Connection refused",
        )

        report = save_scan_summary_report(
            [r1, r2],
            out_dir,
            vless_config=v,
            total_targets_count=100,
            tcp_alive_count=10,
        )

        assert report.exists()
        assert report.name == "scan_summary_report.txt"
        text = report.read_text(encoding="utf-8")
        assert "TestServer" in text
        assert "example.com:443" in text
        assert "104.16.1.1:443" in text
        assert "85.50 Mbps" in text
        assert "22.30 Mbps" in text
        assert "FRA" in text


def test_save_results_none_longevity_loss_no_crash():
    with tempfile.TemporaryDirectory() as td:
        out_dir = Path(td)
        v = VlessConfig(uuid="test-uuid", host="test.com", port=443)
        results = [
            ScanResult(ip="104.16.1.1", port=443, ok=True, latency_ms=50.0, sustained=False, longevity_loss=None),
            ScanResult(ip="104.16.1.2", port=8443, ok=True, latency_ms=55.0, sustained=None, longevity_loss=None),
        ]
        txt, csv_path = save_results(results, out_dir, "clean_ips_longevity", vless_config=v)
        assert txt.exists() and csv_path.exists()
        assert "DROPPED" in txt.read_text(encoding="utf-8")
        report = save_scan_summary_report(results, out_dir, vless_config=v)
        assert report.exists()


def test_save_results_zero_working_vs_filtered(tmp_path):
    failed_only = [ScanResult(ip="104.16.1.1", port=443, ok=False, error="Timeout")]
    txt1, _ = save_results(failed_only, tmp_path, "clean_ips_empty")
    content1 = txt1.read_text(encoding="utf-8")
    assert "No working endpoints were found." in content1
    assert "No results matched the selected filters." not in content1

    ok_slow = [ScanResult(ip="104.16.1.1", port=443, ok=True, latency_ms=500.0)]
    txt2, _ = save_results(ok_slow, tmp_path, "clean_ips_filtered", max_latency_ms=100.0)
    assert "No results matched the selected filters." in txt2.read_text(encoding="utf-8")


def test_save_results_recheck_longevity_keeps_jitter_and_loss(tmp_path):
    res = ScanResult(
        ip="104.16.1.1",
        port=443,
        ok=True,
        latency_ms=120.0,
        jitter_ms=12.3,
        packet_loss=5.0,
        sustained=True,
    )
    txt, csv_file = save_results([res], tmp_path, "clean_ips_longevity")
    csv_lines = csv_file.read_text(encoding="utf-8").splitlines()
    assert len(csv_lines) == 2
    assert "jitter_ms" in csv_lines[0]
    assert "packet_loss_pct" in csv_lines[0]
    assert "anti_drop_sustained" in csv_lines[0]
    assert "12.3" in csv_lines[1]
    assert "True" in csv_lines[1]

    txt_content = txt.read_text(encoding="utf-8")
    assert "104.16.1.1" in txt_content
    assert "12.3" in txt_content


def test_save_results_recheck_upload_only_keeps_full_columns(tmp_path):
    res = ScanResult(
        ip="104.16.1.2",
        port=443,
        ok=True,
        latency_ms=110.0,
        jitter_ms=8.4,
        packet_loss=0.0,
        upload_mbps=14.5,
    )
    txt, csv_file = save_results([res], tmp_path, "clean_ips_speed_tested")
    csv_lines = csv_file.read_text(encoding="utf-8").splitlines()
    assert len(csv_lines) == 2
    assert "jitter_ms" in csv_lines[0]
    assert "packet_loss_pct" in csv_lines[0]
    assert "upload_mbps" in csv_lines[0]
    assert "8.4" in csv_lines[1]
    assert "14.50" in csv_lines[1]

    txt_content = txt.read_text(encoding="utf-8")
    assert "104.16.1.2" in txt_content
    assert "14.5" in txt_content


def test_stale_artifacts_cleaned_when_zero_working(tmp_path):
    # Pre-create stale vless and by_port files
    stale_vless = tmp_path / "clean_ips_vless.txt"
    stale_vless.write_text("vless://stale-old-link@1.1.1.1:443#Old\n", encoding="utf-8")
    by_port = tmp_path / "by_port"
    by_port.mkdir()
    (by_port / "clean_ips_port_443.txt").write_text("old content\n", encoding="utf-8")

    v = VlessConfig(uuid="test-uuid", host="test.com", port=443)
    failed = [ScanResult(ip="104.16.1.1", port=443, ok=False, error="Timeout")]
    save_results(failed, tmp_path, "clean_ips", vless_config=v)

    # Stale VLESS should be overwritten with empty notice, not left with obsolete links
    assert "No working endpoints found" in stale_vless.read_text(encoding="utf-8")
    assert not (by_port / "clean_ips_port_443.txt").exists()


def test_save_recommended_configs_empty_overwrites_stale(tmp_path):
    rec_file = tmp_path / "recommended_configs.txt"
    rec_file.write_text("Old obsolete recommendations\n", encoding="utf-8")

    result_path = save_recommended_configs([], tmp_path)
    assert result_path == rec_file
    content = rec_file.read_text(encoding="utf-8")
    assert "No recommended endpoints available for this scan run" in content


def test_summary_report_masks_uuid_and_keeps_section_numbering(tmp_path):
    v = VlessConfig(uuid="12345678-abcd-ef01-2345-6789abcdef01", host="example.com", port=443)
    r = ScanResult(ip="104.16.1.1", port=443, ok=True, latency_ms=45.0)

    report_path = save_scan_summary_report([r], tmp_path, vless_config=v, recommendations=None)
    content = report_path.read_text(encoding="utf-8")

    # UUID should be masked
    assert "12345678..." in content
    assert "6789abcdef01" not in content

    # Section 3 should be present with fallback message, no jump from 2 to 4
    assert "2. STAGE-BY-STAGE FUNNEL STATISTICS" in content
    assert "3. SMART RECOMMENDATIONS" in content
    assert "4. DETAILED ENDPOINT BENCHMARK TABLE" in content
    assert "(No smart recommendations available for this scan run)" in content


def test_clean_error_message_simplifies_exception_repr():
    from scanner.storage import _clean_error_message

    raw = "('Connection aborted.', RemoteDisconnected('Remote end closed connection without response'))"
    cleaned = _clean_error_message(raw)
    assert cleaned == "Connection aborted."

    pool_err = "HTTPSConnectionPool(host='cp.cloudflare.com', port=443): Read timed out."
    cleaned_pool = _clean_error_message(pool_err)
    assert "Read timed out." in cleaned_pool

    tuple_pool_err = "(\"HTTPSConnectionPool(host='example.com', port=443): Max retries exceeded\", 123)"
    cleaned_tuple_pool = _clean_error_message(tuple_pool_err)
    assert cleaned_tuple_pool == "Max retries exceeded"



def test_by_port_cleanup_does_not_delete_other_stage_prefixes(tmp_path):
    by_port = tmp_path / "by_port"
    by_port.mkdir()
    other_stage_file = by_port / "clean_ips_full_tested_port_443.txt"
    other_stage_file.write_text("stage content\n", encoding="utf-8")

    r1 = ScanResult(ip="104.16.1.1", port=443, ok=True, latency_ms=50.0)
    r2 = ScanResult(ip="104.16.1.2", port=8443, ok=True, latency_ms=60.0)

    save_results([r1, r2], tmp_path, "clean_ips")

    assert (by_port / "clean_ips_port_443.txt").exists()
    assert (by_port / "clean_ips_port_8443.txt").exists()
    # The other stage's files must not be wiped out by clean_ips save
    assert other_stage_file.exists()
    assert other_stage_file.read_text(encoding="utf-8") == "stage content\n"

    # Now simulate a subsequent single-port scan for clean_ips: it should clean stale clean_ips files
    r_single = ScanResult(ip="104.16.1.1", port=443, ok=True, latency_ms=50.0)
    save_results([r_single], tmp_path, "clean_ips")

    assert not (by_port / "clean_ips_port_8443.txt").exists()
    assert other_stage_file.exists()



