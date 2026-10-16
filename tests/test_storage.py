import csv
import tempfile
from pathlib import Path

from scanner.models import ScanResult, SmartRecommendation, VlessConfig
from scanner.storage import save_recommended_configs, save_results


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
