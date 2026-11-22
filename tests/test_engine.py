import pytest

from scanner.constants import mb_to_bytes
from scanner.engine import calc_percentile, calc_rfc_jitter, summarize_latency
from scanner.models import ScanResult


def test_mb_to_bytes_decimal_standard():
    """Verify decimal networking standard (1 MB = 1,000,000 bytes)."""
    assert mb_to_bytes(1) == 1_000_000
    assert mb_to_bytes(5) == 5_000_000
    assert mb_to_bytes(25) == 25_000_000


def test_calc_rfc_jitter_standard():
    """Verify RFC 3393 / RFC 3550 consecutive packet delta mean."""
    # [100, 105, 95, 110]
    # |105 - 100| = 5
    # |95 - 105| = 10
    # |110 - 95| = 15
    # mean of diffs = (5 + 10 + 15) / 3 = 10.0
    lats = [100.0, 105.0, 95.0, 110.0]
    assert calc_rfc_jitter(lats) == pytest.approx(10.0)

    # Identical latencies -> 0 jitter
    assert calc_rfc_jitter([50.0, 50.0, 50.0]) == 0.0

    # Single sample -> 0 jitter
    assert calc_rfc_jitter([50.0]) == 0.0


def test_calc_percentile():
    data = [10.0, 20.0, 30.0, 40.0, 50.0]
    assert calc_percentile(data, 0.0) == 10.0
    assert calc_percentile(data, 50.0) == 30.0
    assert calc_percentile(data, 100.0) == 50.0
    assert calc_percentile(data, 90.0) == pytest.approx(46.0)


def test_summarize_latency_median_and_rfc_jitter():
    samples = [
        ScanResult(ip="1.1.1.1", port=443, ok=True, latency_ms=100.0, status_code=204),
        ScanResult(ip="1.1.1.1", port=443, ok=True, latency_ms=105.0, status_code=204),
        ScanResult(ip="1.1.1.1", port=443, ok=True, latency_ms=95.0, status_code=204),
        ScanResult(ip="1.1.1.1", port=443, ok=True, latency_ms=110.0, status_code=204),
        ScanResult(ip="1.1.1.1", port=443, ok=False, error="Timeout"),
    ]
    summary = summarize_latency(samples)
    assert summary.ok is True
    # Total 5, passed 4 -> packet loss 20%
    assert summary.packet_loss == pytest.approx(20.0)
    assert summary.recheck_passed == 4
    assert summary.recheck_total == 5
    # Median of [95, 100, 105, 110] is 102.5
    assert summary.latency_ms == pytest.approx(102.5)
    # Jitter of [100, 105, 95, 110] is 10.0
    assert summary.jitter_ms == pytest.approx(10.0)
    assert "p90" in summary.latency_stats
    assert summary.error == ""


def test_summarize_latency_single_sample_returns_none_jitter():
    """When only 1 sample passes (e.g. 1 pass, 7 fails), jitter cannot be computed and must be None, not 0.0."""
    from scanner.engine import summarize_latency

    samples = [
        ScanResult(ip="1.1.1.1", port=443, ok=True, latency_ms=100.0, status_code=204),
    ] + [ScanResult(ip="1.1.1.1", port=443, ok=False, error="Timeout") for _ in range(7)]

    summary = summarize_latency(samples)
    assert summary.ok is True
    assert summary.recheck_passed == 1
    assert summary.recheck_total == 8
    assert summary.packet_loss == pytest.approx(87.5)
    assert summary.latency_ms == pytest.approx(100.0)
    assert summary.jitter_ms is None


def test_stream_upload_payload():
    from scanner.engine import StreamUploadPayload

    payload = StreamUploadPayload(size=128 * 1024, chunk_size=32 * 1024)
    assert len(payload) == 128 * 1024
    assert payload.transfer_start is None
    assert payload.transfer_end is None

    chunks = []
    for c in payload:
        assert payload.transfer_start is not None
        chunks.append(c)

    assert len(chunks) == 4
    assert payload.bytes_sent == 128 * 1024
    assert payload.transfer_end is not None
    assert payload.transfer_end >= payload.transfer_start


def test_run_upload_probe_realistic_mbps_calculation(monkeypatch):
    """Verify upload probe isolates network RTT, applies 0.04s floor, and avoids astronomical numbers."""
    from unittest.mock import MagicMock

    from scanner.engine import _run_upload_probe

    # Case 1: Realistic upload (250 KB over 0.20s total, 0.05s RTT)
    mock_session = MagicMock()
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_session.post.return_value = mock_resp

    call_times = [0.0, 0.20]

    def mock_perf_counter():
        return call_times.pop(0) if call_times else 0.20

    monkeypatch.setattr("time.perf_counter", mock_perf_counter)

    mbps, bytes_sent, effective, err = _run_upload_probe(
        mock_session, "http://test.url", size_bytes=250_000, timeout_s=10.0, rtt_sec=0.05
    )
    assert err == ""
    assert bytes_sent == 250_000
    # effective = 0.20 - 0.05 = 0.15s -> (250_000 * 8) / (0.15 * 1e6) = 13.33 Mbps
    assert effective == pytest.approx(0.15, abs=0.01)
    assert mbps == pytest.approx(13.33, abs=0.1)

    # Case 2: Very fast response clamps to 0.04s floor (avoiding 200/400 Mbps)
    call_times_fast = [0.0, 0.025]
    monkeypatch.setattr("time.perf_counter", lambda: call_times_fast.pop(0) if call_times_fast else 0.025)
    mbps_fast, _, effective_fast, _ = _run_upload_probe(
        mock_session, "http://test.url", size_bytes=250_000, timeout_s=10.0, rtt_sec=0.0
    )
    assert effective_fast == pytest.approx(0.04, abs=0.001)
    assert mbps_fast == pytest.approx(50.0, abs=0.1)

    # Case 3: HTTP error status
    mock_err_resp = MagicMock()
    mock_err_resp.status_code = 502
    mock_session.post.return_value = mock_err_resp
    mbps_err, bytes_err, _, err_msg = _run_upload_probe(
        mock_session, "http://test.url", size_bytes=250_000, timeout_s=10.0, rtt_sec=0.05
    )
    assert mbps_err is None
    assert bytes_err == 0
    assert "502" in err_msg


def test_longevity_test_ip_soft_stall_and_success(monkeypatch):
    import tempfile
    from pathlib import Path

    from scanner.engine import longevity_test_ip
    from scanner.models import VlessConfig

    v = VlessConfig(uuid="dummy", host="test.com", port=443)
    base = ScanResult(ip="1.1.1.1", port=443, ok=True)
    with tempfile.TemporaryDirectory() as td:
        fake_xray = Path(td) / "xray"
        fake_xray.touch()

        # Mock XrayProcess
        class MockXray:
            def __init__(self, *args, **kwargs):
                self.proxies = {"http": "socks5://127.0.0.1:1080", "https": "socks5://127.0.0.1:1080"}

            def __enter__(self):
                return self

            def __exit__(self, *args):
                pass

        monkeypatch.setattr("scanner.engine.XrayProcess", MockXray)

        # 1. Soft-stall simulation (ReadTimeout)
        import requests

        def mock_get_soft_stall(*args, **kwargs):
            raise requests.exceptions.ReadTimeout("Stream hung mid-transfer")

        monkeypatch.setattr(requests, "get", mock_get_soft_stall)
        res_stall = longevity_test_ip(v, base, fake_xray, duration=2, timeout=1)
        assert res_stall.sustained is False
        assert res_stall.longevity_loss > 0

        # 2. Continuous success stream simulation
        class MockStreamResponse:
            status_code = 200

            def __enter__(self):
                return self

            def __exit__(self, *args):
                pass

            def iter_content(self, chunk_size=32 * 1024):
                # Yield 4 chunks of 32KB = 128KB total (> 100KB threshold)
                for _ in range(4):
                    yield b"\x00" * chunk_size

        def mock_get_success(*args, **kwargs):
            return MockStreamResponse()

        monkeypatch.setattr(requests, "get", mock_get_success)
        res_ok = longevity_test_ip(v, base, fake_xray, duration=1, timeout=1)
        assert res_ok.sustained is True
        assert res_ok.longevity_loss <= 5.0


def test_longevity_test_ip_does_not_abort_at_three_consecutive_failures(monkeypatch):
    import tempfile
    from pathlib import Path

    import requests

    from scanner.engine import longevity_test_ip
    from scanner.models import ScanResult, VlessConfig

    v = VlessConfig(uuid="dummy", host="test.com", port=443)
    base = ScanResult(ip="1.1.1.1", port=443, ok=True)

    class MockXray:
        def __init__(self, *args, **kwargs):
            self.proxies = {"http": "socks5://127.0.0.1:1080", "https": "socks5://127.0.0.1:1080"}

        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

    monkeypatch.setattr("scanner.engine.XrayProcess", MockXray)

    call_count = 0

    class MockStreamResponse:
        status_code = 200

        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

        def iter_content(self, chunk_size=32 * 1024):
            yield b"\x00" * (128 * 1024)

    def mock_get(*args, **kwargs):
        nonlocal call_count
        call_count += 1
        if call_count <= 4:
            raise requests.exceptions.ConnectionError("Transient connection reset")
        return MockStreamResponse()

    monkeypatch.setattr(requests, "get", mock_get)

    with tempfile.TemporaryDirectory() as td:
        fake_xray = Path(td) / "xray"
        fake_xray.touch()
        res = longevity_test_ip(v, base, fake_xray, duration=3, timeout=1)

    assert call_count >= 5
    assert res.ok is True


def test_daemon_thread_pool_executor():
    import threading

    from scanner.engine import DaemonThreadPoolExecutor

    ex = DaemonThreadPoolExecutor(max_workers=2)
    fut = ex.submit(lambda: threading.current_thread().daemon)
    assert fut.result() is True
    ex.shutdown(wait=False)


def test_run_concurrent_tasks_abort_event():
    import threading

    from scanner.engine import _run_concurrent_tasks
    from scanner.models import ScanInterrupted

    ev = threading.Event()

    def buggy_task(x: int) -> int:
        raise KeyboardInterrupt()

    with pytest.raises(ScanInterrupted):
        _run_concurrent_tasks([1, 2, 3], buggy_task, workers=2, stage_name="test_abort", abort_event=ev)

    assert ev.is_set() is True


def test_summarize_latency_preserves_passing_status_code():
    samples = [
        ScanResult(ip="1.1.1.1", port=443, ok=False, status_code=None, error="Timeout"),
        ScanResult(ip="1.1.1.1", port=443, ok=True, latency_ms=80.0, status_code=204),
    ]
    summary = summarize_latency(samples)
    assert summary.ok is True
    assert summary.status_code == 204


def test_longevity_test_ip_abort_not_sustained(monkeypatch):
    import tempfile
    import threading
    from pathlib import Path

    from scanner.engine import longevity_test_ip
    from scanner.models import VlessConfig

    v = VlessConfig(uuid="dummy", host="test.com", port=443)
    base = ScanResult(ip="1.1.1.1", port=443, ok=True)
    ev = threading.Event()

    class MockXray:
        def __init__(self, *args, **kwargs):
            self.proxies = {"http": "socks5://127.0.0.1:1080", "https": "socks5://127.0.0.1:1080"}

        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

    class MockStream:
        status_code = 200

        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

        def close(self):
            pass

        def iter_content(self, chunk_size=32 * 1024):
            yield b"\x00" * (128 * 1024)
            ev.set()
            yield b"\x00" * chunk_size

    import requests

    monkeypatch.setattr("scanner.engine.XrayProcess", MockXray)
    monkeypatch.setattr(requests, "get", lambda *a, **kw: MockStream())

    with tempfile.TemporaryDirectory() as td:
        fake_xray = Path(td) / "xray"
        fake_xray.touch()
        res = longevity_test_ip(v, base, fake_xray, duration=5, timeout=1, abort_event=ev)
        assert res.ok is False
        assert res.sustained is None
        assert res.longevity_loss is None
        assert res.error == "Aborted"


def test_execute_post_scan_stability_skips_longevity(monkeypatch):
    import tempfile
    from pathlib import Path

    from scanner.engine import execute_configured_post_scan_tests
    from scanner.models import AppSettings, VlessConfig

    v = VlessConfig(uuid="dummy", host="test.com", port=443)
    working = [ScanResult(ip="1.1.1.1", port=443, ok=True, latency_ms=40.0, status_code=204)]
    called = {"longevity": False}

    monkeypatch.setattr(
        "scanner.engine.run_stability_stage",
        lambda *a, **kw: [ScanResult(ip="1.1.1.1", port=443, ok=True, latency_ms=42.0, jitter_ms=2.0, status_code=204)],
    )
    monkeypatch.setattr(
        "scanner.engine.run_longevity_stage",
        lambda *a, **kw: called.__setitem__("longevity", True) or [],
    )
    monkeypatch.setattr("scanner.engine.enrich_results_with_colo", lambda *a, **kw: None)

    with tempfile.TemporaryDirectory() as td:
        settings = AppSettings(post_scan_mode="stability", longevity_test=True)
        out_res, _, _, prefix = execute_configured_post_scan_tests(settings, v, working, Path(td) / "xray", Path(td))
        assert called["longevity"] is False
        assert prefix == "clean_ips_rechecked"
        assert len(out_res) == 1


def test_run_latency_scan_batch_fallback_no_duplicate_on_interrupt(monkeypatch, tmp_path):
    from scanner.engine import run_latency_scan
    from scanner.models import ScanInterrupted, VlessConfig

    v = VlessConfig(uuid="dummy", host="test.com", port=443)
    pairs = [(f"104.16.1.{i}", 443) for i in range(1, 13)]  # 2 chunks when concurrency=2 -> batch_size=10 (10 + 2)

    class FakeBatch:
        call_num = 0

        def __init__(self, *args, **kwargs):
            FakeBatch.call_num += 1
            self.idx = FakeBatch.call_num

        def __enter__(self):
            if self.idx == 2:
                raise RuntimeError("Batch failed on chunk 2")
            return self

        def __exit__(self, *args):
            pass

        def get_proxies_for_endpoint(self, ip, port):
            return {"http": "socks5h://127.0.0.1:1080"}

    def fake_probe(ip, port, proxies, timeout, url):
        return ScanResult(ip=ip, port=port, ok=True, latency_ms=25.0, status_code=204), ""

    def fake_fallback_test_ip(*args, **kwargs):
        raise KeyboardInterrupt()

    monkeypatch.setattr("scanner.engine.BatchXrayProcess", FakeBatch)
    monkeypatch.setattr("scanner.engine._probe_via_proxies", fake_probe)
    monkeypatch.setattr("scanner.engine.test_ip", fake_fallback_test_ip)

    with pytest.raises(ScanInterrupted) as exc_info:
        run_latency_scan(v, pairs, tmp_path / "xray", concurrency=2, timeout=2, tries=1)

    partial = exc_info.value.results
    assert len(partial) == 10
    assert len({(r.ip, r.port) for r in partial}) == 10


def test_enrich_results_with_colo_concurrent_fallback(monkeypatch, tmp_path):
    from scanner.engine import enrich_results_with_colo
    from scanner.models import VlessConfig

    v = VlessConfig(uuid="dummy", host="test.com", port=443)
    res = [ScanResult(ip=f"104.16.1.{i}", port=443, ok=True) for i in range(1, 4)]

    class FailBatch:
        def __init__(self, *args, **kwargs):
            pass

        def __enter__(self):
            raise RuntimeError("Batch init failed")

        def __exit__(self, *args):
            pass

    monkeypatch.setattr("scanner.engine.enrich_results_with_geoip", lambda *a, **kw: None)
    monkeypatch.setattr("scanner.engine.BatchXrayProcess", FailBatch)
    monkeypatch.setattr("scanner.engine.resolve_endpoint_colo", lambda _v, ip, port, _x, timeout=3: "FRA")

    enrich_results_with_colo(v, res, tmp_path / "xray", workers=3, timeout=2)
    assert [r.colo for r in res] == ["FRA", "FRA", "FRA"]


def test_run_latency_scan_aborts_fast_on_xray_startup_error(monkeypatch, tmp_path):
    from scanner.engine import run_latency_scan
    from scanner.models import VlessConfig
    from scanner.xray import XrayStartupError

    v = VlessConfig(uuid="dummy", host="test.com", port=443)
    pairs = [(f"104.16.1.{i}", 443) for i in range(1, 26)]  # >1 chunk
    calls = {"batch": 0, "fallback": 0}

    class BrokenBatch:
        def __init__(self, *args, **kwargs):
            calls["batch"] += 1

        def __enter__(self):
            raise XrayStartupError("Xray exited early (code 23): invalid config")

        def __exit__(self, *args):
            pass

    monkeypatch.setattr("scanner.engine.BatchXrayProcess", BrokenBatch)
    monkeypatch.setattr(
        "scanner.engine.test_ip",
        lambda *a, **kw: calls.__setitem__("fallback", calls["fallback"] + 1) or ScanResult(ip="1.1.1.1"),
    )

    out = run_latency_scan(v, pairs, tmp_path / "xray", concurrency=2, timeout=2, tries=1)
    assert len(out) == 25
    assert all(not r.ok and "code 23" in r.error for r in out)
    assert calls["batch"] == 1
    assert calls["fallback"] == 0


def test_run_speed_stage_skips_when_zero_sizes(tmp_path):
    from scanner.engine import run_speed_stage
    from scanner.models import VlessConfig

    v = VlessConfig(uuid="dummy", host="test.com", port=443)
    base = [ScanResult(ip="1.1.1.1", port=443, ok=True, latency_ms=20.0)]
    out = run_speed_stage(v, base, tmp_path / "xray", workers=2, duration=5, timeout=5, download_mb=0, upload_mb=0)
    assert out == base


def test_build_target_pairs_respects_explicit_ports_and_deduplicates():
    from scanner.engine import build_target_pairs

    pairs = build_target_pairs(["1.1.1.1:443", "1.1.1.1:443", "1.0.0.1"], [443, 8443])
    assert pairs == [("1.1.1.1", 443), ("1.0.0.1", 443), ("1.0.0.1", 8443)]


def test_run_speed_stage_filters_dead_candidates(tmp_path, monkeypatch):
    from scanner.engine import run_speed_stage
    from scanner.models import VlessConfig

    v = VlessConfig(uuid="dummy", host="test.com", port=443)
    tested_ips = []

    monkeypatch.setattr(
        "scanner.engine.speed_test_ip",
        lambda _v, r, *a, **kw: tested_ips.append(r.ip) or r,
    )

    candidates = [
        ScanResult(ip="1.1.1.1", port=443, ok=False, error="Timeout"),
        ScanResult(ip="1.1.1.2", port=443, ok=True, latency_ms=30.0),
    ]

    out = run_speed_stage(v, candidates, tmp_path / "xray", workers=1, duration=5, timeout=5, download_mb=5)
    assert tested_ips == ["1.1.1.2"]
    assert len(out) == 1
    assert out[0].ip == "1.1.1.2"


def test_scanner_engine_forwards_tries_and_speed_urls(tmp_path, monkeypatch):
    from scanner.engine import ScannerEngine
    from scanner.models import VlessConfig

    v = VlessConfig(uuid="dummy", host="test.com", port=443)
    captured = {}

    def _spy_run_scan(**kw):
        captured["scan_tries"] = kw.get("tries")
        return [ScanResult(ip="1.1.1.1", port=443, ok=True)]

    def _spy_run_speed(*a, **kw):
        captured["speed_url_template"] = a[7] if len(a) > 7 else kw.get("speed_url_template")
        captured["upload_url"] = kw.get("upload_url")
        return [ScanResult(ip="1.1.1.1", port=443, ok=True)]

    monkeypatch.setattr("scanner.engine.run_scan", _spy_run_scan)
    monkeypatch.setattr("scanner.engine.run_speed_tests", _spy_run_speed)

    dummy_xray = tmp_path / "xray.exe"
    dummy_xray.write_text("xray")
    engine = ScannerEngine(xray_path=dummy_xray)

    engine.scan(v, ["1.1.1.1"], [443], tries=3)
    assert captured["scan_tries"] == 3

    engine.test_speed(
        v,
        [ScanResult(ip="1.1.1.1", port=443, ok=True)],
        speed_url_template="https://custom.speed/{bytes}",
        upload_url="https://custom.upload",
    )
    assert captured["speed_url_template"] == "https://custom.speed/{bytes}"
    assert captured["upload_url"] == "https://custom.upload"


def test_retest_ip_latency_aborted_sets_ok_false(tmp_path, monkeypatch):
    import threading

    from scanner.engine import retest_ip_latency
    from scanner.models import VlessConfig

    v = VlessConfig(uuid="dummy", host="test.com", port=443)
    base = ScanResult(ip="1.1.1.1", port=443, ok=True, latency_ms=40.0)

    abort_ev = threading.Event()
    abort_ev.set()  # Already aborted before sampling

    class FakeXP:
        def __init__(self, *a, **kw):
            self.proxies = {}

        def __enter__(self):
            return self

        def __exit__(self, *a):
            pass

    monkeypatch.setattr("scanner.engine.XrayProcess", FakeXP)

    out = retest_ip_latency(v, base, tmp_path / "xray", timeout=2, sample_count=4, abort_event=abort_ev)
    assert out.ok is False
    assert out.error == "Aborted"




