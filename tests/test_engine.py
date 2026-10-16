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



