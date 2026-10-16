from scanner.analytics import (
    _fmt_loss,
    _fmt_ms,
    _sustained_rank,
    full_sort_key,
    get_smart_recommendations,
    latency_sort_key,
    longevity_sort_key,
    recheck_sort_key,
)
from scanner.models import ScanResult, VlessConfig


def test_sustained_rank_order():
    """Verify that True (0.0) ranks ahead of None (1.0), which ranks ahead of False (2.0)."""
    assert _sustained_rank(True) == 0.0
    assert _sustained_rank(None) == 1.0
    assert _sustained_rank(False) == 2.0
    assert _sustained_rank(True) < _sustained_rank(None) < _sustained_rank(False)


def test_sort_keys_handle_none_sustained():
    """Ensure untested endpoints (sustained=None) rank between tested success (True) and failure (False)."""
    r_true = ScanResult(ip="1.1.1.1", ok=True, latency_ms=50.0, sustained=True)
    r_none = ScanResult(ip="1.1.1.2", ok=True, latency_ms=50.0, sustained=None)
    r_false = ScanResult(ip="1.1.1.3", ok=True, latency_ms=50.0, sustained=False)

    results = [r_false, r_true, r_none]

    # recheck_sort_key
    sorted_recheck = sorted(results, key=recheck_sort_key)
    assert [r.ip for r in sorted_recheck] == ["1.1.1.1", "1.1.1.2", "1.1.1.3"]

    # full_sort_key
    sorted_full = sorted(results, key=full_sort_key)
    assert [r.ip for r in sorted_full] == ["1.1.1.1", "1.1.1.2", "1.1.1.3"]

    # longevity_sort_key
    sorted_long = sorted(results, key=longevity_sort_key)
    assert [r.ip for r in sorted_long] == ["1.1.1.1", "1.1.1.2", "1.1.1.3"]


def test_fmt_helpers():
    """Verify safe formatting for None values."""
    assert _fmt_ms(None) == "-"
    assert _fmt_ms(45.6) == "46"
    assert _fmt_loss(None) == "-"
    assert _fmt_loss(0.0) == "0"
    assert _fmt_loss(12.3) == "12"


def test_smart_recommendations_none_latency_no_crash():
    """Recommendations must not crash if latency_ms is None."""
    r1 = ScanResult(ip="104.16.1.1", port=443, ok=True, latency_ms=None, packet_loss=0.0)
    r2 = ScanResult(ip="104.16.1.2", port=443, ok=True, latency_ms=40.0, speed_mbps=25.0)

    vless = VlessConfig(raw="vless://test@example.com:443", host="example.com")
    recs = get_smart_recommendations([r1, r2], vless_config=vless)

    assert len(recs) > 0
    for rec in recs:
        assert isinstance(rec.reason, str)
        assert isinstance(rec.vless_link, str)


def test_latency_sort_key_none_handling():
    """None latency should sort last."""
    r_fast = ScanResult(ip="1.1.1.1", ok=True, latency_ms=20.0)
    r_none = ScanResult(ip="1.1.1.2", ok=True, latency_ms=None)
    sorted_res = sorted([r_none, r_fast], key=latency_sort_key)
    assert sorted_res[0].ip == "1.1.1.1"
    assert sorted_res[1].ip == "1.1.1.2"
