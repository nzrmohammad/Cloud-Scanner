from scanner.analytics import (
    _fmt_loss,
    _fmt_ms,
    _sustained_rank,
    full_sort_key,
    get_smart_recommendations,
    latency_sort_key,
    longevity_sort_key,
    recheck_sort_key,
    summarize_failure_diagnostics,
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


def test_smart_recommendations_prefers_sustained_and_sorted_fallbacks():
    r_slow_bad = ScanResult(ip="1.1.1.1", port=443, ok=True, latency_ms=500.0, jitter_ms=1.0, packet_loss=0.0, sustained=False)
    r_fast_good = ScanResult(ip="1.1.1.2", port=443, ok=True, latency_ms=50.0, jitter_ms=5.0, packet_loss=0.0, sustained=True)
    r_mid_good = ScanResult(ip="1.1.1.3", port=443, ok=True, latency_ms=80.0, jitter_ms=6.0, packet_loss=0.0, sustained=True)
    recs = get_smart_recommendations([r_slow_bad, r_mid_good, r_fast_good])
    by_cat = {rec.category: rec.result.ip for rec in recs}
    assert by_cat["Gaming"] == "1.1.1.2"
    assert by_cat["Streaming"] == "1.1.1.3"


def test_summarize_failure_diagnostics():
    results = [
        ScanResult(ip="1.1.1.1", ok=False, error="SSLError(SSLEOFError(8, '[SSL: UNEXPECTED_EOF_WHILE_READING]'))"),
        ScanResult(ip="1.1.1.2", ok=False, error="SSLError(SSLEOFError(8, '[SSL: UNEXPECTED_EOF_WHILE_READING]'))"),
        ScanResult(ip="1.1.1.3", ok=False, error="Read timed out. (read timeout=3)"),
    ]
    reasons, hints = summarize_failure_diagnostics(results)
    assert reasons[0][1] == 2
    assert "SSLEOFError" in reasons[0][0]
    assert reasons[1][1] == 1
    assert any("VLESS" in h for h in hints)


def test_streaming_recommendation_ranking_prefers_loss_and_jitter_over_raw_speed():
    """Verify that an IP with adequate speed (12M), 0% loss, and 4ms jitter beats 55M with 25% loss and 85ms jitter."""
    r_lossy_fast = ScanResult(
        ip="1.1.1.1", port=443, ok=True, latency_ms=45.0, jitter_ms=85.0, packet_loss=25.0, speed_mbps=55.0, upload_mbps=10.0, sustained=True
    )
    r_clean_stable = ScanResult(
        ip="2.2.2.2", port=443, ok=True, latency_ms=35.0, jitter_ms=4.0, packet_loss=0.0, speed_mbps=12.0, upload_mbps=3.0, sustained=True
    )

    recs = get_smart_recommendations([r_lossy_fast, r_clean_stable])
    streaming_rec = next(r for r in recs if r.category == "Streaming")
    assert streaming_rec.result.ip == "2.2.2.2"


def test_anti_drop_recommendation_prefers_lower_longevity_loss_and_reports_true_percent():
    """Verify that Anti-Drop prefers 0% longevity loss over 4% and accurately reports the percentage."""
    r_drop4 = ScanResult(
        ip="1.1.1.1", port=443, ok=True, latency_ms=40.0, sustained=True, longevity_loss=4.0, speed_mbps=60.0
    )
    r_drop0 = ScanResult(
        ip="2.2.2.2", port=443, ok=True, latency_ms=50.0, sustained=True, longevity_loss=0.0, speed_mbps=20.0
    )

    recs = get_smart_recommendations([r_drop4, r_drop0])
    anti_rec = next(r for r in recs if r.category == "Anti-Drop")
    assert anti_rec.result.ip == "2.2.2.2"
    assert "0% drop" in anti_rec.reason


def test_full_sort_key_prioritizes_loss_and_jitter_over_speed():
    """full_sort_key must place low packet loss and low jitter ahead of high raw burst speed."""
    r_lossy_burst = ScanResult(
        ip="1.1.1.1", port=443, ok=True, latency_ms=40.0, jitter_ms=75.0, packet_loss=20.0, speed_mbps=80.0, sustained=True
    )
    r_clean_stable = ScanResult(
        ip="2.2.2.2", port=443, ok=True, latency_ms=50.0, jitter_ms=5.0, packet_loss=0.0, speed_mbps=15.0, sustained=True
    )

    sorted_res = sorted([r_lossy_burst, r_clean_stable], key=full_sort_key)
    assert sorted_res[0].ip == "2.2.2.2"


def test_full_sort_key_dropped_ranks_by_longevity_loss_and_stability():
    """Within the dropped (sustained=False) group, endpoints must rank by longevity loss and stability over raw speed."""
    r_dropped_burst = ScanResult(
        ip="1.1.1.1", port=443, ok=True, latency_ms=40.0, jitter_ms=20.0,
        packet_loss=5.0, longevity_loss=25.0, speed_mbps=100.0, sustained=False,
    )
    r_dropped_resilient = ScanResult(
        ip="2.2.2.2", port=443, ok=True, latency_ms=50.0, jitter_ms=5.0,
        packet_loss=1.0, longevity_loss=2.0, speed_mbps=20.0, sustained=False,
    )

    sorted_res = sorted([r_dropped_burst, r_dropped_resilient], key=full_sort_key)
    assert sorted_res[0].ip == "2.2.2.2"


def test_untested_packet_loss_does_not_beat_tested_zero_loss():
    """An untested endpoint (packet_loss=None) must not rank ahead of verified 0% packet loss."""
    r_tested_zero = ScanResult(ip="1.1.1.1", port=443, ok=True, latency_ms=60.0, packet_loss=0.0, sustained=True)
    r_untested = ScanResult(ip="2.2.2.2", port=443, ok=True, latency_ms=40.0, packet_loss=None, sustained=True)

    sorted_res = sorted([r_untested, r_tested_zero], key=recheck_sort_key)
    assert sorted_res[0].ip == "1.1.1.1"


def test_streaming_prefers_high_bandwidth_when_clean():
    """Streaming must prefer 100 Mbps clean over 12 Mbps clean, avoiding inverted ranking inside tiers."""
    r_100m = ScanResult(
        ip="1.1.1.1", port=443, ok=True, latency_ms=45.0, jitter_ms=10.0, packet_loss=0.0, speed_mbps=100.0, sustained=True
    )
    r_12m = ScanResult(
        ip="2.2.2.2", port=443, ok=True, latency_ms=45.0, jitter_ms=4.0, packet_loss=0.0, speed_mbps=12.0, sustained=True
    )
    recs = get_smart_recommendations([r_12m, r_100m])
    streaming_rec = next(r for r in recs if r.category == "Streaming")
    assert streaming_rec.result.ip == "1.1.1.1"


def test_anti_drop_untested_loss_does_not_beat_tested_zero():
    """Anti-Drop must rank tested 0% loss ahead of unmeasured longevity loss (None)."""
    r_untested = ScanResult(ip="1.1.1.1", port=443, ok=True, latency_ms=40.0, sustained=True, longevity_loss=None)
    r_tested_zero = ScanResult(ip="2.2.2.2", port=443, ok=True, latency_ms=50.0, sustained=True, longevity_loss=0.0)

    recs = get_smart_recommendations([r_untested, r_tested_zero])
    anti_rec = next(r for r in recs if r.category == "Anti-Drop")
    assert anti_rec.result.ip == "2.2.2.2"
    assert "0% drop" in anti_rec.reason


def test_untested_penalties_in_usable_speed_and_loss_score():
    """Verify that unmeasured loss/jitter receives baseline penalties (R9)."""
    from scanner.analytics import _loss_score, _usable_speed_score

    # Tested clean connection
    clean_score = _usable_speed_score(speed=20.0, loss=0.0, jitter=5.0)
    # Untested loss and jitter (both None) -> penalizes with loss=10.0%, jitter=25.0ms
    untested_score = _usable_speed_score(speed=20.0, loss=None, jitter=None)
    assert clean_score > untested_score
    # Untested score with speed=None returns -1.0
    assert _usable_speed_score(speed=None, loss=0.0, jitter=5.0) == -1.0

    # _loss_score returns 50.0 penalty for None
    assert _loss_score(None) == 50.0
    assert _loss_score(0.0) == 0.0
    assert _loss_score(2.5) == 2.5


def test_filter_diverse_endpoints():
    """Verify IP deduplication, /24 subnet diversity, and graceful backfill."""
    from scanner.analytics import extract_subnet_prefix, filter_diverse_endpoints

    assert extract_subnet_prefix("104.16.1.10") == "104.16.1.0/24"
    assert "::/64" in extract_subnet_prefix("2606:4700:3030::1")

    # 1. Deduplication of ports on same IP
    r_same_ip_443 = ScanResult(ip="1.1.1.1", port=443, ok=True, latency_ms=20.0)
    r_same_ip_8443 = ScanResult(ip="1.1.1.1", port=8443, ok=True, latency_ms=25.0)
    r_diff_ip = ScanResult(ip="1.1.1.2", port=443, ok=True, latency_ms=30.0)

    deduped = filter_diverse_endpoints([r_same_ip_443, r_same_ip_8443, r_diff_ip], max_targets=10)
    assert len(deduped) == 2
    assert [r.port for r in deduped if r.ip == "1.1.1.1"] == [443]

    # 2. Subnet diversity capping (max 2 per /24)
    cluster = [
        ScanResult(ip=f"104.16.1.{i}", port=443, ok=True, latency_ms=float(i))
        for i in range(1, 10)
    ]
    other_subnet = [
        ScanResult(ip="104.16.2.1", port=443, ok=True, latency_ms=50.0),
        ScanResult(ip="104.16.2.2", port=443, ok=True, latency_ms=51.0),
    ]
    diverse = filter_diverse_endpoints(cluster + other_subnet, max_targets=4, max_per_subnet=2)
    assert len(diverse) == 4
    # Must have 2 from .1. and 2 from .2.
    ips = [r.ip for r in diverse]
    assert ips == ["104.16.1.1", "104.16.1.2", "104.16.2.1", "104.16.2.2"]

    # 3. Graceful backfill when diverse subnets are fewer than max_targets
    single_subnet = [
        ScanResult(ip=f"104.16.1.{i}", port=443, ok=True, latency_ms=float(i))
        for i in range(1, 6)
    ]
    backfilled = filter_diverse_endpoints(single_subnet, max_targets=4, max_per_subnet=2)
    assert len(backfilled) == 4
    assert [r.ip for r in backfilled] == ["104.16.1.1", "104.16.1.2", "104.16.1.3", "104.16.1.4"]



