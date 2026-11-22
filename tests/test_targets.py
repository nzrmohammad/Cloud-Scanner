from scanner.targets import clean_target_token, expand_targets, parse_ip_and_port


def test_clean_target_token():
    assert clean_target_token("  104.16.1.1  # comment") == "104.16.1.1"
    assert clean_target_token("// comment only") == ""
    assert clean_target_token("104.16.0.0/24, other junk") == "104.16.0.0/24"
    assert clean_target_token("1.1.1.1 - 1.1.1.5 # spaced range") == "1.1.1.1-1.1.1.5"


def test_parse_ip_and_port_ipv4():
    ip, port = parse_ip_and_port("1.1.1.1")
    assert ip == "1.1.1.1"
    assert port is None

    ip, port = parse_ip_and_port("1.1.1.1:8443")
    assert ip == "1.1.1.1"
    assert port == 8443


def test_parse_ip_and_port_ipv6():
    ip, port = parse_ip_and_port("2606:4700:4700::1111")
    assert ip == "2606:4700:4700::1111"
    assert port is None

    ip, port = parse_ip_and_port("[2606:4700:4700::1111]:2053")
    assert ip == "2606:4700:4700::1111"
    assert port == 2053


def test_expand_targets_cidr_and_sampling():
    # Expand /30 (4 total, 2 usable hosts)
    targets = expand_targets(["192.168.1.0/30"], max_hosts=10)
    assert len(targets) == 2
    assert "192.168.1.1" in targets
    assert "192.168.1.2" in targets

    # Limit sampling
    targets_limited = expand_targets(["192.168.1.0/24"], max_hosts=5, sample_if_too_many=True)
    assert len(targets_limited) == 5


def test_expand_targets_short_range_and_ipv6_safe_cap():
    short_rng = expand_targets(["192.168.1.10-14"], max_hosts=10)
    assert short_rng == [f"192.168.1.{i}" for i in range(10, 15)]

    # Huge IPv6 /32 with max_hosts=0 must auto-sample safely without OOM
    v6_targets = expand_targets(["2400:cb00::/32"], max_hosts=0, sample_if_too_many=True)
    assert 0 < len(v6_targets) <= 2000

    # Mixed IPv4 + huge IPv6 must not starve IPv4 ranges
    mixed = expand_targets(["192.168.1.0/24", "2a10:1fc0::/29"], max_hosts=20, sample_if_too_many=True)
    v4_count = sum(1 for x in mixed if ":" not in x)
    v6_count = sum(1 for x in mixed if ":" in x)
    assert v4_count >= 5
    assert v6_count >= 1


def test_overlapping_ranges_merged_before_sampling():
    sampled = expand_targets(["192.168.1.1-10", "192.168.1.5-15"], max_hosts=15, sample_if_too_many=True)
    assert len(sampled) == 15
    assert set(sampled) == {f"192.168.1.{i}" for i in range(1, 16)}


def test_expand_targets_range_with_port():
    res1 = expand_targets(["192.168.1.10-12:8443"], max_hosts=10)
    assert res1 == ["192.168.1.10:8443", "192.168.1.11:8443", "192.168.1.12:8443"]
    res2 = expand_targets(["192.168.1.20-192.168.1.21:2053"], max_hosts=10)
    assert res2 == ["192.168.1.20:2053", "192.168.1.21:2053"]


def test_resolve_target_file_rejects_unc():
    from scanner.targets import _resolve_target_file

    assert _resolve_target_file(r"\\malicious\share\ips.txt", "ips") is None
    assert _resolve_target_file("//malicious/share/ips.txt", "ips") is None


def test_small_ipv6_not_formatted_as_ipv4():
    res = expand_targets(["::1", "::2", "::ffff"])
    assert res == ["::1", "::2", "::ffff"]


def test_sampling_budget_one_prefers_ipv4():
    # When max_hosts=1 and equal weight between v4 and v6, deterministic largest remainder preserves IPv4
    res_v4_v6 = expand_targets(["1.1.1.1", "2606:4700:4700::1111"], max_hosts=1, sample_if_too_many=True)
    res_v6_v4 = expand_targets(["2606:4700:4700::1111", "1.1.1.1"], max_hosts=1, sample_if_too_many=True)
    assert res_v4_v6 == ["1.1.1.1"]
    assert res_v6_v4 == ["1.1.1.1"]


def test_overlapping_port_and_wildcard_targets_merged():
    # 1.2.3.4 (wildcard) subsumes 1.2.3.4:443; with max_hosts=2, 1.2.3.5 is not crowded out
    sampled = expand_targets(["1.2.3.4", "1.2.3.4:443", "1.2.3.5"], max_hosts=2, sample_if_too_many=True)
    assert len(sampled) == 2
    assert "1.2.3.4" in sampled
    assert "1.2.3.5" in sampled
