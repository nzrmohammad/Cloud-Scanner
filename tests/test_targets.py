from scanner.targets import clean_target_token, expand_targets, parse_ip_and_port


def test_clean_target_token():
    assert clean_target_token("  104.16.1.1  # comment") == "104.16.1.1"
    assert clean_target_token("// comment only") == ""
    assert clean_target_token("104.16.0.0/24, other junk") == "104.16.0.0/24"


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
