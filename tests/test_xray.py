import pytest

from scanner.config import parse_vless
from scanner.xray import make_batch_xray_config, make_xray_config, vless_to_xray_outbound


@pytest.fixture
def sample_vless():
    link = "vless://11111111-2222-3333-4444-555555555555@example.com:443?encryption=none&security=tls&sni=example.com&type=ws&host=example.com&path=%2Fws#Sample"
    return parse_vless(link)


def test_vless_to_xray_outbound(sample_vless):
    outbound = vless_to_xray_outbound(sample_vless, "104.16.1.1", port=443)
    assert outbound["protocol"] == "vless"
    assert outbound["settings"]["vnext"][0]["address"] == "104.16.1.1"
    assert outbound["settings"]["vnext"][0]["port"] == 443
    assert outbound["streamSettings"]["network"] == "ws"
    assert outbound["streamSettings"]["security"] == "tls"
    assert outbound["streamSettings"]["wsSettings"]["path"] == "/ws"


def test_make_xray_config(sample_vless):
    cfg = make_xray_config(sample_vless, "104.16.1.1", 10808)
    assert "inbounds" in cfg
    assert "outbounds" in cfg
    assert cfg["inbounds"][0]["port"] == 10808
    assert cfg["outbounds"][0]["settings"]["vnext"][0]["address"] == "104.16.1.1"


def test_make_batch_xray_config(sample_vless):
    endpoints = [
        ("104.16.1.1", 443, 10801),
        ("104.16.1.2", 8443, 10802),
    ]
    cfg = make_batch_xray_config(sample_vless, endpoints)
    assert len(cfg["inbounds"]) == 2
    assert len(cfg["routing"]["rules"]) == 2
    assert cfg["inbounds"][0]["port"] == 10801
    assert cfg["inbounds"][1]["port"] == 10802
    assert cfg["routing"]["rules"][0]["inboundTag"] == ["socks-0"]
    assert cfg["routing"]["rules"][0]["outboundTag"] == "proxy-0"
    assert cfg["routing"]["rules"][1]["inboundTag"] == ["socks-1"]
    assert cfg["routing"]["rules"][1]["outboundTag"] == "proxy-1"
