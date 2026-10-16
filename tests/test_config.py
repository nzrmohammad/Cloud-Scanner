from scanner.config import make_vless_link, parse_vless
from scanner.xray import make_xray_config


def test_parse_vless_standard():
    raw = "vless://a1b2c3d4-e5f6-7a8b-9c0d-e1f2a3b4c5d6@cf.example.com:443?encryption=none&security=tls&sni=cf.example.com&fp=chrome&type=ws&host=cf.example.com&path=%2Fws#TestConfig"
    v = parse_vless(raw)
    assert v.uuid == "a1b2c3d4-e5f6-7a8b-9c0d-e1f2a3b4c5d6"
    assert v.host == "cf.example.com"
    assert v.port == 443
    assert v.query.get("type") == "ws"
    assert v.query.get("security") == "tls"
    assert v.remark == "TestConfig"


def test_parse_vless_insecure_handling():
    # allowInsecure=1
    raw1 = "vless://uuid@host.com:443?security=tls&allowInsecure=1"
    v1 = parse_vless(raw1)
    cfg1 = make_xray_config(v1, "1.1.1.1", 1080)
    tls_settings1 = cfg1["outbounds"][0]["streamSettings"]["tlsSettings"]
    assert tls_settings1["allowInsecure"] is True

    # insecure=1
    raw2 = "vless://uuid@host.com:443?security=tls&insecure=1"
    v2 = parse_vless(raw2)
    cfg2 = make_xray_config(v2, "1.1.1.1", 1080)
    tls_settings2 = cfg2["outbounds"][0]["streamSettings"]["tlsSettings"]
    assert tls_settings2["allowInsecure"] is True

    # insecure=0
    raw3 = "vless://uuid@host.com:443?security=tls&insecure=0"
    v3 = parse_vless(raw3)
    cfg3 = make_xray_config(v3, "1.1.1.1", 1080)
    tls_settings3 = cfg3["outbounds"][0]["streamSettings"]["tlsSettings"]
    assert tls_settings3["allowInsecure"] is False


def test_make_vless_link_replacement():
    raw = "vless://uuid@old-host.com:443?security=tls&type=ws#OldRemark"
    v = parse_vless(raw)
    new_link = make_vless_link(v, "104.16.1.1", 8443, "CustomTag")
    assert "104.16.1.1:8443" in new_link
    assert "CustomTag" in new_link
    assert "old-host.com" not in new_link.split("@")[1].split("?")[0]


def test_config_manager_load_and_save_vless():
    import tempfile
    from pathlib import Path

    from scanner.config import ConfigManager

    with tempfile.TemporaryDirectory() as td:
        cfg_file = Path(td) / "config.txt"
        content = (
            "# Settings\n"
            "vless = vless://test-uuid@host.com:443?security=tls#OldRemark\n"
            "workers = 20\n"
            "ports = 443, 8443\n"
            "ping_samples = 6\n"
            "longevity_duration = 25\n"
            "speed_workers = 4\n"
        )
        cfg_file.write_text(content, encoding="utf-8")

        mgr = ConfigManager(cfg_file)
        settings = mgr.load_settings()

        assert settings.vless_raw == "vless://test-uuid@host.com:443?security=tls#OldRemark"
        assert settings.workers == 20
        assert settings.ports == [443, 8443]
        assert settings.ping_samples == 6
        assert settings.longevity_duration == 25
        assert settings.speed_workers == 4

        # Test updating vless link preserving other settings
        new_vless = "vless://new-uuid@new-host.com:443?security=tls#NewRemark"
        mgr.save_vless(new_vless)
        updated_settings = mgr.load_settings()
        assert updated_settings.vless_raw == new_vless
        assert updated_settings.workers == 20



