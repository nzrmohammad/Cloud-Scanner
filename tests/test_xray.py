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


def test_version_comparison_and_asset_name():
    from scanner.xray import get_platform_asset_name, is_newer_version, parse_version_tuple

    assert parse_version_tuple("v26.3.27") == (26, 3, 27)
    assert is_newer_version("v26.4.1", "26.3.27") is True
    assert is_newer_version("v26.10.0", "26.3.27") is True
    assert is_newer_version("v26.3.27", "26.3.27") is False
    assert is_newer_version("v25.12.0", "26.3.27") is False
    assert is_newer_version(None, "26.3.27") is False
    asset = get_platform_asset_name()
    assert asset.startswith("Xray-") and asset.endswith(".zip")


def test_fetch_latest_xray_tag_head_and_fallback(monkeypatch):
    import requests

    from scanner.xray import fetch_latest_xray_tag

    class MockHeadResp:
        headers = {"Location": "https://github.com/XTLS/Xray-core/releases/tag/v26.4.5"}

    monkeypatch.setattr(requests, "head", lambda *a, **kw: MockHeadResp())
    assert fetch_latest_xray_tag(timeout=1.0) == "v26.4.5"

    def raise_err(*a, **kw):
        raise OSError("offline")

    monkeypatch.setattr(requests, "head", raise_err)
    monkeypatch.setattr(requests, "get", raise_err)
    assert fetch_latest_xray_tag(timeout=1.0) is None


def test_vless_strips_trailing_dot_from_sni_and_host():
    raw = "vless://uuid@example.com:443?security=tls&sni=Static.Fox1.Org.&type=ws&host=Static.Fox1.Org.&path=%2Fws#Dot"
    v = parse_vless(raw)
    outbound = vless_to_xray_outbound(v, "1.1.1.1", port=443)
    assert outbound["streamSettings"]["tlsSettings"]["serverName"] == "Static.Fox1.Org"
    assert outbound["streamSettings"]["wsSettings"]["headers"]["Host"] == "Static.Fox1.Org"


def test_adapt_config_for_xray_version():
    from scanner.xray import adapt_config_for_xray_version

    v_insecure = parse_vless("vless://uuid@example.com:443?security=tls&allowInsecure=1&sni=example.com.&type=ws&host=example.com.&path=%2Fws#Test")
    base_cfg = make_xray_config(v_insecure, "1.1.1.1", 10808)

    # Legacy version retains allowInsecure and headers.Host
    legacy_cfg = adapt_config_for_xray_version(make_xray_config(v_insecure, "1.1.1.1", 10808), "26.3.27")
    assert legacy_cfg["outbounds"][0]["streamSettings"]["tlsSettings"]["allowInsecure"] is True
    assert legacy_cfg["outbounds"][0]["streamSettings"]["wsSettings"]["headers"]["Host"] == "example.com"

    # Modern Xray >= 26.4 drops removed allowInsecure and migrates wsSettings Host -> host
    modern_cfg = adapt_config_for_xray_version(base_cfg, "26.11.9")
    tls_settings = modern_cfg["outbounds"][0]["streamSettings"]["tlsSettings"]
    ws_settings = modern_cfg["outbounds"][0]["streamSettings"]["wsSettings"]
    assert "allowInsecure" not in tls_settings
    assert ws_settings["host"] == "example.com"
    assert "headers" not in ws_settings


def test_xray_early_exit_raises_runtime_error_quickly(monkeypatch, tmp_path):
    import time

    from scanner.xray import XrayProcess

    class FakeProc:
        def poll(self):
            return 23

        def terminate(self):
            pass

        def wait(self, timeout=None):
            return 23

        def kill(self):
            pass

    def fake_popen(cmd, **kwargs):
        stderr_file = kwargs.get("stderr")
        if stderr_file is not None:
            stderr_file.write(b"failed to start: invalid tls config\n")
            stderr_file.flush()
        return FakeProc()

    monkeypatch.setattr("subprocess.Popen", fake_popen)
    monkeypatch.setattr("scanner.xray._cached_xray_version", lambda _p: "26.11.9")

    v = parse_vless("vless://uuid@example.com:443?security=tls&type=ws#Early")
    t0 = time.monotonic()
    with pytest.raises(RuntimeError) as exc_info:
        with XrayProcess(tmp_path / "xray", v, "1.1.1.1", 443, ready_timeout=5.0):
            pass
    elapsed = time.monotonic() - t0
    assert elapsed < 1.0
    assert "code 23" in str(exc_info.value)
    assert "invalid tls config" in str(exc_info.value)


def test_normalize_xray_tag_handles_numeric_and_v_prefix():
    from scanner.xray import normalize_xray_tag

    assert normalize_xray_tag("26.11.9") == "v26.11.9"
    assert normalize_xray_tag("v26.3.27") == "v26.3.27"
    assert normalize_xray_tag("") == ""
    assert normalize_xray_tag(None) == ""


def test_xray_transient_bind_error_retries_with_fresh_port(monkeypatch, tmp_path):
    from scanner.xray import XrayProcess

    ports_seq = iter([51001, 51002])
    attempts = {"count": 0}

    class FakeProc:
        def __init__(self, rc):
            self._rc = rc

        def poll(self):
            return self._rc

        def terminate(self):
            pass

        def wait(self, timeout=None):
            return self._rc or 0

        def kill(self):
            pass

    def fake_popen(cmd, **kwargs):
        attempts["count"] += 1
        if attempts["count"] == 1:
            stderr_file = kwargs.get("stderr")
            if stderr_file is not None:
                stderr_file.write(b"listen tcp 127.0.0.1:51001: bind: address already in use\n")
                stderr_file.flush()
            return FakeProc(23)
        return FakeProc(None)

    monkeypatch.setattr("scanner.xray.free_port", lambda: next(ports_seq))
    monkeypatch.setattr("subprocess.Popen", fake_popen)
    monkeypatch.setattr("scanner.xray._cached_xray_version", lambda _p: "26.11.9")
    monkeypatch.setattr("scanner.xray.wait_ports", lambda ports, timeout, proc=None: proc is not None and proc.poll() is None)

    v = parse_vless("vless://uuid@example.com:443?security=tls&type=ws#RetryBind")
    with XrayProcess(tmp_path / "xray", v, "1.1.1.1", 443, ready_timeout=2.0) as xp:
        assert xp.socks_port == 51002
    assert attempts["count"] == 2
