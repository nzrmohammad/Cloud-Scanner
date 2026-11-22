import pytest

from scanner.config import parse_vless
from scanner.xray import (
    adapt_config_for_xray_version,
    make_batch_xray_config,
    make_xray_config,
    vless_to_xray_outbound,
)


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
    legacy_cfg = adapt_config_for_xray_version(make_xray_config(v_insecure, "1.1.1.1", 10808), "24.9.30")
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
    assert elapsed < 3.0
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


def test_adapt_config_migrates_h2_to_xhttp_for_modern_xray():
    from scanner.xray import adapt_config_for_xray_version

    v_h2 = parse_vless("vless://uuid@example.com:443?security=tls&type=h2&alpn=http%2F1.1&sni=Ex.Com.&host=Ex.Com.&path=%2Fh2#H2")
    legacy_cfg = adapt_config_for_xray_version(make_xray_config(v_h2, "1.1.1.1", 10808), "24.9.30")
    assert legacy_cfg["outbounds"][0]["streamSettings"]["network"] == "h2"
    assert "httpSettings" in legacy_cfg["outbounds"][0]["streamSettings"]

    modern_cfg = adapt_config_for_xray_version(make_xray_config(v_h2, "1.1.1.1", 10808), "26.11.9")
    stream = modern_cfg["outbounds"][0]["streamSettings"]
    assert stream["network"] == "xhttp"
    assert "httpSettings" not in stream
    assert stream["xhttpSettings"] == {"path": "/h2", "host": "Ex.Com", "mode": "stream-one"}
    # ALPN must include h2 for xHTTP
    assert "h2" in stream["tlsSettings"]["alpn"]


def test_xhttp_mode_param_and_splithttp_migration():
    from scanner.config import parse_vless
    from scanner.xray import adapt_config_for_xray_version, make_xray_config

    # Custom mode in query
    v_split = parse_vless(
        "vless://uuid@example.com:443?security=tls&type=splithttp&mode=packet-up&sni=Ex.Com.&host=Ex.Com.&path=%2Fsp#Split"
    )
    legacy_cfg = adapt_config_for_xray_version(make_xray_config(v_split, "1.1.1.1", 10808), "24.9.30")
    stream_leg = legacy_cfg["outbounds"][0]["streamSettings"]
    assert stream_leg["network"] == "splithttp"
    assert stream_leg["splithttpSettings"]["mode"] == "packet-up"

    # In modern Xray >= 24.12.18, splithttp migrates to xhttp with preserved mode
    modern_cfg = adapt_config_for_xray_version(make_xray_config(v_split, "1.1.1.1", 10808), "26.11.9")
    stream_mod = modern_cfg["outbounds"][0]["streamSettings"]
    assert stream_mod["network"] == "xhttp"
    assert stream_mod["xhttpSettings"] == {"path": "/sp", "host": "Ex.Com", "mode": "packet-up"}


def test_port_allocation_reservation_and_release():
    from scanner.xray import _RESERVED_LOCAL_PORTS, free_port, free_ports, release_ports

    p1 = free_port()
    assert p1 in _RESERVED_LOCAL_PORTS

    ports = free_ports(3)
    assert len(ports) == 3
    assert len(set(ports)) == 3
    assert p1 not in ports
    for p in ports:
        assert p in _RESERVED_LOCAL_PORTS

    release_ports([p1] + ports)
    assert p1 not in _RESERVED_LOCAL_PORTS
    for p in ports:
        assert p not in _RESERVED_LOCAL_PORTS


def test_vless_flow_omitted_on_non_tcp_or_non_tls():
    from scanner.config import parse_vless
    from scanner.xray import vless_to_xray_outbound

    # flow on ws should be omitted
    v_ws = parse_vless("vless://uuid@example.com:443?type=ws&security=tls&flow=xtls-rprx-vision#WS")
    out_ws = vless_to_xray_outbound(v_ws, "1.1.1.1")
    assert "flow" not in out_ws["settings"]["vnext"][0]["users"][0]

    # flow on tcp with security=none should be omitted
    v_none = parse_vless("vless://uuid@example.com:443?type=tcp&security=none&flow=xtls-rprx-vision#None")
    out_none = vless_to_xray_outbound(v_none, "1.1.1.1")
    assert "flow" not in out_none["settings"]["vnext"][0]["users"][0]

    # flow on tcp with tls or reality is kept
    v_tcp = parse_vless("vless://uuid@example.com:443?type=tcp&security=tls&flow=xtls-rprx-vision#TCP")
    out_tcp = vless_to_xray_outbound(v_tcp, "1.1.1.1")
    assert out_tcp["settings"]["vnext"][0]["users"][0]["flow"] == "xtls-rprx-vision"


def test_vless_empty_encryption_defaults_to_none():
    v = parse_vless("vless://uuid@example.com:443?type=ws&security=tls&encryption=#EmptyEnc")
    out = vless_to_xray_outbound(v, "1.1.1.1")
    assert out["settings"]["vnext"][0]["users"][0]["encryption"] == "none"


def test_vless_reality_validation_missing_pbk_and_bad_transport():
    # Missing pbk
    v_no_pbk = parse_vless("vless://uuid@example.com:443?type=tcp&security=reality&sni=example.com#NoPBK")
    with pytest.raises(ValueError, match="missing required public key"):
        vless_to_xray_outbound(v_no_pbk, "1.1.1.1")

    # Unsupported transport for reality (e.g. ws)
    v_bad_net = parse_vless("vless://uuid@example.com:443?type=ws&security=reality&pbk=1234567890abcdef#BadNet")
    with pytest.raises(ValueError, match="only supports 'tcp', 'xhttp', and 'grpc'"):
        vless_to_xray_outbound(v_bad_net, "1.1.1.1")


def test_vless_extracts_host_header_from_headers_param():
    v = parse_vless(
        "vless://uuid@example.com:443?type=ws&security=tls&headers=%7B%22Host%22%3A%22custom.domain.com%22%7D#Headers"
    )
    out = vless_to_xray_outbound(v, "1.1.1.1")
    assert out["streamSettings"]["wsSettings"]["headers"]["Host"] == "custom.domain.com"

    # List header value should not be stringified as "['custom.domain.com']"
    v_list = parse_vless(
        "vless://uuid@example.com:443?type=ws&security=tls&headers=%7B%22Host%22%3A%5B%22custom.domain.com%22%5D%7D#HeadersList"
    )
    out_list = vless_to_xray_outbound(v_list, "1.1.1.1")
    assert out_list["streamSettings"]["wsSettings"]["headers"]["Host"] == "custom.domain.com"


def test_vless_flow_omitted_when_encryption_not_none():
    v = parse_vless(
        "vless://uuid@example.com:443?type=tcp&security=tls&flow=xtls-rprx-vision&encryption=chacha20-poly1305#BadEnc"
    )
    out = vless_to_xray_outbound(v, "1.1.1.1")
    assert "flow" not in out["settings"]["vnext"][0]["users"][0]


def test_adapt_config_sets_alpn_when_missing():
    v = parse_vless("vless://uuid@example.com:443?type=h2&security=tls#NoALPN")
    raw_cfg = make_xray_config(v, "1.1.1.1", 10808)
    adapted = adapt_config_for_xray_version(raw_cfg, version="26.11.9")
    tls_cfg = adapted["outbounds"][0]["streamSettings"]["tlsSettings"]
    assert tls_cfg["alpn"] == ["h2", "http/1.1"]


def test_real_xray_binary_runs_test_successfully(tmp_path):
    import json
    import subprocess

    from scanner.constants import app_dir

    xray_exe = app_dir() / "core" / "xray.exe"
    if not xray_exe.is_file():
        pytest.skip("core/xray.exe not present in local workspace")

    v = parse_vless(
        "vless://11111111-2222-3333-4444-555555555555@example.com:443?type=h2&security=tls&insecure=1&host=example.com#TestReal"
    )
    raw_cfg = make_xray_config(v, "104.16.1.1", 10808)
    adapted_cfg = adapt_config_for_xray_version(raw_cfg, version="26.11.9")

    cfg_file = tmp_path / "config.json"
    cfg_file.write_text(json.dumps(adapted_cfg, indent=2), encoding="utf-8")

    res = subprocess.run(
        [str(xray_exe), "run", "-test", "-config", str(cfg_file)],
        capture_output=True,
        text=True,
        timeout=5.0,
    )
    assert res.returncode == 0, f"Xray test failed with rc={res.returncode}: {res.stderr}"


def test_xhttp_mode_multi_sanitized_to_auto():
    # Direct xhttp with mode=multi
    v_xhttp = parse_vless("vless://uuid@example.com:443?type=xhttp&mode=multi#XHTTPMulti")
    out = vless_to_xray_outbound(v_xhttp, "1.1.1.1")
    assert out["streamSettings"]["xhttpSettings"]["mode"] == "auto"

    # Migration from splithttp with mode=multi
    v_split = parse_vless("vless://uuid@example.com:443?type=splithttp&mode=multi#SplitMulti")
    cfg = adapt_config_for_xray_version({"outbounds": [vless_to_xray_outbound(v_split, "1.1.1.1")]}, "26.11.9")
    assert cfg["outbounds"][0]["streamSettings"]["xhttpSettings"]["mode"] == "auto"


def test_socks_inbound_has_udp_enabled():
    v = parse_vless("vless://uuid@example.com:443?type=ws&security=tls#Socks")
    cfg = make_xray_config(v, "1.1.1.1", 10808)
    assert cfg["inbounds"][0]["settings"]["udp"] is True

    batch_cfg = make_batch_xray_config(v, [("1.1.1.1", 443, 10808)])
    assert batch_cfg["inbounds"][0]["settings"]["udp"] is True


def test_adapt_config_handles_none_version():
    v = parse_vless("vless://uuid@example.com:443?type=h2&security=tls&insecure=1&host=example.com#H2")
    cfg = adapt_config_for_xray_version(make_xray_config(v, "1.1.1.1", 10808), version=None)
    stream = cfg["outbounds"][0]["streamSettings"]
    # Should migrate h2 to xhttp
    assert stream["network"] == "xhttp"
    # Should strip allowInsecure
    assert "allowInsecure" not in stream["tlsSettings"]


def test_free_ports_rollback_on_failure(monkeypatch):
    import socket

    from scanner.xray import _PORT_LOCK, _RESERVED_LOCAL_PORTS, free_ports

    orig_bind = socket.socket.bind
    calls = 0

    def mock_bind(self, addr):
        nonlocal calls
        calls += 1
        if calls > 1:
            raise OSError("Simulated port exhaustion")
        return orig_bind(self, addr)

    monkeypatch.setattr(socket.socket, "bind", mock_bind)

    with _PORT_LOCK:
        initial_reserved = set(_RESERVED_LOCAL_PORTS)

    with pytest.raises(RuntimeError, match="Could not allocate"):
        free_ports(2)

    with _PORT_LOCK:
        assert _RESERVED_LOCAL_PORTS == initial_reserved


def test_batch_reallocate_ports_releases_on_failure(monkeypatch, sample_vless, tmp_path):
    import scanner.xray as xray_mod
    from scanner.xray import _PORT_LOCK, _RESERVED_LOCAL_PORTS, BatchXrayProcess

    xray_bin = tmp_path / "xray.exe"
    xray_bin.write_text("dummy", encoding="utf-8")

    batch = BatchXrayProcess(
        xray_path=xray_bin,
        vless_config=sample_vless,
        endpoints=[("104.16.1.1", 443), ("104.16.1.2", 443)],
    )
    old_ports = batch._ready_ports()
    assert len(old_ports) == 2

    def mock_free_ports(count):
        port = 99991
        with _PORT_LOCK:
            _RESERVED_LOCAL_PORTS.add(port)
        # Return fewer ports than expected to trigger failure branch in _reallocate_ports
        return [port]

    monkeypatch.setattr(xray_mod, "free_ports", mock_free_ports)

    with pytest.raises(RuntimeError, match="Requested 2 ports, got 1"):
        batch._reallocate_ports()

    with _PORT_LOCK:
        assert 99991 not in _RESERVED_LOCAL_PORTS

    batch.close()


def test_base_xray_process_gc_safe_uninitialized():
    from scanner.xray import _BaseXrayProcess

    # Create uninitialized instance (bypassing __init__)
    proc = _BaseXrayProcess.__new__(_BaseXrayProcess)
    # close() and __del__() must not raise AttributeError on missing _lock
    proc.close()
    proc.__del__()


