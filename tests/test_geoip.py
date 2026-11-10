import json
import tempfile
from pathlib import Path

from scanner.geoip import _load_cache, _save_cache_entry, format_ip_location


def test_format_ip_location():
    assert format_ip_location("IR", "Tehran") == "[IR] Tehran"
    assert format_ip_location("US", "-") == "[US]"
    assert format_ip_location("DE", "unknown") == "[DE]"
    assert format_ip_location(None, None) == "-"




def test_geoip_disk_cache(monkeypatch):
    with tempfile.TemporaryDirectory() as td:
        test_cache_file = Path(td) / "geoip_cache.json"
        monkeypatch.setattr("scanner.geoip._GEOIP_CACHE_FILE", test_cache_file)
        monkeypatch.setattr("scanner.geoip._GEOIP_CACHE", {})
        monkeypatch.setattr("scanner.geoip._CACHE_LOADED", False)

        # Save entry
        _save_cache_entry("1.1.1.1", ("AU", "Sydney", "Cloudflare"))
        assert test_cache_file.exists()

        data = json.loads(test_cache_file.read_text(encoding="utf-8"))
        assert "1.1.1.1" in data
        assert data["1.1.1.1"]["country"] == "AU"
        assert data["1.1.1.1"]["city"] == "Sydney"

        # Reset in-memory cache and load from disk
        monkeypatch.setattr("scanner.geoip._GEOIP_CACHE", {})
        monkeypatch.setattr("scanner.geoip._CACHE_LOADED", False)
        _load_cache()
        from scanner.geoip import _GEOIP_CACHE
        assert _GEOIP_CACHE["1.1.1.1"] == ("AU", "Sydney", "Cloudflare")


def test_lookup_local_geoip():
    from scanner.geoip import lookup_local_geoip
    from scanner.xray import find_asset

    assert lookup_local_geoip("not_an_ip") is None
    if find_asset("geoip.dat"):
        cf_code = lookup_local_geoip("104.16.132.229")
        assert cf_code is not None
        assert isinstance(cf_code, str)
        assert len(cf_code) >= 2

        ir_code = lookup_local_geoip("178.22.122.100")
        assert ir_code is not None
        assert isinstance(ir_code, str)
        assert len(ir_code) >= 2

        # Nested overlapping CIDR check (1.18.128.0/24 CN inside 1.16.0.0/14 KR)
        assert lookup_local_geoip("1.18.129.0") == "KR"
        # IPv6 local DB support
        assert lookup_local_geoip("2606:4700::1") is not None


def test_build_interval_index_overlap():
    from scanner.geoip import _build_interval_index, _lookup_interval_index

    raw = [(100, 200, "KR"), (120, 150, "CN")]
    ranges, starts, max_ends = _build_interval_index(raw)
    assert _lookup_interval_index(130, ranges, starts, max_ends) == "CN"
    assert _lookup_interval_index(170, ranges, starts, max_ends) == "KR"
    assert _lookup_interval_index(250, ranges, starts, max_ends) is None


