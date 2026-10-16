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


