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

        # GeoIP DBs vary across Xray releases (overlap logic is covered by test_build_interval_index_overlap)
        res_1_18 = lookup_local_geoip("1.18.129.0")
        assert res_1_18 is None or isinstance(res_1_18, str)
        # IPv6 local DB support
        assert lookup_local_geoip("2606:4700::1") is not None


def test_build_interval_index_overlap():
    from scanner.geoip import _build_interval_index, _lookup_interval_index

    raw = [(100, 200, "KR"), (120, 150, "CN")]
    ranges, starts, max_ends = _build_interval_index(raw)
    assert _lookup_interval_index(130, ranges, starts, max_ends) == "CN"
    assert _lookup_interval_index(170, ranges, starts, max_ends) == "KR"
    assert _lookup_interval_index(250, ranges, starts, max_ends) is None


def test_set_geoip_cache_dir_clears_memory_and_switches_path(monkeypatch, tmp_path):
    from scanner import geoip

    dir1 = tmp_path / "run1"
    dir2 = tmp_path / "run2"
    monkeypatch.setattr(geoip, "_GEOIP_CACHE", {"1.2.3.4": ("DE", "Berlin", "Org")})
    monkeypatch.setattr(geoip, "_GEOIP_CACHE_TS", {"1.2.3.4": 100.0})
    monkeypatch.setattr(geoip, "_GEOIP_CACHE_FILE", dir1 / "geoip_cache.json")

    geoip.set_geoip_cache_dir(dir2)
    assert geoip._GEOIP_CACHE_FILE == dir2 / "geoip_cache.json"
    assert geoip._GEOIP_CACHE == {}
    assert geoip._GEOIP_CACHE_TS == {}
    # Unflushed in-memory cache was persisted to old path
    assert (dir1 / "geoip_cache.json").exists()
    old_data = json.loads((dir1 / "geoip_cache.json").read_text(encoding="utf-8"))
    assert "1.2.3.4" in old_data


def test_provider_circuit_breaker_decay(monkeypatch):
    from scanner import geoip

    # Simulate 5 failures
    for _ in range(5):
        geoip._record_provider_outcome("test_prov", success=False)

    assert geoip._REMOTE_FAIL_STREAK["test_prov"] == 5
    # When cooldown expires (set timestamp in past), checking availability decays the streak
    monkeypatch.setitem(geoip._REMOTE_COOLDOWN_UNTIL, "test_prov", 1.0)
    assert geoip._provider_available("test_prov") is True
    assert geoip._REMOTE_FAIL_STREAK["test_prov"] == 4


def test_flush_cache_unique_tmp_file_and_cleanup(monkeypatch, tmp_path):
    import os

    from scanner import geoip

    cache_file = tmp_path / "geoip_cache.json"
    monkeypatch.setattr(geoip, "_GEOIP_CACHE_FILE", cache_file)
    monkeypatch.setattr(geoip, "_GEOIP_CACHE", {"8.8.8.8": ("US", "Mountain View", "Google")})
    monkeypatch.setattr(geoip, "_GEOIP_CACHE_TS", {"8.8.8.8": 12345.0})

    created_tmp_files = []
    orig_replace = Path.replace

    def spy_replace(self, target):
        created_tmp_files.append(self)
        assert f".{os.getpid()}_" in self.name
        assert self.name.endswith(".tmp")
        return orig_replace(self, target)

    monkeypatch.setattr(Path, "replace", spy_replace)

    geoip._flush_cache()

    assert cache_file.exists()
    assert len(created_tmp_files) == 1
    # Ensure no lingering .tmp files
    assert list(tmp_path.glob("*.tmp")) == []

    # Verify failure cleanup removes the tmp file
    def failing_replace(self, target):
        raise OSError("Simulated disk error during replace")

    monkeypatch.setattr(Path, "replace", failing_replace)
    geoip._flush_cache()
    assert list(tmp_path.glob("*.tmp")) == []




