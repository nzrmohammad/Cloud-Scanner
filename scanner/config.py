from pathlib import Path
from typing import Optional
from urllib.parse import parse_qs, unquote, urlencode, urlparse, quote

from scanner.constants import (
    DEFAULT_CONFIG_FILENAME,
    DEFAULT_CONFIG_TEMPLATE,
    app_dir,
)
from scanner.models import AppSettings, VlessConfig


def parse_vless(uri_or_file: str) -> VlessConfig:
    """Parse a VLESS URI or path to a file containing a VLESS URI."""
    value = uri_or_file.strip().strip('"').strip("'")
    possible = Path(value)
    if not value.startswith("vless://") and possible.exists():
        value = possible.read_text(encoding="utf-8").strip()
    if not value.startswith("vless://"):
        raise ValueError("VLESS config must start with vless:// or be a file containing a vless:// link.")
    parsed = urlparse(value)
    uuid = parsed.username or parsed.netloc.split("@")[0]
    host = parsed.hostname or ""
    port = parsed.port or 443
    if not uuid or not host:
        raise ValueError("Invalid VLESS link: missing UUID or server address.")
    query_multi = parse_qs(parsed.query, keep_blank_values=True)
    query = {k: unquote(v[-1]) if v else "" for k, v in query_multi.items()}
    remark = unquote(parsed.fragment or "RKh-CFS")
    return VlessConfig(raw=value, uuid=uuid, host=host, port=port, remark=remark, query=query)


def make_vless_link(v: VlessConfig, server_ip: str, port: int, remark_extra: str = "") -> str:
    """Build a complete ready-to-import vless:// URI with clean IP, port, and remark."""
    query_params = dict(v.query)
    q_str = urlencode(query_params)
    base_remark = v.remark or "CleanIP"
    if remark_extra:
        full_remark = f"{base_remark}-{server_ip}:{port}-{remark_extra}"
    else:
        full_remark = f"{base_remark}-{server_ip}:{port}"
    return f"vless://{v.uuid}@{server_ip}:{port}?{q_str}#{quote(full_remark)}"


class ConfigManager:
    """Manages configuration files and application settings."""

    def __init__(self, filename: str = DEFAULT_CONFIG_FILENAME):
        self.config_path = app_dir() / filename

    def generate_default_config(self, vless: str = "") -> None:
        """Create a default configuration file."""
        try:
            self.config_path.write_text(DEFAULT_CONFIG_TEMPLATE.format(vless=vless.strip()), encoding="utf-8")
        except Exception:
            pass

    def load_settings(self) -> AppSettings:
        """Load and parse application settings from config.txt."""
        settings = AppSettings()
        if not self.config_path.exists():
            self.generate_default_config()
            return settings

        try:
            content = self.config_path.read_text(encoding="utf-8").strip()
            if not content:
                return settings

            # Backward-compatibility: if file contains only a raw vless link
            if content.startswith("vless://") and "\n" not in content:
                settings.vless_raw = content
                return settings

            for line in content.splitlines():
                line = line.strip()
                if not line or line.startswith("#") or line.startswith(";") or line.startswith("//"):
                    continue
                if "=" in line:
                    key, _, val = line.partition("=")
                    key = key.strip().lower()
                    val = val.strip()

                    if key == "vless":
                        settings.vless_raw = val
                    elif key == "ports":
                        if val.lower() in ("config", "auto"):
                            settings.ports = []
                        else:
                            parsed_ports = []
                            for p_str in val.split(","):
                                p_str = p_str.strip()
                                if p_str.isdigit():
                                    port_int = int(p_str)
                                    if 1 <= port_int <= 65535 and port_int not in parsed_ports:
                                        parsed_ports.append(port_int)
                            if parsed_ports:
                                settings.ports = parsed_ports
                    elif key in ("workers", "concurrency"):
                        if val.isdigit():
                            settings.workers = max(1, int(val))
                    elif key == "timeout":
                        if val.isdigit():
                            settings.timeout = max(1, int(val))
                    elif key in ("tcp_prefilter", "prefilter"):
                        settings.tcp_prefilter = val.lower() in ("true", "1", "yes", "on")
                    elif key in ("test_url", "url"):
                        if val.startswith("http"):
                            settings.test_url = val
                    elif key in ("max_targets", "max_hosts", "target_limit"):
                        if val.lower() in ("0", "unlimited", "none", "all", "inf", "infinity"):
                            settings.max_targets = 0
                        elif val.isdigit():
                            settings.max_targets = max(0, int(val))
                    elif key == "output_dir":
                        if val:
                            settings.output_dir = Path(val)
                    elif key in ("post_scan_mode", "mode"):
                        mode_val = val.lower()
                        if mode_val in ("full", "stability", "longevity", "speed", "none"):
                            settings.post_scan_mode = mode_val
                    elif key in ("top_targets", "top_count"):
                        if val.lower() in ("0", "unlimited", "none", "all", "inf", "infinity"):
                            settings.top_targets = 0
                        elif val.isdigit():
                            settings.top_targets = max(0, int(val))
                    elif key in ("ping_samples", "samples"):
                        if val.isdigit():
                            settings.ping_samples = max(2, int(val))
                    elif key in ("longevity_test", "anti_drop", "anti_drop_test"):
                        settings.longevity_test = val.lower() in ("true", "1", "yes", "on")
                    elif key in ("longevity_duration", "anti_drop_duration"):
                        if val.isdigit():
                            settings.longevity_duration = max(5, int(val))
                    elif key in ("download_mb", "speed_mb"):
                        if val.isdigit():
                            settings.download_mb = max(0, int(val))
                    elif key in ("upload_mb", "speed_upload_mb"):
                        if val.isdigit():
                            settings.upload_mb = max(0, int(val))
                    elif key in ("speed_duration", "duration"):
                        if val.isdigit():
                            settings.speed_duration = max(1, int(val))
                    elif key == "speed_workers":
                        if val.isdigit():
                            settings.speed_workers = max(1, int(val))
                elif line.startswith("vless://") and not settings.vless_raw:
                    settings.vless_raw = line
        except Exception:
            pass

        return settings

    def save_vless(self, raw_vless: str) -> None:
        """Update the VLESS link in config.txt while preserving user comments."""
        try:
            if self.config_path.exists():
                content = self.config_path.read_text(encoding="utf-8")
                lines = content.splitlines()
                found = False
                new_lines = []
                for line in lines:
                    stripped = line.strip()
                    if stripped.startswith("vless") and "=" in stripped:
                        new_lines.append(f"vless = {raw_vless.strip()}")
                        found = True
                    else:
                        new_lines.append(line)
                if not found:
                    if content.strip().startswith("vless://"):
                        self.config_path.write_text(DEFAULT_CONFIG_TEMPLATE.format(vless=raw_vless.strip()), encoding="utf-8")
                        return
                    new_lines.append(f"\nvless = {raw_vless.strip()}")
                self.config_path.write_text("\n".join(new_lines) + "\n", encoding="utf-8")
                return
            self.generate_default_config(vless=raw_vless.strip())
        except Exception:
            pass


# Global module-level convenience functions
_default_config_manager = ConfigManager()


def load_app_settings() -> AppSettings:
    return _default_config_manager.load_settings()


def load_saved_vless_config() -> str:
    return _default_config_manager.load_settings().vless_raw


def save_vless_config(raw_vless: str) -> None:
    _default_config_manager.save_vless(raw_vless)


def generate_default_config_file(vless: str = "") -> None:
    _default_config_manager.generate_default_config(vless=vless)
