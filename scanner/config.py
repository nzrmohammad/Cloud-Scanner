from pathlib import Path
from typing import Dict, Union
from urllib.parse import quote, unquote, urlencode, urlparse

from scanner.constants import (
    DEFAULT_CONFIG_FILENAME,
    DEFAULT_CONFIG_TEMPLATE,
    app_dir,
    format_host_port,
)
from scanner.logger import get_logger
from scanner.models import AppSettings, VlessConfig

logger = get_logger("config")


def _parse_query_params(raw_query: str) -> Dict[str, str]:
    """Parse URI query string preserving '+' literally and decoding percent-escapes once."""
    query: Dict[str, str] = {}
    if not raw_query:
        return query
    for part in raw_query.split("&"):
        if not part:
            continue
        key_raw, sep, val_raw = part.partition("=")
        key = unquote(key_raw)
        val = unquote(val_raw) if sep else ""
        if key:
            query[key] = val
    return query


def parse_vless(uri_or_file: str) -> VlessConfig:
    """Parse a VLESS URI or path to a file containing a VLESS URI."""
    value = uri_or_file.strip().strip('"').strip("'")
    possible = Path(value)
    if not value.startswith("vless://") and possible.exists():
        value = possible.read_text(encoding="utf-8").strip()
    if not value.startswith("vless://"):
        raise ValueError("VLESS config must start with vless:// or be a file containing a vless:// link.")
    parsed = urlparse(value)
    userinfo = parsed.netloc.rsplit("@", 1)[0] if "@" in parsed.netloc else ""
    uuid = unquote(parsed.username or userinfo)
    host = parsed.hostname or ""
    port = parsed.port or 443
    if not uuid or not host:
        raise ValueError("Invalid VLESS link: missing UUID or server address.")
    query = _parse_query_params(parsed.query)
    remark = unquote(parsed.fragment or "RKh-CFS")
    return VlessConfig(raw=value, uuid=uuid, host=host, port=port, remark=remark, query=query)


def make_vless_link(v: VlessConfig, server_ip: str, port: int, remark_extra: str = "") -> str:
    """Build a complete ready-to-import vless:// URI with clean IP, port, and remark."""
    query_params = dict(v.query)
    q_str = urlencode(query_params, quote_via=quote)
    base_remark = v.remark or "CleanIP"
    endpoint = format_host_port(server_ip, port)
    full_remark = f"{base_remark}-{endpoint}-{remark_extra}" if remark_extra else f"{base_remark}-{endpoint}"
    return f"vless://{v.uuid}@{endpoint}?{q_str}#{quote(full_remark)}"


def _parse_bounded_int(key: str, val: str, min_val: int) -> int | None:
    """Parse an integer config setting safely, logging a warning if malformed."""
    try:
        parsed = int(float(val)) if "." in val else int(val)
    except ValueError:
        logger.warning("Ignoring non-numeric setting %s = %r in config.txt", key, val)
        return None
    return max(min_val, parsed)


class ConfigManager:
    """Manages configuration files and application settings."""

    def __init__(self, filename: Union[str, Path] = DEFAULT_CONFIG_FILENAME):
        self.config_path = app_dir() / filename

    def generate_default_config(self, vless: str = "") -> None:
        """Create a default configuration file."""
        try:
            self.config_path.write_text(DEFAULT_CONFIG_TEMPLATE.format(vless=vless.strip()), encoding="utf-8")
        except Exception as exc:
            logger.warning("Failed to write default config to %s: %s", self.config_path, exc)

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
                        parsed_int = _parse_bounded_int(key, val, 1)
                        if parsed_int is not None:
                            settings.workers = parsed_int
                    elif key == "timeout":
                        parsed_int = _parse_bounded_int(key, val, 1)
                        if parsed_int is not None:
                            settings.timeout = parsed_int
                    elif key in ("tcp_prefilter", "prefilter"):
                        settings.tcp_prefilter = val.lower() in ("true", "1", "yes", "on")
                    elif key in ("test_url", "url"):
                        if val.startswith("http"):
                            settings.test_url = val
                    elif key in ("max_targets", "max_hosts", "target_limit"):
                        if val.lower() in ("0", "unlimited", "none", "all", "inf", "infinity"):
                            settings.max_targets = 0
                        else:
                            parsed_int = _parse_bounded_int(key, val, 0)
                            if parsed_int is not None:
                                settings.max_targets = parsed_int
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
                        else:
                            parsed_int = _parse_bounded_int(key, val, 0)
                            if parsed_int is not None:
                                settings.top_targets = parsed_int
                    elif key in ("ping_samples", "samples"):
                        parsed_int = _parse_bounded_int(key, val, 2)
                        if parsed_int is not None:
                            settings.ping_samples = parsed_int
                    elif key in ("longevity_test", "anti_drop", "anti_drop_test"):
                        settings.longevity_test = val.lower() in ("true", "1", "yes", "on")
                    elif key in ("longevity_duration", "anti_drop_duration"):
                        parsed_int = _parse_bounded_int(key, val, 5)
                        if parsed_int is not None:
                            settings.longevity_duration = parsed_int
                    elif key in ("download_mb", "speed_mb"):
                        parsed_int = _parse_bounded_int(key, val, 0)
                        if parsed_int is not None:
                            settings.download_mb = parsed_int
                    elif key in ("upload_mb", "speed_upload_mb"):
                        parsed_int = _parse_bounded_int(key, val, 0)
                        if parsed_int is not None:
                            settings.upload_mb = parsed_int
                    elif key in ("speed_duration", "duration"):
                        parsed_int = _parse_bounded_int(key, val, 1)
                        if parsed_int is not None:
                            settings.speed_duration = parsed_int
                    elif key == "speed_workers":
                        parsed_int = _parse_bounded_int(key, val, 1)
                        if parsed_int is not None:
                            settings.speed_workers = parsed_int
                elif line.startswith("vless://") and not settings.vless_raw:
                    settings.vless_raw = line

        except Exception as exc:
            logger.warning("Failed to load settings from config %s: %s", self.config_path, exc)

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
                    key_part, eq, _ = stripped.partition("=")
                    if eq and key_part.strip().lower() == "vless":
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
        except Exception as exc:
            logger.warning("Failed to save vless config to %s: %s", self.config_path, exc)


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
