import json
import os
import platform
import re
import shutil
import socket
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from scanner.constants import app_dir
from scanner.logger import get_logger
from scanner.models import VlessConfig

logger = get_logger("xray")

try:
    import requests
except ImportError:
    requests = None  # type: ignore[assignment]


def free_port() -> int:
    """Find and return an unused local TCP port."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


def wait_port(port: int, timeout: float) -> bool:
    """Wait until a local port is accepting TCP connections."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                return True
        except OSError:
            time.sleep(0.05)
    return False


def find_xray(explicit: Optional[str] = None) -> Optional[Path]:
    """Find the xray executable path in core/, bin/, root, or system PATH."""
    candidates: List[Path] = []
    if explicit:
        candidates.append(Path(explicit))
    base = app_dir()
    exe = "xray.exe" if platform.system().lower().startswith("win") else "xray"
    candidates.extend([
        base / "core" / exe,
        base / "bin" / exe,
        base / exe,
        base / "xray.exe",
        base / "xray",
    ])
    for c in candidates:
        if c.exists() and c.is_file():
            return c.resolve()
    from_path = shutil.which("xray")
    if from_path:
        return Path(from_path).resolve()
    return None


def find_asset(name: str, xray_path: Optional[Path] = None) -> Optional[Path]:
    """Find asset files like geoip.dat or geosite.dat in core/, bin/, beside xray, or in root."""
    candidates: List[Path] = []
    if xray_path:
        candidates.append(xray_path.parent / name)
    base = app_dir()
    candidates.extend([
        base / "core" / name,
        base / "bin" / name,
        base / name,
    ])
    for c in candidates:
        if c.exists() and c.is_file():
            return c.resolve()
    return None


def get_xray_version(xray_path: Optional[Path]) -> Optional[str]:
    """Get the installed Xray-core version string."""
    if not xray_path or not xray_path.exists():
        return None
    try:
        proc = subprocess.run(
            [str(xray_path), "version"],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            timeout=2.0,
            check=False,
        )
        match = re.search(r"Xray\s+([\d\.]+)", proc.stdout)
        if match:
            return match.group(1).strip()
    except Exception as exc:
        logger.debug("Failed to get xray version: %s", exc)
    return None


def get_environment_status(xray_path: Optional[Path]) -> Dict[str, Any]:
    """Inspect environment files and dependencies headlessly."""
    geoip_file = find_asset("geoip.dat", xray_path)
    geosite_file = find_asset("geosite.dat", xray_path)
    local_ver = get_xray_version(xray_path) if xray_path else None
    has_xray = bool(xray_path and xray_path.exists())
    has_requests = requests is not None

    return {
        "xray_path": xray_path,
        "xray_ok": has_xray,
        "xray_version": local_ver,
        "geoip_ok": bool(geoip_file),
        "geosite_ok": bool(geosite_file),
        "requests_ok": has_requests,
        "ok": bool(has_xray and has_requests),
    }


def check_environment(xray_path: Optional[Path], show_help: bool = True) -> bool:
    """Check availability of required binary and data files headlessly."""
    status = get_environment_status(xray_path)
    return status["ok"]


def vless_to_xray_outbound(v: VlessConfig, server_ip: str, port: Optional[int] = None) -> Dict[str, Any]:
    """Convert VlessConfig to an Xray outbound configuration dictionary."""
    q = v.query
    network = (q.get("type") or q.get("network") or "tcp").lower()
    security = (q.get("security") or "none").lower()
    flow = q.get("flow", "")
    target_port = port if port is not None else v.port

    outbound: Dict[str, Any] = {
        "tag": "proxy",
        "protocol": "vless",
        "settings": {
            "vnext": [
                {
                    "address": server_ip,
                    "port": target_port,
                    "users": [{"id": v.uuid, "encryption": q.get("encryption", "none")}],
                }
            ]
        },
        "streamSettings": {"network": network, "security": security},
    }
    if flow:
        outbound["settings"]["vnext"][0]["users"][0]["flow"] = flow

    sni = q.get("sni") or q.get("servername") or q.get("serverName") or v.host
    fp = q.get("fp") or q.get("fingerprint") or "chrome"
    alpn = q.get("alpn", "")

    if security in {"tls", "reality"}:
        tls_key = "realitySettings" if security == "reality" else "tlsSettings"
        outbound["streamSettings"][tls_key] = {
            "serverName": sni,
            "fingerprint": fp,
            "allowInsecure": (q.get("allowInsecure") or q.get("insecure", "0")) in {"1", "true"},
        }
        if alpn:
            outbound["streamSettings"][tls_key]["alpn"] = [x.strip() for x in alpn.split(",") if x.strip()]
        if security == "reality":
            if q.get("pbk"):
                outbound["streamSettings"][tls_key]["publicKey"] = q.get("pbk")
            if q.get("sid"):
                outbound["streamSettings"][tls_key]["shortId"] = q.get("sid")
            if q.get("spx"):
                outbound["streamSettings"][tls_key]["spiderX"] = q.get("spx")

    host_header = q.get("host") or q.get("authority") or sni
    path = q.get("path") or "/"

    if network == "ws":
        outbound["streamSettings"]["wsSettings"] = {"path": path, "headers": {"Host": host_header}}
    elif network == "grpc":
        outbound["streamSettings"]["grpcSettings"] = {
            "serviceName": q.get("serviceName") or q.get("serviceNameMode") or q.get("path", "").strip("/")
        }
    elif network in {"http", "h2"}:
        outbound["streamSettings"]["httpSettings"] = {"path": path, "host": [host_header]}
    elif network in {"httpupgrade", "httpupgrade".lower()}:
        outbound["streamSettings"]["httpupgradeSettings"] = {"path": path, "host": host_header}
    elif network in {"xhttp", "splithttp"}:
        outbound["streamSettings"]["splithttpSettings"] = {"path": path, "host": host_header}
    elif network == "tcp" and q.get("headerType") == "http":
        outbound["streamSettings"]["tcpSettings"] = {
            "header": {"type": "http", "request": {"path": [path], "headers": {"Host": [host_header]}}}
        }
    return outbound


def make_xray_config(
    v: VlessConfig,
    server_ip: str,
    socks_port: int,
    loglevel: str = "warning",
    port: Optional[int] = None,
) -> Dict[str, Any]:
    """Generate complete Xray configuration dict for testing an endpoint."""
    return {
        "log": {"loglevel": loglevel},
        "inbounds": [
            {
                "tag": "socks-in",
                "listen": "127.0.0.1",
                "port": socks_port,
                "protocol": "socks",
                "settings": {"udp": False},
            }
        ],
        "outbounds": [
            vless_to_xray_outbound(v, server_ip, port=port),
            {"tag": "direct", "protocol": "freedom"},
            {"tag": "block", "protocol": "blackhole"},
        ],
    }


def make_batch_xray_config(
    v: VlessConfig,
    endpoint_ports: List[Tuple[str, int, int]],  # (ip, port, socks_port)
    loglevel: str = "warning",
) -> Dict[str, Any]:
    """Generate multi-inbound, multi-outbound Xray configuration for batch testing."""
    inbounds = []
    outbounds = []
    rules = []
    for idx, (ip, p, socks_p) in enumerate(endpoint_ports):
        tag_in = f"socks-{idx}"
        tag_out = f"proxy-{idx}"
        inbounds.append({
            "tag": tag_in,
            "listen": "127.0.0.1",
            "port": socks_p,
            "protocol": "socks",
            "settings": {"udp": False},
        })
        outbound = vless_to_xray_outbound(v, ip, port=p)
        outbound["tag"] = tag_out
        outbounds.append(outbound)
        rules.append({
            "type": "field",
            "inboundTag": [tag_in],
            "outboundTag": tag_out,
        })

    outbounds.append({"tag": "direct", "protocol": "freedom"})
    outbounds.append({"tag": "block", "protocol": "blackhole"})

    return {
        "log": {"loglevel": loglevel},
        "inbounds": inbounds,
        "outbounds": outbounds,
        "routing": {
            "domainStrategy": "AsIs",
            "rules": rules,
        },
    }


class XrayProcess:
    """Context manager to run and automatically terminate an Xray instance cleanly."""

    def __init__(
        self,
        xray_path: Path,
        vless_config: VlessConfig,
        server_ip: str,
        port: int,
        loglevel: str = "warning",
        ready_timeout: float = 3.0,
    ):
        self.xray_path = xray_path
        self.vless_config = vless_config
        self.server_ip = server_ip
        self.port = port
        self.loglevel = loglevel
        self.ready_timeout = ready_timeout
        self.socks_port = free_port()
        self.temp_dir: Optional[tempfile.TemporaryDirectory] = None
        self.proc: Optional[subprocess.Popen] = None

    def __enter__(self) -> "XrayProcess":
        try:
            self.temp_dir = tempfile.TemporaryDirectory(prefix="rkh_cfs_", ignore_cleanup_errors=True)  # type: ignore[call-overload]
        except TypeError:
            self.temp_dir = tempfile.TemporaryDirectory(prefix="rkh_cfs_")
        cfg_path = Path(self.temp_dir.name) / "config.json"
        config_dict = make_xray_config(
            self.vless_config,
            self.server_ip,
            self.socks_port,
            self.loglevel,
            port=self.port,
        )
        cfg_path.write_text(json.dumps(config_dict, indent=2), encoding="utf-8")

        xray_dir = self.xray_path.parent
        env = os.environ.copy()
        env["XRAY_LOCATION_ASSET"] = str(xray_dir)
        self.proc = subprocess.Popen(
            [str(self.xray_path), "run", "-config", str(cfg_path)],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            cwd=str(xray_dir),
            env=env,
        )
        if not wait_port(self.socks_port, self.ready_timeout):
            self.close()
            raise TimeoutError("Xray did not open SOCKS port within timeout")
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

    def close(self) -> None:
        """Safely terminate subprocess and remove temporary configuration directory."""
        if self.proc is not None:
            try:
                self.proc.terminate()
                self.proc.wait(timeout=1.0)
            except Exception as exc:
                logger.debug("Clean termination failed, forcing kill: %s", exc)
            try:
                if self.proc.poll() is None:
                    self.proc.kill()
                    self.proc.wait(timeout=0.5)
            except Exception as exc:
                logger.debug("Subprocess kill failed: %s", exc)
            self.proc = None

        if self.temp_dir is not None:
            try:
                self.temp_dir.cleanup()
            except Exception as exc:
                logger.debug("Temp directory cleanup failed: %s", exc)
            self.temp_dir = None

    @property
    def socks_url(self) -> str:
        return f"socks5h://127.0.0.1:{self.socks_port}"

    @property
    def proxies(self) -> Dict[str, str]:
        return {"http": self.socks_url, "https": self.socks_url}


class BatchXrayProcess:
    """Context manager running a single Xray process routing multiple endpoints via separate local SOCKS ports."""

    def __init__(
        self,
        xray_path: Path,
        vless_config: VlessConfig,
        endpoints: List[Tuple[str, int]],  # List of (ip, port)
        loglevel: str = "warning",
        ready_timeout: float = 4.0,
    ):
        self.xray_path = xray_path
        self.vless_config = vless_config
        self.endpoints = endpoints
        self.loglevel = loglevel
        self.ready_timeout = ready_timeout
        self.endpoint_ports = [(ip, p, free_port()) for ip, p in endpoints]
        self.temp_dir: Optional[tempfile.TemporaryDirectory] = None
        self.proc: Optional[subprocess.Popen] = None

    def __enter__(self) -> "BatchXrayProcess":
        try:
            self.temp_dir = tempfile.TemporaryDirectory(prefix="rkh_cfs_batch_", ignore_cleanup_errors=True)  # type: ignore[call-overload]
        except TypeError:
            self.temp_dir = tempfile.TemporaryDirectory(prefix="rkh_cfs_batch_")
        cfg_path = Path(self.temp_dir.name) / "config.json"
        config_dict = make_batch_xray_config(
            self.vless_config,
            self.endpoint_ports,
            self.loglevel,
        )
        cfg_path.write_text(json.dumps(config_dict, indent=2), encoding="utf-8")

        xray_dir = self.xray_path.parent
        env = os.environ.copy()
        env["XRAY_LOCATION_ASSET"] = str(xray_dir)
        self.proc = subprocess.Popen(
            [str(self.xray_path), "run", "-config", str(cfg_path)],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            cwd=str(xray_dir),
            env=env,
        )
        if self.endpoint_ports:
            if not wait_port(self.endpoint_ports[0][2], self.ready_timeout):
                self.close()
                raise TimeoutError("Batch Xray did not open SOCKS port within timeout")
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

    def close(self) -> None:
        if self.proc is not None:
            try:
                self.proc.terminate()
                self.proc.wait(timeout=1.0)
            except Exception as exc:
                logger.debug("Batch Xray clean termination failed: %s", exc)
            try:
                if self.proc.poll() is None:
                    self.proc.kill()
                    self.proc.wait(timeout=0.5)
            except Exception as exc:
                logger.debug("Batch Xray force kill failed: %s", exc)
            self.proc = None

        if self.temp_dir is not None:
            try:
                self.temp_dir.cleanup()
            except Exception as exc:
                logger.debug("Batch temp directory cleanup failed: %s", exc)
            self.temp_dir = None

    def get_proxies_for_endpoint(self, ip: str, port: int) -> Optional[Dict[str, str]]:
        for ep_ip, ep_port, socks_port in self.endpoint_ports:
            if ep_ip == ip and ep_port == port:
                url = f"socks5h://127.0.0.1:{socks_port}"
                return {"http": url, "https": url}
        return None

