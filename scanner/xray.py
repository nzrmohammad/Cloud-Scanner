import json
import os
import platform
import re
import shutil
import socket
import stat
import subprocess
import tempfile
import threading
import time
import zipfile
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

from scanner.constants import app_dir
from scanner.logger import get_logger
from scanner.models import VlessConfig

logger = get_logger("xray")

try:
    import requests
except ImportError:
    requests = None  # type: ignore[assignment]

_ACTIVE_PROC_LOCK = threading.Lock()
_ACTIVE_PROCESSES: Set["_BaseXrayProcess"] = set()


def terminate_active_xray_processes() -> int:
    """Forcefully close all currently tracked Xray subprocesses (used on Ctrl+C abort)."""
    with _ACTIVE_PROC_LOCK:
        procs = list(_ACTIVE_PROCESSES)
    closed = 0
    for xp in procs:
        try:
            xp.close()
            closed += 1
        except Exception as exc:
            logger.debug("Error closing active Xray process: %s", exc)
    return closed


def free_ports(count: int) -> List[int]:
    """Allocate `count` distinct unused local TCP ports atomically."""
    sockets: List[socket.socket] = []
    ports: List[int] = []
    try:
        for _ in range(max(0, count)):
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.bind(("127.0.0.1", 0))
            sockets.append(s)
            ports.append(int(s.getsockname()[1]))
    finally:
        for s in sockets:
            try:
                s.close()
            except OSError:
                pass
    return ports


def free_port() -> int:
    """Find and return an unused local TCP port."""
    return free_ports(1)[0]


def wait_ports(ports: List[int], timeout: float) -> bool:
    """Wait until all local TCP ports in `ports` are accepting connections."""
    if not ports:
        return True
    deadline = time.monotonic() + timeout
    pending = list(ports)
    while pending and time.monotonic() < deadline:
        remaining: List[int] = []
        for p in pending:
            try:
                with socket.create_connection(("127.0.0.1", p), timeout=0.2):
                    continue
            except OSError:
                remaining.append(p)
        if not remaining:
            return True
        pending = remaining
        time.sleep(0.03)
    return False


def wait_port(port: int, timeout: float) -> bool:
    """Wait until a local port is accepting TCP connections."""
    return wait_ports([port], timeout)


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


def parse_version_tuple(version_str: str) -> Tuple[int, ...]:
    """Parse a version tag like 'v26.3.27' or '26.3.27' into a comparable tuple of ints."""
    nums = re.findall(r"\d+", version_str or "")
    return tuple(int(n) for n in nums)


def is_newer_version(latest: Optional[str], current: Optional[str]) -> bool:
    """Return True if `latest` represents a strictly newer version than `current`."""
    if not latest or not current:
        return False
    lt = parse_version_tuple(latest)
    ct = parse_version_tuple(current)
    if not lt or not ct:
        return False
    max_len = max(len(lt), len(ct))
    lt_pad = lt + (0,) * (max_len - len(lt))
    ct_pad = ct + (0,) * (max_len - len(ct))
    return lt_pad > ct_pad


def get_platform_asset_name() -> str:
    """Return the official Xray-core GitHub release zip asset name for this OS/arch."""
    system = platform.system().lower()
    machine = platform.machine().lower()

    if "windows" in system:
        if "arm" in machine:
            return "Xray-windows-arm64-v8a.zip"
        if "32" in machine or machine in ("i386", "i686"):
            return "Xray-windows-32.zip"
        return "Xray-windows-64.zip"

    if "linux" in system:
        if "aarch64" in machine or "arm64" in machine:
            return "Xray-linux-arm64-v8a.zip"
        if "arm" in machine:
            return "Xray-linux-arm32-v7a.zip"
        if "32" in machine or machine in ("i386", "i686"):
            return "Xray-linux-32.zip"
        return "Xray-linux-64.zip"

    if "darwin" in system:
        if "arm64" in machine or "aarch64" in machine:
            return "Xray-macos-arm64-v8a.zip"
        return "Xray-macos-64.zip"

    raise RuntimeError(f"Unsupported operating system: {system} ({machine})")


def fetch_latest_xray_tag(
    timeout: float = 2.5,
    proxies: Optional[Dict[str, str]] = None,
    fallback_default: Optional[str] = None,
) -> Optional[str]:
    """Check GitHub for the latest Xray-core release tag, returning None on network errors."""
    if requests is None:
        return fallback_default
    headers = {"User-Agent": "CloudScanner"}
    try:
        r = requests.head(
            "https://github.com/XTLS/Xray-core/releases/latest",
            allow_redirects=False,
            timeout=timeout,
            proxies=proxies,
            headers=headers,
        )
        loc = r.headers.get("Location") or ""
        if "/tag/" in loc:
            tag = loc.rsplit("/tag/", 1)[-1].strip()
            if tag:
                return tag
    except Exception as exc:
        logger.debug("Xray latest HEAD check failed: %s", exc)

    try:
        res = requests.get(
            "https://api.github.com/repos/XTLS/Xray-core/releases/latest",
            timeout=timeout,
            proxies=proxies,
            headers=headers,
        )
        if res.status_code == 200:
            tag = res.json().get("tag_name")
            if isinstance(tag, str) and tag.strip():
                return tag.strip()
    except Exception as exc:
        logger.debug("Xray latest API check failed: %s", exc)

    return fallback_default


def extract_xray_archive(zip_path: Path, target_dir: Path) -> None:
    """Extract Xray binary and .dat/.txt assets cleanly into `target_dir`."""
    target_dir.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(zip_path, "r") as zf:
        for member in zf.namelist():
            filename = os.path.basename(member)
            if not filename:
                continue
            low = filename.lower()
            if low.startswith("xray") or low.endswith(".dat") or low.endswith(".txt"):
                target_file = target_dir / filename
                tmp_file = target_dir / f".{filename}.tmp"
                with zf.open(member) as source, open(tmp_file, "wb") as target:
                    shutil.copyfileobj(source, target)
                tmp_file.replace(target_file)

    for exe_name in ("xray",):
        exe_path = target_dir / exe_name
        if exe_path.exists():
            current = os.stat(exe_path).st_mode
            os.chmod(exe_path, current | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)


def download_xray_release(
    target_dir: Path,
    tag: Optional[str] = None,
    proxies: Optional[Dict[str, str]] = None,
    timeout: float = 30.0,
    on_progress: Optional[Callable[[int, int], None]] = None,
) -> Tuple[bool, str]:
    """Download, extract, and verify official Xray-core into `target_dir`.

    Returns: (success, installed_version_or_error_message)
    """
    if requests is None:
        return False, "Package 'requests' is required"

    try:
        asset_name = get_platform_asset_name()
        resolved_tag = tag or fetch_latest_xray_tag(timeout=min(5.0, timeout), proxies=proxies)
        if not resolved_tag:
            return False, "Could not resolve latest Xray-core release tag from GitHub"
        if not resolved_tag.startswith("v") and not resolved_tag[0].isdigit():
            resolved_tag = f"v{resolved_tag}"

        download_url = f"https://github.com/XTLS/Xray-core/releases/download/{resolved_tag}/{asset_name}"
        terminate_active_xray_processes()

        with tempfile.TemporaryDirectory(prefix="xray_dl_") as tmp:
            tmp_zip = Path(tmp) / asset_name
            with requests.get(
                download_url,
                stream=True,
                timeout=timeout,
                proxies=proxies,
                headers={"User-Agent": "CloudScanner"},
            ) as resp:
                resp.raise_for_status()
                total = int(resp.headers.get("content-length", 0))
                downloaded = 0
                with open(tmp_zip, "wb") as f:
                    for chunk in resp.iter_content(chunk_size=64 * 1024):
                        if chunk:
                            f.write(chunk)
                            downloaded += len(chunk)
                            if on_progress:
                                on_progress(downloaded, total)
            extract_xray_archive(tmp_zip, target_dir)

        exe = "xray.exe" if platform.system().lower().startswith("win") else "xray"
        ver = get_xray_version(target_dir / exe)
        if ver:
            return True, ver
        return False, "Files extracted, but xray binary verification failed"
    except Exception as exc:
        logger.warning("Failed to download/update Xray-core: %s", exc)
        return False, str(exc).split("\n", 1)[0][:180]


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
        allow_insecure = any(
            q.get(k, "").strip().lower() in {"1", "true"}
            for k in ("allowInsecure", "insecure")
        )
        outbound["streamSettings"][tls_key] = {
            "serverName": sni,
            "fingerprint": fp,
            "allowInsecure": allow_insecure,
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
    elif network == "httpupgrade":
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


class _BaseXrayProcess:
    """Shared lifecycle manager for single and batched Xray subprocesses."""

    _temp_prefix: str = "rkh_cfs_"

    def __init__(self, xray_path: Path, ready_timeout: float = 3.0):
        self.xray_path = xray_path
        self.ready_timeout = ready_timeout
        self.temp_dir: Optional[tempfile.TemporaryDirectory] = None
        self.proc: Optional[subprocess.Popen] = None

    def _build_config(self) -> Dict[str, Any]:
        raise NotImplementedError

    def _ready_ports(self) -> List[int]:
        raise NotImplementedError

    def __enter__(self):
        with _ACTIVE_PROC_LOCK:
            _ACTIVE_PROCESSES.add(self)
        try:
            try:
                self.temp_dir = tempfile.TemporaryDirectory(prefix=self._temp_prefix, ignore_cleanup_errors=True)  # type: ignore[call-overload]
            except TypeError:
                self.temp_dir = tempfile.TemporaryDirectory(prefix=self._temp_prefix)
            cfg_path = Path(self.temp_dir.name) / "config.json"
            cfg_path.write_text(json.dumps(self._build_config(), separators=(",", ":")), encoding="utf-8")

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
            if not wait_ports(self._ready_ports(), self.ready_timeout):
                raise TimeoutError("Xray did not open SOCKS port(s) within timeout")
            return self
        except BaseException:
            self.close()
            raise

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

    def close(self) -> None:
        """Safely terminate subprocess and remove temporary configuration directory."""
        with _ACTIVE_PROC_LOCK:
            _ACTIVE_PROCESSES.discard(self)

        proc = self.proc
        self.proc = None
        if proc is not None:
            try:
                proc.terminate()
                proc.wait(timeout=1.0)
            except Exception as exc:
                logger.debug("Clean termination failed, forcing kill: %s", exc)
            try:
                if proc.poll() is None:
                    proc.kill()
                    proc.wait(timeout=0.5)
            except Exception as exc:
                logger.debug("Subprocess kill failed: %s", exc)

        temp_dir = self.temp_dir
        self.temp_dir = None
        if temp_dir is not None:
            try:
                temp_dir.cleanup()
            except Exception as exc:
                logger.debug("Temp directory cleanup failed: %s", exc)


class XrayProcess(_BaseXrayProcess):
    """Context manager to run and automatically terminate an Xray instance cleanly."""

    _temp_prefix = "rkh_cfs_"

    def __init__(
        self,
        xray_path: Path,
        vless_config: VlessConfig,
        server_ip: str,
        port: int,
        loglevel: str = "warning",
        ready_timeout: float = 3.0,
    ):
        super().__init__(xray_path=xray_path, ready_timeout=ready_timeout)
        self.vless_config = vless_config
        self.server_ip = server_ip
        self.port = port
        self.loglevel = loglevel
        self.socks_port = free_port()

    def _build_config(self) -> Dict[str, Any]:
        return make_xray_config(
            self.vless_config,
            self.server_ip,
            self.socks_port,
            self.loglevel,
            port=self.port,
        )

    def _ready_ports(self) -> List[int]:
        return [self.socks_port]

    @property
    def socks_url(self) -> str:
        return f"socks5h://127.0.0.1:{self.socks_port}"

    @property
    def proxies(self) -> Dict[str, str]:
        return {"http": self.socks_url, "https": self.socks_url}


class BatchXrayProcess(_BaseXrayProcess):
    """Context manager running a single Xray process routing multiple endpoints via separate local SOCKS ports."""

    _temp_prefix = "rkh_cfs_batch_"

    def __init__(
        self,
        xray_path: Path,
        vless_config: VlessConfig,
        endpoints: List[Tuple[str, int]],  # List of (ip, port)
        loglevel: str = "warning",
        ready_timeout: float = 4.0,
    ):
        super().__init__(xray_path=xray_path, ready_timeout=ready_timeout)
        self.vless_config = vless_config
        self.endpoints = endpoints
        self.loglevel = loglevel
        allocated = free_ports(len(endpoints))
        self.endpoint_ports = [(ip, p, sp) for (ip, p), sp in zip(endpoints, allocated)]

    def _build_config(self) -> Dict[str, Any]:
        return make_batch_xray_config(
            self.vless_config,
            self.endpoint_ports,
            self.loglevel,
        )

    def _ready_ports(self) -> List[int]:
        return [sp for _, _, sp in self.endpoint_ports]

    def get_proxies_for_endpoint(self, ip: str, port: int) -> Optional[Dict[str, str]]:
        for ep_ip, ep_port, socks_port in self.endpoint_ports:
            if ep_ip == ip and ep_port == port:
                url = f"socks5h://127.0.0.1:{socks_port}"
                return {"http": url, "https": url}
        return None

