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
from typing import Any, Callable, Dict, Iterable, List, Optional, Set, Tuple

from scanner.constants import app_dir, clean_dns_host
from scanner.logger import get_logger
from scanner.models import VlessConfig

logger = get_logger("xray")

try:
    import requests
except ImportError:
    requests = None  # type: ignore[assignment]

_ACTIVE_PROC_LOCK = threading.Lock()
_ACTIVE_PROCESSES: Set["_BaseXrayProcess"] = set()
_PORT_LOCK = threading.Lock()
_RESERVED_LOCAL_PORTS: Set[int] = set()

_WIN32_JOB_HANDLE: Any = None
_WIN32_JOB_INIT_DONE: bool = False
_WIN32_JOB_LOCK = threading.Lock()


def _get_win32_job_handle() -> Any:
    """Initialize a Win32 Job Object with JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE on Windows lazily."""
    global _WIN32_JOB_HANDLE, _WIN32_JOB_INIT_DONE
    if platform.system() != "Windows":
        return None
    with _WIN32_JOB_LOCK:
        if _WIN32_JOB_INIT_DONE:
            return _WIN32_JOB_HANDLE
        _WIN32_JOB_INIT_DONE = True
        try:
            import ctypes

            kernel32 = ctypes.windll.kernel32
            kernel32.CreateJobObjectW.restype = ctypes.c_void_p
            kernel32.CreateJobObjectW.argtypes = [ctypes.c_void_p, ctypes.c_wchar_p]
            kernel32.SetInformationJobObject.restype = ctypes.c_bool
            kernel32.SetInformationJobObject.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_void_p, ctypes.c_uint32]
            kernel32.AssignProcessToJobObject.restype = ctypes.c_bool
            kernel32.AssignProcessToJobObject.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
            kernel32.CloseHandle.restype = ctypes.c_bool
            kernel32.CloseHandle.argtypes = [ctypes.c_void_p]

            job = kernel32.CreateJobObjectW(None, None)
            if not job:
                return None

            class IO_COUNTERS(ctypes.Structure):
                _fields_ = [
                    ("ReadOperationCount", ctypes.c_uint64),
                    ("WriteOperationCount", ctypes.c_uint64),
                    ("OtherOperationCount", ctypes.c_uint64),
                    ("ReadTransferCount", ctypes.c_uint64),
                    ("WriteTransferCount", ctypes.c_uint64),
                    ("OtherTransferCount", ctypes.c_uint64),
                ]

            class JOBOBJECT_BASIC_LIMIT_INFORMATION(ctypes.Structure):
                _fields_ = [
                    ("PerProcessUserTimeLimit", ctypes.c_int64),
                    ("PerJobUserTimeLimit", ctypes.c_int64),
                    ("LimitFlags", ctypes.c_uint32),
                    ("MinimumWorkingSetSize", ctypes.c_size_t),
                    ("MaximumWorkingSetSize", ctypes.c_size_t),
                    ("ActiveProcessLimit", ctypes.c_uint32),
                    ("Affinity", ctypes.c_size_t),
                    ("PriorityClass", ctypes.c_uint32),
                    ("SchedulingClass", ctypes.c_uint32),
                ]

            class JOBOBJECT_EXTENDED_LIMIT_INFORMATION(ctypes.Structure):
                _fields_ = [
                    ("BasicLimitInformation", JOBOBJECT_BASIC_LIMIT_INFORMATION),
                    ("IoInfo", IO_COUNTERS),
                    ("ProcessMemoryLimit", ctypes.c_size_t),
                    ("JobMemoryLimit", ctypes.c_size_t),
                    ("PeakProcessMemoryLimit", ctypes.c_size_t),
                    ("PeakJobMemoryLimit", ctypes.c_size_t),
                ]

            job_info_type = 9  # JobObjectExtendedLimitInformation
            kill_on_close = 0x00002000  # JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE

            info = JOBOBJECT_EXTENDED_LIMIT_INFORMATION()
            info.BasicLimitInformation.LimitFlags = kill_on_close

            res = kernel32.SetInformationJobObject(
                job,
                job_info_type,
                ctypes.byref(info),
                ctypes.sizeof(info),
            )
            if res:
                _WIN32_JOB_HANDLE = job
            else:
                kernel32.CloseHandle(job)
        except Exception as exc:
            logger.debug("Initializing Win32 Job Object failed: %s", exc)
        return _WIN32_JOB_HANDLE


def _assign_process_to_job(proc: subprocess.Popen) -> None:
    """Assign a child subprocess to the Win32 Job Object so it is killed if the parent exits."""
    if platform.system() != "Windows":
        return
    job = _get_win32_job_handle()
    if not job:
        return
    try:
        import ctypes

        kernel32 = ctypes.windll.kernel32
        handle = getattr(proc, "_handle", None)
        if handle:
            kernel32.AssignProcessToJobObject(job, ctypes.c_void_p(int(handle)))
    except Exception as exc:
        logger.debug("Assigning process to Win32 Job Object failed: %s", exc)


class XrayStartupError(RuntimeError):
    """Raised when the Xray binary exits with an error before opening SOCKS ports."""

    def __init__(self, message: str, transient: bool = False):
        super().__init__(message)
        self.transient = transient


def _is_port_bind_error(detail: str) -> bool:
    """Return True if Xray stderr indicates a local SOCKS port-bind collision."""
    low = (detail or "").lower()
    return any(
        hint in low
        for hint in (
            "address already in use",
            "only one usage of each socket address",
            "failed to listen on",
        )
    )


def normalize_xray_tag(tag: Optional[str]) -> str:
    """Ensure an Xray-core release tag has a leading 'v' prefix when non-empty."""
    cleaned = (tag or "").strip()
    if cleaned and not cleaned.startswith("v"):
        return f"v{cleaned}"
    return cleaned


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
    """Allocate `count` distinct unused local TCP ports atomically and reserve them."""
    if count <= 0:
        return []
    with _PORT_LOCK:
        ports: List[int] = []
        sockets: List[socket.socket] = []
        try:
            attempts = 0
            while len(ports) < count and attempts < 1000:
                attempts += 1
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                try:
                    s.bind(("127.0.0.1", 0))
                    p = int(s.getsockname()[1])
                    if p not in _RESERVED_LOCAL_PORTS:
                        sockets.append(s)
                        ports.append(p)
                        _RESERVED_LOCAL_PORTS.add(p)
                    else:
                        s.close()
                except OSError:
                    try:
                        s.close()
                    except OSError:
                        pass
            if len(ports) < count:
                for p in ports:
                    _RESERVED_LOCAL_PORTS.discard(p)
                raise RuntimeError(f"Could not allocate {count} free local ports (got {len(ports)})")
            return list(ports)
        except Exception:
            for p in ports:
                _RESERVED_LOCAL_PORTS.discard(p)
            raise
        finally:
            for s in sockets:
                try:
                    s.close()
                except OSError as exc:
                    logger.debug("Closing probe socket failed: %s", exc)


def free_port() -> int:
    """Find and return an unused local TCP port."""
    return free_ports(1)[0]


def release_ports(ports: Iterable[int]) -> None:
    """Release allocated ports from the local reservation registry."""
    with _PORT_LOCK:
        for p in ports:
            _RESERVED_LOCAL_PORTS.discard(p)


def wait_ports(ports: List[int], timeout: float, proc: Optional[subprocess.Popen] = None) -> bool:
    """Wait until all local TCP ports in `ports` accept connections or process exits."""
    if not ports:
        return True
    deadline = time.monotonic() + timeout
    pending = list(ports)
    while pending and time.monotonic() < deadline:
        if proc is not None and proc.poll() is not None:
            return False
        remaining: List[int] = []
        for p in pending:
            try:
                with socket.create_connection(("127.0.0.1", p), timeout=0.2):
                    continue
            except OSError:
                remaining.append(p)
        if not remaining:
            if proc is not None and proc.poll() is not None:
                return False
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


_XRAY_VERSION_CACHE: Dict[Tuple[str, int], Optional[str]] = {}
_WARNED_REMOVED_ALLOW_INSECURE: Set[str] = set()


def _cached_xray_version(xray_path: Optional[Path]) -> Optional[str]:
    """Return cached Xray version keyed by resolved path and mtime_ns."""
    if not xray_path or not xray_path.exists():
        return None
    try:
        resolved = xray_path.resolve()
        key = (str(resolved), int(resolved.stat().st_mtime_ns))
    except OSError:
        return get_xray_version(xray_path)
    if key not in _XRAY_VERSION_CACHE:
        _XRAY_VERSION_CACHE[key] = get_xray_version(xray_path)
    return _XRAY_VERSION_CACHE[key]


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
        resolved_tag = normalize_xray_tag(tag or fetch_latest_xray_tag(timeout=min(5.0, timeout), proxies=proxies))
        if not resolved_tag:
            return False, "Could not resolve latest Xray-core release tag from GitHub"

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


VALID_XHTTP_MODES = {"auto", "packet-up", "stream-up", "stream-one"}


def _sanitize_xhttp_mode(mode: Optional[str]) -> str:
    """Ensure xHTTP mode is one of the supported modes (auto, packet-up, stream-up, stream-one)."""
    m = (mode or "").strip().lower()
    if m in VALID_XHTTP_MODES:
        return m
    return "auto"


def _extract_host_header(q: Dict[str, str], default: str) -> str:
    """Extract host header from host, authority, headers.Host, or JSON headers dict."""
    if q.get("host"):
        return clean_dns_host(q["host"])
    if q.get("authority"):
        return clean_dns_host(q["authority"])
    for k, v in q.items():
        low_k = k.lower()
        if low_k in ("headers.host", "header.host", "headers[host]"):
            return clean_dns_host(v)
    raw_h = q.get("headers") or q.get("header")
    if raw_h:
        try:
            h_obj = json.loads(raw_h)
            if isinstance(h_obj, dict):
                for hk, hv in h_obj.items():
                    if hk.lower() == "host":
                        if isinstance(hv, list) and hv:
                            return clean_dns_host(str(hv[0]))
                        return clean_dns_host(str(hv))
        except (ValueError, TypeError) as exc:
            logger.debug("Failed parsing JSON headers in VLESS query: %s", exc)
    return default


def vless_to_xray_outbound(v: VlessConfig, server_ip: str, port: Optional[int] = None) -> Dict[str, Any]:
    """Convert VlessConfig to an Xray outbound configuration dictionary."""
    q = v.query
    network = (q.get("type") or q.get("network") or "tcp").lower()
    security = (q.get("security") or "none").lower()
    flow = q.get("flow", "")
    target_port = port if port is not None else v.port
    enc = (q.get("encryption") or "none").strip().lower() or "none"

    outbound: Dict[str, Any] = {
        "tag": "proxy",
        "protocol": "vless",
        "settings": {
            "vnext": [
                {
                    "address": server_ip,
                    "port": target_port,
                    "users": [{"id": v.uuid, "encryption": enc}],
                }
            ]
        },
        "streamSettings": {"network": network, "security": security},
    }

    # XTLS flow (e.g. xtls-rprx-vision) is only supported on tcp + tls/reality with encryption='none'
    valid_flow = flow if (network == "tcp" and security in {"tls", "reality"} and enc == "none") else ""
    if valid_flow:
        outbound["settings"]["vnext"][0]["users"][0]["flow"] = valid_flow
    elif flow:
        logger.debug(
            "Omitted invalid flow %r for transport %s with security %s and encryption %s",
            flow, network, security, enc
        )

    sni = clean_dns_host(q.get("sni") or q.get("servername") or q.get("serverName") or v.host)
    fp = q.get("fp") or q.get("fingerprint") or "chrome"
    alpn = q.get("alpn", "")

    if security in {"tls", "reality"}:
        if security == "reality":
            pbk = q.get("pbk") or ""
            if not pbk:
                raise ValueError("Invalid VLESS REALITY link: missing required public key 'pbk'.")
            if network not in {"tcp", "xhttp", "grpc"}:
                raise ValueError(
                    f"VLESS REALITY only supports 'tcp', 'xhttp', and 'grpc' transports (got '{network}')."
                )

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
            outbound["streamSettings"][tls_key]["publicKey"] = q["pbk"]
            if q.get("sid"):
                outbound["streamSettings"][tls_key]["shortId"] = q["sid"]
            if q.get("spx"):
                outbound["streamSettings"][tls_key]["spiderX"] = q["spx"]

    host_header = _extract_host_header(q, sni)
    path = q.get("path") or "/"

    if network == "ws":
        outbound["streamSettings"]["wsSettings"] = {"path": path, "headers": {"Host": host_header}}
    elif network == "grpc":
        outbound["streamSettings"]["grpcSettings"] = {
            "serviceName": q.get("serviceName") or q.get("serviceNameMode") or q.get("path", "").strip("/")
        }
    elif network in {"http", "h2"}:
        h_cfg: Dict[str, Any] = {"path": path, "host": [host_header]}
        if q.get("mode"):
            h_cfg["mode"] = q["mode"]
        outbound["streamSettings"]["httpSettings"] = h_cfg
    elif network == "httpupgrade":
        outbound["streamSettings"]["httpupgradeSettings"] = {"path": path, "host": host_header}
    elif network == "xhttp":
        mode_val = _sanitize_xhttp_mode(q.get("mode"))
        outbound["streamSettings"]["xhttpSettings"] = {
            "path": path,
            "host": host_header,
            "mode": mode_val,
        }
    elif network == "splithttp":
        s_cfg: Dict[str, Any] = {"path": path, "host": host_header}
        if q.get("mode"):
            s_cfg["mode"] = q["mode"]
        outbound["streamSettings"]["splithttpSettings"] = s_cfg
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
                "settings": {"udp": True},
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
            "settings": {"udp": True},
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
        self._lock = threading.Lock()
        self.xray_path = xray_path
        self.ready_timeout = ready_timeout
        self.temp_dir: Optional[tempfile.TemporaryDirectory] = None
        self.proc: Optional[subprocess.Popen] = None

    def _build_config(self) -> Dict[str, Any]:
        raise NotImplementedError

    def _ready_ports(self) -> List[int]:
        raise NotImplementedError

    def _reallocate_ports(self) -> None:
        """Reallocate local SOCKS ports on transient bind conflict."""

    def __enter__(self):
        try:
            xray_dir = self.xray_path.parent
            env = os.environ.copy()
            env["XRAY_LOCATION_ASSET"] = str(xray_dir)

            for attempt in range(2):
                with _ACTIVE_PROC_LOCK:
                    _ACTIVE_PROCESSES.add(self)
                try:
                    self.temp_dir = tempfile.TemporaryDirectory(prefix=self._temp_prefix, ignore_cleanup_errors=True)  # type: ignore[call-overload]
                except TypeError:
                    self.temp_dir = tempfile.TemporaryDirectory(prefix=self._temp_prefix)
                cfg_path = Path(self.temp_dir.name) / "config.json"
                cfg_path.write_text(json.dumps(self._build_config(), separators=(",", ":")), encoding="utf-8")

                err_path = Path(self.temp_dir.name) / "xray_stderr.log"
                err_fp = open(err_path, "wb")
                try:
                    self.proc = subprocess.Popen(
                        [str(self.xray_path), "run", "-config", str(cfg_path)],
                        stdout=subprocess.DEVNULL,
                        stderr=err_fp,
                        cwd=str(xray_dir),
                        env=env,
                    )
                    _assign_process_to_job(self.proc)
                finally:
                    err_fp.close()

                if wait_ports(self._ready_ports(), self.ready_timeout, proc=self.proc):
                    if self.proc is not None and self.proc.poll() is None:
                        return self

                rc = self.proc.poll()
                if rc is not None:
                    detail = ""
                    try:
                        raw_err = err_path.read_text(encoding="utf-8", errors="replace").strip()
                        if raw_err:
                            detail = raw_err.splitlines()[-1][:200]
                    except OSError as exc:
                        logger.debug("Could not read Xray stderr log %s: %s", err_path, exc)
                    is_bind_conflict = _is_port_bind_error(detail)
                    if is_bind_conflict and attempt == 0:
                        logger.debug("Transient SOCKS port-bind collision for Xray, retrying with fresh port(s): %s", detail)
                        self.close()
                        self._reallocate_ports()
                        continue
                    msg = f"Xray exited early (code {rc}): {detail}" if detail else f"Xray exited early (code {rc})"
                    logger.warning("%s", msg)
                    raise XrayStartupError(msg, transient=is_bind_conflict)
                raise TimeoutError("Xray did not open SOCKS port(s) within timeout")
            return self
        except BaseException:
            self.close()
            raise

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

    def close(self) -> None:
        """Safely terminate subprocess and remove temporary configuration directory."""
        if not hasattr(self, "_lock"):
            return
        with self._lock:
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

            try:
                release_ports(self._ready_ports())
            except Exception as exc:
                logger.debug("Port release failed: %s", exc)

    def __del__(self) -> None:
        try:
            self.close()
        except Exception as exc:
            logger.debug("Exception in %s.__del__: %s", self.__class__.__name__, exc)


def adapt_config_for_xray_version(cfg: Dict[str, Any], version: Optional[str]) -> Dict[str, Any]:
    """Adapt generated Xray config for newer Xray-core releases.

    - Xray >= 24.12.18 (or unknown version): HTTP/H2 and SplitHTTP migrated to xHTTP; ALPN includes h2; mode is sanitized.
    - Xray >= 26.1.31 (or unknown version): allowInsecure removed from TLS/Reality outbounds.
    """
    raw_tuple = parse_version_tuple(version or "") if version else ()
    ver_tuple = raw_tuple if raw_tuple else None

    # If an older legacy Xray (< 24.12.18) is detected, preserve legacy configuration verbatim
    if ver_tuple is not None and ver_tuple < (24, 12, 18):
        return cfg

    needs_xhttp_migration = (ver_tuple is None) or (ver_tuple >= (24, 12, 18))
    needs_allow_insecure_removal = (ver_tuple is None) or (ver_tuple >= (26, 1, 31))

    for outbound in cfg.get("outbounds", []):
        stream = outbound.get("streamSettings")
        if not isinstance(stream, dict):
            continue

        if needs_allow_insecure_removal:
            for tls_key in ("tlsSettings", "realitySettings"):
                tls_cfg = stream.get(tls_key)
                if isinstance(tls_cfg, dict) and "allowInsecure" in tls_cfg:
                    was_insecure = bool(tls_cfg.pop("allowInsecure"))
                    if was_insecure and version and version not in _WARNED_REMOVED_ALLOW_INSECURE:
                        _WARNED_REMOVED_ALLOW_INSECURE.add(version)
                        logger.warning(
                            "Xray %s removed 'allowInsecure'; omitting it so Xray can start with standard TLS checks.",
                            version,
                        )

        ws_cfg = stream.get("wsSettings")
        if isinstance(ws_cfg, dict):
            headers = ws_cfg.get("headers")
            if isinstance(headers, dict) and "Host" in headers:
                host_val = str(headers.pop("Host")).strip().rstrip(".")
                if host_val and "host" not in ws_cfg:
                    ws_cfg["host"] = host_val
                if not headers:
                    ws_cfg.pop("headers", None)

        net_type = str(stream.get("network") or "").lower()

        if needs_xhttp_migration:
            http_cfg = stream.get("httpSettings")
            if net_type in ("http", "h2") and isinstance(http_cfg, dict):
                hosts = http_cfg.get("host")
                first_host = clean_dns_host(hosts[0] if isinstance(hosts, list) and hosts else str(hosts or ""))
                mode_val = _sanitize_xhttp_mode(http_cfg.get("mode") or "stream-one")
                xhttp_cfg: Dict[str, Any] = {
                    "path": http_cfg.get("path") or "/",
                    "mode": mode_val,
                }
                if first_host:
                    xhttp_cfg["host"] = first_host
                stream["network"] = "xhttp"
                stream["xhttpSettings"] = xhttp_cfg
                stream.pop("httpSettings", None)

                # Ensure ALPN includes 'h2' for XHTTP over TLS/Reality
                for tls_key in ("tlsSettings", "realitySettings"):
                    t_cfg = stream.get(tls_key)
                    if isinstance(t_cfg, dict):
                        alpn_list = t_cfg.get("alpn")
                        if isinstance(alpn_list, list):
                            if "h2" not in alpn_list:
                                alpn_list.insert(0, "h2")
                        else:
                            t_cfg["alpn"] = ["h2", "http/1.1"]

            split_cfg = stream.pop("splithttpSettings", None)
            if net_type in ("splithttp", "xhttp") or split_cfg is not None:
                raw_cfg = split_cfg if isinstance(split_cfg, dict) else (stream.get("xhttpSettings") or {})
                path_val = raw_cfg.get("path") or "/"
                host_val = clean_dns_host(raw_cfg.get("host") or "")
                mode_val = _sanitize_xhttp_mode(raw_cfg.get("mode") or "auto")
                migrated_xhttp: Dict[str, Any] = {
                    "path": path_val,
                    "mode": mode_val,
                }
                if host_val:
                    migrated_xhttp["host"] = host_val
                stream["network"] = "xhttp"
                stream["xhttpSettings"] = migrated_xhttp

                # Ensure ALPN includes 'h2'
                for tls_key in ("tlsSettings", "realitySettings"):
                    t_cfg = stream.get(tls_key)
                    if isinstance(t_cfg, dict):
                        alpn_list = t_cfg.get("alpn")
                        if isinstance(alpn_list, list):
                            if "h2" not in alpn_list:
                                alpn_list.insert(0, "h2")
                        else:
                            t_cfg["alpn"] = ["h2", "http/1.1"]
        else:
            if net_type == "xhttp" and "xhttpSettings" in stream:
                m = stream["xhttpSettings"].get("mode")
                stream["xhttpSettings"]["mode"] = _sanitize_xhttp_mode(m)
    return cfg


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
        cfg = make_xray_config(
            self.vless_config,
            self.server_ip,
            self.socks_port,
            self.loglevel,
            port=self.port,
        )
        return adapt_config_for_xray_version(cfg, _cached_xray_version(self.xray_path))

    def _ready_ports(self) -> List[int]:
        return [self.socks_port]

    def _reallocate_ports(self) -> None:
        old_ports = self._ready_ports()
        new_port: Optional[int] = None
        try:
            new_port = free_port()
            self.socks_port = new_port
            release_ports(old_ports)
        except Exception:
            if new_port is not None:
                release_ports([new_port])
            raise

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
        self.endpoint_ports: List[Tuple[str, int, int]] = []
        self._reallocate_ports()

    def _build_config(self) -> Dict[str, Any]:
        cfg = make_batch_xray_config(
            self.vless_config,
            self.endpoint_ports,
            self.loglevel,
        )
        return adapt_config_for_xray_version(cfg, _cached_xray_version(self.xray_path))

    def _ready_ports(self) -> List[int]:
        return [sp for _, _, sp in self.endpoint_ports]

    def _reallocate_ports(self) -> None:
        old_ports = self._ready_ports()
        allocated: List[int] = []
        try:
            allocated = free_ports(len(self.endpoints))
            if len(allocated) != len(self.endpoints):
                raise RuntimeError(f"Requested {len(self.endpoints)} ports, got {len(allocated)}")
            self.endpoint_ports = [(ip, p, sp) for (ip, p), sp in zip(self.endpoints, allocated, strict=True)]
            release_ports(old_ports)
        except Exception:
            if allocated:
                release_ports(allocated)
            raise

    def get_proxies_for_endpoint(self, ip: str, port: int) -> Optional[Dict[str, str]]:
        for ep_ip, ep_port, socks_port in self.endpoint_ports:
            if ep_ip == ip and ep_port == port:
                url = f"socks5h://127.0.0.1:{socks_port}"
                return {"http": url, "https": url}
        return None

