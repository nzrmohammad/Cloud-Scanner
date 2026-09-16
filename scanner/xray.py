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
from typing import Any, Dict, List, Optional

from scanner.constants import app_dir
from scanner.models import VlessConfig

try:
    import requests
except ImportError:
    requests = None


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
    except Exception:
        pass
    return None


def check_latest_xray_version(timeout: float = 1.8) -> Optional[str]:
    """Check the latest release tag of Xray-core from GitHub releases."""
    if requests is None:
        return None
    try:
        r = requests.head(
            "https://github.com/XTLS/Xray-core/releases/latest",
            allow_redirects=False,
            timeout=timeout,
            headers={"User-Agent": "CloudScanner"},
        )
        loc = r.headers.get("Location") or ""
        if "/tag/" in loc:
            tag = loc.rsplit("/tag/", 1)[-1].strip()
            return tag.lstrip("v")
    except Exception:
        pass
    return None


def check_environment(xray_path: Optional[Path], show_help: bool = True) -> bool:
    """Check availability of required binary and data files."""
    ok = True
    rows = []
    geoip_file = find_asset("geoip.dat", xray_path)
    geosite_file = find_asset("geosite.dat", xray_path)

    # Determine Xray version and update status
    xray_status = "[red]MISSING[/red]"
    update_notice = ""
    if xray_path:
        local_ver = get_xray_version(xray_path)
        latest_ver = check_latest_xray_version()
        if local_ver and latest_ver:
            if local_ver == latest_ver:
                xray_status = f"[green]FOUND (v{local_ver}) [Latest][/green]"
            else:
                xray_status = f"[yellow]FOUND (v{local_ver}) -> Update: v{latest_ver}[/yellow]"
                update_notice = f"New Xray v{latest_ver} available! Run: python scripts/download_core.py"
        elif local_ver:
            xray_status = f"[green]FOUND (v{local_ver})[/green]"
        else:
            xray_status = "[green]FOUND[/green]"
    else:
        ok = False

    rows.append(("xray.exe / xray", xray_status))
    rows.append(("geoip.dat", "[green]FOUND[/green]" if geoip_file else "[red]MISSING[/red]"))
    rows.append(("geosite.dat", "[green]FOUND[/green]" if geosite_file else "[red]MISSING[/red]"))
    rows.append(("requests[socks]", "[green]FOUND[/green]" if requests is not None else "[red]MISSING[/red]"))

    if requests is None:
        ok = False

    try:
        from rich import box
        from rich.console import Console
        from rich.table import Table

        console = Console()
        table = Table(title="Startup Check", box=box.ROUNDED, border_style="cyan")
        table.add_column("Component", style="white")
        table.add_column("Status")
        for name, status in rows:
            table.add_row(name, status)
        console.print(table)
        if update_notice:
            console.print(f"[dim yellow]💡 {update_notice}[/dim yellow]")
    except ImportError:
        for name, status in rows:
            print(f"{name}: {status}")
        if update_notice:
            print(f"Notice: {update_notice}")

    if not ok and show_help:
        print("\nPlace xray.exe/xray in core/ and install dependencies with: pip install -r requirements.txt")
    return ok


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
            "allowInsecure": q.get("allowInsecure", "0") in {"1", "true"},
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
            raise RuntimeError("Xray SOCKS port did not start in time")
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

    def close(self) -> None:
        """Safely terminate subprocess and remove temporary configuration directory."""
        if self.proc is not None:
            try:
                self.proc.terminate()
                self.proc.wait(timeout=1.5)
            except Exception:
                try:
                    self.proc.kill()
                except Exception:
                    pass
            self.proc = None

        if self.temp_dir is not None:
            try:
                self.temp_dir.cleanup()
            except Exception:
                pass
            self.temp_dir = None

    @property
    def socks_url(self) -> str:
        return f"socks5h://127.0.0.1:{self.socks_port}"

    @property
    def proxies(self) -> Dict[str, str]:
        return {"http": self.socks_url, "https": self.socks_url}
