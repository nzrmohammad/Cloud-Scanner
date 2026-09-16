#!/usr/bin/env python3
"""
Cloud Scanner - Automatic Xray-core Downloader & Updater.

Downloads the official latest Xray-core release and dat files directly from
https://github.com/XTLS/Xray-core/releases into the project's `core/` folder.
"""
from __future__ import annotations

import argparse
import os
import platform
import shutil
import stat
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path

try:
    import requests
except ImportError:
    requests = None

try:
    from rich.console import Console
    from rich.progress import BarColumn, DownloadColumn, Progress, TextColumn, TimeRemainingColumn, TransferSpeedColumn
    console = Console()
    RICH = True
except ImportError:
    console = None
    RICH = False


def app_root() -> Path:
    return Path(__file__).resolve().parent.parent


def get_platform_asset_name() -> str:
    system = platform.system().lower()
    machine = platform.machine().lower()

    if "windows" in system:
        if "arm" in machine:
            return "Xray-windows-arm64-v8a.zip"
        if "32" in machine or machine in ("i386", "i686"):
            return "Xray-windows-32.zip"
        return "Xray-windows-64.zip"

    elif "linux" in system:
        if "aarch64" in machine or "arm64" in machine:
            return "Xray-linux-arm64-v8a.zip"
        if "arm" in machine:
            return "Xray-linux-arm32-v7a.zip"
        if "32" in machine or machine in ("i386", "i686"):
            return "Xray-linux-32.zip"
        return "Xray-linux-64.zip"

    elif "darwin" in system:
        if "arm64" in machine or "aarch64" in machine:
            return "Xray-macos-arm64-v8a.zip"
        return "Xray-macos-64.zip"

    raise RuntimeError(f"Unsupported operating system: {system} ({machine})")


def get_latest_tag(proxies: dict | None = None) -> str:
    if requests is None:
        raise RuntimeError("Package 'requests' is required. Run: pip install requests")

    url = "https://github.com/XTLS/Xray-core/releases/latest"
    r = requests.head(url, allow_redirects=False, timeout=5.0, proxies=proxies, headers={"User-Agent": "CloudScanner"})
    loc = r.headers.get("Location") or ""
    if "/tag/" in loc:
        return loc.rsplit("/tag/", 1)[-1].strip()
    # Fallback to GitHub API
    api_url = "https://api.github.com/repos/XTLS/Xray-core/releases/latest"
    res = requests.get(api_url, timeout=5.0, proxies=proxies, headers={"User-Agent": "CloudScanner"})
    if res.status_code == 200:
        return res.json().get("tag_name", "v26.3.27")
    return "v26.3.27"


def download_file(url: str, dest: Path, proxies: dict | None = None) -> None:
    if requests is None:
        raise RuntimeError("Package 'requests' is required. Run: pip install requests")

    with requests.get(url, stream=True, timeout=30.0, proxies=proxies, headers={"User-Agent": "CloudScanner"}) as response:
        response.raise_for_status()
        total = int(response.headers.get("content-length", 0))

        if RICH and console is not None and total > 0:
            progress = Progress(
                TextColumn("[bold cyan]{task.description}"),
                BarColumn(),
                DownloadColumn(),
                TransferSpeedColumn(),
                TimeRemainingColumn(),
                console=console,
            )
            with progress:
                task = progress.add_task(f"Downloading {dest.name}", total=total)
                with open(dest, "wb") as f:
                    for chunk in response.iter_content(chunk_size=64 * 1024):
                        if chunk:
                            f.write(chunk)
                            progress.advance(task, len(chunk))
        else:
            downloaded = 0
            with open(dest, "wb") as f:
                for chunk in response.iter_content(chunk_size=64 * 1024):
                    if chunk:
                        f.write(chunk)
                        downloaded += len(chunk)
                        if total > 0:
                            percent = (downloaded / total) * 100
                            print(f"\rDownloading {dest.name}: {downloaded / 1024 / 1024:.1f} MB / {total / 1024 / 1024:.1f} MB ({percent:.1f}%)", end="")
            print()


def extract_core(zip_path: Path, target_dir: Path) -> None:
    target_dir.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(zip_path, "r") as zf:
        for member in zf.namelist():
            filename = os.path.basename(member)
            # Only extract main binary and data files
            if not filename:
                continue
            low = filename.lower()
            if low.startswith("xray") or low.endswith(".dat") or low.endswith(".txt"):
                source = zf.open(member)
                target_file = target_dir / filename
                with open(target_file, "wb") as target:
                    shutil.copyfileobj(source, target)

    # Set executable bit on Linux / macOS
    for exe_name in ("xray", "xray.exe"):
        exe_path = target_dir / exe_name
        if exe_path.exists() and not exe_name.endswith(".exe"):
            current = os.stat(exe_path).st_mode
            os.chmod(exe_path, current | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)


def verify_installation(target_dir: Path) -> bool:
    exe = "xray.exe" if platform.system().lower().startswith("win") else "xray"
    exe_path = target_dir / exe
    if not exe_path.exists():
        return False

    try:
        res = subprocess.run([str(exe_path), "version"], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, timeout=3.0)
        return "Xray" in res.stdout
    except Exception:
        return False


def main() -> int:
    parser = argparse.ArgumentParser(description="Cloud Scanner - Download and install official Xray-core")
    parser.add_argument("-t", "--tag", help="Explicit Xray version tag (e.g. v26.3.27). Default: latest")
    parser.add_argument("-p", "--proxy", help="HTTP/SOCKS proxy to use for download (e.g. http://127.0.0.1:10808)")
    parser.add_argument("-d", "--dir", help="Destination core directory. Default: ./core")
    args = parser.parse_args()

    proxies = None
    if args.proxy:
        proxies = {"http": args.proxy, "https": args.proxy}
    elif os.environ.get("HTTPS_PROXY") or os.environ.get("HTTP_PROXY"):
        proxies = {
            "http": os.environ.get("HTTP_PROXY") or os.environ.get("HTTPS_PROXY"),
            "https": os.environ.get("HTTPS_PROXY") or os.environ.get("HTTP_PROXY"),
        }

    target_dir = Path(args.dir) if args.dir else (app_root() / "core")
    print(f"Target directory: {target_dir}")

    try:
        asset_name = get_platform_asset_name()
    except Exception as e:
        print(f"Error detecting platform: {e}")
        return 1

    print("Checking latest Xray-core release on GitHub...")
    tag = args.tag or get_latest_tag(proxies)
    if not tag.startswith("v") and not tag[0].isdigit():
        tag = f"v{tag}"
    print(f"Target version: {tag}")

    download_url = f"https://github.com/XTLS/Xray-core/releases/download/{tag}/{asset_name}"
    print(f"Download URL: {download_url}")

    with tempfile.TemporaryDirectory(prefix="xray_dl_") as tmp:
        tmp_zip = Path(tmp) / asset_name
        try:
            download_file(download_url, tmp_zip, proxies=proxies)
        except Exception as e:
            print(f"Download failed: {e}")
            print("\nTip: If GitHub is slow or blocked in your network, pass a proxy: python scripts/download_core.py -p http://127.0.0.1:10808")
            return 2

        print("Extracting files into core/ ...")
        extract_core(tmp_zip, target_dir)

    if verify_installation(target_dir):
        print(f"\n[SUCCESS] Xray-core {tag} installed successfully in {target_dir}!")
        return 0
    else:
        print(f"\n[WARNING] Files extracted to {target_dir}, but binary verification failed.")
        return 1


if __name__ == "__main__":
    sys.exit(main())
