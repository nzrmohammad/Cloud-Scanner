#!/usr/bin/env python3
"""
Cloud Scanner - Automatic Xray-core Downloader & Updater.

Downloads the official latest Xray-core release and dat files directly from
https://github.com/XTLS/Xray-core/releases into the project's `core/` folder.
"""
from __future__ import annotations

import argparse
import os
import sys
import tempfile
from pathlib import Path
from typing import Dict, Optional


def app_root() -> Path:
    return Path(__file__).resolve().parent.parent


if str(app_root()) not in sys.path:
    sys.path.insert(0, str(app_root()))

from scanner.xray import (  # noqa: E402
    extract_xray_archive,
    fetch_latest_xray_tag,
    get_platform_asset_name,
    get_xray_version,
)

try:
    import requests
except ImportError:
    requests = None  # type: ignore[assignment]

try:
    from rich.console import Console
    from rich.progress import BarColumn, DownloadColumn, Progress, TextColumn, TimeRemainingColumn, TransferSpeedColumn
    console = Console()
    RICH = True
except ImportError:
    console = None
    RICH = False


def get_latest_tag(proxies: dict | None = None) -> str:
    if requests is None:
        raise RuntimeError("Package 'requests' is required. Run: pip install requests")
    tag = fetch_latest_xray_tag(timeout=5.0, proxies=proxies, fallback_default="v26.3.27")
    return tag or "v26.3.27"


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
    extract_xray_archive(zip_path, target_dir)


def verify_installation(target_dir: Path) -> bool:
    import platform

    exe = "xray.exe" if platform.system().lower().startswith("win") else "xray"
    return bool(get_xray_version(target_dir / exe))


def main() -> int:
    parser = argparse.ArgumentParser(description="Cloud Scanner - Download and install official Xray-core")
    parser.add_argument("-t", "--tag", help="Explicit Xray version tag (e.g. v26.3.27). Default: latest")
    parser.add_argument("-p", "--proxy", help="HTTP/SOCKS proxy to use for download (e.g. http://127.0.0.1:10808)")
    parser.add_argument("-d", "--dir", help="Destination core directory. Default: ./core")
    args = parser.parse_args()

    proxies: Optional[Dict[str, str]] = None
    if args.proxy:
        proxies = {"http": str(args.proxy), "https": str(args.proxy)}
    elif os.environ.get("HTTPS_PROXY") or os.environ.get("HTTP_PROXY"):
        http_p = os.environ.get("HTTP_PROXY") or os.environ.get("HTTPS_PROXY") or ""
        https_p = os.environ.get("HTTPS_PROXY") or http_p
        proxies = {"http": http_p, "https": https_p}

    target_dir = Path(args.dir) if args.dir else (app_root() / "core")
    print(f"Target directory: {target_dir}")

    try:
        asset_name = get_platform_asset_name()
    except Exception as e:
        print(f"Error detecting platform: {e}")
        return 1

    print("Checking latest Xray-core release on GitHub...")
    try:
        tag = args.tag or get_latest_tag(proxies)
    except Exception as e:
        print(f"Failed to resolve latest Xray-core release tag: {e}")
        print("\nTip: If GitHub is slow or blocked in your network, pass a proxy: python scripts/download_core.py -p http://127.0.0.1:10808")
        return 2
    if tag and not tag.startswith("v"):
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
