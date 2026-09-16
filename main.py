#!/usr/bin/env python3
"""
Cloud Scanner v0.2.0 - Fast, Modular Cloudflare Clean-IP Scanner.

An asynchronous, modular scanner designed to test and rank Cloudflare IP ranges
against real VLESS + Xray endpoints with latency, jitter, packet loss, download,
and upload speed diagnostics.
"""
from __future__ import annotations

import sys

if sys.platform == "win32":
    try:
        if hasattr(sys.stdout, "reconfigure"):
            sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        if hasattr(sys.stderr, "reconfigure"):
            sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

from scanner.app import CloudScannerApp


def main() -> int:
    """Entry point for Cloud Scanner CLI and interactive TUI."""
    app = CloudScannerApp()
    return app.run()


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(130)
