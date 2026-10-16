"""Centralized logging infrastructure for Cloud Scanner.

Directs diagnostic messages and exceptions to results/scanner.log while keeping
the terminal user interface pristine and uncluttered.
"""
from __future__ import annotations

import logging
from pathlib import Path
from typing import Optional

_LOG_FORMAT = "%(asctime)s [%(levelname)s] [%(name)s] %(message)s"
_INITIALIZED = False


def setup_logging(output_dir: Optional[Path] = None, log_level: int = logging.DEBUG) -> logging.Logger:
    """Initialize the root 'cloud_scanner' logger with a file handler in output_dir."""
    global _INITIALIZED
    root_logger = logging.getLogger("cloud_scanner")
    if _INITIALIZED:
        return root_logger

    root_logger.setLevel(log_level)

    if output_dir is None:
        from scanner.constants import app_dir
        output_dir = app_dir() / "results"

    try:
        output_dir.mkdir(parents=True, exist_ok=True)
        log_file = output_dir / "scanner.log"
        handler = logging.FileHandler(str(log_file), mode="a", encoding="utf-8")
        handler.setLevel(log_level)
        handler.setFormatter(logging.Formatter(_LOG_FORMAT))
        root_logger.addHandler(handler)
        _INITIALIZED = True
    except Exception:
        # Fall back gracefully if disk writes are restricted
        pass

    return root_logger


def get_logger(name: Optional[str] = None) -> logging.Logger:
    """Return a scoped logger under the 'cloud_scanner' hierarchy."""
    if not _INITIALIZED:
        setup_logging()
    if name:
        return logging.getLogger(f"cloud_scanner.{name}")
    return logging.getLogger("cloud_scanner")
