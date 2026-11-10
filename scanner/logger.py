"""Centralized logging infrastructure for Cloud Scanner.

Directs diagnostic messages and exceptions to results/scanner.log while keeping
the terminal user interface pristine and uncluttered.
"""
from __future__ import annotations

import logging
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Optional

_LOG_FORMAT = "%(asctime)s [%(levelname)s] [%(name)s] %(message)s"
_INITIALIZED = False
_CONFIGURED_OUTPUT_DIR: Optional[Path] = None
_MAX_LOG_BYTES = 2 * 1024 * 1024  # 2 MB per file, max 3 files (~6 MB total)


def setup_logging(output_dir: Optional[Path] = None, log_level: int = logging.DEBUG) -> logging.Logger:
    """Initialize the root 'cloud_scanner' logger with a rotating file handler in output_dir."""
    global _INITIALIZED, _CONFIGURED_OUTPUT_DIR
    root_logger = logging.getLogger("cloud_scanner")

    if output_dir is None:
        from scanner.constants import app_dir
        target_dir = app_dir() / "results"
    else:
        target_dir = Path(output_dir)

    if _INITIALIZED and (output_dir is None or _CONFIGURED_OUTPUT_DIR == target_dir):
        return root_logger

    root_logger.setLevel(log_level)

    try:
        target_dir.mkdir(parents=True, exist_ok=True)
        log_file = target_dir / "scanner.log"

        for existing in list(root_logger.handlers):
            root_logger.removeHandler(existing)
            try:
                existing.close()
            except Exception:
                pass

        handler = RotatingFileHandler(
            str(log_file),
            mode="a",
            maxBytes=_MAX_LOG_BYTES,
            backupCount=2,
            encoding="utf-8",
        )
        handler.setLevel(log_level)
        handler.setFormatter(logging.Formatter(_LOG_FORMAT))
        root_logger.addHandler(handler)
        _INITIALIZED = True
        _CONFIGURED_OUTPUT_DIR = target_dir
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
