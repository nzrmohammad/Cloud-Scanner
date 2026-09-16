#!/usr/bin/env bash
set -e

# Detect Python 3 command
if command -v python3 &>/dev/null; then
    PYTHON_CMD=python3
elif command -v python &>/dev/null; then
    PYTHON_CMD=python
else
    echo "[ERROR] Python 3 is not installed or not in PATH."
    exit 1
fi

# Install dependencies if needed
$PYTHON_CMD -m pip install -q -r requirements.txt

# Check if Xray Core exists
if [ ! -f "core/xray" ] && [ ! -f "xray" ]; then
    echo "[INFO] Xray-core not found. Downloading latest official core..."
    $PYTHON_CMD scripts/download_core.py
fi

# Ensure executable permissions on xray if present
if [ -f "core/xray" ]; then
    chmod +x core/xray
fi

# Run Cloud Scanner
$PYTHON_CMD main.py "$@"
