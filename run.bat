@echo off
chcp 65001 >nul
title Cloud Scanner v0.3.0

echo ==============================================================
echo        Cloud Scanner - Starting environment...
echo ==============================================================

set "PY_CMD=python"
if exist "venv\Scripts\python.exe" (
    set "PY_CMD=venv\Scripts\python.exe"
) else (
    where python >nul 2>nul
    if %errorlevel% neq 0 (
        echo [ERROR] Python is not installed or not added to PATH.
        echo Please install Python 3.10+ from https://www.python.org/
        pause
        exit /b 1
    )
)

:: Install/verify dependencies
"%PY_CMD%" -m pip install -q -r requirements.txt

:: Check if Xray Core exists
if not exist "core\xray.exe" (
    if not exist "xray.exe" (
        echo [INFO] Xray-core not found. Downloading latest official core...
        "%PY_CMD%" scripts/download_core.py
    )
)

:: Run Cloud Scanner
"%PY_CMD%" main.py %*

if %errorlevel% neq 0 (
    if %errorlevel% neq 130 (
        echo.
        echo [Scanner closed with error code %errorlevel%]
        pause
    )
)
