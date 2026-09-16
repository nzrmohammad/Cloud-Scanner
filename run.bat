@echo off
chcp 65001 >nul
title Cloud Scanner v0.2.0

echo ==============================================================
echo        Cloud Scanner - Starting environment...
echo ==============================================================

where python >nul 2>nul
if %errorlevel% neq 0 (
    echo [ERROR] Python is not installed or not added to PATH.
    echo Please install Python 3.9+ from https://www.python.org/
    pause
    exit /b 1
)

:: Install/verify dependencies
python -m pip install -q -r requirements.txt

:: Check if Xray Core exists
if not exist "core\xray.exe" (
    if not exist "xray.exe" (
        echo [INFO] Xray-core not found. Downloading latest official core...
        python scripts/download_core.py
    )
)

:: Run Cloud Scanner
python main.py %*

if %errorlevel% neq 0 (
    if %errorlevel% neq 130 (
        echo.
        echo [Scanner closed with error code %errorlevel%]
        pause
    )
)
