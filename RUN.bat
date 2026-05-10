@echo off
title SCAM SNIFFER v2.0
echo.
echo  =============================================
echo   SCAM SNIFFER v2.0
echo   Singapore Threat Intelligence Scanner
echo  =============================================
echo.

:: Check Python
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] Python not found!
    echo         Install Python 3.10+ from https://python.org
    echo         Check "Add Python to PATH" during install.
    echo.
    pause
    exit /b 1
)

:: Install anthropic SDK (optional but recommended)
echo [*] Installing dependencies...
pip install anthropic --quiet >nul 2>&1

:: Launch
echo [*] Launching Scam Sniffer...
echo     (Free mode works without API key)
echo.
python "%~dp0scam_sniffer.py"

if %errorlevel% neq 0 (
    echo.
    echo [ERROR] Something went wrong. See error above.
    pause
)
