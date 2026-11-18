@echo off
setlocal enabledelayedexpansion
title TraceX - Digital Forensics & Cyber Investigation Suite
cd /d "%~dp0"

echo ==============================================================================
echo        TRACEX - DIGITAL FORENSICS & CYBER INVESTIGATION SUITE
echo                       Discover. Analyze. Investigate.
echo ==============================================================================
echo.

rem ------------------------------------------------------------------
rem 1. Initialize Configuration (.env) if Missing
rem ------------------------------------------------------------------
if not exist ".env" (
    if exist ".env.example" (
        echo [*] Initializing configuration from .env.example...
        copy ".env.example" ".env" >nul 2>&1
    )
)

rem ------------------------------------------------------------------
rem 2. Activate Virtual Environment or Locate Python Interpreter
rem ------------------------------------------------------------------
set "PYCMD="
if exist ".venv\Scripts\activate.bat" (
    call ".venv\Scripts\activate.bat"
    set "PYCMD=python"
) else (
    if exist "%LOCALAPPDATA%\Programs\Python\Launcher\py.exe" (
        set "PYCMD=%LOCALAPPDATA%\Programs\Python\Launcher\py.exe -3.11"
    )
    if not defined PYCMD (
        py -3.11 --version >nul 2>&1
        if !errorlevel! equ 0 set "PYCMD=py -3.11"
    )
    if not defined PYCMD (
        python --version >nul 2>&1
        if !errorlevel! equ 0 set "PYCMD=python"
    )
    if not defined PYCMD (
        for /f "delims=" %%p in ('where py.exe 2^>nul') do if not defined PYCMD set "PYCMD=%%p -3.11"
    )
    if not defined PYCMD (
        for /f "delims=" %%p in ('where python.exe 2^>nul') do if not defined PYCMD set "PYCMD=%%p"
    )
)

if not defined PYCMD (
    echo [X] ERROR: Python was not found on your system.
    echo     Please run "install.bat" first to set up your environment,
    echo     or install Python 3.11 from https://www.python.org/downloads/
    echo.
    pause
    exit /b 1
)

rem ------------------------------------------------------------------
rem 3. Ensure Frontend Assets are Built
rem ------------------------------------------------------------------
if not exist "frontend\dist\index.html" (
    echo [*] Frontend production bundle not found. Building now...
    set "NPMCMD=npm"
    if exist "%ProgramFiles%\nodejs\npm.cmd" set "NPMCMD=%ProgramFiles%\nodejs\npm.cmd"
    if exist "%USERPROFILE%\Tools\node\npm.cmd" set "NPMCMD=%USERPROFILE%\Tools\node\npm.cmd"
    for /f "delims=" %%n in ('where npm.cmd 2^>nul') do set "NPMCMD=%%n"

    where !NPMCMD! >nul 2>&1
    if !errorlevel! equ 0 (
        cd frontend
        call "!NPMCMD!" run build
        cd ..
    ) else (
        echo [!] WARNING: npm was not found to build frontend bundle.
        echo     Run "install.bat" to perform full setup.
    )
)

rem ------------------------------------------------------------------
rem 4. Launch TraceX Unified Server & Open Browser
rem ------------------------------------------------------------------
echo [*] Starting TraceX Forensic Engine...
echo [*] Application Interface: http://127.0.0.1:8000
echo [*] Opening your browser automatically...
echo.
echo ==============================================================================
echo  TraceX is running. Press Ctrl+C in this window to stop the server.
echo ==============================================================================
echo.

%PYCMD% launcher.py --open-browser

if %errorlevel% neq 0 (
    echo.
    echo [!] Server exited with status %errorlevel%.
    echo     If packages are missing, please run "install.bat" to resolve dependencies.
    echo.
    pause
)
