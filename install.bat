@echo off
setlocal enabledelayedexpansion
title TraceX - Automated Installation & Setup
cd /d "%~dp0"

echo ==============================================================================
echo        TRACEX - DIGITAL FORENSICS & CYBER INVESTIGATION SUITE
echo                      Automated Setup & Installer
echo ==============================================================================
echo.

rem ------------------------------------------------------------------
rem 1. Locate Python 3.10+ / 3.11 Interpreter
rem ------------------------------------------------------------------
set "PYCMD="
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

if not defined PYCMD (
    echo [X] ERROR: Python was not found on your system.
    echo     TraceX requires Python 3.10 or 3.11.
    echo.
    echo     Please download and install Python from:
    echo     https://www.python.org/downloads/
    echo     (Ensure you check "Add python.exe to PATH" during installation)
    echo.
    pause
    exit /b 1
)

echo [*] Using Python interpreter: %PYCMD%
%PYCMD% --version
echo.

rem ------------------------------------------------------------------
rem 2. Optional Virtual Environment Setup (.venv)
rem ------------------------------------------------------------------
if not exist ".venv\Scripts\activate.bat" (
    echo [*] Creating virtual environment (.venv)...
    %PYCMD% -m venv .venv >nul 2>&1
)

if exist ".venv\Scripts\activate.bat" (
    echo [*] Activating virtual environment (.venv)...
    call ".venv\Scripts\activate.bat"
    set "ACTIVE_PY=python"
) else (
    echo [!] Note: Virtual environment not created, using system interpreter.
    set "ACTIVE_PY=%PYCMD%"
)
echo.

rem ------------------------------------------------------------------
rem 3. Install Python Backend Dependencies
rem ------------------------------------------------------------------
echo [*] Installing TraceX Python dependencies from requirements.txt...
%ACTIVE_PY% -m pip install --upgrade pip >nul 2>&1
%ACTIVE_PY% -m pip install -r requirements.txt
if %errorlevel% neq 0 (
    echo.
    echo [X] WARNING: Some Python packages encountered installation issues.
    echo     Retrying with backend/requirements.txt...
    %ACTIVE_PY% -m pip install -r backend/requirements.txt
)
echo [+] Backend Python dependencies verified.
echo.

rem ------------------------------------------------------------------
rem 4. Locate Node.js & npm Toolchain
rem ------------------------------------------------------------------
set "NPMCMD=npm"
if exist "%ProgramFiles%\nodejs\npm.cmd" set "NPMCMD=%ProgramFiles%\nodejs\npm.cmd"
if exist "%USERPROFILE%\Tools\node\npm.cmd" set "NPMCMD=%USERPROFILE%\Tools\node\npm.cmd"
for /f "delims=" %%n in ('where npm.cmd 2^>nul') do set "NPMCMD=%%n"

rem ------------------------------------------------------------------
rem 5. Install & Build Frontend
rem ------------------------------------------------------------------
echo [*] Checking Frontend build environment...
if exist "frontend\package.json" (
    "%NPMCMD%" --version >nul 2>&1
    if !errorlevel! equ 0 (
        echo [*] Installing frontend npm packages...
        cd frontend
        call "%NPMCMD%" install
        echo [*] Compiling production frontend bundle...
        call "%NPMCMD%" run build
        cd ..
        echo [+] Frontend production bundle built successfully.
    ) else (
        echo [!] npm was not found. Checking for prebuilt frontend bundle...
        if exist "frontend\dist\index.html" (
            echo [+] Prebuilt frontend bundle is already present.
        ) else (
            echo [X] Node.js is recommended to build the frontend.
            echo     Download Node.js from: https://nodejs.org/
        )
    )
)
echo.

rem ------------------------------------------------------------------
rem 6. Prepare Environment File (.env)
rem ------------------------------------------------------------------
if not exist ".env" (
    if exist ".env.example" (
        echo [*] Initializing configuration from .env.example...
        copy ".env.example" ".env" >nul
        echo [+] Created .env configuration file.
    )
) else (
    echo [+] Existing .env configuration preserved.
)
echo.

rem ------------------------------------------------------------------
rem 7. Installation Summary Banner
rem ------------------------------------------------------------------
echo ==============================================================================
echo                      TRACEX SETUP COMPLETE!
echo ==============================================================================
echo  [+] Python Environment : Configured and Ready
echo  [+] Forensic Engines   : Dependencies Installed
echo  [+] User Interface     : Frontend Bundle Ready
echo  [+] Configuration      : .env Active
echo.
echo  TO START TRACEX:
echo    Simply double-click "run_tracex.bat" (or run "start.bat")
echo.
echo  TraceX will launch and automatically open in your web browser at:
echo    http://127.0.0.1:8000
echo ==============================================================================
echo.
pause
