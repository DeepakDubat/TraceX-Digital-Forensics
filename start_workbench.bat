@echo off
title TRACEX - DIGITAL FORENSICS ^& CYBER INVESTIGATION SUITE (DEV WORKBENCH)
cd /d "%~dp0"

rem ------------------------------------------------------------------
rem  Locate the Python launcher and the Node/npm toolchain
rem ------------------------------------------------------------------
set "PYEXE="
set "PYARGS="
if exist "%LOCALAPPDATA%\Programs\Python\Launcher\py.exe" (
    set "PYEXE=%LOCALAPPDATA%\Programs\Python\Launcher\py.exe"
    set "PYARGS=-3.11"
)
if not defined PYEXE for /f "delims=" %%p in ('where py.exe 2^>nul') do if not defined PYEXE (set "PYEXE=%%p" & set "PYARGS=-3.11")
if not defined PYEXE for /f "delims=" %%p in ('where python.exe 2^>nul') do if not defined PYEXE set "PYEXE=%%p"

if not defined PYEXE (
    echo [X] ERROR: Python was not found on this machine.
    echo     Please run "install.bat" to configure your environment.
    pause
    exit /b 1
)

set "NPMCMD=npm.cmd"
if exist "%USERPROFILE%\Tools\node\npm.cmd" set "NPMCMD=%USERPROFILE%\Tools\node\npm.cmd"
if exist "%ProgramFiles%\nodejs\npm.cmd" if "%NPMCMD%"=="npm.cmd" set "NPMCMD=%ProgramFiles%\nodejs\npm.cmd"

rem --- Lab toolchain on PATH for child processes ---
set "PATH=%USERPROFILE%\Tools\node;%USERPROFILE%\Tools\jadx\bin;%USERPROFILE%\Tools\apktool;%USERPROFILE%\Tools\jre\bin;%PATH%"
set "JAVA_HOME=%USERPROFILE%\Tools\jre"

rem --- Ensure .env exists ---
if not exist ".env" if exist ".env.example" copy ".env.example" ".env" >nul 2>&1

echo ==============================================================================
echo        TRACEX - DIGITAL FORENSICS ^& CYBER INVESTIGATION SUITE
echo                      Developer Workbench Launcher
echo ==============================================================================
echo [+] Project root : %CD%
echo [+] Python       : %PYEXE% %PYARGS%
echo [+] npm          : %NPMCMD%
echo.

rem ------------------------------------------------------------------
rem  Helper scripts for isolated console windows
rem ------------------------------------------------------------------
set "HELPER=%TEMP%\tracex_workbench"
if not exist "%HELPER%" mkdir "%HELPER%" >nul 2>&1

> "%HELPER%\backend.cmd" echo @echo off
>>"%HELPER%\backend.cmd" echo title TraceX Backend Server
>>"%HELPER%\backend.cmd" echo cd /d "%~dp0"
>>"%HELPER%\backend.cmd" echo "%PYEXE%" %PYARGS% run_backend.py

> "%HELPER%\frontend.cmd" echo @echo off
>>"%HELPER%\frontend.cmd" echo title TraceX Frontend Dev Server
>>"%HELPER%\frontend.cmd" echo cd /d "%~dp0frontend"
>>"%HELPER%\frontend.cmd" echo "%NPMCMD%" run dev

> "%HELPER%\proxy.cmd" echo @echo off
>>"%HELPER%\proxy.cmd" echo title TraceX Reverse Proxy
>>"%HELPER%\proxy.cmd" echo cd /d "%~dp0"
>>"%HELPER%\proxy.cmd" echo "%PYEXE%" %PYARGS% run_proxy.py

echo [*] Starting TraceX Backend on http://127.0.0.1:8000 ...
start "TraceX Backend" cmd /k "%HELPER%\backend.cmd"

echo [*] Starting TraceX Frontend on http://localhost:5173 ...
start "TraceX Frontend" cmd /k "%HELPER%\frontend.cmd"

echo [*] Starting Web Preview Reverse Proxy on http://127.0.0.1:9000 ...
start "TraceX Reverse Proxy" cmd /k "%HELPER%\proxy.cmd"

echo.
echo ==============================================================================
echo  TraceX Workbench active.
echo  UI (Dev Server) : http://localhost:5173
echo  Backend API     : http://127.0.0.1:8000
echo  Web Preview URL : http://127.0.0.1:9000/http://127.0.0.1:8000/
echo ==============================================================================
echo  (To stop all services cleanly, run stop_workbench.bat or close windows.)
echo.
pause
