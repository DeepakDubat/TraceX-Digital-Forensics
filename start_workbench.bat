@echo off
title APK FORENSICS ^& THREAT INTELLIGENCE WORKBENCH
cd /d "%~dp0"

rem ------------------------------------------------------------------
rem  Locate the Python 3.11 launcher and the Node/npm toolchain without
rem  relying on the PATH (works even in a session started before install).
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
    echo     Install Python 3.11 for the current user, then run this again.
    pause
    exit /b 1
)

set "NPMCMD=npm.cmd"
if exist "%USERPROFILE%\Tools\node\npm.cmd" set "NPMCMD=%USERPROFILE%\Tools\node\npm.cmd"
if exist "%ProgramFiles%\nodejs\npm.cmd" if "%NPMCMD%"=="npm.cmd" set "NPMCMD=%ProgramFiles%\nodejs\npm.cmd"

rem --- lab toolchain on PATH for the child windows ---
set "PATH=%USERPROFILE%\Tools\node;%USERPROFILE%\Tools\jadx\bin;%USERPROFILE%\Tools\apktool;%USERPROFILE%\Tools\jre\bin;%PATH%"
set "JAVA_HOME=%USERPROFILE%\Tools\jre"

echo ==============================================================================
echo           APK FORENSICS ^& THREAT INTELLIGENCE WORKBENCH
echo ==============================================================================
echo [+] Project root : %CD%
echo [+] Python       : %PYEXE% %PYARGS%
echo [+] npm          : %NPMCMD%
echo.

rem ------------------------------------------------------------------
rem  Build tiny helper scripts so the "start" calls need no nested quoting.
rem ------------------------------------------------------------------
set "HELPER=%TEMP%\apk_workbench"
if not exist "%HELPER%" mkdir "%HELPER%" >nul 2>&1

> "%HELPER%\backend.cmd" echo @echo off
>>"%HELPER%\backend.cmd" echo title APK Forensics Backend
>>"%HELPER%\backend.cmd" echo cd /d "%~dp0"
>>"%HELPER%\backend.cmd" echo "%PYEXE%" %PYARGS% run_backend.py

> "%HELPER%\frontend.cmd" echo @echo off
>>"%HELPER%\frontend.cmd" echo title APK Forensics Frontend
>>"%HELPER%\frontend.cmd" echo cd /d "%~dp0frontend"
>>"%HELPER%\frontend.cmd" echo "%NPMCMD%" run dev

> "%HELPER%\proxy.cmd" echo @echo off
>>"%HELPER%\proxy.cmd" echo title APK Forensics Reverse Proxy
>>"%HELPER%\proxy.cmd" echo cd /d "%~dp0"
>>"%HELPER%\proxy.cmd" echo "%PYEXE%" %PYARGS% run_proxy.py

echo [*] Starting Backend Server on http://127.0.0.1:8000 ...
start "APK Forensics Backend" cmd /k "%HELPER%\backend.cmd"

echo [*] Starting Vite Frontend on http://localhost:5173 ...
start "APK Forensics Frontend" cmd /k "%HELPER%\frontend.cmd"

echo [*] Starting Web Preview Reverse Proxy on http://127.0.0.1:9000 ...
start "APK Forensics Reverse Proxy" cmd /k "%HELPER%\proxy.cmd"

echo.
echo ==============================================================================
echo  Workbench launched successfully.
echo  UI (Dev Server) : http://localhost:5173
echo  Backend API     : http://127.0.0.1:8000
echo  Web Preview URL : http://127.0.0.1:9000/http://127.0.0.1:8000/
echo ==============================================================================
echo  (To stop the workbench, run stop_workbench.bat or close the console windows.)
echo.
pause
