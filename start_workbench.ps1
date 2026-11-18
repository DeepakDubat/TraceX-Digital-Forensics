# start_workbench.ps1 - PowerShell launcher for Forensics Workbench
$root = $PSScriptRoot
if (-not $root) { $root = (Get-Location).Path }

Write-Host "=============================================================================="
Write-Host "          APK FORENSICS & THREAT INTELLIGENCE WORKBENCH"
Write-Host "=============================================================================="
Write-Host "[+] Project root : $root"

# Locate Python 3.11 launcher
$pyExe = "py.exe"
if (Test-Path "$env:LOCALAPPDATA\Programs\Python\Launcher\py.exe") {
    $pyExe = "$env:LOCALAPPDATA\Programs\Python\Launcher\py.exe"
}

# Locate npm
$npmCmd = "npm.cmd"
if (Test-Path "$env:ProgramFiles\nodejs\npm.cmd") {
    $npmCmd = "$env:ProgramFiles\nodejs\npm.cmd"
}

Write-Host "[+] Python       : $pyExe -3.11"
Write-Host "[+] npm          : $npmCmd"
Write-Host ""

Write-Host "[*] Starting Backend Server on http://127.0.0.1:8000 ..."
Start-Process -FilePath $pyExe -ArgumentList "-3.11", "run_backend.py" -WorkingDirectory $root

Write-Host "[*] Starting Web Preview Reverse Proxy on http://127.0.0.1:9000 ..."
Start-Process -FilePath $pyExe -ArgumentList "-3.11", "run_proxy.py" -WorkingDirectory $root

Write-Host "[*] Starting Vite Frontend on http://localhost:5173 ..."
Start-Process -FilePath $npmCmd -ArgumentList "run", "dev" -WorkingDirectory "$root\frontend"

Write-Host ""
Write-Host "=============================================================================="
Write-Host "  Workbench launched successfully."
Write-Host "  UI (Dev Server) : http://localhost:5173"
Write-Host "  Backend API     : http://127.0.0.1:8000"
Write-Host "  Web Preview URL : http://127.0.0.1:9000/http://127.0.0.1:8000/"
Write-Host "=============================================================================="
Write-Host "  (To stop all services cleanly, run .\stop_workbench.ps1)"
Write-Host ""

