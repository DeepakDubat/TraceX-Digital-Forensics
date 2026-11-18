<#
.SYNOPSIS
    Packages the TraceX Desktop Host and Backend into a standalone bundle using PyInstaller.
#>
[CmdletBinding()]
param()

$ErrorActionPreference = "Stop"
$ScriptDir = $PSScriptRoot
$ProjectRoot = Split-Path $ScriptDir -Parent
$SpecFile = Join-Path $ScriptDir "TraceX.spec"
$FrontendDist = Join-Path $ProjectRoot "frontend\dist"

Write-Host "======================================================================" -ForegroundColor Cyan
Write-Host "             PACKAGING TRACEX DESKTOP APPLICATION & RUNTIME" -ForegroundColor Cyan
Write-Host "======================================================================" -ForegroundColor Cyan

# Ensure frontend is built first
if (-not (Test-Path (Join-Path $FrontendDist "index.html"))) {
    Write-Host "[*] Frontend dist missing. Invoking package_frontend.ps1 ..." -ForegroundColor Yellow
    & (Join-Path $ScriptDir "package_frontend.ps1")
}

# Resolve Python 3.11
$pythonCmd = "py"
$pythonArgs = @("-3.11")
$testPy = & py -3.11 -c 'import sys; print(sys.version.split()[0])' 2>$null
if (-not $testPy) {
    $pythonCmd = "python"
    $pythonArgs = @()
    $testPy = & python -c 'import sys; print(sys.version.split()[0])' 2>$null
    if (-not $testPy) {
        Write-Error "Python 3.11 interpreter was not found. Please verify Python installation."
        exit 1
    }
}

Write-Host "[*] Active Python interpreter version: $testPy" -ForegroundColor Gray
Write-Host "[*] PyInstaller spec file: $SpecFile" -ForegroundColor Gray

# Clean previous build artifacts
$BuildOutputDir = Join-Path $ProjectRoot "dist\TraceX"
if (Test-Path $BuildOutputDir) {
    Write-Host "[*] Cleaning previous build directory: $BuildOutputDir ..." -ForegroundColor Gray
    Remove-Item $BuildOutputDir -Recurse -Force -ErrorAction SilentlyContinue
}

Push-Location $ProjectRoot
try {
    $cmdArgs = $pythonArgs + @("-m", "PyInstaller", "--noconfirm", "--distpath", (Join-Path $ProjectRoot "dist"), "--workpath", (Join-Path $ProjectRoot "build\work"), $SpecFile)
    Write-Host "[*] Running: $pythonCmd $($cmdArgs -join ' ') ..." -ForegroundColor Gray
    & $pythonCmd $cmdArgs
    if ($LASTEXITCODE -ne 0) {
        throw "PyInstaller compilation failed with exit code $LASTEXITCODE"
    }
} finally {
    Pop-Location
}

# Verification
$HostExe = Join-Path $BuildOutputDir "TraceX.exe"
$BackendExe = Join-Path $BuildOutputDir "TraceX-Backend.exe"
if (-not (Test-Path $HostExe)) {
    Write-Error "Packaging failed: TraceX.exe was not created in $BuildOutputDir"
    exit 1
}

$HostSize = (Get-Item $HostExe).Length
$AllFiles = Get-ChildItem -Path $BuildOutputDir -Recurse -File
$TotalSize = ($AllFiles | Measure-Object -Property Length -Sum).Sum

Write-Host "`n[+] Packaged TraceX verified successfully!" -ForegroundColor Green
Write-Host "    Host Executable   : $HostExe ($([math]::Round($HostSize/1MB, 2)) MB)" -ForegroundColor Gray
if (Test-Path $BackendExe) {
    $BackendSize = (Get-Item $BackendExe).Length
    Write-Host "    Backend Engine    : $BackendExe ($([math]::Round($BackendSize/1MB, 2)) MB)" -ForegroundColor Gray
}
Write-Host "    Total Bundle Size : $([math]::Round($TotalSize/1MB, 2)) MB ($($AllFiles.Count) files)" -ForegroundColor Gray
