<#
.SYNOPSIS
    Compiles the Inno Setup Windows Installer TraceX-Setup.exe
#>
[CmdletBinding()]
param()

$ErrorActionPreference = "Stop"
$ScriptDir = $PSScriptRoot
$ProjectRoot = Split-Path $ScriptDir -Parent
$BuildDir = Join-Path $ProjectRoot "dist\TraceX"
$DistDir = Join-Path $ProjectRoot "dist"
$IssScript = Join-Path $ScriptDir "TraceX.iss"
$SetupExe = Join-Path $DistDir "TraceX-Setup.exe"

Write-Host "======================================================================" -ForegroundColor Cyan
Write-Host "             COMPILING TRACEX INNO SETUP WINDOWS INSTALLER" -ForegroundColor Cyan
Write-Host "======================================================================" -ForegroundColor Cyan

# Locate Inno Setup Compiler (ISCC.exe)
$isccCandidates = @(
    (Get-Command iscc.exe -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Source),
    "$env:LOCALAPPDATA\Programs\Inno Setup 6\ISCC.exe",
    "$env:ProgramFiles\Inno Setup 6\ISCC.exe",
    "${env:ProgramFiles(x86)}\Inno Setup 6\ISCC.exe",
    "$env:LOCALAPPDATA\Programs\Inno Setup 7\ISCC.exe",
    "$env:ProgramFiles\Inno Setup 7\ISCC.exe",
    "${env:ProgramFiles(x86)}\Inno Setup 7\ISCC.exe"
)

$isccPath = $null
foreach ($cand in $isccCandidates) {
    if ($cand -and (Test-Path $cand)) {
        $isccPath = $cand
        break
    }
}

if (-not $isccPath) {
    Write-Error "Inno Setup Compiler (ISCC.exe) was not found. Please install Inno Setup 6 or 7 via 'winget install JRSoftware.InnoSetup' or download from https://jrsoftware.org/isinfo.php"
    exit 1
}

Write-Host "[*] Located Inno Setup Compiler : $isccPath" -ForegroundColor Gray

# Ensure backend package exists
if (-not (Test-Path (Join-Path $BuildDir "TraceX.exe"))) {
    Write-Host "[*] Packaged backend missing. Invoking package_backend.ps1 ..." -ForegroundColor Yellow
    & (Join-Path $ScriptDir "package_backend.ps1")
}

# Ensure bundled forensic tools exist in dist\TraceX\tools
$distToolsDir = Join-Path $BuildDir "tools"
if (-not (Test-Path (Join-Path $distToolsDir "java\bin\java.exe")) -or -not (Test-Path (Join-Path $distToolsDir "exiftool\exiftool.exe")) -or -not (Test-Path (Join-Path $distToolsDir "tshark\tshark.exe")) -or -not (Test-Path (Join-Path $distToolsDir "suricata\suricata.exe"))) {
    Write-Host "[*] Bundled forensic tools missing or incomplete in dist\TraceX\tools. Staging tools..." -ForegroundColor Yellow
    & powershell -ExecutionPolicy Bypass -File (Join-Path $ScriptDir "stage_bundled_tools.ps1") -TargetToolsDir $distToolsDir
}

New-Item -ItemType Directory -Force -Path $DistDir | Out-Null
if (Test-Path $SetupExe) {
    Remove-Item $SetupExe -Force -ErrorAction SilentlyContinue
}

Write-Host "[*] Compiling Inno Setup script: $IssScript ..." -ForegroundColor Gray
Push-Location $ScriptDir
try {
    & $isccPath /Qp $IssScript
    if ($LASTEXITCODE -ne 0) {
        throw "Inno Setup compilation failed with exit code $LASTEXITCODE"
    }
} finally {
    Pop-Location
}

# Verification
if (-not (Test-Path $SetupExe)) {
    Write-Error "Installer compilation failed: $SetupExe was not created."
    exit 1
}

$ExeSize = (Get-Item $SetupExe).Length
$ExeHash = (Get-FileHash -Path $SetupExe -Algorithm SHA256).Hash

Write-Host "`n[+] Windows Installer compiled successfully!" -ForegroundColor Green
Write-Host "    Artifact : $SetupExe" -ForegroundColor Gray
Write-Host "    Size     : $([math]::Round($ExeSize/1MB, 2)) MB" -ForegroundColor Gray
Write-Host "    SHA-256  : $ExeHash" -ForegroundColor Gray
