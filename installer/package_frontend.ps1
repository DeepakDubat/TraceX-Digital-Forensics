<#
.SYNOPSIS
    Builds the production React/TypeScript/Vite frontend bundle.
#>
[CmdletBinding()]
param()

$ErrorActionPreference = "Stop"
$ScriptDir = $PSScriptRoot
$ProjectRoot = Split-Path $ScriptDir -Parent
$FrontendDir = Join-Path $ProjectRoot "frontend"
$DistDir = Join-Path $FrontendDir "dist"

Write-Host "======================================================================" -ForegroundColor Cyan
Write-Host "             BUILDING PRODUCTION FRONTEND ASSETS" -ForegroundColor Cyan
Write-Host "======================================================================" -ForegroundColor Cyan

if (-not (Test-Path (Join-Path $FrontendDir "package.json"))) {
    Write-Error "Frontend package.json not found at $FrontendDir"
    exit 1
}

# Resolve npm.cmd
$npmCmd = "npm.cmd"
if (-not (Get-Command $npmCmd -ErrorAction SilentlyContinue)) {
    $fallbackNpm = "$env:ProgramFiles\nodejs\npm.cmd"
    if (Test-Path $fallbackNpm) {
        $npmCmd = $fallbackNpm
    } else {
        Write-Error "npm.cmd was not found on PATH or in standard Node.js installation directory."
        exit 1
    }
}

Write-Host "[*] Frontend directory : $FrontendDir" -ForegroundColor Gray
Write-Host "[*] Executing build command: $npmCmd run build ..." -ForegroundColor Gray

Push-Location $FrontendDir
try {
    & $npmCmd run build
    if ($LASTEXITCODE -ne 0) {
        throw "Frontend compilation failed with exit code $LASTEXITCODE"
    }
} finally {
    Pop-Location
}

$IndexHtml = Join-Path $DistDir "index.html"
if (-not (Test-Path $IndexHtml)) {
    Write-Error "Frontend build verification failed: index.html was not generated in $DistDir"
    exit 1
}

$AssetFiles = Get-ChildItem -Path (Join-Path $DistDir "assets") -File -ErrorAction SilentlyContinue
$TotalBytes = ($AssetFiles | Measure-Object -Property Length -Sum).Sum

Write-Host "[+] Frontend build verified successfully!" -ForegroundColor Green
Write-Host "    Output directory : $DistDir" -ForegroundColor Gray
Write-Host "    Assets generated : $($AssetFiles.Count) files ($([math]::Round($TotalBytes/1KB, 1)) KB)" -ForegroundColor Gray
