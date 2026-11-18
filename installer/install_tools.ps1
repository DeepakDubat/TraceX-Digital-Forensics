<#
.SYNOPSIS
    Universal Forensics Workbench - Optional External Tools Installation Wizard
.DESCRIPTION
    Safely downloads, cryptographically verifies (SHA-256), and configures optional
    decompilation and forensic analysis utilities (JADX, Apktool) into the per-user
    tools directory without requiring administrator privileges.
#>

[CmdletBinding()]
param(
    [ValidateSet("all", "jadx", "apktool", "status")]
    [string]$Tool = "all",

    [string]$TargetDir = "$env:LOCALAPPDATA\ForensicsWorkbench\tools",

    [switch]$NonInteractive,

    [switch]$Force
)

$ErrorActionPreference = "Stop"

$ManifestPath = Join-Path $PSScriptRoot "tool_manifest.json"
if (-not (Test-Path $ManifestPath)) {
    $ManifestPath = Join-Path (Split-Path $PSScriptRoot -Parent) "installer\tool_manifest.json"
}

if (-not (Test-Path $ManifestPath)) {
    Write-Error "Tool manifest not found at $ManifestPath"
    exit 1
}

$Manifest = Get-Content $ManifestPath -Raw | ConvertFrom-Json

function Test-JavaAvailable {
    $java = Get-Command java -ErrorAction SilentlyContinue
    if ($java) {
        try {
            $ver = & java -version 2>&1 | Out-String
            return @{ Available = $true; Version = $ver.Trim() }
        } catch {
            return @{ Available = $false; Version = $null }
        }
    }
    return @{ Available = $false; Version = $null }
}

function Show-ToolStatus {
    Write-Host "======================================================================" -ForegroundColor Cyan
    Write-Host "         OPTIONAL FORENSIC TOOLS INTEGRATION STATUS" -ForegroundColor Cyan
    Write-Host "======================================================================" -ForegroundColor Cyan
    
    $javaCheck = Test-JavaAvailable
    if ($javaCheck.Available) {
        Write-Host "[+] Java Runtime Environment : DETECTED" -ForegroundColor Green
    } else {
        Write-Host "[-] Java Runtime Environment : NOT FOUND (Required for JADX & Apktool)" -ForegroundColor Yellow
        Write-Host "    Download OpenJDK 17+: https://adoptium.net/" -ForegroundColor Gray
    }

    foreach ($t in $Manifest.tools) {
        Write-Host ""
        Write-Host "[$($t.classification)] $($t.name)" -ForegroundColor White
        Write-Host "    Version       : $(if ($t.pinned_version) { $t.pinned_version } else { $t.version })" -ForegroundColor Gray
        Write-Host "    License       : $($t.license)" -ForegroundColor Gray
        Write-Host "    Description   : $($t.description)" -ForegroundColor Gray
    }
    Write-Host "======================================================================" -ForegroundColor Cyan
}

function Install-JadxComponent {
    param([string]$Destination)
    $jadxMeta = $Manifest.tools | Where-Object { $_.id -eq "jadx" }
    $jadxDir = Join-Path $Destination "jadx"
    $jadxBat = Join-Path $jadxDir "bin\jadx.bat"

    Write-Host "`n[*] Inspecting JADX Decompiler component..." -ForegroundColor Cyan
    if ((Test-Path $jadxBat) -and -not $Force) {
        Write-Host "[+] JADX is already installed at $jadxBat" -ForegroundColor Green
        return $jadxBat
    }

    if (-not $NonInteractive) {
        $confirm = Read-Host "Download and install JADX $($jadxMeta.pinned_version) from official GitHub release? (Y/N)"
        if ($confirm -ne 'Y' -and $confirm -ne 'y') {
            Write-Host "[-] JADX installation skipped by user." -ForegroundColor Yellow
            return $null
        }
    }

    New-Item -ItemType Directory -Force -Path $jadxDir | Out-Null
    $zipTemp = Join-Path $env:TEMP "jadx-$($jadxMeta.pinned_version).zip"

    Write-Host "[*] Downloading $($jadxMeta.download_url) ..." -ForegroundColor Gray
    Invoke-WebRequest -Uri $jadxMeta.download_url -OutFile $zipTemp -UseBasicParsing

    Write-Host "[*] Verifying SHA-256 hash..." -ForegroundColor Gray
    $computedHash = (Get-FileHash -Path $zipTemp -Algorithm SHA256).Hash.ToLower()
    if ($computedHash -ne $jadxMeta.expected_sha256.ToLower()) {
        Remove-Item $zipTemp -Force -ErrorAction SilentlyContinue
        throw "Hash mismatch for JADX package! Expected: $($jadxMeta.expected_sha256) Got: $computedHash"
    }
    Write-Host "[+] Hash verified: $computedHash" -ForegroundColor Green

    Write-Host "[*] Extracting JADX archive..." -ForegroundColor Gray
    Expand-Archive -Path $zipTemp -DestinationPath $jadxDir -Force
    Remove-Item $zipTemp -Force -ErrorAction SilentlyContinue

    if (Test-Path $jadxBat) {
        Write-Host "[+] JADX installed successfully to $jadxBat" -ForegroundColor Green
        return $jadxBat
    } else {
        throw "JADX executable missing after extraction"
    }
}

function Install-ApktoolComponent {
    param([string]$Destination)
    $apktoolMeta = $Manifest.tools | Where-Object { $_.id -eq "apktool" }
    $apktoolDir = Join-Path $Destination "apktool"
    $apktoolBat = Join-Path $apktoolDir "apktool.bat"
    $apktoolJar = Join-Path $apktoolDir "apktool.jar"

    Write-Host "`n[*] Inspecting Apktool Resource Decoder component..." -ForegroundColor Cyan
    if ((Test-Path $apktoolBat) -and (Test-Path $apktoolJar) -and -not $Force) {
        Write-Host "[+] Apktool is already installed at $apktoolBat" -ForegroundColor Green
        return $apktoolBat
    }

    if (-not $NonInteractive) {
        $confirm = Read-Host "Download and install Apktool $($apktoolMeta.pinned_version)? (Y/N)"
        if ($confirm -ne 'Y' -and $confirm -ne 'y') {
            Write-Host "[-] Apktool installation skipped by user." -ForegroundColor Yellow
            return $null
        }
    }

    New-Item -ItemType Directory -Force -Path $apktoolDir | Out-Null
    $jarTemp = Join-Path $env:TEMP "apktool-$($apktoolMeta.pinned_version).jar"

    Write-Host "[*] Downloading $($apktoolMeta.download_url) ..." -ForegroundColor Gray
    Invoke-WebRequest -Uri $apktoolMeta.download_url -OutFile $jarTemp -UseBasicParsing

    Write-Host "[*] Verifying SHA-256 hash..." -ForegroundColor Gray
    $computedHash = (Get-FileHash -Path $jarTemp -Algorithm SHA256).Hash.ToLower()
    if ($computedHash -ne $apktoolMeta.expected_sha256.ToLower()) {
        Remove-Item $jarTemp -Force -ErrorAction SilentlyContinue
        throw "Hash mismatch for Apktool package! Expected: $($apktoolMeta.expected_sha256) Got: $computedHash"
    }
    Write-Host "[+] Hash verified: $computedHash" -ForegroundColor Green

    Copy-Item $jarTemp -Destination $apktoolJar -Force
    Remove-Item $jarTemp -Force -ErrorAction SilentlyContinue

    Write-Host "[*] Writing safe Windows apktool.bat wrapper..." -ForegroundColor Gray
    # The upstream wrapper ends with 'pause', which blocks headless subprocess
    # callers. Write an equivalent wrapper without any interactive pause.
    $wrapperContent = @'
@echo off
setlocal
set "JAVA_EXE=java.exe"
if defined JAVA_HOME set "JAVA_EXE=%JAVA_HOME%\bin\java.exe"
"%JAVA_EXE%" -jar -Xmx1024M -Duser.language=en -Dfile.encoding=UTF8 "%~dp0apktool.jar" %*
endlocal
'@
    Set-Content -Path $apktoolBat -Value $wrapperContent -Encoding ASCII

    if (Test-Path $apktoolBat) {
        Write-Host "[+] Apktool installed successfully to $apktoolBat" -ForegroundColor Green
        return $apktoolBat
    } else {
        throw "Apktool wrapper missing after installation"
    }
}

# Execution Dispatcher
if ($Tool -eq "status") {
    Show-ToolStatus
    exit 0
}

Show-ToolStatus

if ($Tool -eq "jadx" -or $Tool -eq "all") {
    try {
        Install-JadxComponent -Destination $TargetDir
    } catch {
        Write-Warning "JADX setup failed: $_"
    }
}

if ($Tool -eq "apktool" -or $Tool -eq "all") {
    try {
        Install-ApktoolComponent -Destination $TargetDir
    } catch {
        Write-Warning "Apktool setup failed: $_"
    }
}

Write-Host "`n[+] Tool installation routine completed." -ForegroundColor Green
