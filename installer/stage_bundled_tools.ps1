<#
.SYNOPSIS
    Stages all redistributable local forensic tools into the target directory.
    Ensures identical tool bundling for both TraceX-Setup.exe and TraceX-Portable.zip.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)]
    [string]$TargetToolsDir
)

$ErrorActionPreference = "Stop"
$ScriptDir = $PSScriptRoot
$ProjectRoot = Split-Path $ScriptDir -Parent

Write-Host "======================================================================" -ForegroundColor Cyan
Write-Host "         STAGING REDISTRIBUTABLE FORENSIC TOOLS FOR TRACEX" -ForegroundColor Cyan
Write-Host "======================================================================" -ForegroundColor Cyan
Write-Host "[*] Target Directory: $TargetToolsDir" -ForegroundColor Gray

# Ensure target directories exist
$subdirs = @(
    "java",
    "jadx",
    "apktool",
    "tesseract",
    "tesseract\tessdata",
    "exiftool",
    "yara",
    "yara\rules",
    "other"
)
foreach ($sd in $subdirs) {
    New-Item -ItemType Directory -Force -Path (Join-Path $TargetToolsDir $sd) | Out-Null
}

# 1. OpenJDK 21 Minimal Runtime (via jlink)
$javaTarget = Join-Path $TargetToolsDir "java"
$jlinkExe = "C:\Program Files\Java\jdk-21.0.10\bin\jlink.exe"
$javaExeTarget = Join-Path $javaTarget "bin\java.exe"

if (-not (Test-Path $javaExeTarget)) {
    if (Test-Path $jlinkExe) {
        Write-Host "[*] Generating minimal OpenJDK 21 runtime via jlink..." -ForegroundColor Yellow
        if (Test-Path $javaTarget) {
            Remove-Item -Recurse -Force $javaTarget -ErrorAction SilentlyContinue
        }
        & $jlinkExe --add-modules java.base,java.desktop,java.logging,java.management,java.naming,java.net.http,java.security.jgss,java.sql,java.xml,jdk.unsupported,jdk.crypto.ec --strip-debug --no-man-pages --no-header-files --compress 2 --output $javaTarget
    } elseif (Test-Path "C:\Program Files\Java\jdk-21.0.10") {
        Write-Host "[*] Copying OpenJDK 21 runtime..." -ForegroundColor Yellow
        Copy-Item "C:\Program Files\Java\jdk-21.0.10\*" -Destination $javaTarget -Recurse -Force
    }
}
if (Test-Path $javaExeTarget) {
    Write-Host "[+] OpenJDK 21 Runtime verified at $javaExeTarget" -ForegroundColor Green
} else {
    Write-Warning "[-] OpenJDK 21 runtime generation failed or JDK missing."
}

# 2. JADX Decompiler CLI & GUI
$jadxTarget = Join-Path $TargetToolsDir "jadx"
if (Test-Path "C:\Tools\jadx") {
    Write-Host "[*] Copying JADX v1.5.6 (CLI & GUI)..." -ForegroundColor Yellow
    Copy-Item "C:\Tools\jadx\*" -Destination $jadxTarget -Recurse -Force
    Write-Host "[+] JADX staged successfully." -ForegroundColor Green
} else {
    Write-Warning "[-] JADX not found at C:\Tools\jadx"
}

# 3. Apktool
$apktoolTarget = Join-Path $TargetToolsDir "apktool"
if (Test-Path "C:\Tools\apktool") {
    Write-Host "[*] Copying Apktool v3.0.3..." -ForegroundColor Yellow
    Copy-Item "C:\Tools\apktool\*" -Destination $apktoolTarget -Recurse -Force
    Write-Host "[+] Apktool staged successfully." -ForegroundColor Green
} else {
    Write-Warning "[-] Apktool not found at C:\Tools\apktool"
}

# 4. Tesseract OCR Engine & Language Data
$tessTarget = Join-Path $TargetToolsDir "tesseract"
if (Test-Path "C:\Program Files\Tesseract-OCR") {
    Write-Host "[*] Copying Tesseract OCR v5.4.0 & tessdata..." -ForegroundColor Yellow
    Copy-Item "C:\Program Files\Tesseract-OCR\*.dll" -Destination $tessTarget -Force
    Copy-Item "C:\Program Files\Tesseract-OCR\tesseract.exe" -Destination $tessTarget -Force
    Copy-Item "C:\Program Files\Tesseract-OCR\tessdata\eng.traineddata" -Destination (Join-Path $tessTarget "tessdata") -Force
    if (Test-Path "C:\Program Files\Tesseract-OCR\tessdata\osd.traineddata") {
        Copy-Item "C:\Program Files\Tesseract-OCR\tessdata\osd.traineddata" -Destination (Join-Path $tessTarget "tessdata") -Force
    }
    Write-Host "[+] Tesseract OCR staged successfully." -ForegroundColor Green
} else {
    Write-Warning "[-] Tesseract-OCR not found at C:\Program Files\Tesseract-OCR"
}

# 5. ExifTool Metadata Extractor
$exifTarget = Join-Path $TargetToolsDir "exiftool"
if (Test-Path "C:\Tools\ExifTool") {
    Write-Host "[*] Copying ExifTool v13.64 (standalone executable + perl library)..." -ForegroundColor Yellow
    Copy-Item "C:\Tools\ExifTool\exiftool.exe" -Destination $exifTarget -Force
    if (Test-Path "C:\Tools\ExifTool\exiftool_files") {
        $exifFilesDest = Join-Path $exifTarget "exiftool_files"
        New-Item -ItemType Directory -Force -Path $exifFilesDest | Out-Null
        # Exclude uninstaller files to save space
        Get-ChildItem -Path "C:\Tools\ExifTool\exiftool_files" | Where-Object { $_.Name -notlike "unins000.*" } | Copy-Item -Destination $exifFilesDest -Recurse -Force
    }
    Write-Host "[+] ExifTool staged successfully." -ForegroundColor Green
} else {
    Write-Warning "[-] ExifTool not found at C:\Tools\ExifTool"
}

# 6. YARA Detection Rules
$yaraRulesSource = Join-Path $ProjectRoot "rules\yara_rules.yar"
$yaraTarget = Join-Path $TargetToolsDir "yara\rules\yara_rules.yar"
if (Test-Path $yaraRulesSource) {
    Write-Host "[*] Copying curated YARA rulesets..." -ForegroundColor Yellow
    Copy-Item $yaraRulesSource -Destination $yaraTarget -Force
    Write-Host "[+] YARA rules staged successfully." -ForegroundColor Green
}

# 7. TShark Standalone Offline PCAP Dissector
$tsharkTarget = Join-Path $TargetToolsDir "tshark"
$wsDir = "C:\Program Files\Wireshark"
if (Test-Path (Join-Path $wsDir "tshark.exe")) {
    Write-Host "[*] Copying TShark v4.6.9 standalone offline dissector and required DLLs..." -ForegroundColor Yellow
    New-Item -ItemType Directory -Force -Path $tsharkTarget | Out-Null
    Copy-Item (Join-Path $wsDir "tshark.exe") -Destination $tsharkTarget -Force
    # Copy required non-GUI DLLs
    Get-ChildItem -Path $wsDir -Filter "*.dll" | Where-Object {
        $_.Name -notlike "Qt6*" -and $_.Name -notlike "opengl*" -and $_.Name -notlike "dx*" -and $_.Name -notlike "d3d*" -and $_.Name -notlike "WinSparkle*"
    } | Copy-Item -Destination $tsharkTarget -Force
    # Copy essential protocol and config directories
    $protoFolders = @("profiles", "diameter", "dtds", "radius", "snmp", "tpncp", "wimaxasncp")
    foreach ($pf in $protoFolders) {
        $pfPath = Join-Path $wsDir $pf
        if (Test-Path $pfPath) {
            Copy-Item $pfPath -Destination (Join-Path $tsharkTarget $pf) -Recurse -Force
        }
    }
    Write-Host "[+] TShark staged successfully for offline PCAP dissection." -ForegroundColor Green
} else {
    Write-Warning "[-] Wireshark / TShark not found at $wsDir"
}

# 8. Suricata Standalone Offline Engine
$suricataTarget = Join-Path $TargetToolsDir "suricata"
$suriDir = "C:\Program Files\Suricata"
if (Test-Path (Join-Path $suriDir "suricata.exe")) {
    Write-Host "[*] Copying Suricata v8.0.8 standalone offline engine..." -ForegroundColor Yellow
    New-Item -ItemType Directory -Force -Path $suricataTarget | Out-Null
    Get-ChildItem -Path $suriDir -File | Copy-Item -Destination $suricataTarget -Force
    if (Test-Path (Join-Path $suriDir "rules")) {
        Copy-Item (Join-Path $suriDir "rules") -Destination (Join-Path $suricataTarget "rules") -Recurse -Force
    }
    Write-Host "[+] Suricata staged successfully for offline analysis." -ForegroundColor Green
} else {
    Write-Warning "[-] Suricata not found at $suriDir"
}

Write-Host "======================================================================" -ForegroundColor Cyan
Write-Host "[+] Tool staging complete in $TargetToolsDir" -ForegroundColor Green
Write-Host "======================================================================" -ForegroundColor Cyan
