<#
.SYNOPSIS
    Creates the standalone, privacy-preserving TraceX Portable Edition (TraceX-Portable.zip)
    Universal Digital Forensics & Cyber Investigation Suite v2.0.0
#>
[CmdletBinding()]
param(
    [string]$DistPath
)

$ErrorActionPreference = "Stop"
$ScriptDir = $PSScriptRoot
$ProjectRoot = Split-Path $ScriptDir -Parent
$BuildDir = Join-Path $ProjectRoot "dist\TraceX"
$DistDir = if ($DistPath) { $DistPath } else { Join-Path $ProjectRoot "dist" }
$StagingDir = Join-Path $ProjectRoot "build\portable_staging"
$PortableZip = Join-Path $DistDir "TraceX-Portable.zip"

Write-Host "======================================================================" -ForegroundColor Cyan
Write-Host "      CREATING CLEAN STANDALONE TRACEX PORTABLE EDITION (v2.0.0)      " -ForegroundColor Cyan
Write-Host "======================================================================" -ForegroundColor Cyan

if (-not (Test-Path (Join-Path $BuildDir "TraceX.exe"))) {
    Write-Host "[*] Packaged application missing. Invoking package_backend.ps1 ..." -ForegroundColor Yellow
    & (Join-Path $ScriptDir "package_backend.ps1")
}

New-Item -ItemType Directory -Force -Path $DistDir | Out-Null
if (Test-Path $StagingDir) {
    Remove-Item $StagingDir -Recurse -Force -ErrorAction SilentlyContinue
}

$PortableAppDir = Join-Path $StagingDir "TraceX-Portable"
New-Item -ItemType Directory -Force -Path $PortableAppDir | Out-Null

Write-Host "[*] Staging core application binaries (allowlist only)..." -ForegroundColor Gray
Copy-Item -Path (Join-Path $BuildDir "TraceX.exe") -Destination $PortableAppDir -Force
Copy-Item -Path (Join-Path $BuildDir "TraceX-Backend.exe") -Destination $PortableAppDir -Force
Copy-Item -Path (Join-Path $BuildDir "_internal") -Destination $PortableAppDir -Recurse -Force

# Create .portable marker file
$MarkerFile = Join-Path $PortableAppDir ".portable"
New-Item -ItemType File -Force -Path $MarkerFile | Out-Null

# Initialize clean UserData structure (Zero developer data, completely empty)
Write-Host "[*] Initializing isolated UserData directory hierarchy..." -ForegroundColor Gray
$UserDataHierarchy = @(
    "UserData",
    "UserData\database",
    "UserData\evidence",
    "UserData\reports",
    "UserData\logs",
    "UserData\cache",
    "UserData\credentials",
    "UserData\settings"
)
foreach ($dir in $UserDataHierarchy) {
    $targetDir = Join-Path $PortableAppDir $dir
    New-Item -ItemType Directory -Force -Path $targetDir | Out-Null
    # Place empty .gitkeep marker
    Set-Content -Path (Join-Path $targetDir ".gitkeep") -Value "" -Encoding ASCII
}

# Create tools directory structure
Write-Host "[*] Bundling redistributable local forensic tools (Phase 4)..." -ForegroundColor Gray
$ToolDirs = @(
    "tools",
    "runtimes",
    "licenses",
    "docs",
    "manifests"
)
foreach ($td in $ToolDirs) {
    New-Item -ItemType Directory -Force -Path (Join-Path $PortableAppDir $td) | Out-Null
}

# Copy staged tools from $BuildDir\tools (or stage them if missing)
$distToolsDir = Join-Path $BuildDir "tools"
if (-not (Test-Path (Join-Path $distToolsDir "java\bin\java.exe")) -or -not (Test-Path (Join-Path $distToolsDir "exiftool\exiftool.exe")) -or -not (Test-Path (Join-Path $distToolsDir "tshark\tshark.exe")) -or -not (Test-Path (Join-Path $distToolsDir "suricata\suricata.exe"))) {
    Write-Host "    -> Staging redistributable forensic tools..." -ForegroundColor Gray
    & powershell -ExecutionPolicy Bypass -File (Join-Path $ScriptDir "stage_bundled_tools.ps1") -TargetToolsDir $distToolsDir
}

Write-Host "    -> Copying bundled tools into portable distribution..." -ForegroundColor Gray
Copy-Item (Join-Path $distToolsDir "*") -Destination (Join-Path $PortableAppDir "tools") -Recurse -Force

# Write tool manifest
$ManifestContent = @"
{
  "edition": "TraceX Portable Edition",
  "version": "2.0.0",
  "platform": "windows-x64",
  "tools": [
    {
      "name": "OpenJDK Runtime",
      "version": "21.0.10 LTS",
      "license": "GPLv2 with Classpath Exception",
      "relative_path": "tools/java/bin/java.exe",
      "bundled": true,
      "purpose": "Execution runtime for JADX and Apktool"
    },
    {
      "name": "JADX Decompiler CLI",
      "version": "1.5.6",
      "license": "Apache License 2.0",
      "relative_path": "tools/jadx/bin/jadx.bat",
      "bundled": true,
      "purpose": "Automated headless DEX to Java decompilation"
    },
    {
      "name": "JADX GUI",
      "version": "1.5.6",
      "license": "Apache License 2.0",
      "relative_path": "tools/jadx/bin/jadx-gui.bat",
      "bundled": true,
      "purpose": "Interactive visual Java and Smali source code browser"
    },
    {
      "name": "Apktool",
      "version": "3.0.3",
      "license": "Apache License 2.0",
      "relative_path": "tools/apktool/apktool.bat",
      "bundled": true,
      "purpose": "APK resource, layout, and Smali bytecode disassembler"
    },
    {
      "name": "Tesseract OCR",
      "version": "5.4.0",
      "license": "Apache License 2.0",
      "relative_path": "tools/tesseract/tesseract.exe",
      "bundled": true,
      "purpose": "Optical character recognition and embedded image text extraction"
    },
    {
      "name": "Androguard",
      "version": "4.1.2",
      "license": "Apache License 2.0",
      "relative_path": "TraceX-Backend.exe (_internal/androguard)",
      "bundled": true,
      "purpose": "APK manifest analysis, permissions, certificate validation"
    },
    {
      "name": "YARA Engine & Rules",
      "version": "4.5.1",
      "license": "BSD 3-Clause",
      "relative_path": "tools/yara/rules/yara_rules.yar",
      "bundled": true,
      "purpose": "Malware signature identification and threat pattern classification"
    },
    {
      "name": "ExifTool Metadata Extractor",
      "version": "13.64",
      "license": "Perl Artistic License / GNU GPL",
      "relative_path": "tools/exiftool/exiftool.exe",
      "bundled": true,
      "purpose": "Comprehensive image, audio, video, PDF, and document metadata extraction"
    },
    {
      "name": "TShark Standalone Dissector",
      "version": "4.6.9",
      "license": "GNU General Public License v2",
      "relative_path": "tools/tshark/tshark.exe",
      "bundled": true,
      "purpose": "Offline command-line packet capture and network protocol dissection"
    },
    {
      "name": "Suricata Offline Engine",
      "version": "8.0.8",
      "license": "GNU General Public License v2",
      "relative_path": "tools/suricata/suricata.exe",
      "bundled": true,
      "purpose": "Offline network intrusion detection, threat signatures, and protocol inspection"
    },
    {
      "name": "Strings Forensic Utilities",
      "version": "2.0 Built-in",
      "license": "TraceX License",
      "relative_path": "TraceX-Backend.exe (string_analyzer)",
      "bundled": true,
      "purpose": "High-throughput pure-Python regex string extraction and classification"
    }
  ]
}
"@
Set-Content -Path (Join-Path $PortableAppDir "manifests\tool_manifest.json") -Value $ManifestContent -Encoding UTF8

# Populate Licenses
Write-Host "[*] Writing license compliance documents..." -ForegroundColor Gray
$LicenseDir = Join-Path $PortableAppDir "licenses"

Set-Content -Path (Join-Path $LicenseDir "LICENSE_TRACEX.txt") -Value @"
TraceX - Digital Forensics & Cyber Investigation Suite v2.0.0
Copyright (c) 2026 TraceX Security. All rights reserved.

Redistribution and use in binary and source forms, with or without modification,
are permitted provided that the copyright notice and this permission notice
appear in all copies.
"@ -Encoding UTF8

Set-Content -Path (Join-Path $LicenseDir "LICENSE_JADX.txt") -Value @"
JADX - Dex to Java decompiler
Copyright 2018 by Skylot
Licensed under the Apache License, Version 2.0.
http://www.apache.org/licenses/LICENSE-2.0
"@ -Encoding UTF8

Set-Content -Path (Join-Path $LicenseDir "LICENSE_APKTOOL.txt") -Value @"
Apktool - A tool for reverse engineering Android apk files
Copyright 2010 Ryszard Wisniewski <brut.alll@gmail.com>
Copyright 2014 Connor Tumbleson <connor.tumbleson@gmail.com>
Licensed under the Apache License, Version 2.0.
"@ -Encoding UTF8

Set-Content -Path (Join-Path $LicenseDir "LICENSE_TESSERACT.txt") -Value @"
Tesseract OCR Engine
Copyright (C) 2018 Google LLC
Licensed under the Apache License, Version 2.0.
"@ -Encoding UTF8

Set-Content -Path (Join-Path $LicenseDir "LICENSE_EXIFTOOL.txt") -Value @"
ExifTool by Phil Harvey
Copyright (c) 2003-2026, Phil Harvey
Licensed under the Perl Artistic License / GNU General Public License (GPL).
https://exiftool.org/
"@ -Encoding UTF8

Set-Content -Path (Join-Path $LicenseDir "LICENSE_WIRESHARK.txt") -Value @"
Wireshark / TShark Network Protocol Analyzer
Copyright (C) 1998-2026 Gerald Combs and contributors.
Licensed under the GNU General Public License Version 2 or later.
https://www.wireshark.org/
"@ -Encoding UTF8

Set-Content -Path (Join-Path $LicenseDir "LICENSE_SURICATA.txt") -Value @"
Suricata IDS / IPS Engine
Copyright (c) 2009-2026 Open Information Security Foundation (OISF).
Licensed under the GNU General Public License Version 2.
https://suricata.io/
"@ -Encoding UTF8

Set-Content -Path (Join-Path $LicenseDir "LICENSE_OPENJDK.txt") -Value @"
The GNU General Public License (GPL) Version 2, June 1991
with the "Classpath" Exception
Copyright (c) 1997, 2026, Oracle and/or its affiliates. All rights reserved.
"@ -Encoding UTF8

Set-Content -Path (Join-Path $LicenseDir "LICENSE_YARA.txt") -Value @"
YARA - The pattern matching swiss knife for malware researchers
Copyright (c) 2007-2026. The YARA Authors. All Rights Reserved.
Licensed under the BSD 3-Clause License.
"@ -Encoding UTF8

Set-Content -Path (Join-Path $LicenseDir "THIRD_PARTY_NOTICES.txt") -Value @"
================================================================================
THIRD-PARTY SOFTWARE NOTICES AND INFORMATION
TraceX Portable Edition v2.0.0
================================================================================
This distribution bundles open-source and redistributable software:
1. OpenJDK 21 (GPLv2 + Classpath Exception) - https://openjdk.org/
2. JADX CLI & GUI (Apache 2.0) - https://github.com/skylot/jadx
3. Apktool (Apache 2.0) - https://apktool.org/
4. Tesseract OCR (Apache 2.0) - https://github.com/tesseract-ocr/tesseract
5. ExifTool (Perl Artistic / GPL) - https://exiftool.org/
6. TShark (GNU GPLv2+) - https://www.wireshark.org/
7. Suricata (GNU GPLv2) - https://suricata.io/
8. YARA (BSD 3-Clause) - https://github.com/VirusTotal/yara
9. Androguard (Apache 2.0) - https://github.com/androguard/androguard
10. Microsoft Edge WebView2 Runtime (Microsoft End User License)
All third-party trademarks and copyrights belong to their respective owners.
"@ -Encoding UTF8

# Populate Offline Documentation
$DocsDir = Join-Path $PortableAppDir "docs"
$UserGuideContent = @"
# TraceX Portable Edition — Offline Forensic User Guide
Version 2.0.0 · Standalone Windows 10/11 x64

## 1. Quick Start
1. Double-click **TraceX.exe**.
2. TraceX starts the headless backend silently on a secure local loopback port and opens the desktop workspace.
3. No console window or terminal is displayed. Zero administrator privileges are required.

## 2. Complete Data Isolation Guarantee
- All application data is stored in the local **UserData/** folder:
  - `UserData/database/tracex_portable.db` - Encrypted/tamper-evident forensic ledger.
  - `UserData/evidence/` - Secure evidentiary storage.
  - `UserData/reports/` - Exported PDF, HTML, JSON, and CSV reports.
  - `UserData/credentials/` - Local Windows DPAPI-protected master keys.
- **Zero Host Residency:** No files, configuration profiles, or registry keys are written to the host computer.
- **Zero Shared Developer Data:** No historical cases or developer API keys are present.

## 3. Bundled Local Forensic Tools
TraceX Portable contains pre-configured, offline static analysis tools:
- **JADX CLI & GUI:** Java source decompilation (Java runtime pre-configured).
- **Apktool:** Android manifest, resource, and Smali disassembly.
- **Tesseract OCR:** Visual text extraction from APK icons and screenshots.
- **YARA Engine:** Curated threat hunting rules.
- **Androguard:** Core manifest parsing and permission analysis.
- **Strings Forensic Utility:** Built-in regex extraction for URLs, C2, and secrets.

## 4. Pure Static Forensic Architecture & Privacy
- **100% Static Forensics:** Never executes untrusted binaries or active malware.
- **Air-Gapped & Self-Contained:** Zero AI dependencies, zero mandatory external cloud connections.
- **Centralized Redaction:** Defensively sanitizes sensitive tokens, passwords, and file paths across all reports and exports.
"@
Set-Content -Path (Join-Path $DocsDir "USER_GUIDE.md") -Value $UserGuideContent -Encoding UTF8

$ReadmeContent = @"
================================================================================
           TRACEX – DIGITAL FORENSICS & CYBER INVESTIGATION SUITE
                              PORTABLE EDITION
================================================================================

Version: 2.0.0
Architecture: Windows 10/11 x64
Release Mode: Standalone Portable (Zero Installation Required)
Tagline: Discover. Analyze. Investigate.

QUICK START:
  1. Extract "TraceX-Portable.zip" to any directory or external drive.
  2. Double-click "TraceX.exe" (the only executable you need to launch).
  3. TraceX automatically manages the backend forensics engine in the background.
  4. No console windows or terminals are displayed. Zero administrator rights needed.
  5. All bundled forensic tools (JADX, Apktool, OpenJDK 21, Tesseract OCR, YARA)
     are detected and configured automatically.

DATA ISOLATION & ZERO-TRACE RESIDENCY:
  All investigator state is contained in .\UserData\:
    .\UserData\database\     - Fresh empty SQLite forensic database
    .\UserData\evidence\     - Ingested evidence files
    .\UserData\reports\      - Exported forensic intelligence reports
    .\UserData\logs\         - Local execution logs
    .\UserData\credentials\  - User-specific DPAPI master keys
    .\UserData\settings\     - Local user settings

SECURITY & INTEGRITY:
  - 100% Static Forensics: Zero live detonation or execution of untrusted binaries.
  - Single Executable: TraceX.exe manages all processes with zero command windows.
  - Ephemeral 256-bit loopback bridge token (X-TraceX-Bridge-Token).
  - DPAPI master key wrapping bound to active Windows user.
  - SHA-256 tamper-evident Chain of Custody ledger.
  - Fully air-gapped, zero cloud dependencies.
================================================================================
"@
Set-Content -Path (Join-Path $PortableAppDir "README_PORTABLE.txt") -Value $ReadmeContent -Encoding UTF8

# Remove previous zip if present
if (Test-Path $PortableZip) {
    Remove-Item $PortableZip -Force -ErrorAction SilentlyContinue
}

Write-Host "[*] Compressing archive to $PortableZip ..." -ForegroundColor Gray
Compress-Archive -Path "$PortableAppDir\*" -DestinationPath $PortableZip -CompressionLevel Optimal

if (-not (Test-Path $PortableZip)) {
    Write-Error "Portable packaging failed: $PortableZip was not created."
    exit 1
}

$ZipSize = (Get-Item $PortableZip).Length
$ZipHash = (Get-FileHash -Path $PortableZip -Algorithm SHA256).Hash

Write-Host "`n[+] Portable package created successfully!" -ForegroundColor Green
Write-Host "    Artifact : $PortableZip" -ForegroundColor Gray
Write-Host "    Size     : $([math]::Round($ZipSize/1MB, 2)) MB" -ForegroundColor Gray
Write-Host "    SHA-256  : $ZipHash" -ForegroundColor Gray

# Phase 3: Run Automated Data Leakage Audit
Write-Host "`n[*] Executing automated data leakage inspection on portable zip (Phase 3)..." -ForegroundColor Cyan
& py -3.11 (Join-Path $ProjectRoot "scripts\audit_portable_leakage.py") $PortableZip
if ($LASTEXITCODE -ne 0) {
    Write-Error "CRITICAL: Portable data leakage audit FAILED! Review TRACEX_PORTABLE_DATA_LEAKAGE_AUDIT.md"
    exit 1
}

Write-Host "[+] Data leakage audit PASSED! Zero developer data detected." -ForegroundColor Green

# Cleanup staging
Remove-Item $StagingDir -Recurse -Force -ErrorAction SilentlyContinue
