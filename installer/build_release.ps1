<#
.SYNOPSIS
    TraceX – Digital Forensics & Cyber Investigation Suite - Master Release Build Orchestrator
.DESCRIPTION
    Executes a reproducible, clean release build for Windows x64:
      1. Verifies build environment prerequisites.
      2. Executes backend automated test suite.
      3. Compiles production frontend assets.
      4. Compiles standalone PyInstaller desktop host & backend runtime (ONEDIR).
      5. Packages Inno Setup Windows Installer (TraceX-Setup.exe).
      6. Packages standalone portable zip archive (TraceX-Portable.zip).
      7. Calculates SHA-256 sums and generates release manifest.
#>

[CmdletBinding()]
param(
    [switch]$SkipTests,
    [switch]$SkipFrontend,
    [switch]$SkipBackend,
    [switch]$SkipInstaller,
    [switch]$SkipPortable
)

$ErrorActionPreference = 'Stop'
$StartTime = Get-Date

$ScriptDir = $PSScriptRoot
$ProjectRoot = Split-Path $ScriptDir -Parent
$DistDir = Join-Path $ProjectRoot 'dist'
$BuildDir = Join-Path $ProjectRoot 'build'

Write-Host '==============================================================================' -ForegroundColor Cyan
Write-Host '         TRACEX – DIGITAL FORENSICS & CYBER INVESTIGATION SUITE' -ForegroundColor Cyan
Write-Host '                         RELEASE BUILD PIPELINE' -ForegroundColor Cyan
Write-Host '==============================================================================' -ForegroundColor Cyan
Write-Host ('[*] Project Root   : ' + $ProjectRoot) -ForegroundColor Gray
Write-Host ('[*] Release Output : ' + $DistDir) -ForegroundColor Gray
Write-Host ('[*] Timestamp UTC  : ' + [DateTime]::UtcNow.ToString('yyyy-MM-dd HH:mm:ss')) -ForegroundColor Gray
Write-Host '==============================================================================' -ForegroundColor Cyan

# 1. PREREQUISITE VERIFICATION
Write-Host ''
Write-Host '[STAGE 1/7] Verifying Build Toolchain...' -ForegroundColor Yellow

# Check Python 3.11
$pyVer = & py -3.11 -c 'import sys; print(sys.version.split()[0])' 2>$null
if (-not $pyVer) {
    Write-Error 'Python 3.11 is required but was not found. Please install Python 3.11.'
    exit 1
}
Write-Host ('[+] Python Runtime: Python ' + $pyVer + ' (x64)') -ForegroundColor Green

# Check PyInstaller
$pyinstallerCheck = & py -3.11 -m PyInstaller --version 2>$null
if (-not $pyinstallerCheck) {
    Write-Error 'PyInstaller is not installed in Python 3.11 environment. Run: py -3.11 -m pip install pyinstaller'
    exit 1
}
Write-Host ('[+] PyInstaller: Version ' + $pyinstallerCheck) -ForegroundColor Green

# Check Node & npm
$nodeCmd = Get-Command node -ErrorAction SilentlyContinue
if (-not $nodeCmd) {
    Write-Error 'Node.js is not found on PATH.'
    exit 1
}
$nodeVer = & node -v
Write-Host ('[+] Node.js: ' + $nodeVer) -ForegroundColor Green

# Check Inno Setup
$isccCandidates = @(
    (Get-Command iscc.exe -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Source),
    "$env:LOCALAPPDATA\Programs\Inno Setup 6\ISCC.exe",
    "$env:ProgramFiles\Inno Setup 6\ISCC.exe",
    "${env:ProgramFiles(x86)}\Inno Setup 6\ISCC.exe",
    "$env:LOCALAPPDATA\Programs\Inno Setup 7\ISCC.exe",
    "$env:ProgramFiles\Inno Setup 7\ISCC.exe"
)
$isccFound = $false
foreach ($c in $isccCandidates) {
    if ($c -and (Test-Path $c)) {
        $isccFound = $true
        Write-Host ('[+] Inno Setup Compiler: ' + $c) -ForegroundColor Green
        break
    }
}
if (-not $isccFound -and -not $SkipInstaller) {
    Write-Error 'Inno Setup Compiler (ISCC.exe) was not found. Install via winget install JRSoftware.InnoSetup or pass -SkipInstaller.'
    exit 1
}

# 2. RUN TEST SUITE
Write-Host ''
Write-Host '[STAGE 2/7] Running Automated Verification Tests...' -ForegroundColor Yellow
if ($SkipTests) {
    Write-Host '[-] Skipping tests per -SkipTests flag.' -ForegroundColor DarkYellow
} else {
    Push-Location $ProjectRoot
    try {
        & py -3.11 -m pytest tests/ --ignore=_pre_rollback_backup -q
        if ($LASTEXITCODE -ne 0) {
            throw 'Automated test suite failed with exit code ' + $LASTEXITCODE
        }
    } finally {
        Pop-Location
    }
    Write-Host '[+] All backend tests passed successfully!' -ForegroundColor Green
}

# Ensure clean dist directory
New-Item -ItemType Directory -Force -Path $DistDir | Out-Null

# 3. BUILD FRONTEND
Write-Host ''
if (-not $SkipFrontend) {
    Write-Host '[STAGE 3/7] Building Production Frontend...' -ForegroundColor Yellow
    & (Join-Path $ScriptDir 'package_frontend.ps1')
    if ($LASTEXITCODE -ne 0) {
        throw 'Frontend packaging failed.'
    }
} else {
    Write-Host '[STAGE 3/7] Skipping frontend build per -SkipFrontend flag.' -ForegroundColor DarkYellow
}

# 4. PACKAGE STANDALONE BACKEND RUNTIME
Write-Host ''
if (-not $SkipBackend) {
    Write-Host '[STAGE 4/7] Packaging Standalone Python Backend...' -ForegroundColor Yellow
    & (Join-Path $ScriptDir 'package_backend.ps1')
    if ($LASTEXITCODE -ne 0) {
        throw 'Backend packaging failed.'
    }
} else {
    Write-Host '[STAGE 4/7] Skipping backend packaging per -SkipBackend flag.' -ForegroundColor DarkYellow
}

# 5. COMPILE INNO SETUP INSTALLER
if (-not $SkipInstaller) {
    Write-Host ''
    Write-Host '[STAGE 5/7] Compiling Windows Installer (Setup.exe)...' -ForegroundColor Yellow
    & (Join-Path $ScriptDir 'build_installer.ps1')
    if ($LASTEXITCODE -ne 0) {
        throw 'Installer compilation failed.'
    }
} else {
    Write-Host ''
    Write-Host '[STAGE 5/7] Skipping installer compilation per -SkipInstaller flag.' -ForegroundColor DarkYellow
}

# 6. PACKAGE PORTABLE EDITION
if (-not $SkipPortable) {
    Write-Host ''
    Write-Host '[STAGE 6/7] Packaging Standalone Portable Archive...' -ForegroundColor Yellow
    & (Join-Path $ScriptDir 'create_portable.ps1')
    if ($LASTEXITCODE -ne 0) {
        throw 'Portable archive creation failed.'
    }
} else {
    Write-Host ''
    Write-Host '[STAGE 6/7] Skipping portable archive per -SkipPortable flag.' -ForegroundColor DarkYellow
}

# 7. GENERATE RELEASE MANIFEST AND INTEGRITY DIGESTS
Write-Host ''
Write-Host '[STAGE 7/7] Generating Release Manifest and SHA-256 Digests...' -ForegroundColor Yellow

# Copy documentation to dist
$DocFiles = @('THIRD_PARTY_NOTICES.txt', 'INSTALLATION_GUIDE.md', 'KNOWN_LIMITATIONS.md', 'tool_manifest.json')
foreach ($doc in $DocFiles) {
    $src = Join-Path $ScriptDir $doc
    if (Test-Path $src) {
        Copy-Item $src -Destination (Join-Path $DistDir $doc) -Force
    }
}

# Compute SHA256 hashes of all artifacts in dist
$ShaFile = Join-Path $DistDir 'SHA256SUMS.txt'
$Artifacts = Get-ChildItem -Path $DistDir -File | Where-Object { $_.Name -ne 'SHA256SUMS.txt' -and $_.Name -ne 'release_manifest.json' }

$HashLines = @()
$ArtifactEntries = @()
foreach ($art in $Artifacts) {
    $hash = (Get-FileHash -Path $art.FullName -Algorithm SHA256).Hash
    $line = $hash + '  ' + $art.Name
    $HashLines += $line
    $ArtifactEntries += [PSCustomObject]@{
        filename = $art.Name
        size_bytes = $art.Length
        size_mb = [math]::Round($art.Length / 1MB, 2)
        sha256 = $hash
    }
}
$nl = [Environment]::NewLine
[System.IO.File]::WriteAllText($ShaFile, ($HashLines -join $nl), [System.Text.Encoding]::UTF8)
Write-Host '[+] Generated SHA256SUMS.txt' -ForegroundColor Green

# Query installed library versions for manifest
$libVersions = @{}
$pipJson = & py -3.11 -m pip list --format=json
$pipOutput = $pipJson | ConvertFrom-Json
foreach ($pkg in $pipOutput) {
    if ($pkg.name -in @('fastapi', 'uvicorn', 'androguard', 'yara-python', 'pefile', 'pypdf', 'pillow', 'python-docx', 'openpyxl', 'cryptography', 'pydantic')) {
        $libVersions[$pkg.name] = $pkg.version
    }
}

# Write release_manifest.json
$ManifestObj = [PSCustomObject]@{
    release_name = 'TraceX – Digital Forensics & Cyber Investigation Suite'
    app_id = 'TraceX'
    tagline = 'Discover. Analyze. Investigate.'
    version = '2.0.0'
    build_timestamp_utc = [DateTime]::UtcNow.ToString('o')
    platform = 'Windows 10/11 x64'
    architecture = 'x64'
    signing_status = 'Unsigned (Community Open-Source Release - Verify via SHA-256)'
    python_runtime = [PSCustomObject]@{
        version = $pyVer
        implementation = 'CPython'
        packaging_tool = 'PyInstaller (ONEDIR)'
    }
    frontend = [PSCustomObject]@{
        framework = 'React 19 + TypeScript + Vite 8 + Tailwind CSS'
        status = 'Pre-compiled production bundle embedded in application'
    }
    bundled_libraries = $libVersions
    artifacts = $ArtifactEntries
    omitted_external_dependencies = @(
        [PSCustomObject]@{ name = 'MobSF'; reason = 'Requires optional local Docker container environment'; setup = 'docker run -it -p 8001:8000 opensecurity/mobsf:latest' },
        [PSCustomObject]@{ name = 'Wireshark / TShark'; reason = 'Requires Windows Npcap kernel driver'; setup = 'https://www.wireshark.org/download.html' }
    )
}

$ManifestJsonPath = Join-Path $DistDir 'release_manifest.json'
$manifestContent = $ManifestObj | ConvertTo-Json -Depth 6
[System.IO.File]::WriteAllText($ManifestJsonPath, $manifestContent, [System.Text.Encoding]::UTF8)
Write-Host '[+] Generated release_manifest.json' -ForegroundColor Green

$Duration = (Get-Date) - $StartTime

Write-Host ''
Write-Host '==============================================================================' -ForegroundColor Green
$secs = [math]::Round($Duration.TotalSeconds, 1)
Write-Host ('           RELEASE BUILD COMPLETED SUCCESSFULLY IN ' + $secs + 's') -ForegroundColor Green
Write-Host '==============================================================================' -ForegroundColor Green
Write-Host ('Dist Directory: ' + $DistDir) -ForegroundColor White
Get-ChildItem -Path $DistDir -File | Select-Object Name, Length, LastWriteTime | Format-Table
