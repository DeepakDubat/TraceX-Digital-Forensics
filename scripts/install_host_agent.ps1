# TraceX VirtualBox Host Controller Agent — Production Installation Script
# Universal Digital Forensics & Evidence Intelligence Platform v2.0.0
# Requires Windows PowerShell with Administrator privileges.

[CmdletBinding()]
param (
    [string]$BindHost = "192.168.56.1",
    [int]$BindPort = 9443,
    [string]$InstallDir = "C:\ProgramData\TraceX\HostAgent"
)

Write-Host "====================================================================" -ForegroundColor Cyan
Write-Host " TraceX VirtualBox Host Controller Agent — Production Installation" -ForegroundColor Cyan
Write-Host " Security: Mutual TLS (mTLS) + HMAC-SHA256 Application Token" -ForegroundColor Cyan
Write-Host "====================================================================" -ForegroundColor Cyan

# 1. Administrator check
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Warning "Installation must be run as Administrator to configure Windows Firewall and Service permissions."
    Write-Warning "Please relaunch PowerShell as Administrator."
}

# 2. Check VirtualBox installation
$vboxPath = "C:\Program Files\Oracle\VirtualBox\VBoxManage.exe"
if (-not (Test-Path $vboxPath)) {
    Write-Error "VirtualBox (VBoxManage.exe) was not found at $vboxPath."
    Write-Error "Please install Oracle VirtualBox 7.x before deploying the Host Controller Agent."
    exit 1
}
$vboxVer = & $vboxPath --version
Write-Host "[+] Detected VirtualBox version: $vboxVer" -ForegroundColor Green

# 3. Check hardware virtualization
$proc = Get-CimInstance Win32_Processor | Select-Object -First 1
if (-not $proc.VirtualizationFirmwareEnabled) {
    Write-Host ""
    Write-Host "********************************************************************" -ForegroundColor Yellow
    Write-Host " ACTION REQUIRED: Enable Intel VT-x in BIOS/UEFI." -ForegroundColor Yellow
    Write-Host " Hardware-assisted virtualization is currently disabled in system BIOS." -ForegroundColor Yellow
    Write-Host " Analysis worker VMs cannot boot headlessly until VT-x/AMD-V is enabled." -ForegroundColor Yellow
    Write-Host "********************************************************************" -ForegroundColor Yellow
    Write-Host ""
} else {
    Write-Host "[+] Hardware virtualization (VT-x/AMD-V) is ENABLED in firmware." -ForegroundColor Green
}

# 4. Create directories with restricted ACLs
$stagingDir = Join-Path $InstallDir "staging"
$certsDir = Join-Path $InstallDir "certs"
$logsDir = Join-Path $InstallDir "logs"

foreach ($d in ($InstallDir, $stagingDir, $certsDir, $logsDir)) {
    if (-not (Test-Path $d)) {
        New-Item -ItemType Directory -Path $d -Force | Out-Null
    }
}

# Apply strict NTFS ACLs: Administrators and SYSTEM only.
# This prevents non-admin users or compromised local accounts from reading private keys or modifying config.
try {
    $acl = Get-Acl $InstallDir
    $acl.SetAccessRuleProtection($true, $false) # Disable inheritance, purge inherited permissions
    $adminRule = New-Object System.Security.AccessControl.FileSystemAccessRule("Administrators", "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow")
    $systemRule = New-Object System.Security.AccessControl.FileSystemAccessRule("SYSTEM", "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow")
    $acl.AddAccessRule($adminRule)
    $acl.AddAccessRule($systemRule)
    Set-Acl -Path $InstallDir -AclObject $acl
    Write-Host "[+] Applied strict NTFS ACLs to $InstallDir (Administrators & SYSTEM only)." -ForegroundColor Green
} catch {
    Write-Warning "Failed to set strict ACLs: $_"
}

# 5. Generate mTLS PKI Certificates (Root CA, Server Cert, Client Cert)
Write-Host "[*] Generating cryptographically signed mutual TLS (mTLS) certificate bundle..." -ForegroundColor White
$genPkiScript = Join-Path $PSScriptRoot "generate_pki.py"
if (Test-Path $genPkiScript) {
    py -3.11 $genPkiScript --output-dir $certsDir
} else {
    # Generate inline via python
    $pyCmd = "from backend.app.analyzers.dynamic.pki_manager import pki_manager; from pathlib import Path; pki_manager.generate_full_pki_bundle(Path('$certsDir'))"
    py -3.11 -c $pyCmd
}
Write-Host "[+] mTLS PKI certificates generated in: $certsDir" -ForegroundColor Green

# 6. Generate high-entropy 64-char hex auth token
$bytes = New-Object byte[] 32
$rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
$rng.GetBytes($bytes)
$authToken = "tracex_hc_" + [System.BitConverter]::ToString($bytes).Replace("-", "").ToLower()

# 7. Write configuration file
$configFile = Join-Path $InstallDir "config.json"
$config = @{
    bind_host = $BindHost
    bind_port = $BindPort
    auth_token = $authToken
    allowed_vm_uuids = @("TraceX-Worker-Win10", "TraceX-Worker-Android")
    allowed_snapshots = @("Clean_Base", "Baseline", "Ready")
    vboxmanage_path = $vboxPath
    staging_root = $stagingDir
    allowed_client_subnets = @("192.168.56.0/24", "127.0.0.1/32")
    require_mtls = $true
    cert_file = (Join-Path $certsDir "server_cert.pem")
    key_file = (Join-Path $certsDir "server_key.pem")
    ca_file = (Join-Path $certsDir "ca_cert.pem")
    audit_log_path = (Join-Path $logsDir "host_agent_audit.log")
} | ConvertTo-Json -Depth 4

$config | Out-File -FilePath $configFile -Encoding utf8 -Force
Write-Host "[+] Created configuration: $configFile" -ForegroundColor Green

# 8. Configure Windows Firewall rule
# Restricts incoming TCP port 9443 strictly to the VirtualBox Host-Only subnet (192.168.56.0/24).
# Blocks all traffic from public LAN, Wi-Fi, and Internet.
$firewallRuleName = "TraceX-VirtualBox-HostController"
try {
    Remove-NetFirewallRule -DisplayName $firewallRuleName -ErrorAction SilentlyContinue | Out-Null
    New-NetFirewallRule -DisplayName $firewallRuleName `
        -Direction Inbound `
        -Protocol TCP `
        -LocalPort $BindPort `
        -RemoteAddress "192.168.56.0/24" `
        -Action Allow `
        -Description "Restricted inbound mTLS access for TraceX Manager VM on VirtualBox Host-Only network." | Out-Null
    Write-Host "[+] Configured Windows Firewall rule '$firewallRuleName' allowing port $BindPort from 192.168.56.0/24 only." -ForegroundColor Green
} catch {
    Write-Warning "Could not configure Windows Firewall rule: $_"
}

# 9. Copy host agent binary/script to install dir
$sourceAgent = Join-Path $PSScriptRoot "..\host_controller\vbox_host_agent.py"
if (Test-Path $sourceAgent) {
    Copy-Item $sourceAgent (Join-Path $InstallDir "vbox_host_agent.py") -Force
}
$sourceBackendAgent = Join-Path $PSScriptRoot "..\backend\app\analyzers\dynamic\vbox_host_agent.py"
if (Test-Path $sourceBackendAgent) {
    Copy-Item $sourceBackendAgent (Join-Path $InstallDir "vbox_host_agent_core.py") -Force
}

# 10. Create launcher batch file
$launcherBat = Join-Path $InstallDir "start_host_agent.bat"
$batContent = "@echo off`r`npy -3.11 `"$InstallDir\vbox_host_agent.py`"`r`n"
$batContent | Out-File -FilePath $launcherBat -Encoding ascii -Force

# 11. Summary & Manager VM Connection Instructions
Write-Host ""
Write-Host "====================================================================" -ForegroundColor Cyan
Write-Host " TraceX Host Controller Agent — Installation Complete" -ForegroundColor Cyan
Write-Host "====================================================================" -ForegroundColor Cyan
Write-Host "Agent Protocol & Interface: HTTPS://$BindHost`:$BindPort (mTLS REQUIRED)" -ForegroundColor Green
Write-Host "Authentication Token:       $authToken" -ForegroundColor Yellow
Write-Host "Root CA Certificate:        $certsDir\ca_cert.pem" -ForegroundColor White
Write-Host "Manager VM Client Cert:     $certsDir\client_cert.pem" -ForegroundColor White
Write-Host "Manager VM Client Key:      $certsDir\client_key.pem" -ForegroundColor White
Write-Host ""
Write-Host "MANAGER VM CONFIGURATION (.env or environment variables):" -ForegroundColor Cyan
Write-Host "VBOX_HOST_AGENT_URL=https://$BindHost`:$BindPort" -ForegroundColor Green
Write-Host "VBOX_HOST_AGENT_TOKEN=$authToken" -ForegroundColor Green
Write-Host "VBOX_HOST_AGENT_CA_CERT=/path/to/ca_cert.pem" -ForegroundColor Green
Write-Host "VBOX_HOST_AGENT_CLIENT_CERT=/path/to/client_cert.pem" -ForegroundColor Green
Write-Host "VBOX_HOST_AGENT_CLIENT_KEY=/path/to/client_key.pem" -ForegroundColor Green
Write-Host ""
Write-Host "To start the Host Controller Agent now, execute:" -ForegroundColor White
Write-Host "& `"$launcherBat`"" -ForegroundColor Cyan
Write-Host "====================================================================" -ForegroundColor Cyan
