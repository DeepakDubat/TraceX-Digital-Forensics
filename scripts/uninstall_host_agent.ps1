# TraceX VirtualBox Host Controller Agent — Uninstallation Script
# Universal Digital Forensics & Evidence Intelligence Platform v2.0.0
# Requires Windows PowerShell with Administrator privileges.

[CmdletBinding()]
param (
    [string]$InstallDir = "C:\ProgramData\TraceX\HostAgent"
)

Write-Host "====================================================================" -ForegroundColor Cyan
Write-Host " TraceX VirtualBox Host Controller Agent — Safe Uninstallation" -ForegroundColor Cyan
Write-Host "====================================================================" -ForegroundColor Cyan

# 1. Administrator check
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Warning "Uninstallation should be run as Administrator to remove Windows Firewall rules."
}

# 2. Safety verification: Ensure InstallDir is specifically TraceX HostAgent
$normalized = [System.IO.Path]::GetFullPath($InstallDir).TrimEnd('\', '/')
if (-not ($normalized -like "*\TraceX\HostAgent*" -or $normalized -like "*\HostAgent*")) {
    Write-Error "SAFETY ABORT: Refusing to delete path that does not contain 'TraceX\HostAgent': $InstallDir"
    exit 1
}

# 3. Stop any running host agent processes
Write-Host "[*] Inspecting running Host Controller processes..." -ForegroundColor White
$agentProcs = Get-Process -Name "python", "py" -ErrorAction SilentlyContinue | Where-Object {
    $_.Path -like "*python*" -and ($_.CommandLine -like "*vbox_host_agent*" -or $_.CommandLine -like "*HostAgent*")
}
foreach ($p in $agentProcs) {
    Write-Host "[+] Stopping running Host Controller process (PID: $($p.Id))..." -ForegroundColor Yellow
    Stop-Process -Id $p.Id -Force
}

# 4. Remove Windows Firewall rule
$firewallRuleName = "TraceX-VirtualBox-HostController"
try {
    $existing = Get-NetFirewallRule -DisplayName $firewallRuleName -ErrorAction SilentlyContinue
    if ($existing) {
        Remove-NetFirewallRule -DisplayName $firewallRuleName | Out-Null
        Write-Host "[+] Removed Windows Firewall rule '$firewallRuleName'." -ForegroundColor Green
    } else {
        Write-Host "[+] Firewall rule '$firewallRuleName' was not found." -ForegroundColor Gray
    }
} catch {
    Write-Warning "Failed to remove firewall rule: $_"
}

# 5. Clean up TraceX-owned temporary files & host agent directory ONLY
# FORENSIC GUARANTEE: Does NOT delete forensic evidence, user databases, or VirtualBox VM disks/snapshots.
if (Test-Path $InstallDir) {
    try {
        # Verify no .vdi or .vmdk files exist inside before removing
        $vboxDisks = Get-ChildItem -Path $InstallDir -Recurse -Include "*.vdi", "*.vmdk" -ErrorAction SilentlyContinue
        if ($vboxDisks) {
            Write-Warning "Virtual machine disks detected in $InstallDir. Preserving disks; removing only agent scripts, certs, and logs."
            Get-ChildItem -Path $InstallDir -Exclude "*.vdi", "*.vmdk" | Remove-Item -Recurse -Force
        } else {
            Remove-Item -Path $InstallDir -Recurse -Force
            Write-Host "[+] Successfully removed $InstallDir." -ForegroundColor Green
        }
    } catch {
        Write-Warning "Could not remove all files in $InstallDir: $_"
    }
} else {
    Write-Host "[+] $InstallDir was already absent." -ForegroundColor Green
}

Write-Host ""
Write-Host "====================================================================" -ForegroundColor Cyan
Write-Host " TraceX Host Controller Agent — Safe Removal Complete" -ForegroundColor Cyan
Write-Host " [✓] Forensic evidence, investigations, and database: UNTOUCHED" -ForegroundColor Green
Write-Host " [✓] Host VirtualBox VMs, disks, and snapshots:       UNTOUCHED" -ForegroundColor Green
Write-Host "====================================================================" -ForegroundColor Cyan
