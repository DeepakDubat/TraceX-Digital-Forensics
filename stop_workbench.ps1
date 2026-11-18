# stop_workbench.ps1 - Graceful shutdown of Workbench services
Write-Host "=============================================================================="
Write-Host "       STOPPING FORENSICS WORKBENCH SERVICES GRACEFULLY"
Write-Host "=============================================================================="

$ports = @(8000, 5173, 9000)
$stoppedAny = $false

foreach ($port in $ports) {
    try {
        $conns = Get-NetTCPConnection -LocalPort $port -State Listen -ErrorAction SilentlyContinue
        if ($conns) {
            foreach ($conn in $conns) {
                $pidToStop = $conn.OwningProcess
                if ($pidToStop -and $pidToStop -gt 4) {
                    $proc = Get-Process -Id $pidToStop -ErrorAction SilentlyContinue
                    if ($proc -and ($proc.ProcessName -like "*python*" -or $proc.ProcessName -like "*node*" -or $proc.ProcessName -like "*cmd*")) {
                        Write-Host "[*] Stopping $($proc.ProcessName) (PID $pidToStop) on port $port..."
                        Stop-Process -Id $pidToStop -ErrorAction SilentlyContinue
                        $stoppedAny = $true
                    }
                }
            }
        }
    } catch {
        # Ignore port check error
    }
}

Start-Sleep -Seconds 1

foreach ($port in $ports) {
    $remaining = Get-NetTCPConnection -LocalPort $port -State Listen -ErrorAction SilentlyContinue
    if ($remaining) {
        Write-Host "[!] Port $port still occupied by PID $($remaining[0].OwningProcess)."
    } else {
        Write-Host "[+] Port $port is clear."
    }
}

Write-Host "=============================================================================="
Write-Host " Workbench shutdown complete."
Write-Host "=============================================================================="

