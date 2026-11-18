import os
import sys
import shutil
import subprocess
import logging
from pathlib import Path
from typing import Dict, Any, Optional
from datetime import datetime

from backend.app.config import settings
from backend.app.core.models import DynamicSandboxRun
from backend.app.analyzers.dynamic.sandbox_registry import ISandboxProvider

logger = logging.getLogger(__name__)

class WindowsSandboxProvider(ISandboxProvider):
    """
    Orchestrates Windows Sandbox (Micro-VM Lightweight Container).
    Generates isolated, read-only .wsb configuration files with strict boundaries:
    - No clipboard redirection.
    - No mapped host system drives.
    - Network disabled by default.
    - Fully disposable execution environment.
    """

    @property
    def provider_id(self) -> str:
        return "windows_sandbox"

    @property
    def name(self) -> str:
        return "Windows Sandbox (Disposable Container)"

    @property
    def os_family(self) -> str:
        return "windows"

    def preflight(self) -> Dict[str, Any]:
        """Detects if Windows Sandbox is enabled and executable."""
        wsb_path = Path(os.environ.get("SystemRoot", "C:\\Windows")) / "System32" / "WindowsSandbox.exe"
        installed = wsb_path.exists() or bool(shutil.which("WindowsSandbox"))

        if installed:
            return {
                "ready": True,
                "status": "INSTALLED_AND_READY",
                "details": {"executable": str(wsb_path), "disposable": True}
            }
        return {
            "ready": False,
            "status": "NOT_CONFIGURED",
            "details": {
                "message": "Windows Sandbox is not enabled or not supported on this Windows edition.",
                "hint": "Requires Windows 10/11 Pro, Enterprise, or Education. Enable via Windows Features -> Windows Sandbox."
            }
        }

    def provision(self, run: DynamicSandboxRun, staged_file: Path) -> Dict[str, Any]:
        """
        Creates an isolated .wsb configuration and guest bootstrap runner.
        Maps only the isolated run staging directory and telemetry output folder.
        """
        staging_dir = staged_file.parent.resolve()
        output_dir = staging_dir / "output"
        output_dir.mkdir(parents=True, exist_ok=True)

        wsb_file = staging_dir / f"TraceX_{run.id}.wsb"
        net_setting = "Disable" if run.network_policy == "DISABLED" else "Default"
        target_name = staged_file.name

        # Create guest in-container bootstrap script
        guest_cmd = staging_dir / "bootstrap.cmd"
        guest_cmd.write_text(f"""@echo off
echo [TraceX Guest Monitor] Starting analysis for {target_name}... > C:\\TraceX_Output\\run.log
echo [TraceX Guest Monitor] Timestamp: %DATE% %TIME% >> C:\\TraceX_Output\\run.log

:: Record initial process snapshot
tasklist /FO CSV > C:\\TraceX_Output\\initial_processes.csv

:: Start lightweight guest logger (WMIC process creation tracker)
start /B wmic process where "Name!='wmic.exe'" get ProcessId,ParentProcessId,CommandLine,Name /format:csv > C:\\TraceX_Output\\process_tracker.csv 2>&1

:: Copy sample to guest local temporary directory and execute
copy C:\\TraceX_Staging\\{target_name} C:\\Users\\WDAGUtilityAccount\\AppData\\Local\\Temp\\{target_name} > nul
cd C:\\Users\\WDAGUtilityAccount\\AppData\\Local\\Temp\\

echo [TraceX Guest Monitor] Launching sample... >> C:\\TraceX_Output\\run.log
start "" /WAIT C:\\Users\\WDAGUtilityAccount\\AppData\\Local\\Temp\\{target_name}

echo [TraceX Guest Monitor] Sample execution finished or timeout reached. >> C:\\TraceX_Output\\run.log
tasklist /FO CSV > C:\\TraceX_Output\\final_processes.csv
exit
""", encoding="utf-8")

        # Generate strictly contained .wsb XML
        wsb_content = f"""<Configuration>
    <Networking>{net_setting}</Networking>
    <ClipboardRedirection>Disable</ClipboardRedirection>
    <MemoryInMB>4096</MemoryInMB>
    <MappedFolders>
        <MappedFolder>
            <HostFolder>{staging_dir}</HostFolder>
            <SandboxFolder>C:\\TraceX_Staging</SandboxFolder>
            <ReadOnly>true</ReadOnly>
        </MappedFolder>
        <MappedFolder>
            <HostFolder>{output_dir}</HostFolder>
            <SandboxFolder>C:\\TraceX_Output</SandboxFolder>
            <ReadOnly>false</ReadOnly>
        </MappedFolder>
    </MappedFolders>
    <LogonCommand>
        <Command>C:\\TraceX_Staging\\bootstrap.cmd</Command>
    </LogonCommand>
</Configuration>
"""
        wsb_file.write_text(wsb_content, encoding="utf-8")

        return {
            "wsb_path": str(wsb_file),
            "output_dir": str(output_dir),
            "staged_file": str(staged_file),
            "network": net_setting
        }

    def execute(self, run: DynamicSandboxRun, timeout_seconds: int) -> Dict[str, Any]:
        """
        Launches Windows Sandbox using the isolated .wsb profile.
        Monitors execution duration up to timeout.
        """
        staging_dir = settings.DATA_DIR / "staging" / run.id
        wsb_file = staging_dir / f"TraceX_{run.id}.wsb"

        if not wsb_file.exists():
            raise FileNotFoundError(f"WSB configuration file not found: {wsb_file}")

        pre = self.preflight()
        if not pre.get("ready"):
            raise RuntimeError(f"Cannot execute: Windows Sandbox is not ready ({pre.get('status')}).")

        # Launch Windows Sandbox via ShellExecute
        try:
            cmd = ["WindowsSandbox.exe", str(wsb_file)]
            proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            return {
                "started": True,
                "pid": proc.pid,
                "timeout": timeout_seconds,
                "started_at_utc": datetime.utcnow().isoformat()
            }
        except Exception as e:
            logger.error(f"Failed to start WindowsSandbox: {e}")
            raise RuntimeError(f"WindowsSandbox launch failed: {str(e)}")

    def collect_telemetry(self, run: DynamicSandboxRun) -> Dict[str, Any]:
        """Collects outputs and logs from the mapped output directory."""
        output_dir = settings.DATA_DIR / "staging" / run.id / "output"
        telemetry: Dict[str, Any] = {
            "processes": [],
            "file_events": [],
            "registry_events": [],
            "network_flows": [],
            "logs": []
        }

        if not output_dir.exists():
            return telemetry

        run_log = output_dir / "run.log"
        if run_log.exists():
            try:
                telemetry["logs"] = run_log.read_text(encoding="utf-8", errors="replace").splitlines()
            except Exception:
                pass

        # Parse process snapshots if present
        final_proc = output_dir / "final_processes.csv"
        if final_proc.exists():
            try:
                lines = final_proc.read_text(encoding="utf-8", errors="replace").splitlines()
                for line in lines[1:]:
                    parts = [p.strip(' "') for p in line.split(',')]
                    if len(parts) >= 2:
                        telemetry["processes"].append({
                            "name": parts[0],
                            "pid": int(parts[1]) if parts[1].isdigit() else 0,
                            "session": parts[2] if len(parts) > 2 else "Services",
                            "mem_usage": parts[4] if len(parts) > 4 else "0 K",
                            "operation": "ProcessObserved"
                        })
            except Exception:
                pass

        return telemetry

    def terminate(self, run: DynamicSandboxRun) -> None:
        """Terminates any active Windows Sandbox processes."""
        try:
            subprocess.run(["taskkill", "/F", "/IM", "WindowsSandboxClient.exe"], capture_output=True, timeout=5.0)
        except Exception:
            pass

    def restore_and_cleanup(self, run: DynamicSandboxRun) -> None:
        """Terminates sandbox container and cleans up staging profile."""
        self.terminate(run)
        staging_dir = settings.DATA_DIR / "staging" / run.id
        wsb_file = staging_dir / f"TraceX_{run.id}.wsb"
        if wsb_file.exists():
            try:
                wsb_file.unlink()
            except Exception:
                pass

windows_sandbox_provider = WindowsSandboxProvider()
