import logging
from typing import Dict, Any, List, Optional
from backend.app.core.models import DynamicTelemetryEvent
from backend.app.database.repository import repo

logger = logging.getLogger(__name__)

class FilesystemMonitor:
    """
    Monitors runtime filesystem activity, dropped artifacts, and path modifications.
    """

    EXECUTABLE_EXTENSIONS = {".exe", ".dll", ".bat", ".cmd", ".vbs", ".ps1", ".apk", ".dex", ".so"}
    SENSITIVE_DIRECTORIES = {"system32", "syswow64", "windows\\temp", "appdata\\roaming\\microsoft\\windows\\start menu"}

    def analyze_file_events(self, investigation_id: str, run_id: Optional[str] = None) -> List[Dict[str, Any]]:
        events = repo.list_telemetry_events(investigation_id, run_id=run_id)
        file_events = [e for e in events if e.event_category == "FILE"]
        findings = []

        for ev in file_events:
            target = (ev.target_path or "").lower()
            op = ev.operation or "WriteFile"

            # Check for executable dropped in temp or appdata
            has_exec_ext = any(target.endswith(ext) for ext in self.EXECUTABLE_EXTENSIONS)
            if has_exec_ext and ("temp" in target or "appdata" in target or "data/local" in target):
                findings.append({
                    "type": "EXECUTABLE_DROPPED_IN_TEMP",
                    "severity": "HIGH",
                    "title": "Executable Binary Dropped in Temporary Directory",
                    "details": f"Operation '{op}' on target path: {ev.target_path}",
                    "mitre_technique": "T1105 - Ingress Tool Transfer",
                    "event_id": ev.id
                })

            # Check for hosts file modification
            if "etc\\hosts" in target or "etc/hosts" in target:
                findings.append({
                    "type": "HOSTS_FILE_MODIFICATION",
                    "severity": "CRITICAL",
                    "title": "System Hosts File Modification Attempt",
                    "details": f"Attempted '{op}' on {ev.target_path}. Possible DNS hijacking or AV sinkholing.",
                    "mitre_technique": "T1565.001 - Stored Data Manipulation",
                    "event_id": ev.id
                })

        return findings

filesystem_monitor = FilesystemMonitor()
