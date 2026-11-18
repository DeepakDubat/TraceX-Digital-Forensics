import logging
from typing import Dict, Any, List, Optional
from backend.app.core.models import DynamicTelemetryEvent
from backend.app.database.repository import repo

logger = logging.getLogger(__name__)

class RegistryMonitor:
    """
    Analyzes Windows Registry modifications, persistence hooks, and defense evasion attempts.
    """

    AUTORUN_KEYS = [
        "currentversion\\run",
        "currentversion\\runonce",
        "currentversion\\runservices",
        "currentversion\\policies\\explorer\\run"
    ]

    DEFENSE_EVASION_KEYS = [
        "windows defender\\real-time protection",
        "system\\currentcontrolset\\services\\sharedaccess\\parameters\\firewallpolicy",
        "currentversion\\policies\\system\\enablelua"
    ]

    def analyze_registry_events(self, investigation_id: str, run_id: Optional[str] = None) -> List[Dict[str, Any]]:
        events = repo.list_telemetry_events(investigation_id, run_id=run_id)
        reg_events = [e for e in events if e.event_category == "REGISTRY"]
        findings = []

        for ev in reg_events:
            target = (ev.target_path or "").lower()
            op = ev.operation or "SetValue"

            # Check Autorun persistence
            if any(k in target for k in self.AUTORUN_KEYS):
                findings.append({
                    "type": "REGISTRY_PERSISTENCE_AUTORUN",
                    "severity": "CRITICAL",
                    "title": "Windows Autostart / Run Key Persistence Modified",
                    "details": f"Registry key modification '{op}' on target: {ev.target_path}",
                    "mitre_technique": "T1547.001 - Registry Run Keys / Startup Folder",
                    "event_id": ev.id
                })

            # Check Security / AV tampering
            if any(k in target for k in self.DEFENSE_EVASION_KEYS):
                findings.append({
                    "type": "SECURITY_TOOL_IMPAIRMENT",
                    "severity": "CRITICAL",
                    "title": "Security Control Impairment / Defender Tampering",
                    "details": f"Attempted to modify security policy key: {ev.target_path}",
                    "mitre_technique": "T1562.001 - Disable or Modify Tools",
                    "event_id": ev.id
                })

        return findings

registry_monitor = RegistryMonitor()
