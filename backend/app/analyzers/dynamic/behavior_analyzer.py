import uuid
import logging
from datetime import datetime
from typing import Dict, Any, List, Optional

from backend.app.core.models import DynamicSandboxRun, DynamicObservation
from backend.app.database.repository import repo
from backend.app.analyzers.dynamic.process_monitor import process_monitor
from backend.app.analyzers.dynamic.filesystem_monitor import filesystem_monitor
from backend.app.analyzers.dynamic.registry_monitor import registry_monitor
from backend.app.analyzers.dynamic.network_monitor import dynamic_network_monitor

logger = logging.getLogger(__name__)

class DynamicBehaviorAnalyzer:
    """
    Synthesizes multi-source telemetry events into high-confidence behavioral findings
    mapped to MITRE ATT&CK techniques, calculating unified dynamic risk metrics.
    """

    SEVERITY_WEIGHTS = {
        "CRITICAL": 3.0,
        "HIGH": 2.0,
        "MEDIUM": 1.0,
        "LOW": 0.5,
        "INFORMATIONAL": 0.1
    }

    def analyze_run_behavior(self, run: DynamicSandboxRun) -> List[DynamicObservation]:
        """Runs behavioral analysis across all observation domains for a sandbox run."""
        observations: List[DynamicObservation] = []

        # 1. File Activity Observations
        file_findings = filesystem_monitor.analyze_file_events(run.investigation_id, run_id=run.id)
        for f in file_findings:
            obs = DynamicObservation(
                id=f"OBS-FILE-{uuid.uuid4().hex[:8]}",
                run_id=run.id,
                investigation_id=run.investigation_id,
                evidence_id=run.evidence_id,
                observation_type="FILESYSTEM",
                severity=f["severity"],
                title=f["title"],
                description=f["details"],
                mitre_technique=f.get("mitre_technique"),
                details=f
            )
            repo.add_dynamic_observation(obs)
            observations.append(obs)

        # 2. Registry Observations
        reg_findings = registry_monitor.analyze_registry_events(run.investigation_id, run_id=run.id)
        for r in reg_findings:
            obs = DynamicObservation(
                id=f"OBS-REG-{uuid.uuid4().hex[:8]}",
                run_id=run.id,
                investigation_id=run.investigation_id,
                evidence_id=run.evidence_id,
                observation_type="REGISTRY",
                severity=r["severity"],
                title=r["title"],
                description=r["details"],
                mitre_technique=r.get("mitre_technique"),
                details=r
            )
            repo.add_dynamic_observation(obs)
            observations.append(obs)

        # 3. Network Observations
        net_findings = dynamic_network_monitor.analyze_network_telemetry(run.investigation_id, run_id=run.id)
        for n in net_findings:
            obs = DynamicObservation(
                id=f"OBS-NET-{uuid.uuid4().hex[:8]}",
                run_id=run.id,
                investigation_id=run.investigation_id,
                evidence_id=run.evidence_id,
                observation_type="NETWORK",
                severity=n["severity"],
                title=n["title"],
                description=n["details"],
                mitre_technique="T1071 - Application Layer Protocol",
                details=n
            )
            repo.add_dynamic_observation(obs)
            observations.append(obs)

        # Calculate composite risk score
        score = 0.0
        for obs in observations:
            score += self.SEVERITY_WEIGHTS.get(obs.severity, 0.1)

        # Cap score at 10.0
        score = min(round(score, 1), 10.0)
        run.risk_score = score
        run.risk_level = self._score_to_severity(score)
        repo.update_sandbox_run(run)

        return observations

    def _score_to_severity(self, score: float) -> str:
        if score >= 8.0:
            return "Critical"
        elif score >= 5.5:
            return "High"
        elif score >= 3.0:
            return "Medium"
        elif score >= 1.0:
            return "Low"
        return "Informational"

behavior_analyzer = DynamicBehaviorAnalyzer()
