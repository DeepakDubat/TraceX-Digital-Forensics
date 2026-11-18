import uuid
from datetime import datetime
from typing import Dict, Any, List, Optional

from backend.app.core.models import (
    EvidenceRiskAssessment,
    UniversalInvestigationDetail
)
from backend.app.database.repository import repo

class EvidenceRiskAssessor:
    """
    Evidence-Backed Multi-Dimensional Risk Engine.
    Strictly separates static capabilities, observed execution, observed network traffic,
    successful protocol exchanges, confirmed data exfiltration, and threat feed reputation.
    Outputs an explainable, source-attributed forensic score with corroborating & contradictory factors.
    """

    def assess_investigation(self, detail: UniversalInvestigationDetail) -> EvidenceRiskAssessment:
        inv_id = detail.record.id

        score_inputs: List[str] = []
        corroboration: List[str] = []
        contradictions: List[str] = []
        missing: List[str] = []
        limitations: List[str] = []

        # 1. Dimension: Static Capability (Weight: 20%)
        static_cap = 0.0
        findings = getattr(detail, "static_findings", [])
        c2s = getattr(detail, "c2_indicators", [])
        secrets = getattr(detail, "secrets", [])
        revshells = getattr(detail, "reverse_shell_findings", [])

        if revshells:
            static_cap += 4.0
            score_inputs.append(f"Reverse shell payload strings detected ({len(revshells)} occurrences).")
        if c2s:
            static_cap += min(3.0, len(c2s) * 0.8)
            score_inputs.append(f"Hardcoded C2 infrastructure endpoints embedded ({len(c2s)} indicators).")
        if secrets:
            static_cap += min(2.0, len(secrets) * 0.5)
            score_inputs.append(f"Exposed API tokens/credentials identified ({len(secrets)} secrets).")
        if findings:
            # Filter out findings categories already scored under revshells, c2s, and secrets to prevent double-counting
            already_scored_categories = {"c2_channel", "database_access", "credentials", "secret", "reverse_shell"}
            high_findings = [
                f for f in findings
                if getattr(f, "severity", "") in ("High", "Critical")
                and getattr(f, "category", "") not in already_scored_categories
            ]
            if high_findings:
                static_cap += min(3.0, len(high_findings) * 0.6)
                score_inputs.append(f"High-severity independent static code patterns ({len(high_findings)} findings).")

        static_cap = min(10.0, static_cap)

        # 2. Dimension: Observed Execution (Weight: 20%)
        obs_exec = 0.0
        dynamic_events = repo.list_telemetry_events(inv_id)
        proc_events = [e for e in dynamic_events if e.event_category == "PROCESS"]
        reg_events = [e for e in dynamic_events if e.event_category == "REGISTRY"]
        dropped = repo.list_dropped_artifact_records(inv_id)

        if proc_events:
            obs_exec += min(4.0, len(proc_events) * 1.0)
            score_inputs.append(f"Observed runtime process tree spawning ({len(proc_events)} events).")
        if reg_events:
            obs_exec += min(3.0, len(reg_events) * 0.5)
            score_inputs.append(f"Observed system registry configuration changes ({len(reg_events)} events).")
        if dropped:
            obs_exec += min(3.0, len(dropped) * 1.5)
            score_inputs.append(f"Dropped secondary binaries on disk ({len(dropped)} files).")

        if not dynamic_events:
            missing.append("No isolated dynamic sandbox execution has been performed yet.")
        obs_exec = min(10.0, obs_exec)

        # 3. Dimension: Observed Network Activity (Weight: 15%)
        obs_net = 0.0
        flows = repo.list_network_flow_records(inv_id)
        dns_events = [e for e in dynamic_events if e.event_category == "DNS_QUERY"]

        if flows:
            obs_net += min(6.0, len(flows) * 1.0)
            score_inputs.append(f"Observed network connection attempts ({len(flows)} flows).")
        if dns_queries := [e for e in dynamic_events if e.event_category == "DNS_QUERY"]:
            obs_net += min(4.0, len(dns_queries) * 0.8)
            score_inputs.append(f"Observed runtime DNS resolution queries ({len(dns_queries)} queries).")

        obs_net = min(10.0, obs_net)

        # 4. Dimension: Successful Protocol Interaction (Weight: 15%)
        succ_proto = 0.0
        tls_events = [e for e in dynamic_events if e.event_category == "TLS_HANDSHAKE"]
        http_events = [e for e in dynamic_events if e.event_category == "HTTP_REQUEST"]

        if tls_events:
            succ_proto += min(5.0, len(tls_events) * 2.0)
            score_inputs.append(f"Completed TLS cryptographic handshakes ({len(tls_events)} sessions).")
        if http_events:
            succ_proto += min(5.0, len(http_events) * 2.0)
            score_inputs.append(f"Formulated structured HTTP request exchanges ({len(http_events)} requests).")

        succ_proto = min(10.0, succ_proto)

        # 5. Dimension: Confirmed Data Transfer (Weight: 15%)
        data_xfer = 0.0
        bytes_out = sum(f.byte_count for f in flows if f.direction == "OUTBOUND")
        if bytes_out > 1024: # >1 KB
            data_xfer = min(10.0, 4.0 + (bytes_out / 50000.0) * 6.0)
            score_inputs.append(f"Measured significant outbound data egress ({bytes_out} bytes).")
        elif bytes_out > 0:
            data_xfer = 2.0
            score_inputs.append(f"Low-volume outbound handshake data observed ({bytes_out} bytes).")
        else:
            if flows:
                contradictions.append("Network flows were attempted but zero sustained data egress occurred.")

        # 6. Dimension: Threat Intelligence Reputation (Weight: 15%)
        threat_rep = 0.0
        ti_results = getattr(detail, "threat_intel", [])
        osint_obs = repo.list_osint_observations(inv_id)

        malicious_providers = 0
        total_queried = len(osint_obs) + len(ti_results)

        for obs in osint_obs:
            data = obs.normalized_data or {}
            if data.get("malicious_count", 0) > 3 or data.get("pulse_count", 0) > 0 or data.get("abuse_confidence_score", 0) > 50:
                malicious_providers += 1

        if malicious_providers > 2:
            threat_rep = 10.0
            corroboration.append(f"Multiple independent threat intelligence providers corroborated malicious activity ({malicious_providers} providers).")
        elif malicious_providers > 0:
            threat_rep = 5.0
            corroboration.append(f"Single provider flagged indicator as malicious ({malicious_providers} provider). Requires corroboration.")
        elif total_queried > 0:
            contradictions.append("Queried public threat intelligence feeds reported NO_DATA or clean verdicts for extracted indicators.")
        else:
            missing.append("No external threat intelligence feeds were queried (e.g. Local-Only Mode active).")

        # Corroboration vs Contradiction checks
        correlations = repo.list_static_dynamic_correlations(inv_id)
        if correlations:
            corroboration.append(f"{len(correlations)} static capabilities were confirmed by observed dynamic runtime events.")
        elif static_cap > 3.0 and obs_exec == 0:
            contradictions.append("Static code suggests suspicious capabilities, but zero runtime activity was observed.")

        # Calculate weighted composite overall score (0.0 to 10.0)
        # In static-only forensics mode (zero dynamic telemetry), static capability and threat reputation drive the score.
        if obs_exec == 0 and obs_net == 0 and succ_proto == 0 and data_xfer == 0:
            if threat_rep > 0:
                overall = static_cap * 0.70 + threat_rep * 0.30
            else:
                overall = static_cap
        else:
            overall = (
                static_cap * 0.20 +
                obs_exec * 0.20 +
                obs_net * 0.15 +
                succ_proto * 0.15 +
                data_xfer * 0.15 +
                threat_rep * 0.15
            )
        overall = round(min(10.0, max(0.0, overall)), 2)

        # Severity
        if overall >= 7.5:
            severity = "Critical"
        elif overall >= 5.0:
            severity = "High"
        elif overall >= 3.0:
            severity = "Medium"
        elif overall >= 1.0:
            severity = "Low"
        else:
            severity = "Informational"

        # Confidence
        if len(corroboration) >= 2 and total_queried > 0 and obs_exec > 0:
            confidence = "Confirmed"
        elif len(corroboration) >= 1 or correlations:
            confidence = "High"
        elif static_cap > 0:
            confidence = "Medium"
        else:
            confidence = "Unverified"

        limitations.append("Threat feed reputation is probabilistic and does not represent absolute ground truth.")
        limitations.append("Simulated network responses must not be confused with live command-and-control interaction.")

        assessment = EvidenceRiskAssessment(
            id=f"RISK-{uuid.uuid4().hex[:8]}",
            investigation_id=inv_id,
            static_capability_score=round(static_cap, 2),
            observed_execution_score=round(obs_exec, 2),
            observed_network_score=round(obs_net, 2),
            successful_protocol_interaction_score=round(succ_proto, 2),
            confirmed_data_transfer_score=round(data_xfer, 2),
            threat_intel_reputation_score=round(threat_rep, 2),
            overall_risk_score=overall,
            severity=severity,
            confidence=confidence,
            score_inputs=score_inputs,
            weighting_method="Evidence-Corroborated Dimensional Scoring (Static 20%, Execution 20%, Network 15%, Protocol 15%, Egress 15%, ThreatIntel 15%)",
            corroboration_sources=corroboration,
            contradictory_evidence=contradictions,
            missing_evidence=missing,
            known_limitations=limitations,
            assessed_at_utc=datetime.utcnow().isoformat()
        )

        repo.create_or_update_risk_assessment(assessment)
        return assessment

evidence_risk_assessor = EvidenceRiskAssessor()

def assess_evidence_dimensional_risk(detail: UniversalInvestigationDetail) -> EvidenceRiskAssessment:
    """Convenience wrapper for assessing evidence-backed multi-dimensional risk."""
    return evidence_risk_assessor.assess_investigation(detail)

