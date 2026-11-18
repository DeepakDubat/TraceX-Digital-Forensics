from typing import List, Dict, Any, Tuple
from backend.app.core.models import (
    StaticFinding, C2Indicator, SecretFinding, PePersistenceFinding, FinalAssessment
)

def evaluate_pe_malware_risk(
    static_findings: List[StaticFinding],
    c2_indicators: List[C2Indicator],
    secrets: List[SecretFinding],
    persistence_findings: List[PePersistenceFinding],
    is_external_intel_used: bool = False,
    threat_intel_detections: int = 0
) -> FinalAssessment:
    """
    Forensic risk assessment engine tailored for Windows PE Executables.
    Calculates weighted numeric risk score (0-100), overall severity,
    confidence rating, and generates clear executive summaries.
    """
    score = 0
    strongest_evidence: List[str] = []
    potential_malicious: List[str] = []
    unanswered: List[str] = []
    limitations: List[str] = []
    recommended_actions: List[str] = []

    # 1. Evaluate Process Injection & Memory Manipulation
    has_injection = any("Injection" in pf.mechanism or "Remote Thread" in pf.mechanism for pf in persistence_findings)
    if has_injection:
        score += 35
        strongest_evidence.append("Cross-process injection capability identified (VirtualAllocEx + WriteProcessMemory + CreateRemoteThread).")
        potential_malicious.append("Process injection and evasion of endpoint detection via foreign thread creation.")

    # 2. Evaluate W+X Section Anomalies
    wx_sections = [f for f in static_findings if "Writable and Executable" in f.title]
    if wx_sections:
        score += 20
        strongest_evidence.append(f"{len(wx_sections)} PE section(s) declared with both Writable and Executable (W+X) permissions.")
        potential_malicious.append("Self-modifying code execution or staging of in-memory unpacked shellcode.")

    # 3. Evaluate High-Entropy & Packer Evidence
    entropy_findings = [f for f in static_findings if "High-Entropy" in f.title]
    packer_findings = [f for f in static_findings if "Packer" in f.title]
    if packer_findings:
        score += 15
        strongest_evidence.append(f"Known packer signature identified: {packer_findings[0].description}")
        potential_malicious.append("Binary obfuscation and packing designed to frustrate static disassembly.")
    elif entropy_findings:
        score += 10
        strongest_evidence.append("High Shannon entropy sections detected (> 7.2/8.0).")

    # 4. Evaluate C2 Indicators
    confirmed_c2 = [c for c in c2_indicators if c.classification == "potential_c2"]
    if confirmed_c2:
        c2_points = min(30, len(confirmed_c2) * 15)
        score += c2_points
        strongest_evidence.append(f"Identified {len(confirmed_c2)} suspicious C2 network destination(s) (e.g. {confirmed_c2[0].value}).")
        potential_malicious.append("Outbound communication with unauthorized remote command-and-control infrastructure.")

    # 5. Evaluate Persistence Mechanisms
    registry_persist = [pf for pf in persistence_findings if "Run" in pf.mechanism or "Startup" in pf.mechanism or "Service" in pf.mechanism]
    if registry_persist:
        score += 20
        strongest_evidence.append(f"{len(registry_persist)} Windows host persistence indicator(s) identified (e.g. {registry_persist[0].mechanism}).")
        potential_malicious.append("Establishment of persistent execution across system reboots or user logins.")

    # 6. Evaluate LOLBAS & Command Evasion
    lolbas_persist = [pf for pf in persistence_findings if "PowerShell" in pf.mechanism or "Ransomware" in pf.mechanism or "Shadow" in pf.mechanism]
    if lolbas_persist:
        score += 25
        strongest_evidence.append(f"High-risk command patterns detected: {lolbas_persist[0].title}")
        potential_malicious.append("Defense evasion or system recovery inhibition via specialized command utilities.")

    # 7. Evaluate Secrets & Credentials
    if secrets:
        score += min(15, len(secrets) * 5)
        strongest_evidence.append(f"Recovered {len(secrets)} hardcoded authentication secret(s) or API token(s).")

    # 8. Threat Intelligence Corroboration
    if threat_intel_detections > 5:
        score += 40
        strongest_evidence.append(f"Threat intelligence corroborated malicious verdict ({threat_intel_detections} engine detections).")
    elif threat_intel_detections > 0:
        score += 20
        strongest_evidence.append(f"Threat intelligence reported {threat_intel_detections} detection(s).")

    # Normalize score
    final_score = min(100, max(0, score))

    # Determine Severity
    if final_score >= 80:
        severity = "Critical"
    elif final_score >= 55:
        severity = "High"
    elif final_score >= 30:
        severity = "Medium"
    elif final_score >= 10:
        severity = "Low"
    else:
        severity = "Informational"

    # Determine Confidence
    if has_injection or len(confirmed_c2) >= 2 or threat_intel_detections > 0:
        confidence = "High"
    elif len(strongest_evidence) >= 2:
        confidence = "Medium"
    elif len(strongest_evidence) == 1:
        confidence = "Low"
    else:
        confidence = "Inconclusive"

    # Transparent Verdict Narrative
    if final_score >= 80:
        verdict_statement = "Likely malicious, based on corroborated forensic evidence."
    elif final_score >= 55:
        verdict_statement = "High-risk behavior patterns detected."
    elif final_score >= 25:
        verdict_statement = "Suspicious indicators detected."
    elif final_score > 0:
        verdict_statement = "Minor anomalous indicators detected."
    else:
        verdict_statement = "No significant suspicious indicators identified."

    exec_summary = (
        f"Forensic examination of Windows executable concluded with a risk score of {final_score}/100 "
        f"({severity} Severity, {confidence} Confidence). Assessment: {verdict_statement} "
        f"Key observations include {len(static_findings)} structural and API findings, "
        f"{len(c2_indicators)} network indicator(s), {len(secrets)} credential token(s), and "
        f"{len(persistence_findings)} persistence mechanism(s)."
    )

    unanswered.extend([
        "Live network protocol interaction and active C2 command structures remain unobserved due to safe offline static analysis.",
        "Runtime payload unpacking stubs and memory-only payloads require isolated sandbox observation to capture post-unpacking binary dumps."
    ])

    limitations.extend([
        "All analysis was conducted purely passively without execution on the forensic analyst host machine.",
        "Absence of detected indicators does not guarantee that the executable is benign; custom obfuscation or delayed execution may exist."
    ])

    if final_score >= 50:
        recommended_actions.extend([
            "Isolate endpoints where this executable hash or related binaries have been identified.",
            "Block identified C2 IP destinations and domain names at network egress perimeters.",
            "Inspect registry Run keys and active Windows services for persistence indicators.",
            "Submit sample hash to passive threat intelligence repository for corroborated family classification."
        ])
    else:
        recommended_actions.extend([
            "Verify digital signature chain and software vendor provenance.",
            "Retain artifact in investigation archive for historical baseline comparison."
        ])

    return FinalAssessment(
        overall_severity=severity,
        overall_confidence=confidence,
        risk_score=final_score,
        executive_summary=exec_summary,
        strongest_evidence=strongest_evidence,
        potential_malicious_functionality=potential_malicious,
        unanswered_questions=unanswered,
        limitations=limitations,
        recommended_actions=recommended_actions,
        dynamic_analysis_conducted=False,
        external_intelligence_used=is_external_intel_used
    )
