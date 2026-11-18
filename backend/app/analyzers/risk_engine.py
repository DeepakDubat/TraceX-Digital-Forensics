from typing import List, Dict, Any, Tuple
from backend.app.core.models import (
    StaticFinding, C2Indicator, SecretFinding, ReverseShellFinding, FinalAssessment
)

def evaluate_malware_risk(
    static_findings: List[StaticFinding],
    c2_indicators: List[C2Indicator],
    secrets: List[SecretFinding],
    reverse_shell_findings: List[ReverseShellFinding],
    is_external_intel_used: bool = False
) -> FinalAssessment:
    """
    Transparent forensic risk engine.
    Computes numerical risk score (0-100), overall severity, overall confidence,
    executive summary, and documented analytical rationale.
    """
    risk_score = 0
    strongest_evidence: List[str] = []
    potential_functionality: List[str] = []
    unanswered_questions: List[str] = []
    limitations: List[str] = [
        "Static analysis assesses capability and structure; dynamic behavioral verification in an isolated sandbox is required to confirm live execution paths.",
        "External active C2 infrastructure validation was intentionally suppressed to prevent alerting potential adversaries or triggering remote wipe commands.",
        "Third-party threat intelligence services reflect historical telemetry and may not encompass novel, newly registered, or targeted zero-day C2 domains."
    ]
    recommended_actions: List[str] = [
        "Conduct isolated dynamic sandbox analysis in an instrumented Android emulator with network capture enabled.",
        "Submit extracted hashes and C2 indicators to authorized law-enforcement threat intelligence repositories.",
        "Decompile associated DEX classes in JADX for manual decompiled Java inspection of command dispatch loops.",
        "Cross-reference signing certificate serial and fingerprints against known actor keystores."
    ]

    # 1. Reverse Shell Evaluation (High to Critical Impact)
    has_critical_revshell = any(rs.severity == "Critical" for rs in reverse_shell_findings)
    has_high_revshell = any(rs.severity == "High" for rs in reverse_shell_findings)
    if has_critical_revshell:
        risk_score += 40
        strongest_evidence.append("Probable interactive reverse-shell execution chain combining network sockets and local shell processes.")
        potential_functionality.append("Interactive Remote Shell Access & Arbitrary OS Command Execution")
    elif has_high_revshell:
        risk_score += 25
        strongest_evidence.append("Remote command execution indicators detected (process spawning alongside socket connectivity).")
        potential_functionality.append("Potential Remote Command Dispatch")

    # 2. C2 Indicators Evaluation
    confirmed_c2 = [c for c in c2_indicators if c.classification == "potential_c2"]
    if confirmed_c2:
        risk_score += min(len(confirmed_c2) * 15, 30)
        strongest_evidence.append(f"Identified {len(confirmed_c2)} potential C2 communication configurations (e.g. Dynamic DNS / non-standard ports).")
        potential_functionality.append("Command-and-Control (C2) Network Beaconing")

    # 3. YARA Signature Matches
    yara_findings = [f for f in static_findings if f.category == "yara_signature"]
    if yara_findings:
        risk_score += min(len(yara_findings) * 15, 25)
        for yf in yara_findings:
            strongest_evidence.append(f"YARA Rule Triggered: {yf.title}")

    # 4. Manifest High Risk Combinations
    manifest_high = [f for f in static_findings if f.category == "manifest" and f.severity in ("High", "Critical")]
    if manifest_high:
        risk_score += min(len(manifest_high) * 10, 20)
        for mf in manifest_high:
            strongest_evidence.append(f"Manifest Finding: {mf.title}")
            if "Accessibility" in mf.title:
                potential_functionality.append("Accessibility-based Screen Scraping / Tapjacking")
            if "SMS" in mf.title:
                potential_functionality.append("SMS Interception / 2FA Verification Theft")
            if "Persistence" in mf.title:
                potential_functionality.append("Boot Startup Persistence")

    # 5. Secrets and Hardcoded Tokens
    sensitive_tokens = [s for s in secrets if s.token_category in ("cloud_credential", "private_key", "telegram_bot", "api_key")]
    if sensitive_tokens:
        risk_score += min(len(sensitive_tokens) * 5, 15)
        strongest_evidence.append(f"Extracted {len(sensitive_tokens)} hardcoded tokens or API credentials.")
        potential_functionality.append("Hardcoded Credential Exposure")

    # Clamp risk score
    risk_score = min(max(risk_score, 0), 100)

    # Determine Severity
    if risk_score >= 75:
        overall_severity = "Critical"
    elif risk_score >= 50:
        overall_severity = "High"
    elif risk_score >= 25:
        overall_severity = "Medium"
    elif risk_score > 5:
        overall_severity = "Low"
    else:
        overall_severity = "Informational"

    # Determine Confidence
    if has_critical_revshell or (confirmed_c2 and yara_findings):
        overall_confidence = "High"
    elif risk_score >= 25:
        overall_confidence = "Medium"
    else:
        overall_confidence = "Low"

    # Executive Summary Generation
    if overall_severity in ("High", "Critical"):
        exec_summary = (
            f"Forensic static analysis of the submitted APK indicates elevated malicious indicators (Severity: {overall_severity}, Risk Score: {risk_score}/100, Confidence: {overall_confidence}). "
            f"Key observations include {'; '.join(strongest_evidence[:3])}. "
            "These capabilities are inconsistent with benign commercial utility applications and warrant immediate quarantine, reverse engineering, and threat intelligence correlation."
        )
    elif overall_severity == "Medium":
        exec_summary = (
            f"Forensic static analysis detected suspicious patterns (Severity: Medium, Risk Score: {risk_score}/100, Confidence: {overall_confidence}). "
            f"Notable indicators include {'; '.join(strongest_evidence[:2]) if strongest_evidence else 'misconfigured permissions or exported services'}. "
            "Further manual analysis of decompiled bytecode is advised to differentiate between dual-use administrative tooling and malicious functionality."
        )
    else:
        exec_summary = (
            f"Forensic static analysis of the submitted APK identified no immediate high-confidence malicious signatures (Severity: {overall_severity}, Risk Score: {risk_score}/100). "
            "Identified indicators represent standard application lifecycle, third-party libraries, or benign development configurations."
        )

    if not confirmed_c2:
        unanswered_questions.append("Are C2 hostnames constructed dynamically at runtime through string concatenation or downloaded from remote configuration?")
    if not reverse_shell_findings:
        unanswered_questions.append("Does the application implement remote command execution via alternative channels such as FCM push notifications or WebView bridges?")

    return FinalAssessment(
        overall_severity=overall_severity,
        overall_confidence=overall_confidence,
        risk_score=risk_score,
        executive_summary=exec_summary,
        strongest_evidence=strongest_evidence,
        potential_malicious_functionality=potential_functionality,
        unanswered_questions=unanswered_questions,
        limitations=limitations,
        recommended_actions=recommended_actions,
        dynamic_analysis_conducted=False,
        external_intelligence_used=is_external_intel_used
    )
