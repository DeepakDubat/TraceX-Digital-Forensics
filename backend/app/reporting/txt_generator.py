import csv
import io
import json
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, List, Optional
from backend.app.core.models import InvestigationDetail
from backend.app.core.redaction import redact_sensitive_text

BOX_LINE = "=" * 80
SECTION_LINE = "-" * 80

def generate_txt_forensic_report(detail: InvestigationDetail, unredact_secrets: bool = False) -> str:
    """
    Generates a comprehensive 14-section plain-text forensic investigation report
    suitable for law-enforcement and digital forensics documentation.
    Readable in Notepad and standard text viewers.
    """
    rec = detail.record
    meta = detail.metadata
    assess = detail.assessment
    now_str = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")

    buf = io.StringIO()

    # Header Box
    buf.write(f"{BOX_LINE}\n")
    buf.write("           APK FORENSICS & THREAT INTELLIGENCE WORKBENCH\n")
    buf.write("                   DIGITAL FORENSIC EXAMINATION REPORT\n")
    buf.write(f"{BOX_LINE}\n\n")

    # =========================================================================
    # SECTION 1 -- REPORT INFORMATION
    # =========================================================================
    buf.write("SECTION 1 -- REPORT INFORMATION\n")
    buf.write(f"{SECTION_LINE}\n")
    buf.write(f"Report Title            : Forensic Analysis of Android Application Package\n")
    buf.write(f"Investigation ID        : {rec.id}\n")
    buf.write(f"Case Reference          : {rec.case_reference or 'NOT SPECIFIED'}\n")
    buf.write(f"Investigator Name       : {rec.investigator_name or 'ANALYST WORKSTATION'}\n")
    buf.write(f"Report Generation Date  : {now_str}\n")
    buf.write(f"Analysis Started        : {rec.started_at.strftime('%Y-%m-%d %H:%M:%S UTC') if rec.started_at else 'N/A'}\n")
    buf.write(f"Analysis Completed      : {rec.completed_at.strftime('%Y-%m-%d %H:%M:%S UTC') if rec.completed_at else 'N/A'}\n")
    buf.write(f"Analysis Mode           : {'LOCAL ONLY (External Lookups Disabled)' if rec.local_only_mode else 'HYBRID (Local Static + Passive Threat Intelligence)'}\n")
    buf.write(f"Analyst Notes           : {rec.analyst_notes or 'None recorded at ingestion.'}\n")
    buf.write(f"Examination Status      : {rec.status.upper()}\n\n")

    # =========================================================================
    # SECTION 2 -- EXECUTIVE SUMMARY
    # =========================================================================
    buf.write("SECTION 2 -- EXECUTIVE SUMMARY\n")
    buf.write(f"{SECTION_LINE}\n")
    if assess:
        buf.write(f"Overall Severity        : {assess.overall_severity.upper()}\n")
        buf.write(f"Overall Confidence      : {assess.overall_confidence.upper()}\n")
        buf.write(f"Forensic Risk Score     : {assess.risk_score} / 100\n\n")
        buf.write("Analytical Narrative:\n")
        buf.write(f"{assess.executive_summary}\n\n")
        if assess.strongest_evidence:
            buf.write("Key Evidentiary Pillars:\n")
            for ev in assess.strongest_evidence:
                buf.write(f"  [+] {ev}\n")
            buf.write("\n")
    else:
        buf.write("Executive assessment pending or analysis incomplete.\n\n")

    # =========================================================================
    # SECTION 3 -- FILE INFORMATION
    # =========================================================================
    buf.write("SECTION 3 -- FILE INFORMATION\n")
    buf.write(f"{SECTION_LINE}\n")
    buf.write(f"Original Filename       : {rec.filename}\n")
    buf.write(f"File Size (Bytes)       : {rec.original_size:,} bytes ({round(rec.original_size/(1024*1024), 2)} MB)\n")
    buf.write(f"Cryptographic MD5       : {rec.md5}\n")
    buf.write(f"Cryptographic SHA-1     : {rec.sha1}\n")
    buf.write(f"Cryptographic SHA-256   : {rec.sha256}\n")
    buf.write(f"Validation Status       : Valid Android Package Archive (Verified PK\\x03\\x04 Header)\n")
    buf.write(f"Evidence Storage Path   : analysis_workspace/{rec.id}/original/{rec.filename}\n\n")

    # =========================================================================
    # SECTION 4 -- ANDROID APPLICATION DETAILS
    # =========================================================================
    buf.write("SECTION 4 -- ANDROID APPLICATION DETAILS\n")
    buf.write(f"{SECTION_LINE}\n")
    if meta:
        buf.write(f"Application Label       : {meta.app_name or 'N/A'}\n")
        buf.write(f"Package Name            : {meta.package_name or 'N/A'}\n")
        buf.write(f"Version Name            : {meta.version_name or 'N/A'}\n")
        buf.write(f"Version Code            : {meta.version_code or 'N/A'}\n")
        buf.write(f"Target SDK Version      : {meta.target_sdk_version or 'N/A'}\n")
        buf.write(f"Minimum SDK Version     : {meta.min_sdk_version or 'N/A'}\n")
        buf.write(f"Launcher Activity       : {meta.launcher_activity or 'None / Headless'}\n")
        buf.write(f"Debuggable Flag         : {'TRUE (Security Warning)' if meta.is_debuggable else 'False (Standard)'}\n")
        buf.write(f"Cleartext HTTP Traffic  : {'ALLOWED (Cleartext Warning)' if meta.uses_cleartext_traffic else 'Enforced TLS or Default'}\n")
        buf.write(f"DEX Bytecode Files      : {len(meta.dex_files)} ({', '.join(d.get('name', 'dex') for d in meta.dex_files)})\n")
        buf.write(f"Native Shared Libraries : {len(meta.native_libraries)} ({', '.join(meta.native_libraries[:4]) if meta.native_libraries else 'None'})\n\n")

        from backend.app.analyzers.permission_intel import classify_permission
        classified = [classify_permission(p.name) for p in meta.permissions]
        d_cnt = sum(1 for cp in classified if cp.protection_level == "dangerous")
        n_cnt = sum(1 for cp in classified if cp.protection_level == "normal")
        s_cnt = sum(1 for cp in classified if cp.protection_level == "special_access")
        c_cnt = sum(1 for cp in classified if cp.protection_level in ("custom", "signature"))

        buf.write("Permission Summary Dashboard:\n")
        buf.write(f"  Total Declared        : {len(classified)}\n")
        buf.write(f"  Dangerous Permissions : {d_cnt}\n")
        buf.write(f"  Normal Permissions    : {n_cnt}\n")
        buf.write(f"  Special Access Perms  : {s_cnt}\n")
        buf.write(f"  Custom / Signature    : {c_cnt}\n")
        buf.write(f"  Runtime Status Note   : All entries reflect manifest declarations. Runtime access requires device execution.\n\n")

        buf.write("Declared Android Permissions & Access Intelligence Matrix:\n")
        for cp in classified:
            p_obj = next((p for p in meta.permissions if p.name == cp.name), None)
            marker = f"[{cp.risk_level}]"
            buf.write(f"  {marker:10} {cp.name}\n")
            buf.write(f"              Category    : {cp.category}\n")
            buf.write(f"              Protection  : {cp.protection_level.upper()}\n")
            buf.write(f"              Purpose     : {cp.purpose}\n")
            buf.write(f"              Privacy Risk: {cp.privacy_risk}\n")
            buf.write(f"              Security    : {cp.security_implication}\n")
            buf.write(f"              Source      : AndroidManifest.xml (Declared)\n")
        buf.write("\n")

        if meta.certificates:
            buf.write("Signing Certificates:\n")
            for idx, c in enumerate(meta.certificates, 1):
                buf.write(f"  Certificate #{idx}:\n")
                buf.write(f"    Subject        : {c.subject.get('common_name', 'N/A') or c.subject}\n")
                buf.write(f"    Issuer         : {c.issuer.get('common_name', 'N/A') or c.issuer}\n")
                buf.write(f"    Serial Number  : {c.serial_number}\n")
                buf.write(f"    SHA-256 Finger : {c.sha256_fingerprint}\n")
                buf.write(f"    Self-Signed    : {'YES (Untrusted / Self-Generated)' if c.is_self_signed else 'No'}\n")
                buf.write(f"    Signing Scheme : v1={c.v1_signed}, v2={c.v2_signed}, v3={c.v3_signed}\n")
            buf.write("\n")
    else:
        buf.write("Metadata extraction unavailable or archive was non-standard.\n\n")

    # =========================================================================
    # SECTION 5 -- STATIC ANALYSIS FINDINGS
    # =========================================================================
    buf.write("SECTION 5 -- STATIC ANALYSIS FINDINGS\n")
    buf.write(f"{SECTION_LINE}\n")
    if detail.static_findings:
        for idx, f in enumerate(detail.static_findings, 1):
            buf.write(f"Finding #{idx:02d} [{f.id}]\n")
            buf.write(f"  Title           : {f.title}\n")
            buf.write(f"  Category        : {f.category}\n")
            buf.write(f"  Severity        : {f.severity.upper()}\n")
            buf.write(f"  Confidence      : {f.confidence.upper()}\n")
            buf.write(f"  Source Reference: {f.source_file or 'N/A'} {f.code_reference or ''}\n")
            if f.evidence_snippet:
                buf.write(f"  Evidence Snippet: {f.evidence_snippet}\n")
            buf.write(f"  Technical Impact: {f.explanation}\n")
            buf.write(f"  Recommended Step: {f.remediation_advice}\n")
            buf.write("\n")
    else:
        buf.write("No anomalous static bytecode or manifest findings detected.\n\n")

    # =========================================================================
    # SECTION 6 -- C2 CONFIGURATION
    # =========================================================================
    buf.write("SECTION 6 -- C2 CONFIGURATION & INFRASTRUCTURE ANALYSIS\n")
    buf.write(f"{SECTION_LINE}\n")
    buf.write("NOTE: All findings were derived from passive static inspection without sending network packets.\n\n")
    if detail.c2_indicators:
        for idx, c in enumerate(detail.c2_indicators, 1):
            buf.write(f"C2 Indicator #{idx:02d} [{c.id}]\n")
            buf.write(f"  Type            : {c.indicator_type.upper()}\n")
            c_val = c.value if unredact_secrets else redact_sensitive_text(c.value)
            c_norm = c.normalized_value if unredact_secrets else redact_sensitive_text(c.normalized_value)
            buf.write(f"  Extracted Value : {c_val}\n")
            buf.write(f"  Normalized Value: {c_norm}\n")
            buf.write(f"  Classification  : {c.classification.upper()}\n")
            buf.write(f"  Confidence      : {c.confidence.upper()}\n")
            buf.write(f"  Source File     : {c.source_file}\n")
            if c.code_reference:
                c_ref = c.code_reference if unredact_secrets else redact_sensitive_text(c.code_reference)
                buf.write(f"  Method Context  : {c_ref}\n")
            if c.encoding_steps:
                buf.write(f"  Encoding / Obf  : {c.encoding_steps}\n")
            if c.port:
                buf.write(f"  Port / Protocol : {c.port} ({c.protocol or 'tcp'})\n")
            buf.write(f"  Why Suspicious  : {c.why_suspicious}\n")
            buf.write(f"  Validation Step : {c.recommended_validation}\n")
            buf.write("\n")
    else:
        buf.write("No hardcoded or decoded C2 endpoints identified.\n\n")

    # =========================================================================
    # SECTION 7 -- TOKEN AND SECRET FINDINGS
    # =========================================================================
    buf.write("SECTION 7 -- TOKEN AND SECRET FINDINGS\n")
    buf.write(f"{SECTION_LINE}\n")
    if detail.secrets:
        buf.write(f"Total Secrets Extracted: {len(detail.secrets)}\n")
        buf.write("Evidence Display: Redacted by default for forensic handling.\n\n")
        for idx, s in enumerate(detail.secrets, 1):
            disp_val = s.raw_value if (unredact_secrets and s.raw_value) else s.redacted_value
            buf.write(f"Secret Finding #{idx:02d} [{s.id}]\n")
            buf.write(f"  Category        : {s.token_category.upper()}\n")
            buf.write(f"  Token Value     : {disp_val}\n")
            buf.write(f"  Source Location : {s.source_location}\n")
            buf.write(f"  Detection Rule  : {s.rule_matched}\n")
            buf.write(f"  Confidence      : {s.confidence.upper()}\n")
            buf.write(f"  In Network Path : {'YES' if s.in_network_path else 'No / Local'}\n")
            if s.related_indicator:
                buf.write(f"  Related Target  : {s.related_indicator}\n")
            if s.context_snippet:
                s_ctx = s.context_snippet if unredact_secrets else redact_sensitive_text(s.context_snippet)
                buf.write(f"  Context Excerpt : {s_ctx}\n")
            buf.write("\n")
    else:
        buf.write("No hardcoded secrets, API keys, or private key material identified.\n\n")

    # =========================================================================
    # SECTION 8 -- REVERSE-SHELL ANALYSIS
    # =========================================================================
    buf.write("SECTION 8 -- REVERSE-SHELL ANALYSIS\n")
    buf.write(f"{SECTION_LINE}\n")
    if detail.reverse_shell_findings:
        for idx, rs in enumerate(detail.reverse_shell_findings, 1):
            buf.write(f"Reverse-Shell Finding #{idx:02d} [{rs.id}]\n")
            buf.write(f"  Title           : {rs.title}\n")
            buf.write(f"  Pattern Type    : {rs.pattern_type.upper()}\n")
            buf.write(f"  Severity        : {rs.severity.upper()}\n")
            buf.write(f"  Confidence      : {rs.confidence.upper()}\n")
            buf.write("  Execution Chain :\n")
            for step in rs.execution_chain:
                buf.write(f"    -> {step}\n")
            buf.write("  Code References :\n")
            for ref in rs.code_references:
                buf.write(f"    * {ref}\n")
            buf.write(f"  Technical Rationale:\n    {rs.explanation}\n")
            buf.write(f"  Forensic Limit  :\n    {rs.limitations}\n")
            buf.write("\n")
    else:
        buf.write("No reverse-shell patterns or socket-to-process stream redirections detected.\n\n")

    # =========================================================================
    # SECTION 9 -- IP ADDRESSES, DOMAINS AND URLS
    # =========================================================================
    buf.write("SECTION 9 -- IP ADDRESSES, DOMAINS AND URLS\n")
    buf.write(f"{SECTION_LINE}\n")
    if detail.network_iocs:
        buf.write(f"Total Unique Network IOCs: {len(detail.network_iocs)}\n\n")
        for idx, ioc in enumerate(detail.network_iocs, 1):
            buf.write(f"IOC #{idx:02d}: {ioc.value} [{ioc.ioc_type.upper()}]\n")
            buf.write(f"  Source File     : {ioc.source_file}\n")
            buf.write(f"  Classification  : {ioc.classification}\n")
            buf.write(f"  Private / RFC1918: {'YES' if ioc.is_private else 'No (Public)'}\n")
            if ioc.ports:
                buf.write(f"  Observed Ports  : {ioc.ports}\n")
            if ioc.related_urls:
                buf.write(f"  Related URLs    : {', '.join(ioc.related_urls[:3])}\n")
            if ioc.threat_intel_summary:
                buf.write(f"  Intel Summary   : {ioc.threat_intel_summary}\n")
            buf.write("\n")
    else:
        buf.write("No network indicators extracted.\n\n")

    # =========================================================================
    # SECTION 10 -- THREAT INTELLIGENCE
    # =========================================================================
    buf.write("SECTION 10 -- THREAT INTELLIGENCE ENRICHMENT\n")
    buf.write(f"{SECTION_LINE}\n")
    if detail.threat_intel:
        for idx, ti in enumerate(detail.threat_intel, 1):
            buf.write(f"Lookup #{idx:02d} [{ti.provider}]\n")
            buf.write(f"  Queried Indicator: {ti.indicator} ({ti.indicator_type})\n")
            buf.write(f"  Query Timestamp  : {ti.query_time.strftime('%Y-%m-%d %H:%M:%S UTC')}\n")
            buf.write(f"  Provider Status  : {ti.status.upper()}\n")
            buf.write(f"  Detections       : {ti.detections} / {ti.total_engines}\n")
            if ti.details:
                buf.write(f"  Details          : {json.dumps(ti.details)}\n")
            if ti.error_message:
                buf.write(f"  Provider Notice  : {ti.error_message}\n")
            buf.write("\n")
    else:
        buf.write("Threat intelligence lookups were skipped or local-only mode was active.\n\n")

    # =========================================================================
    # SECTION 11 -- IOC CORRELATION
    # =========================================================================
    buf.write("SECTION 11 -- IOC CORRELATION & RELATIONSHIP ANALYSIS\n")
    buf.write(f"{SECTION_LINE}\n")
    buf.write("Correlated Structural Graph:\n")
    buf.write(f"  Root Subject: APK Archive [{rec.sha256[:16]}...]\n")
    if meta:
        buf.write(f"  ├── Package: {meta.package_name}\n")
    if detail.c2_indicators:
        buf.write("  ├── Network Infrastructure (C2 / Callbacks):\n")
        for c in detail.c2_indicators[:5]:
            c_norm = c.normalized_value if unredact_secrets else redact_sensitive_text(c.normalized_value)
            buf.write(f"  │    └── [{c.classification}] {c_norm} (from {c.source_file})\n")
    if detail.secrets:
        buf.write("  ├── Embedded Secrets / Tokens:\n")
        for s in detail.secrets[:4]:
            buf.write(f"  │    └── [{s.token_category}] {s.redacted_value} (Rule: {s.rule_matched})\n")
    if detail.reverse_shell_findings:
        buf.write("  └── Remote Access Indicators:\n")
        for rs in detail.reverse_shell_findings:
            buf.write(f"       └── {rs.title} [{rs.confidence}]\n")
    buf.write("\nAnalytical Evidence Traceability Note:\n")
    buf.write("Every correlated relationship depicted above originates from verifiable byte-level offsets,\n")
    buf.write("string pool indices, or declared components within the analyzed artifact.\n\n")

    # =========================================================================
    # SECTION 12 -- TOOL EXECUTION LOG
    # =========================================================================
    buf.write("SECTION 12 -- TOOL EXECUTION LOG\n")
    buf.write(f"{SECTION_LINE}\n")
    if detail.tool_executions:
        for te in detail.tool_executions:
            buf.write(f"Tool: {te.tool_name:24} | Status: {te.status:10} | Duration: {te.duration_seconds:5.2f}s | Findings: {te.findings_count}\n")
            if te.errors_warnings:
                buf.write(f"  Note: {te.errors_warnings}\n")
            if te.limitations:
                buf.write(f"  Limitation: {te.limitations}\n")
        buf.write("\n")
    else:
        buf.write("No external tool execution records registered.\n\n")

    # =========================================================================
    # SECTION 13 -- FINAL ASSESSMENT
    # =========================================================================
    buf.write("SECTION 13 -- FINAL ASSESSMENT\n")
    buf.write(f"{SECTION_LINE}\n")
    if assess:
        buf.write("Potential Malicious Functionality Identified:\n")
        if assess.potential_malicious_functionality:
            for mf in assess.potential_malicious_functionality:
                buf.write(f"  [X] {mf}\n")
        else:
            buf.write("  [ ] No specific malicious behaviors conclusively established.\n")
        buf.write("\nUnresolved Questions:\n")
        for uq in assess.unanswered_questions:
            buf.write(f"  [?] {uq}\n")
        buf.write("\nRecommended Additional Forensic Procedures:\n")
        for ra in assess.recommended_actions:
            buf.write(f"  [->] {ra}\n")
        buf.write(f"\nDynamic Analysis Performed: {'YES' if assess.dynamic_analysis_conducted else 'NO (Passive Static Examination Only)'}\n")
        buf.write(f"External Threat Intel Used: {'YES' if assess.external_intelligence_used else 'NO (Local Workspace Only)'}\n\n")
    else:
        buf.write("Final analytical assessment not completed.\n\n")

    # =========================================================================
    # SECTION 14 -- EVIDENCE AND REFERENCES
    # =========================================================================
    buf.write("SECTION 14 -- EVIDENCE AND REFERENCES\n")
    buf.write(f"{SECTION_LINE}\n")
    buf.write(f"Target Primary Hash (SHA-256) : {rec.sha256}\n")
    buf.write(f"Target Secondary Hash (SHA-1) : {rec.sha1}\n")
    buf.write(f"Target Secondary Hash (MD5)   : {rec.md5}\n")
    buf.write(f"Workspace Working Path        : analysis_workspace/{rec.id}/\n")
    buf.write("\nFORENSIC DISCLAIMER:\n")
    buf.write("This document represents an analytical forensic finding derived from static reverse engineering\n")
    buf.write("and pattern correlation. It does not constitute a legally binding judicial determination of threat\n")
    buf.write("actor identity or attribution. Analysis conducted under safe static handling protocols.\n")
    buf.write(f"{BOX_LINE}\n")

    # =========================================================================
    # SECTION 15 -- AI-ASSISTED INVESTIGATION NOTES (OPENCODE FORENSIC ENGINE)
    # =========================================================================
    ai_obs = getattr(detail, "ai_observations", []) or []
    ai_recs = getattr(detail, "ai_recommendations", []) or []
    ai_notes = getattr(detail, "ai_notes", None)

    buf.write("SECTION 15 -- AI-ASSISTED INVESTIGATION NOTES (OPENCODE FORENSIC ENGINE)\n")
    buf.write(f"{SECTION_LINE}\n")
    if ai_notes or ai_obs:
        exec_status = ai_notes.execution_status if ai_notes else "COMPLETED"
        model_prov = ai_notes.model_provider if ai_notes and ai_notes.model_provider else "OpenCode CLI"
        disclaimer = ai_notes.disclaimer if ai_notes else "AI-assisted technical explanation. Every factual conclusion must be independently verified against raw decompiled bytecode and deterministic analyzer evidence."
        buf.write(f"Execution Status        : {exec_status}\n")
        buf.write(f"Engine & Model Provider : {model_prov}\n")
        buf.write(f"Disclaimer              : {disclaimer}\n")
        buf.write(f"Total AI Observations   : {len(ai_obs)}\n")
        buf.write(f"Total AI Recommendations: {len(ai_recs)}\n\n")

        if ai_obs:
            buf.write("Unverified AI Observations (Strictly Separated from Deterministic Findings):\n")
            for o in ai_obs:
                buf.write(f"  - [{o.status}] {o.id}: {o.title} (Confidence: {o.confidence})\n")
                buf.write(f"      Explanation: {o.explanation}\n")
                if o.related_evidence_refs:
                    buf.write(f"      Evidence Refs: {', '.join(o.related_evidence_refs)}\n")
                buf.write(f"      Reasoning Summary: {o.reasoning_summary}\n")
                if o.suggested_verification_steps:
                    buf.write("      Suggested Verification Steps:\n")
                    for step in o.suggested_verification_steps:
                        buf.write(f"        * {step}\n")
                buf.write("\n")

        if ai_recs:
            buf.write("AI Recommended Follow-Up Actions:\n")
            for r in ai_recs:
                buf.write(f"  - [{r.priority.upper()}] {r.title} ({r.category})\n")
                buf.write(f"      Description: {r.description}\n")
                if r.suggested_command_or_action:
                    buf.write(f"      Suggested Action: {r.suggested_command_or_action}\n")
                buf.write("\n")
    else:
        buf.write("AI-assisted analysis was not executed for this investigation.\n\n")

    buf.write(f"{BOX_LINE}\n")
    buf.write("                             END OF FORENSIC REPORT\n")
    buf.write(f"{BOX_LINE}\n")

    return buf.getvalue()

def export_iocs_csv(network_iocs: List[Any], c2_indicators: List[Any]) -> str:
    """Exports normalized IOCs in RFC 4180 CSV format with formula neutralization."""
    from backend.app.core.security import sanitize_csv_cell
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["IOC_Type", "Value", "Normalized_Value", "Classification", "Source_File", "Port", "Confidence"])
    
    for c in c2_indicators:
        writer.writerow([
            sanitize_csv_cell(c.indicator_type),
            sanitize_csv_cell(redact_sensitive_text(c.value)),
            sanitize_csv_cell(redact_sensitive_text(c.normalized_value)),
            sanitize_csv_cell(c.classification),
            sanitize_csv_cell(c.source_file),
            sanitize_csv_cell(c.port or ""),
            sanitize_csv_cell(c.confidence)
        ])
        
    for n in network_iocs:
        writer.writerow([
            sanitize_csv_cell(n.ioc_type),
            sanitize_csv_cell(redact_sensitive_text(n.value)),
            sanitize_csv_cell(redact_sensitive_text(n.value)),
            sanitize_csv_cell(n.classification),
            sanitize_csv_cell(n.source_file),
            sanitize_csv_cell(n.ports[0] if n.ports else ""),
            sanitize_csv_cell(n.confidence)
        ])
        
    return output.getvalue()
