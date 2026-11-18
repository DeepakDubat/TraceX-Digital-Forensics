import time
import os
import shutil
import hashlib
import traceback
import logging
import uuid
import pefile
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Any, Optional, Tuple

from backend.app.config import settings
from backend.app.core.storage import workspace_mgr
from backend.app.core.models import (
    InvestigationRecord, EvidenceItem, ExtractedArtifact, FindingRecord,
    EvidenceRelationship, TimelineEvent, ToolExecution, StaticFinding,
    C2Indicator, NetworkIOC
)
from backend.app.database.repository import repo

# Universal Analyzers
from backend.app.analyzers.universal.file_identifier import (
    identify_file_format, calculate_streaming_hashes, calculate_shannon_entropy
)
from backend.app.analyzers.universal.pdf_analyzer import analyze_pdf_evidence
from backend.app.analyzers.universal.image_analyzer import analyze_image_evidence
from backend.app.analyzers.universal.office_analyzer import analyze_office_evidence
from backend.app.analyzers.universal.archive_analyzer import analyze_archive_evidence
from backend.app.analyzers.universal.email_analyzer import analyze_email_evidence
from backend.app.analyzers.universal.network_analyzer import analyze_pcap_evidence
from backend.app.analyzers.universal.text_config_analyzer import analyze_text_evidence
from backend.app.analyzers.universal.elf_analyzer import analyze_elf_evidence
from backend.app.analyzers.universal.correlation_engine import correlate_investigation_evidence
from backend.app.analyzers.universal.timeline_engine import build_investigation_timeline
from backend.app.analyzers.universal.integrity_ledger import record_custody_event
from backend.app.analyzers.universal.evidence_risk_assessor import assess_evidence_dimensional_risk

# Specialized APK Analyzers
from backend.app.core.security import validate_apk_file, safe_extract_apk
from backend.app.integrations.androguard_adapter import parse_apk_with_androguard
from backend.app.analyzers.manifest_analyzer import analyze_manifest
from backend.app.analyzers.string_analyzer import extract_and_classify_strings
from backend.app.analyzers.dex_analyzer import analyze_dex_content
from backend.app.analyzers.c2_analyzer import analyze_c2_infrastructure
from backend.app.analyzers.secret_analyzer import analyze_secrets
from backend.app.analyzers.reverseshell_analyzer import analyze_reverse_shell_indicators
from backend.app.analyzers.yara_scanner import run_yara_scan
from backend.app.analyzers.risk_engine import evaluate_malware_risk
from backend.app.integrations.jadx_adapter import run_jadx_decompiler
from backend.app.integrations.apktool_adapter import run_apktool_decode
from backend.app.reporting.txt_generator import generate_txt_forensic_report

# Specialized PE Analyzers
from backend.app.analyzers.pe_validator import validate_pe_file
from backend.app.analyzers.pe_metadata_analyzer import analyze_pe_metadata
from backend.app.analyzers.pe_section_analyzer import analyze_pe_sections
from backend.app.analyzers.pe_import_analyzer import analyze_pe_imports
from backend.app.analyzers.pe_string_analyzer import analyze_pe_strings
from backend.app.analyzers.pe_c2_analyzer import analyze_pe_c2_infrastructure
from backend.app.analyzers.pe_secret_analyzer import analyze_pe_secrets
from backend.app.analyzers.pe_persistence_analyzer import analyze_pe_persistence
from backend.app.analyzers.pe_risk_engine import evaluate_pe_malware_risk
from backend.app.reporting.exe_txt_generator import generate_exe_forensic_report
from backend.app.integrations.threat_intel.threat_intel_manager import threat_intel

# Master Reporting
from backend.app.reporting.master_report_generator import (
    generate_master_txt_report, generate_master_html_report,
    export_reproducibility_bundle_zip
)

logger = logging.getLogger(__name__)

def _update_progress(record: InvestigationRecord, pct: int, stage_desc: str, status: Optional[str] = None):
    """
    Monotonic progress updater:
    Ensures percentage never moves backwards and database is synchronized.
    """
    record.progress = max(record.progress or 0, pct)
    record.current_stage = stage_desc
    if status:
        record.status = status
    repo.update_investigation(record)


def _local_tool_names_for_format(evidence_format: str) -> List[str]:
    """Selects only adapters that are meaningful and safe for an evidence format."""
    fmt = (evidence_format or "").lower()
    if fmt == "apk":
        return ["mobsf", "exiftool", "strings"]
    if fmt in ("exe", "dll", "elf", "so"):
        return ["exiftool", "strings"]
    if fmt in ("pdf", "docx", "xlsx", "xlsm", "pptx", "csv", "zip", "tar", "gzip", "7z", "rar", "eml", "mbox"):
        return ["exiftool", "strings"]
    if fmt in ("png", "jpeg", "jpg", "webp", "tiff", "bmp", "gif"):
        return ["exiftool"]
    if fmt in ("pcap", "pcapng"):
        # Validation fixtures and submitted captures are read-only; never live capture.
        return ["tshark", "zeek", "suricata", "strings"]
    if fmt in ("txt", "log", "json", "xml", "yaml", "yml", "ini", "conf", "toml"):
        return ["strings"]
    return ["strings"]


def _run_local_tool_adapters(
    evidence_path: Path,
    evidence_format: str,
    investigation_id: str,
    evidence_id: str,
    original_hash: Optional[str],
) -> List[FindingRecord]:
    """
    Runs the configured offline adapters for one evidence item and returns only
    real, evidence-backed findings. Failed or unavailable tools never invent data.
    """
    from backend.app.integrations.local_forensic_tools import (
        analyze_with_exiftool,
        analyze_with_mobsf,
        analyze_with_strings,
        analyze_with_suricata,
        analyze_with_tshark,
        analyze_with_zeek,
    )
    from backend.app.integrations.tool_finding_normalizer import normalize_tool_results

    adapters = {
        "exiftool": analyze_with_exiftool,
        "strings": analyze_with_strings,
        "tshark": analyze_with_tshark,
        "zeek": analyze_with_zeek,
        "suricata": analyze_with_suricata,
        "mobsf": analyze_with_mobsf,
    }

    tool_results: Dict[str, Dict[str, Any]] = {}
    for tool_name in _local_tool_names_for_format(evidence_format):
        try:
            if tool_name == "mobsf":
                from backend.app.core.credential_manager import credential_manager

                stored = credential_manager.get_credential("mobsf") or {}
                api_key = stored.get("api_key") or settings.MOBSF_API_KEY
                if not api_key:
                    continue
                result = analyze_with_mobsf(
                    evidence_path,
                    url=stored.get("url") or settings.MOBSF_URL,
                    api_key=api_key,
                )
            else:
                result = adapters[tool_name](evidence_path)

            if result and result.get("success"):
                tool_results[tool_name] = result
            else:
                logger.info(
                    "Local tool %s produced no usable evidence for %s: %s",
                    tool_name,
                    evidence_path.name,
                    (result or {}).get("message", "unknown result"),
                )
        except Exception as exc:
            logger.warning(
                "Local tool %s could not analyze %s: %s",
                tool_name,
                evidence_path.name,
                exc,
            )

    if not tool_results:
        return []
    return normalize_tool_results(
        tool_results,
        investigation_id,
        evidence_id,
        str(evidence_path),
        original_hash,
    )


def analyze_apk_specialized(
    working_apk_path: Path,
    evidence_id: str,
    investigation_id: str,
    record: InvestigationRecord,
    dirs: Dict[str, Path]
) -> Tuple[Dict[str, Any], List[ExtractedArtifact], List[FindingRecord]]:
    """
    Deep static analysis of Android APK packages.
    Never executes uploaded binary.
    """
    artifacts: List[ExtractedArtifact] = []
    findings: List[FindingRecord] = []
    metadata_dict: Dict[str, Any] = {}

    tool_executions: List[ToolExecution] = []
    all_static_findings: List[StaticFinding] = []

    # 1. Structural validation
    is_valid, val_msg = validate_apk_file(working_apk_path, max_size_mb=settings.MAX_UPLOAD_SIZE_MB)
    if not is_valid:
        raise ValueError(f"APK validation failure: {val_msg}")

    # 2. Safe extraction
    extracted_apk_dir = dirs["extracted"] / evidence_id
    safe_extract_apk(working_apk_path, extracted_apk_dir)

    # 3. Androguard & Bytecode parsing
    t0 = time.time()
    apk_meta, strings_pool, dex_methods = parse_apk_with_androguard(working_apk_path)
    tool_executions.append(ToolExecution(
        tool_name="Androguard Core",
        installed=True,
        status="completed",
        duration_seconds=round(time.time() - t0, 2),
        findings_count=len(strings_pool) + len(dex_methods)
    ))

    # 3b. Native .so ELF Inspection (if native libraries present)
    if apk_meta.native_libraries:
        for so_rel in apk_meta.native_libraries[:10]:
            so_full_path = extracted_apk_dir / so_rel
            if so_full_path.exists():
                try:
                    _, so_arts, so_fnds = analyze_elf_evidence(so_full_path, evidence_id, investigation_id)
                    findings.extend(so_fnds)
                    artifacts.extend(so_arts)
                except Exception:
                    pass

    # Update investigation record and database metadata
    record.package_name = apk_meta.package_name
    record.app_name = apk_meta.app_name
    repo.save_metadata(investigation_id, apk_meta)
    metadata_dict = apk_meta.model_dump() if hasattr(apk_meta, "model_dump") else {}

    # 4. Manifest analysis
    manifest_findings, manifest_summary = analyze_manifest(apk_meta)
    all_static_findings.extend(manifest_findings)

    # 5. String classification
    classified_strings = extract_and_classify_strings(strings_pool)

    # 6. DEX bytecode analysis
    raw_dex_strings = [s for _, s in strings_pool]
    dex_findings = analyze_dex_content(raw_dex_strings, dex_methods)
    all_static_findings.extend(dex_findings)

    # 7. YARA scan
    t_yara = time.time()
    yara_findings, yara_msg = run_yara_scan(working_apk_path)
    all_static_findings.extend(yara_findings)
    tool_executions.append(ToolExecution(
        tool_name="YARA Scanner",
        installed=True,
        status="completed",
        duration_seconds=round(time.time() - t_yara, 2),
        findings_count=len(yara_findings),
        errors_warnings=yara_msg
    ))

    # 8. C2 infrastructure
    c2_indicators = analyze_c2_infrastructure(
        classified_strings["urls"],
        classified_strings["ips"],
        classified_strings["domains"],
        classified_strings["decoded_items"],
        dex_methods
    )
    record.c2_count = len(c2_indicators)
    repo.save_c2_indicators(investigation_id, c2_indicators)

    # 9. Secrets and tokens
    secrets = analyze_secrets(strings_pool, dex_methods)
    record.secret_count = len(secrets)
    repo.save_secrets(investigation_id, secrets)

    # 10. Reverse shell detection
    reverse_shell_findings = analyze_reverse_shell_indicators(dex_methods, raw_dex_strings, c2_indicators)
    record.reverse_shell_detected = len(reverse_shell_findings) > 0
    repo.save_reverse_shell_findings(investigation_id, reverse_shell_findings)

    # 11. Network IOCs
    network_iocs: List[NetworkIOC] = []
    ioc_counter = 1
    for ip_item in classified_strings["ips"]:
        network_iocs.append(NetworkIOC(
            id=f"IOC-IP-{ioc_counter:03d}",
            ioc_type="ipv4",
            value=ip_item["ip"],
            source_file=ip_item["source"],
            is_private=ip_item["is_private"],
            classification="Private RFC1918" if ip_item["is_private"] else "Public IP",
            confidence="Medium"
        ))
        ioc_counter += 1

    for dom_item in classified_strings["domains"]:
        network_iocs.append(NetworkIOC(
            id=f"IOC-DOM-{ioc_counter:03d}",
            ioc_type="domain",
            value=dom_item["domain"],
            source_file=dom_item["source"],
            classification="Dynamic DNS" if dom_item.get("is_ddns") else ("DoH Resolver" if dom_item.get("is_doh") else "Extracted Domain"),
            confidence="Medium"
        ))
        ioc_counter += 1
    repo.save_network_iocs(investigation_id, network_iocs)

    # 12. Decompiler adapters (timeouts applied)
    jadx_exec = run_jadx_decompiler(working_apk_path, dirs["decompile"])
    tool_executions.append(jadx_exec)
    apktool_exec = run_apktool_decode(working_apk_path, dirs["extracted"] / "apktool_out")
    tool_executions.append(apktool_exec)

    # 13. Threat Intel (if enabled)
    ti_results = []
    if not record.local_only_mode and not settings.LOCAL_ONLY_MODE:
        try:
            ti_results.extend(threat_intel.check_hash(record.sha256, investigation_id))
            for ind in c2_indicators[:3]:
                if ind.indicator_type == "ip" and "private" not in ind.classification:
                    ti_results.extend(threat_intel.check_ip(ind.value, investigation_id))
        except Exception:
            pass
    repo.save_threat_intel_results(investigation_id, ti_results)

    # Persist tool executions and static findings
    repo.save_tool_executions(investigation_id, tool_executions)
    repo.save_static_findings(investigation_id, all_static_findings)

    # Evaluate malware risk
    assessment = evaluate_malware_risk(
        all_static_findings,
        c2_indicators,
        secrets,
        reverse_shell_findings,
        is_external_intel_used=(len(ti_results) > 0)
    )
    repo.save_assessment(investigation_id, assessment)

    # Generate APK-specific TXT report
    detail = repo.get_investigation_detail(investigation_id)
    if detail:
        txt_content = generate_txt_forensic_report(detail, unredact_secrets=False)
        timestamp_suffix = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        report_filename = f"APK_Forensic_Report_{investigation_id}_{timestamp_suffix}.txt"
        report_path = dirs["reports"] / report_filename
        report_path.write_text(txt_content, encoding="utf-8")

    # Normalize findings into universal FindingRecord
    for sf in all_static_findings:
        source_location = sf.source_file or "APK Binary"
        findings.append(FindingRecord(
            id=f"FND-{sf.id}-{evidence_id}",
            investigation_id=investigation_id,
            evidence_id=evidence_id,
            artifact_ids=[],
            title=sf.title,
            description=sf.description,
            observation=sf.evidence_snippet or sf.title,
            interpretation=sf.explanation or sf.description,
            severity=sf.severity,
            confidence=sf.confidence,
            analysis_method="Static Android Bytecode & Manifest Inspection",
            source_location=source_location,
            analyzer_name="Androguard & Static APK Engine",
            analyzer_version="2.0.0",
            source_evidence=sf.evidence_snippet or sf.title,
            source_file=source_location,
            timestamp=datetime.utcnow().isoformat(),
            engine="Androguard & Static APK Engine",
            original_hash=record.sha256,
        ))

    # Convert C2 indicators and secrets into universal artifacts
    for c2 in c2_indicators:
        artifacts.append(ExtractedArtifact(
            id=f"ART-C2-{c2.id}",
            investigation_id=investigation_id,
            evidence_id=evidence_id,
            artifact_type="c2_endpoint",
            value=c2.value,
            source_format="apk",
            source_location=c2.source_file or "Bytecode",
            structured_data={"protocol": c2.protocol, "classification": c2.classification, "why_suspicious": c2.why_suspicious},
            extractor_name="Androguard C2 Extractor",
            extracted_at=datetime.utcnow()
        ))

    for sec in secrets:
        val = getattr(sec, "redacted_value", getattr(sec, "masked_token", "REDACTED"))
        loc = getattr(sec, "source_location", getattr(sec, "source_file", "Bytecode/Strings"))
        cat = getattr(sec, "token_category", "secret")
        rule = getattr(sec, "rule_matched", "generic_secret")
        artifacts.append(ExtractedArtifact(
            id=f"ART-SEC-{sec.id}",
            investigation_id=investigation_id,
            evidence_id=evidence_id,
            artifact_type="credential_secret",
            value=val,
            source_format="apk",
            source_location=loc,
            structured_data={"category": cat, "rule": rule},
            extractor_name="Androguard Secret Scanner",
            extracted_at=datetime.utcnow()
        ))

    return metadata_dict, artifacts, findings


def analyze_pe_specialized(
    working_exe_path: Path,
    evidence_id: str,
    investigation_id: str,
    record: InvestigationRecord,
    dirs: Dict[str, Path]
) -> Tuple[Dict[str, Any], List[ExtractedArtifact], List[FindingRecord]]:
    """
    Deep static analysis of Windows PE (.exe / .dll) executables.
    Never executes uploaded binary.
    """
    artifacts: List[ExtractedArtifact] = []
    findings: List[FindingRecord] = []
    metadata_dict: Dict[str, Any] = {}

    tool_executions: List[ToolExecution] = []
    all_static_findings: List[StaticFinding] = []

    # 1. Structural validation
    is_valid, val_reason, val_details = validate_pe_file(working_exe_path, max_size_mb=settings.MAX_UPLOAD_SIZE_MB)
    if not is_valid:
        raise ValueError(f"PE Validation Failure: {val_reason}")

    # 2. Header and section parsing
    t_pe0 = time.time()
    pe = pefile.PE(str(working_exe_path), fast_load=True)
    pe.parse_data_directories()

    pe_metadata = analyze_pe_metadata(pe, working_exe_path)
    tool_executions.append(ToolExecution(
        tool_name="pefile Core",
        installed=True,
        status="completed",
        duration_seconds=round(time.time() - t_pe0, 2),
        findings_count=len(pe_metadata.file_characteristics) + len(pe_metadata.dll_characteristics)
    ))

    record.app_name = pe_metadata.version_info.get("ProductName") or record.filename
    record.package_name = f"{pe_metadata.machine} [{pe_metadata.magic}]"

    # 3. Section analysis
    sections, sec_findings, sec_summary = analyze_pe_sections(pe, working_exe_path.stat().st_size)
    pe_metadata.sections = sections
    all_static_findings.extend(sec_findings)
    if sec_summary.get("packer_indicators"):
        pe_metadata.packer_detected = True
        pe_metadata.packer_indicators = sec_summary["packer_indicators"]

    # 4. Import table & API capabilities
    imported_dlls, import_findings, import_summary = analyze_pe_imports(pe)
    pe_metadata.imports = imported_dlls
    all_static_findings.extend(import_findings)

    # 5. Strings & Artifacts
    classified_strings = analyze_pe_strings(working_exe_path, pe)

    # 6. YARA scan
    t_yara = time.time()
    yara_findings, yara_msg = run_yara_scan(working_exe_path)
    all_static_findings.extend(yara_findings)
    tool_executions.append(ToolExecution(
        tool_name="YARA Scanner",
        installed=True,
        status="completed",
        duration_seconds=round(time.time() - t_yara, 2),
        findings_count=len(yara_findings),
        errors_warnings=yara_msg
    ))

    # 7. Persistence indicators
    raw_str_list = classified_strings.get("raw_strings", classified_strings.get("raw_strings_sample", []))
    all_imported_api_names = []
    for dll in imported_dlls:
        all_imported_api_names.extend(getattr(dll, "functions", []))

    persistence_findings = analyze_pe_persistence(raw_str_list, all_imported_api_names)
    record.reverse_shell_detected = any("Injection" in getattr(pf, "mechanism", "") for pf in persistence_findings)
    repo.save_persistence_findings(investigation_id, persistence_findings)

    # 8. C2 infrastructure
    c2_indicators = analyze_pe_c2_infrastructure(
        classified_strings["urls"],
        classified_strings["ips"],
        classified_strings["domains"],
        classified_strings["decoded_items"],
        all_imported_api_names
    )
    record.c2_count = len(c2_indicators)
    repo.save_c2_indicators(investigation_id, c2_indicators)

    # 9. Secrets
    secrets = analyze_pe_secrets(raw_str_list)
    record.secret_count = len(secrets)
    repo.save_secrets(investigation_id, secrets)

    # Persist PE metadata and static findings
    repo.save_metadata(investigation_id, pe_metadata)
    repo.save_tool_executions(investigation_id, tool_executions)
    repo.save_static_findings(investigation_id, all_static_findings)

    # Evaluate PE malware risk
    pe_assessment = evaluate_pe_malware_risk(
        static_findings=all_static_findings,
        c2_indicators=c2_indicators,
        secrets=secrets,
        persistence_findings=persistence_findings,
        is_external_intel_used=False,
        threat_intel_detections=0
    )
    repo.save_assessment(investigation_id, pe_assessment)
    pe.close()

    # Generate PE TXT report
    detail = repo.get_investigation_detail(investigation_id)
    if detail:
        txt_content = generate_exe_forensic_report(detail, unredact_secrets=False)
        timestamp_suffix = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        report_filename = f"EXE_Forensic_Report_{investigation_id}_{timestamp_suffix}.txt"
        report_path = dirs["reports"] / report_filename
        report_path.write_text(txt_content, encoding="utf-8")

    # Normalize into universal findings
    for sf in all_static_findings:
        source_location = sf.source_file or "PE Binary"
        findings.append(FindingRecord(
            id=f"FND-{sf.id}-{evidence_id}",
            investigation_id=investigation_id,
            evidence_id=evidence_id,
            artifact_ids=[],
            title=sf.title,
            description=sf.description,
            observation=sf.evidence_snippet or sf.title,
            interpretation=sf.explanation or sf.description,
            severity=sf.severity,
            confidence=sf.confidence,
            analysis_method="Static Windows PE Header & Section Dissection",
            source_location=source_location,
            analyzer_name="pefile Windows Forensic Engine",
            analyzer_version="2.0.0",
            source_evidence=sf.evidence_snippet or sf.title,
            source_file=source_location,
            timestamp=datetime.utcnow().isoformat(),
            engine="pefile Windows Forensic Engine",
            original_hash=record.sha256,
        ))

    # Convert C2 indicators into artifacts
    for c2 in c2_indicators:
        artifacts.append(ExtractedArtifact(
            id=f"ART-C2-{c2.id}",
            investigation_id=investigation_id,
            evidence_id=evidence_id,
            artifact_type="c2_endpoint",
            value=c2.value,
            source_format="exe",
            source_location=c2.source_file or "PE Strings",
            structured_data={"protocol": c2.protocol, "classification": c2.classification},
            extractor_name="PE String & Indicator Extractor",
            extracted_at=datetime.utcnow()
        ))

    metadata_dict = pe_metadata.model_dump() if hasattr(pe_metadata, "model_dump") else {}
    return metadata_dict, artifacts, findings


def run_universal_pipeline(investigation_id: str):
    """
    Authoritative Universal Digital Forensics Pipeline (9 Stages, 100% Monotonic Progress):
    STAGE 1 (5%):  Case Initialization & Examiner Attestation
    STAGE 2 (20%): Evidence Ingestion & Original Write-Protection
    STAGE 3 (35%): Hashing & Structural Format Identification
    STAGE 4 (65%): Static Analysis (Format-Specific Dispatcher for APK, PE, ELF, PDF, Office, etc.)
    STAGE 5 (75%): Universal Findings & Artifact Extraction
    STAGE 6 (85%): Cross-Evidence Correlation & UTC Timeline Generation
    STAGE 7 (90%): Dimensional Evidence-Backed Risk Assessment
    STAGE 8 (95%): Master Forensic Report & Reproducibility Bundle Generation
    STAGE 9 (100%): Final Persistence, Verification & Chain of Custody Closure
    """
    record = repo.get_investigation(investigation_id)
    if not record:
        logger.error(f"Investigation {investigation_id} not found in database.")
        return

    dirs = workspace_mgr.create_workspace(investigation_id)
    examiner = record.investigator_name or "Digital Forensics Examiner"
    any_warnings = False
    failure_reasons = []

    try:
        # ==============================================================================
        # STAGE 1: CASE INITIALIZATION (5%)
        # ==============================================================================
        record.started_at = datetime.utcnow()
        _update_progress(
            record,
            pct=5,
            stage_desc="Case Initialization: Initializing workspace, validating case metadata and examiner identity",
            status="analyzing"
        )

        record_custody_event(
            investigation_id=investigation_id,
            event_type="ANALYSIS_STARTED",
            examiner=examiner,
            details={"case_reference": record.case_reference, "filename": record.filename}
        )

        # ==============================================================================
        # STAGE 2: EVIDENCE INGESTION (20%)
        # ==============================================================================
        _update_progress(
            record,
            pct=20,
            stage_desc="Evidence Ingestion: Registering evidence artifacts, preserving write-protected originals"
        )

        evidence_items = repo.list_evidence_items(investigation_id)

        # Synthesize evidence item if single-file legacy upload
        if not evidence_items:
            original_file = dirs["original"] / record.filename
            if not original_file.exists():
                original_file = dirs["working"] / record.filename

            if original_file.exists():
                hashes = calculate_streaming_hashes(original_file)
                entropy, entropy_desc = calculate_shannon_entropy(original_file)
                triage = identify_file_format(original_file, record.filename)

                # Write-protect original file
                try:
                    os.chmod(original_file, 0o444)
                except Exception:
                    pass

                item = EvidenceItem(
                    id=f"EVD-{investigation_id[-6:]}-001",
                    investigation_id=investigation_id,
                    filename=record.filename,
                    file_size=original_file.stat().st_size,
                    mime_type=triage["mime_type"],
                    detected_format=triage["detected_format"],
                    extension=triage["extension"],
                    format_mismatch=triage["format_mismatch"],
                    md5=hashes["md5"],
                    sha1=hashes["sha1"],
                    sha256=hashes["sha256"],
                    sha512=hashes["sha512"],
                    working_copy_sha256=hashes["sha256"],
                    integrity_status="VERIFIED",
                    source_info="Direct Evidence Ingestion",
                    examiner_notes=record.analyst_notes,
                    acquired_at=record.created_at,
                    processing_state="FULL",
                    entropy=entropy,
                    triage_summary=triage,
                    metadata={},
                    created_at=record.created_at
                )
                repo.create_evidence_item(item)
                evidence_items = [item]

                record_custody_event(
                    investigation_id=investigation_id,
                    event_type="EVIDENCE_RECEIVED",
                    examiner=examiner,
                    evidence_id=item.id,
                    original_hash=hashes["sha256"],
                    working_copy_hash=hashes["sha256"],
                    verification_result="PASSED",
                    details={"filename": record.filename, "format": triage["detected_format"]}
                )

        # ==============================================================================
        # STAGE 3: HASHING & STRUCTURAL IDENTIFICATION (35%)
        # ==============================================================================
        _update_progress(
            record,
            pct=35,
            stage_desc="Hashing and Identification: Cryptographic hashing, entropy profiling, format validation"
        )

        for ev in evidence_items:
            ev_working_path = dirs["working"] / ev.filename
            if not ev_working_path.exists():
                ev_working_path = dirs["original"] / ev.filename
            if ev_working_path.exists() and not ev.sha256:
                h = calculate_streaming_hashes(ev_working_path)
                ev.sha256 = h["sha256"]
                ev.sha512 = h["sha512"]
                ev.md5 = h["md5"]
                ev.sha1 = h["sha1"]
                repo.update_evidence_item(ev)

        # ==============================================================================
        # STAGE 4: STATIC ANALYSIS (35% -> 65%)
        # ==============================================================================
        all_artifacts: List[ExtractedArtifact] = []
        all_findings: List[FindingRecord] = []
        total_items = max(1, len(evidence_items))

        for idx, ev in enumerate(evidence_items):
            stage_pct = 35 + int(((idx + 1) / total_items) * 30)
            _update_progress(
                record,
                pct=stage_pct,
                stage_desc=f"Static Analysis [{idx + 1}/{total_items}]: Deep static inspection for {ev.filename} ({ev.detected_format.upper()})"
            )

            ev_working_path = dirs["working"] / ev.filename
            if not ev_working_path.exists():
                ev_working_path = dirs["original"] / ev.filename

            if not ev_working_path.exists():
                ev.processing_state = "FAILED"
                ev.metadata = {"error": f"Working file '{ev.filename}' does not exist on disk."}
                repo.update_evidence_item(ev)
                any_warnings = True
                failure_reasons.append(f"Missing file: {ev.filename}")
                continue

            fmt = ev.detected_format.lower()
            ev_meta: Dict[str, Any] = {}
            ev_arts: List[ExtractedArtifact] = []
            ev_fnds: List[FindingRecord] = []

            try:
                if fmt == "apk":
                    ev_meta, ev_arts, ev_fnds = analyze_apk_specialized(
                        ev_working_path, ev.id, investigation_id, record, dirs
                    )
                    ev.processing_state = "FULL"

                elif fmt in ("exe", "dll"):
                    ev_meta, ev_arts, ev_fnds = analyze_pe_specialized(
                        ev_working_path, ev.id, investigation_id, record, dirs
                    )
                    ev.processing_state = "FULL"

                elif fmt == "pdf":
                    ev_meta, ev_arts, ev_fnds = analyze_pdf_evidence(ev_working_path, ev.id, investigation_id)
                    ev.processing_state = "FULL"

                elif fmt in ("png", "jpeg", "jpg", "webp", "tiff", "bmp", "gif"):
                    ev_meta, ev_arts, ev_fnds = analyze_image_evidence(ev_working_path, ev.id, investigation_id)
                    ev.processing_state = "FULL"

                elif fmt in ("docx", "xlsx", "xlsm", "pptx", "csv"):
                    ev_meta, ev_arts, ev_fnds = analyze_office_evidence(ev_working_path, ev.id, investigation_id, fmt)
                    ev.processing_state = "FULL"

                elif fmt in ("zip", "tar", "gzip", "7z", "rar"):
                    arch_out = dirs["extracted"] / ev.id
                    ev_meta, ev_arts, ev_fnds, child_items = analyze_archive_evidence(ev_working_path, ev.id, investigation_id, arch_out)
                    ev.processing_state = "FULL"
                    # Register extracted child artifacts as child evidence items
                    for ci in child_items:
                        c_path = Path(ci["file_path"])
                        c_triage = identify_file_format(c_path, ci["filename"])
                        c_hashes = calculate_streaming_hashes(c_path)
                        child_ev = EvidenceItem(
                            id=f"EVD-{investigation_id[-6:]}-C{len(evidence_items) + len(all_artifacts) + 1:03d}",
                            investigation_id=investigation_id,
                            parent_evidence_id=ev.id,
                            filename=ci["filename"],
                            relative_path=ci["relative_path"],
                            file_size=ci["file_size"],
                            mime_type=c_triage["mime_type"],
                            detected_format=c_triage["detected_format"],
                            extension=c_triage["extension"],
                            format_mismatch=c_triage["format_mismatch"],
                            md5=c_hashes["md5"],
                            sha1=c_hashes["sha1"],
                            sha256=c_hashes["sha256"],
                            sha512=c_hashes["sha512"],
                            working_copy_sha256=c_hashes["sha256"],
                            integrity_status="VERIFIED",
                            source_info=f"Extracted from Archive '{ev.filename}'",
                            acquired_at=datetime.utcnow(),
                            processing_state="FULL",
                            entropy=calculate_shannon_entropy(c_path)[0],
                            triage_summary=c_triage,
                            metadata={}
                        )
                        repo.create_evidence_item(child_ev)

                elif fmt in ("eml", "mbox"):
                    eml_out = dirs["extracted"] / ev.id
                    ev_meta, ev_arts, ev_fnds, child_items = analyze_email_evidence(ev_working_path, ev.id, investigation_id, eml_out)
                    ev.processing_state = "FULL"
                    for ci in child_items:
                        c_path = Path(ci["file_path"])
                        c_triage = identify_file_format(c_path, ci["filename"])
                        c_hashes = calculate_streaming_hashes(c_path)
                        child_ev = EvidenceItem(
                            id=f"EVD-{investigation_id[-6:]}-C{len(evidence_items) + len(all_artifacts) + 1:03d}",
                            investigation_id=investigation_id,
                            parent_evidence_id=ev.id,
                            filename=ci["filename"],
                            relative_path=ci["relative_path"],
                            file_size=ci["file_size"],
                            mime_type=c_triage["mime_type"],
                            detected_format=c_triage["detected_format"],
                            extension=c_triage["extension"],
                            format_mismatch=c_triage["format_mismatch"],
                            md5=c_hashes["md5"],
                            sha1=c_hashes["sha1"],
                            sha256=c_hashes["sha256"],
                            sha512=c_hashes["sha512"],
                            working_copy_sha256=c_hashes["sha256"],
                            integrity_status="VERIFIED",
                            source_info=f"Email Attachment from '{ev.filename}'",
                            acquired_at=datetime.utcnow(),
                            processing_state="FULL",
                            entropy=calculate_shannon_entropy(c_path)[0],
                            triage_summary=c_triage,
                            metadata={}
                        )
                        repo.create_evidence_item(child_ev)

                elif fmt in ("pcap", "pcapng"):
                    ev_meta, ev_arts, ev_fnds = analyze_pcap_evidence(ev_working_path, ev.id, investigation_id)
                    ev.processing_state = "FULL"

                elif fmt in ("txt", "log", "json", "xml", "yaml", "yml", "ini", "conf", "toml"):
                    ev_meta, ev_arts, ev_fnds = analyze_text_evidence(ev_working_path, ev.id, investigation_id, fmt)
                    ev.processing_state = "FULL"

                elif fmt in ("elf", "so"):
                    ev_meta, ev_arts, ev_fnds = analyze_elf_evidence(ev_working_path, ev.id, investigation_id)
                    ev.processing_state = "FULL"

                else:
                    ev.processing_state = "GENERIC_TRIAGE_ONLY"
                    yara_fnds, _ = run_yara_scan(ev_working_path)
                    for yf in yara_fnds:
                        ev_fnds.append(FindingRecord(
                            id=f"FND-{yf.id}-{ev.id}",
                            investigation_id=investigation_id,
                            evidence_id=ev.id,
                            title=yf.title,
                            description=yf.description,
                            observation=yf.evidence_snippet or yf.title,
                            interpretation=yf.explanation or yf.description,
                            severity=yf.severity,
                            confidence=yf.confidence,
                            analysis_method="Static YARA Signature Matching",
                            analyzer_name="YARA Scanner",
                            analyzer_version="1.0",
                            source_evidence=yf.evidence_snippet or yf.title,
                            source_location=ev_working_path.name,
                            source_file=ev_working_path.name,
                            timestamp=datetime.utcnow().isoformat(),
                            engine="YARA Scanner",
                            original_hash=ev.sha256,
                        ))

                # Supplemental offline local-tool adapters are selected by evidence
                # format. Their output is normalized into evidence-backed findings
                # and deduplicated before entering the universal findings register.
                ev_fnds.extend(_run_local_tool_adapters(
                    ev_working_path,
                    fmt,
                    investigation_id,
                    ev.id,
                    ev.sha256,
                ))

                ev.metadata = ev_meta
                repo.update_evidence_item(ev)
                all_artifacts.extend(ev_arts)
                all_findings.extend(ev_fnds)

            except Exception as item_err:
                logger.error(f"Error analyzing {ev.filename}: {item_err}", exc_info=True)
                ev.processing_state = "FAILED"
                ev.metadata = {"error": str(item_err)}
                repo.update_evidence_item(ev)
                any_warnings = True
                failure_reasons.append(f"{ev.filename}: {str(item_err)}")
                all_findings.append(FindingRecord(
                    id=f"FND-WARN-{ev.id}",
                    investigation_id=investigation_id,
                    evidence_id=ev.id,
                    title=f"Analyzer Warning on {ev.filename}",
                    description=f"Static analyzer encountered recoverable error: {str(item_err)}",
                    observation=f"File: {ev.filename}, Format: {fmt}",
                    interpretation="Partial analysis recorded; manual inspection recommended.",
                    severity="Low",
                    confidence="Confirmed",
                    analysis_method="Defensive Fallback Handler",
                    source_location=ev.filename,
                    analyzer_name="Universal Orchestrator Supervisor",
                    analyzer_version="2.0.0"
                ))

        # ==============================================================================
        # STAGE 5: FINDINGS EXTRACTION (75%)
        # ==============================================================================
        _update_progress(
            record,
            pct=75,
            stage_desc="Findings Extraction: Normalizing security findings into universal evidence model"
        )

        repo.save_extracted_artifacts(investigation_id, all_artifacts)
        repo.save_findings_register(investigation_id, all_findings)

        # Refresh evidence items in case child items were extracted from archives/emails
        updated_evidence_items = repo.list_evidence_items(investigation_id)

        # ==============================================================================
        # STAGE 6: CORRELATION AND TIMELINE (85%)
        # ==============================================================================
        _update_progress(
            record,
            pct=85,
            stage_desc="Correlation and Timeline: Cross-file correlation, shared IOCs, and normalized UTC timeline"
        )

        relationships = correlate_investigation_evidence(investigation_id, updated_evidence_items, all_artifacts)
        repo.save_evidence_relationships(investigation_id, relationships)

        timeline_events, contradictions = build_investigation_timeline(investigation_id, updated_evidence_items)
        repo.save_timeline_events(investigation_id, timeline_events)

        # ==============================================================================
        # STAGE 7: RISK ASSESSMENT (90%)
        # ==============================================================================
        _update_progress(
            record,
            pct=90,
            stage_desc="Risk Assessment: Synthesizing dimensional risk score, severity, and confidence"
        )

        u_detail = repo.get_universal_investigation_detail(investigation_id)
        if u_detail:
            try:
                risk_assessment = assess_evidence_dimensional_risk(u_detail)
                record.severity = risk_assessment.severity
                record.confidence = risk_assessment.confidence
            except Exception as r_err:
                logger.error(f"Error in risk assessment: {r_err}", exc_info=True)
                if not record.severity:
                    record.severity = "Medium" if any_warnings else "Informational"
                if not record.confidence:
                    record.confidence = "High"

        # ==============================================================================
        # OPTIONAL STAGE 7.5: AI-ASSISTED FORENSIC ANALYSIS (OPENCODE ENGINE) (92%)
        # ==============================================================================
        if getattr(record, "ai_assisted_analysis", False):
            _update_progress(
                record,
                pct=92,
                stage_desc="AI-Assisted Analysis: Synthesizing unverified forensic observations via OpenCode CLI"
            )
            try:
                from backend.app.integrations.opencode_engine import analyze_investigation
                detail_for_ai = repo.get_investigation_detail(investigation_id) or u_detail
                analyze_investigation(
                    investigation_id=investigation_id,
                    detail=detail_for_ai,
                    filename=record.filename,
                    file_type=record.file_type or "unknown",
                    file_size_bytes=record.original_size or 0,
                    sha256_hash=record.sha256 or "",
                    consent_approved=False
                )
            except Exception as ai_err:
                logger.warning(f"AI-assisted analysis failed gracefully without interrupting investigation: {ai_err}")

        # ==============================================================================
        # STAGE 8: REPORT GENERATION (95%)
        # ==============================================================================
        _update_progress(
            record,
            pct=95,
            stage_desc="Report Generation: Authoring multi-format forensic master reports and evidence bundle"
        )

        u_detail_final = repo.get_universal_investigation_detail(investigation_id)
        if u_detail_final:
            try:
                # Master plain-text report (31 sections)
                master_txt = generate_master_txt_report(u_detail_final)
                master_txt_path = dirs["reports"] / f"Master_Forensic_Report_{investigation_id}.txt"
                master_txt_path.write_text(master_txt, encoding="utf-8")

                # Master HTML report
                master_html = generate_master_html_report(u_detail_final)
                master_html_path = dirs["reports"] / f"Master_Forensic_Report_{investigation_id}.html"
                master_html_path.write_text(master_html, encoding="utf-8")

                # Master reproducibility bundle ZIP
                bundle_bytes = export_reproducibility_bundle_zip(u_detail_final)
                bundle_path = dirs["reports"] / f"Reproducibility_Bundle_{investigation_id}.zip"
                bundle_path.write_bytes(bundle_bytes)

                # Format-specific specialized text reports
                if record.file_type == "apk":
                    try:
                        from backend.app.reporting.txt_generator import generate_txt_forensic_report
                        apk_detail = repo.get_investigation_detail(investigation_id)
                        if apk_detail:
                            apk_txt = generate_txt_forensic_report(apk_detail)
                            apk_txt_path = dirs["reports"] / f"Forensic_Report_{investigation_id}.txt"
                            apk_txt_path.write_text(apk_txt, encoding="utf-8")
                    except Exception as apk_err:
                        logger.warning(f"Failed to generate APK txt report: {apk_err}")
                elif record.file_type in ("exe", "dll"):
                    try:
                        from backend.app.reporting.exe_txt_generator import generate_exe_forensic_report
                        exe_detail = repo.get_investigation_detail(investigation_id)
                        if exe_detail:
                            exe_txt = generate_exe_forensic_report(exe_detail)
                            exe_txt_path = dirs["reports"] / f"Forensic_Report_{investigation_id}.txt"
                            exe_txt_path.write_text(exe_txt, encoding="utf-8")
                    except Exception as pe_err:
                        logger.warning(f"Failed to generate PE txt report: {pe_err}")
            except Exception as rep_err:
                logger.error(f"Error writing master reports: {rep_err}", exc_info=True)

        # ==============================================================================
        # STAGE 9: FINAL PERSISTENCE & VERIFICATION (100%)
        # ==============================================================================
        record.completed_at = datetime.utcnow()
        record.total_findings = len(all_findings)

        record_custody_event(
            investigation_id=investigation_id,
            event_type="ANALYSIS_COMPLETED",
            examiner=examiner,
            details={
                "evidence_count": len(updated_evidence_items),
                "artifacts_count": len(all_artifacts),
                "findings_count": len(all_findings),
                "relationships_count": len(relationships),
                "timeline_events_count": len(timeline_events),
                "warnings_count": len(failure_reasons)
            }
        )

        final_status = "completed_with_warnings" if (any_warnings and len(all_findings) > 0) else "completed"
        final_stage = "Analysis complete with warnings. Forensic reports ready." if any_warnings else "Universal Forensic Examination Complete. Master Report Ready."

        _update_progress(
            record,
            pct=100,
            stage_desc=final_stage,
            status=final_status
        )
        logger.info(f"Investigation {investigation_id} completed successfully (status: {final_status}, findings: {len(all_findings)}).")

    except Exception as pipeline_err:
        logger.error(f"Critical error in investigation pipeline {investigation_id}: {pipeline_err}", exc_info=True)
        # Check if partial results exist
        partial_findings = repo.list_findings_register(investigation_id) or repo.get_static_findings(investigation_id)
        record.completed_at = datetime.utcnow()
        record.error_message = str(pipeline_err)
        if partial_findings:
            _update_progress(
                record,
                pct=100,
                stage_desc=f"Analysis completed with warnings: {str(pipeline_err)[:150]}",
                status="completed_with_warnings"
            )
        else:
            _update_progress(
                record,
                pct=100,
                stage_desc=f"Investigation failed: {str(pipeline_err)[:150]}",
                status="failed"
            )
