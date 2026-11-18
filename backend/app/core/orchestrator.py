import time
import pefile
from datetime import datetime
from pathlib import Path
from typing import Optional, List, Dict, Any

from backend.app.config import settings
from backend.app.core.storage import workspace_mgr
from backend.app.core.security import (
    validate_apk_file, safe_extract_apk, calculate_hashes
)
from backend.app.core.models import (
    InvestigationRecord, StaticFinding, ToolExecution, NetworkIOC
)
from backend.app.database.repository import repo

# APK Analyzers & Adapters
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

# Windows PE Analyzers & Adapters
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

# Shared Threat Intelligence
from backend.app.integrations.threat_intel.threat_intel_manager import threat_intel

def run_investigation_pipeline(investigation_id: str):
    """
    Main background entry point for investigation processing.
    Delegates to the authoritative 9-stage universal pipeline.
    """
    from backend.app.core.universal_orchestrator import run_universal_pipeline
    return run_universal_pipeline(investigation_id)

def run_apk_pipeline(investigation_id: str, record: InvestigationRecord):
    """
    Preserved Android APK forensic analysis pipeline.
    """
    record.status = "analyzing"
    record.started_at = datetime.utcnow()
    record.progress = 5
    record.current_stage = "Validating archive integrity and hash verification"
    repo.update_investigation(record)

    dirs = workspace_mgr.create_workspace(investigation_id)
    working_apk_path = dirs["working"] / record.filename

    tool_executions: List[ToolExecution] = []
    all_static_findings: List[StaticFinding] = []

    try:
        # Step 1: File Validation
        is_valid, val_msg = validate_apk_file(working_apk_path, max_size_mb=settings.MAX_UPLOAD_SIZE_MB)
        if not is_valid:
            raise ValueError(f"APK validation failure: {val_msg}")

        # Step 2: Safe extraction with Zip-Slip protection
        record.progress = 15
        record.current_stage = "Extracting archive members with Zip-Slip protection"
        repo.update_investigation(record)
        safe_extract_apk(working_apk_path, dirs["extracted"])

        # Step 3: Androguard / Bytecode & Metadata Parsing
        record.progress = 25
        record.current_stage = "Parsing manifest, components, certificates, and DEX bytecode"
        repo.update_investigation(record)
        
        t0 = time.time()
        metadata, strings_pool, dex_methods = parse_apk_with_androguard(working_apk_path)
        tool_executions.append(ToolExecution(
            tool_name="Androguard Core",
            installed=True,
            status="completed",
            duration_seconds=round(time.time() - t0, 2),
            findings_count=len(strings_pool) + len(dex_methods)
        ))
        
        # Save metadata and record updates
        record.package_name = metadata.package_name
        record.app_name = metadata.app_name
        repo.save_metadata(investigation_id, metadata)

        # Step 4: Manifest Analysis
        record.progress = 35
        record.current_stage = "Analyzing permissions, exported components, and security flags"
        repo.update_investigation(record)
        manifest_findings, manifest_summary = analyze_manifest(metadata)
        all_static_findings.extend(manifest_findings)

        # Step 5: String Extraction & Offline Decoding
        record.progress = 45
        record.current_stage = "Extracting URLs, IPs, domains, and attempting offline Base64/Hex decoding"
        repo.update_investigation(record)
        classified_strings = extract_and_classify_strings(strings_pool)

        # Step 6: DEX Bytecode Pattern Analysis
        record.progress = 55
        record.current_stage = "Inspecting DEX bytecode for reflection, dynamic loading, and ciphers"
        repo.update_investigation(record)
        raw_dex_strings = [s for _, s in strings_pool]
        dex_findings = analyze_dex_content(raw_dex_strings, dex_methods)
        all_static_findings.extend(dex_findings)

        # Step 7: YARA Scanning
        record.progress = 65
        record.current_stage = "Executing compiled YARA signature rules"
        repo.update_investigation(record)
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

        # Step 8: C2 Infrastructure & Reconstruction
        record.progress = 75
        record.current_stage = "Reconstructing potential Command-and-Control (C2) configurations"
        repo.update_investigation(record)
        c2_indicators = analyze_c2_infrastructure(
            classified_strings["urls"],
            classified_strings["ips"],
            classified_strings["domains"],
            classified_strings["decoded_items"],
            dex_methods
        )
        record.c2_count = len(c2_indicators)
        repo.save_c2_indicators(investigation_id, c2_indicators)

        # Step 9: Token and Secret Analysis
        record.progress = 80
        record.current_stage = "Analyzing hardcoded secrets, API keys, and authentication tokens"
        repo.update_investigation(record)
        secrets = analyze_secrets(strings_pool, dex_methods)
        record.secret_count = len(secrets)
        repo.save_secrets(investigation_id, secrets)

        # Step 10: Remote Access & Reverse-Shell Correlation
        record.progress = 85
        record.current_stage = "Correlating reverse-shell indicators and execution chains"
        repo.update_investigation(record)
        reverse_shell_findings = analyze_reverse_shell_indicators(dex_methods, raw_dex_strings, c2_indicators)
        record.reverse_shell_detected = len(reverse_shell_findings) > 0
        repo.save_reverse_shell_findings(investigation_id, reverse_shell_findings)

        # Step 11: Build Network IOC list
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

        # Step 12: External Tool Integrations (JADX & Apktool if installed)
        record.progress = 90
        record.current_stage = "Running installed auxiliary decompilation adapters"
        repo.update_investigation(record)
        jadx_exec = run_jadx_decompiler(working_apk_path, dirs["decompile"])
        tool_executions.append(jadx_exec)
        apktool_exec = run_apktool_decode(working_apk_path, dirs["extracted"] / "apktool_out")
        tool_executions.append(apktool_exec)

        # Step 13: Threat Intelligence (if enabled and not local-only)
        ti_results = []
        if not record.local_only_mode and not settings.LOCAL_ONLY_MODE:
            record.current_stage = "Querying passive threat intelligence providers"
            repo.update_investigation(record)
            ti_results.extend(threat_intel.check_hash(record.sha256, investigation_id))
            for ind in c2_indicators[:3]:
                if ind.indicator_type == "ip" and "private" not in ind.classification:
                    ti_results.extend(threat_intel.check_ip(ind.value, investigation_id))
        repo.save_threat_intel_results(investigation_id, ti_results)

        # Step 14: Save Static Findings & Tool Executions
        repo.save_static_findings(investigation_id, all_static_findings)
        repo.save_tool_executions(investigation_id, tool_executions)

        # Step 15: Risk Assessment Evaluation
        record.progress = 95
        record.current_stage = "Evaluating forensic risk score and executive narrative"
        repo.update_investigation(record)
        assessment = evaluate_malware_risk(
            all_static_findings,
            c2_indicators,
            secrets,
            reverse_shell_findings,
            is_external_intel_used=(len(ti_results) > 0)
        )
        repo.save_assessment(investigation_id, assessment)

        # Optional: AI-Assisted Forensic Analysis (OpenCode Engine)
        if getattr(record, "ai_assisted_analysis", False):
            try:
                from backend.app.integrations.opencode_engine import analyze_investigation
                record.progress = 96
                record.current_stage = "OpenCode Engine: Synthesizing unverified forensic observations"
                repo.update_investigation(record)
                detail_for_ai = repo.get_investigation_detail(investigation_id)
                if detail_for_ai:
                    analyze_investigation(
                        investigation_id=investigation_id,
                        detail=detail_for_ai,
                        filename=record.filename,
                        file_type="apk",
                        file_size_bytes=record.original_size or 0,
                        sha256_hash=record.sha256 or "",
                        consent_approved=False
                    )
            except Exception as ai_err:
                logger.warning(f"AI-assisted analysis failed gracefully: {ai_err}")

        # Step 16: Generate and Persist Mandatory TXT Report
        record.current_stage = "Generating comprehensive downloadable plain-text forensic report"
        repo.update_investigation(record)
        detail = repo.get_investigation_detail(investigation_id)
        if detail:
            txt_content = generate_txt_forensic_report(detail, unredact_secrets=False)
            timestamp_suffix = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
            report_filename = f"APK_Forensic_Report_{investigation_id}_{timestamp_suffix}.txt"
            report_path = dirs["reports"] / report_filename
            with open(report_path, "w", encoding="utf-8") as rf:
                rf.write(txt_content)

        # Finalize record
        record.total_findings = len(all_static_findings)
        record.severity = assessment.overall_severity
        record.confidence = assessment.overall_confidence
        record.status = "completed"
        record.progress = 100
        record.current_stage = "Analysis complete. Report generated and available for download."
        record.completed_at = datetime.utcnow()
        repo.update_investigation(record)

    except Exception as e:
        record.status = "failed"
        record.progress = 100
        record.error_message = str(e)
        record.current_stage = f"Error during analysis: {str(e)}"
        record.completed_at = datetime.utcnow()
        repo.update_investigation(record)

def run_pe_pipeline(investigation_id: str, record: InvestigationRecord):
    """
    Dedicated, modular Windows PE (.exe) static forensic analysis pipeline.
    Never executes uploaded binary on the host workstation.
    """
    record.status = "analyzing"
    record.started_at = datetime.utcnow()
    record.progress = 5
    record.current_stage = "Validating Windows PE structure and DOS/COFF headers"
    repo.update_investigation(record)

    dirs = workspace_mgr.create_workspace(investigation_id)
    working_exe_path = dirs["working"] / record.filename
    file_size = record.original_size

    tool_executions: List[ToolExecution] = []
    all_static_findings: List[StaticFinding] = []

    try:
        # Step 1: PE Structural Validation
        is_valid, val_reason, val_details = validate_pe_file(working_exe_path, max_size_mb=settings.MAX_UPLOAD_SIZE_MB)
        if not is_valid:
            raise ValueError(f"PE Validation Failure: {val_reason}")

        # Step 2: PE Header & Metadata Parsing
        record.progress = 20
        record.current_stage = "Parsing PE headers, timestamp, image base, and version resources"
        repo.update_investigation(record)
        
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

        # Record basic architecture in app_name / package_name for dashboard overview
        record.app_name = pe_metadata.version_info.get("ProductName") or record.filename
        record.package_name = f"{pe_metadata.machine} [{pe_metadata.magic}]"

        # Step 3: Section Analysis (Entropy, Permissions, Anomalies)
        record.progress = 35
        record.current_stage = "Analyzing section permissions, Shannon entropy, and memory unrolling"
        repo.update_investigation(record)
        
        sections, sec_findings, sec_summary = analyze_pe_sections(pe, file_size)
        pe_metadata.sections = sections
        all_static_findings.extend(sec_findings)
        if sec_summary["packer_indicators"]:
            pe_metadata.packer_detected = True
            pe_metadata.packer_indicators = sec_summary["packer_indicators"]

        # Step 4: Import Table & API Capabilities
        record.progress = 50
        record.current_stage = "Mapping imported Windows APIs to forensic capability behaviors"
        repo.update_investigation(record)
        
        imported_dlls, import_findings, import_summary = analyze_pe_imports(pe)
        pe_metadata.imports = imported_dlls
        all_static_findings.extend(import_findings)

        all_imported_api_names = [
            f.name for dll in imported_dlls for f in dll.functions
        ]

        # Step 5: Strings & Forensic Artifact Extraction
        record.progress = 65
        record.current_stage = "Extracting ASCII/UTF-16LE strings, registry keys, and offline decoding"
        repo.update_investigation(record)
        
        classified_strings = analyze_pe_strings(working_exe_path, pe)

        # Step 6: YARA Scanning
        record.progress = 75
        record.current_stage = "Executing compiled YARA signature rules against binary and sections"
        repo.update_investigation(record)
        
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

        # Step 7: C2 Infrastructure & Network Correlation
        record.progress = 80
        record.current_stage = "Correlating network destinations, Dynamic DNS, and C2 endpoints"
        repo.update_investigation(record)
        
        c2_indicators = analyze_pe_c2_infrastructure(
            classified_strings["urls"],
            classified_strings["ips"],
            classified_strings["domains"],
            classified_strings["decoded_items"],
            all_imported_api_names
        )
        record.c2_count = len(c2_indicators)
        repo.save_c2_indicators(investigation_id, c2_indicators)

        # Step 8: Token and Secret Analysis
        record.progress = 85
        record.current_stage = "Scanning for embedded API keys, credentials, and authentication secrets"
        repo.update_investigation(record)
        
        secrets = analyze_pe_secrets(classified_strings["raw_strings_sample"])
        record.secret_count = len(secrets)
        repo.save_secrets(investigation_id, secrets)

        # Step 9: Windows Persistence & Execution Indicators
        record.progress = 90
        record.current_stage = "Investigating registry Run keys, services, injection, and LOLBAS commands"
        repo.update_investigation(record)
        
        persistence_findings = analyze_pe_persistence(
            classified_strings["raw_strings_sample"],
            all_imported_api_names
        )
        record.reverse_shell_detected = any("Injection" in pf.mechanism for pf in persistence_findings)
        repo.save_persistence_findings(investigation_id, persistence_findings)

        # Step 10: Build Network IOC list
        network_iocs: List[NetworkIOC] = []
        ioc_counter = 1
        for ip_item in classified_strings["ips"]:
            network_iocs.append(NetworkIOC(
                id=f"IOC-PE-IP-{ioc_counter:03d}",
                ioc_type="ipv4",
                value=ip_item["ip"],
                source_file=f"PE Section: {ip_item.get('section', 'Unknown')}",
                is_private=ip_item.get("is_private", False),
                classification="Private RFC1918" if ip_item.get("is_private") else "Public IP",
                confidence="Medium"
            ))
            ioc_counter += 1

        for dom_item in classified_strings["domains"]:
            network_iocs.append(NetworkIOC(
                id=f"IOC-PE-DOM-{ioc_counter:03d}",
                ioc_type="domain",
                value=dom_item["domain"],
                source_file=f"PE Section: {dom_item.get('section', 'Unknown')}",
                classification="Dynamic DNS" if dom_item.get("is_ddns") else ("DoH Endpoint" if dom_item.get("is_doh") else "Embedded Domain"),
                confidence="Medium"
            ))
            ioc_counter += 1
        repo.save_network_iocs(investigation_id, network_iocs)

        # Step 11: Record Status for Optional Forensic Tools (Truth in Reporting)
        optional_tools = [
            ("LIEF Parsing Library", False, "Advanced multi-format structural analysis"),
            ("FLOSS String Deobfuscator", False, "Mandiant FLOSS: Obfuscated string decoding"),
            ("capa Capability Detector", False, "Mandiant capa: Rule-based malware capability detection"),
            ("Detect It Easy (DIE)", False, "Heuristic compiler and packer identification"),
            ("Ghidra Headless Decompiler", False, "NSA Ghidra automated disassembly engine")
        ]
        for t_name, t_inst, t_role in optional_tools:
            tool_executions.append(ToolExecution(
                tool_name=t_name,
                installed=t_inst,
                status="skipped",
                limitations=f"{t_role} (Not installed on analysis workstation. Safe static parser utilized)."
            ))

        # Step 12: Threat Intelligence Lookups (Passive hash and IOC enrichment)
        ti_results: List[ThreatIntelResult] = []
        threat_intel_detections = 0
        if not record.local_only_mode and not settings.LOCAL_ONLY_MODE:
            record.current_stage = "Querying passive threat intelligence providers for hash and IOC reputation"
            repo.update_investigation(record)
            
            hash_results = threat_intel.check_hash(record.sha256, investigation_id)
            ti_results.extend(hash_results)
            for hr in hash_results:
                threat_intel_detections = max(threat_intel_detections, hr.detections)
                
            for c2 in c2_indicators[:3]:
                if c2.indicator_type == "ip" and "private" not in c2.classification:
                    ti_results.extend(threat_intel.check_ip(c2.value, investigation_id))
        repo.save_threat_intel_results(investigation_id, ti_results)

        # Save metadata, static findings, and tool executions
        repo.save_metadata(investigation_id, pe_metadata)
        repo.save_static_findings(investigation_id, all_static_findings)
        repo.save_tool_executions(investigation_id, tool_executions)

        # Step 13: Risk Assessment Evaluation
        record.progress = 95
        record.current_stage = "Evaluating Windows PE risk score and executive narrative"
        repo.update_investigation(record)
        
        assessment = evaluate_pe_malware_risk(
            static_findings=all_static_findings,
            c2_indicators=c2_indicators,
            secrets=secrets,
            persistence_findings=persistence_findings,
            is_external_intel_used=(len(ti_results) > 0),
            threat_intel_detections=threat_intel_detections
        )
        repo.save_assessment(investigation_id, assessment)

        # Close pefile handle
        pe.close()

        # Optional: AI-Assisted Forensic Analysis (OpenCode Engine)
        if getattr(record, "ai_assisted_analysis", False):
            try:
                from backend.app.integrations.opencode_engine import analyze_investigation
                record.progress = 96
                record.current_stage = "OpenCode Engine: Synthesizing unverified forensic observations"
                repo.update_investigation(record)
                detail_for_ai = repo.get_investigation_detail(investigation_id)
                if detail_for_ai:
                    analyze_investigation(
                        investigation_id=investigation_id,
                        detail=detail_for_ai,
                        filename=record.filename,
                        file_type="exe",
                        file_size_bytes=record.original_size or 0,
                        sha256_hash=record.sha256 or "",
                        consent_approved=False
                    )
            except Exception as ai_err:
                logger.warning(f"AI-assisted analysis failed gracefully: {ai_err}")

        # Step 14: Generate and Persist Mandatory 22-Section EXE Report
        record.current_stage = "Generating comprehensive downloadable Windows PE forensic report"
        repo.update_investigation(record)
        detail = repo.get_investigation_detail(investigation_id)
        if detail:
            txt_content = generate_exe_forensic_report(detail, unredact_secrets=False)
            timestamp_suffix = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
            report_filename = f"EXE_Forensic_Report_{investigation_id}_{timestamp_suffix}.txt"
            report_path = dirs["reports"] / report_filename
            with open(report_path, "w", encoding="utf-8") as rf:
                rf.write(txt_content)

        # Finalize record
        record.total_findings = len(all_static_findings)
        record.severity = assessment.overall_severity
        record.confidence = assessment.overall_confidence
        record.status = "completed"
        record.progress = 100
        record.current_stage = "Analysis complete. Windows PE Forensic Report ready."
        record.completed_at = datetime.utcnow()
        repo.update_investigation(record)

    except Exception as e:
        record.status = "failed"
        record.progress = 100
        record.error_message = str(e)
        record.current_stage = f"Error during Windows PE analysis: {str(e)}"
        record.completed_at = datetime.utcnow()
        repo.update_investigation(record)
