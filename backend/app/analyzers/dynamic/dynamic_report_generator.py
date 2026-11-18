import uuid
import json
import logging
from datetime import datetime
from typing import Dict, Any, Optional

from backend.app.core.models import DynamicSandboxRun, DynamicReport
from backend.app.database.repository import repo
from backend.app.analyzers.dynamic.process_monitor import process_monitor

logger = logging.getLogger(__name__)

class DynamicReportGenerator:
    """
    Compiles formal forensic dynamic malware analysis reports in Markdown and structured JSON.
    Integrates behavioral observations, process trees, network traces, and custody records.
    """

    def generate_report(self, run: DynamicSandboxRun, report_type: str = "DYNAMIC") -> DynamicReport:
        report_id = f"RPT-DYN-{datetime.utcnow().strftime('%Y%m%d')}-{uuid.uuid4().hex[:6].upper()}"

        observations = repo.list_dynamic_observations(run.investigation_id, run_id=run.id)
        artifacts = repo.list_dynamic_artifacts(run.investigation_id, run_id=run.id)
        flows = repo.list_network_flow_records(run.investigation_id, run_id=run.id)
        process_tree = process_monitor.build_process_tree(run.investigation_id, run_id=run.id)

        # Build Markdown Summary
        md = []
        md.append(f"# TraceX Forensic Analysis Report: {run.target_binary}")
        md.append(f"**Report ID:** `{report_id}` | **Run ID:** `{run.id}`")
        md.append(f"**Generated:** {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}")
        md.append(f"**Target Type:** {run.target_type.upper()} | **SHA-256:** `{run.target_sha256 or 'N/A'}`")
        md.append(f"**Sandbox Environment:** {run.sandbox_environment} ({run.provider or 'Standard'})")
        md.append(f"**Network Containment Policy:** `{run.network_policy}`")
        md.append(f"**Dynamic Risk Score:** **{run.risk_score} / 10.0 ({run.risk_level.upper()})**\n")

        md.append("## 1. Executive Summary")
        md.append(f"The sample `{run.target_binary}` was staged and observed in an isolated environment for {run.duration_seconds:.1f} seconds. "
                  f"A total of {len(observations)} behavioral observations were recorded across processes, filesystem, registry, and network domains.")

        md.append("\n## 2. Key Behavioral Observations")
        if observations:
            md.append("| Severity | Category | Title | Description | MITRE Technique |")
            md.append("| :--- | :--- | :--- | :--- | :--- |")
            for obs in observations:
                mitre = obs.mitre_technique or "—"
                md.append(f"| **{obs.severity}** | {obs.observation_type} | {obs.title} | {obs.description} | `{mitre}` |")
        else:
            md.append("*No suspicious runtime observations were triggered during the observation window.*")

        md.append("\n## 3. Network Flows & Telemetry")
        if flows:
            md.append("| Protocol | Source | Destination | DNS / Hostname | HTTP Details |")
            md.append("| :--- | :--- | :--- | :--- | :--- |")
            for fl in flows:
                http = f"{fl.http_method} {fl.http_status}" if fl.http_method else "—"
                md.append(f"| {fl.protocol} | {fl.src_ip}:{fl.src_port} | {fl.dst_ip}:{fl.dst_port} | {fl.dns_hostname or '—'} | {http} |")
        else:
            md.append("*Zero external network connections observed (Network Policy: " + run.network_policy + ").*")

        md.append("\n## 4. Dropped Artifacts & Hashes")
        if artifacts:
            md.append("| Type | Filename | Size (Bytes) | SHA-256 Digest |")
            md.append("| :--- | :--- | :---: | :--- |")
            for art in artifacts:
                md.append(f"| {art.artifact_type} | `{art.filename}` | {art.size_bytes} | `{art.sha256}` |")
        else:
            md.append("*No files or memory artifacts were dropped during analysis.*")

        md.append("\n## 5. Forensic Integrity & Legal Disclosures")
        md.append("> [!NOTE]")
        md.append("> **Zero Host Execution Disclosure:** This analysis was executed exclusively in a disposable guest environment. "
                  "The original forensic evidence remained unchanged on the TraceX host workstation. "
                  "Absence of malicious behavior during a bounded sandbox window does not guarantee that a sample is harmless (anti-sandbox/evasion techniques may be present).")

        summary_text = "\n".join(md)

        full_json = {
            "report_id": report_id,
            "run_id": run.id,
            "investigation_id": run.investigation_id,
            "target_binary": run.target_binary,
            "target_sha256": run.target_sha256,
            "target_type": run.target_type,
            "environment": run.sandbox_environment,
            "network_policy": run.network_policy,
            "duration_seconds": run.duration_seconds,
            "risk_score": run.risk_score,
            "risk_level": run.risk_level,
            "observations_count": len(observations),
            "artifacts_count": len(artifacts),
            "flows_count": len(flows)
        }

        report = DynamicReport(
            id=report_id,
            run_id=run.id,
            investigation_id=run.investigation_id,
            report_type=report_type,
            title=f"Dynamic Malware Analysis: {run.target_binary}",
            summary_markdown=summary_text,
            full_report=full_json,
            risk_score=run.risk_score,
            risk_severity=run.risk_level,
            generated_at_utc=datetime.utcnow().isoformat()
        )

        repo.save_dynamic_report(report)
        run.report_id = report_id
        repo.update_sandbox_run(run)

        return report

dynamic_report_generator = DynamicReportGenerator()
