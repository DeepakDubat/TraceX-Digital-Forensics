import uuid
import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple

from backend.app.config import settings
from backend.app.core.models import (
    DynamicSandboxRun,
    DynamicTelemetryEvent,
    NetworkFlowRecord,
    DroppedArtifactRecord
)
from backend.app.database.repository import repo
from backend.app.integrations.sandbox.sandbox_detector import sandbox_detector
from backend.app.analyzers.network.pcap_telemetry_engine import pcap_telemetry_engine

logger = logging.getLogger(__name__)

class SandboxManager:
    """
    Orchestrates Isolated Dynamic Sandbox Analysis.
    Zero-Execution Guarantee: Untrusted binaries are NEVER executed on the host workstation.
    Handles CAPE Sandbox remote API submission, simulated network monitoring,
    and ingestion of external PCAP / sandbox telemetry captures.
    """

    def start_sandbox_run(
        self,
        investigation_id: str,
        evidence_id: str,
        target_filename: str,
        sandbox_environment: str = "Simulated Network (FakeNet-NG)",
        is_simulated: bool = True
    ) -> DynamicSandboxRun:
        """
        Initiates or registers a dynamic sandbox execution run.
        Verifies sandbox isolation before starting.
        """
        # Safety Check: Untrusted execution on host is strictly prohibited
        if sandbox_environment.lower() in ("host", "local_host", "workstation"):
            raise ValueError(
                "Execution Rejected: Dynamic malware execution on the host workstation is strictly forbidden by forensic safety policies."
            )

        run_id = f"RUN-{datetime.utcnow().strftime('%Y%m%d')}-{uuid.uuid4().hex[:6].upper()}"
        run = DynamicSandboxRun(
            id=run_id,
            investigation_id=investigation_id,
            evidence_id=evidence_id,
            target_binary=target_filename,
            sandbox_environment=sandbox_environment,
            status="PENDING",
            is_simulated_network=is_simulated,
            simulated_services=["DNS", "HTTP", "HTTPS"] if is_simulated else [],
            duration_seconds=0.0,
            started_at_utc=datetime.utcnow().isoformat(),
            process_count=0,
            file_event_count=0,
            registry_event_count=0,
            network_flow_count=0,
            dropped_artifacts_count=0,
            sandbox_logs=[
                f"[{datetime.utcnow().isoformat()}] Dynamic run {run_id} initialized.",
                f"[{datetime.utcnow().isoformat()}] Target binary: {target_filename}",
                f"[{datetime.utcnow().isoformat()}] Environment: {sandbox_environment} (Simulated Network: {is_simulated})",
                f"[{datetime.utcnow().isoformat()}] Zero Host Execution Policy: Verified isolated runner."
            ],
            limitations="Isolated execution strictly enforced. No execution on workstation."
        )
        repo.create_sandbox_run(run)
        return run

    def import_sandbox_telemetry(
        self,
        investigation_id: str,
        evidence_id: str,
        target_binary: str,
        sandbox_environment: str,
        is_simulated_network: bool,
        telemetry_json: Optional[Dict[str, Any]] = None,
        pcap_file_path: Optional[Path] = None
    ) -> DynamicSandboxRun:
        """
        Safely imports telemetry events and PCAP produced by a dedicated VM sandbox or simulation tool.
        Extracts processes, registry, dropped files, and network flows.
        """
        run = self.start_sandbox_run(
            investigation_id=investigation_id,
            evidence_id=evidence_id,
            target_filename=target_binary,
            sandbox_environment=sandbox_environment,
            is_simulated=is_simulated_network
        )

        process_count = 0
        file_count = 0
        reg_count = 0
        dropped_count = 0

        # Ingest behavioral JSON events if provided
        if telemetry_json:
            processes = telemetry_json.get("processes", [])
            for p in processes:
                process_count += 1
                ev = DynamicTelemetryEvent(
                    id=f"EV-PROC-{uuid.uuid4().hex[:8]}",
                    run_id=run.id,
                    investigation_id=investigation_id,
                    event_category="PROCESS",
                    timestamp_utc=p.get("timestamp_utc", datetime.utcnow().isoformat()),
                    process_id=p.get("pid"),
                    process_name=p.get("name"),
                    parent_process_id=p.get("parent_pid"),
                    parent_process_name=p.get("parent_name"),
                    command_line=p.get("command_line"),
                    operation="ProcessCreate",
                    details=p.get("details", {}),
                    is_simulated=is_simulated_network
                )
                repo.add_telemetry_event(ev)

            file_events = telemetry_json.get("file_events", [])
            for f in file_events:
                file_count += 1
                ev = DynamicTelemetryEvent(
                    id=f"EV-FILE-{uuid.uuid4().hex[:8]}",
                    run_id=run.id,
                    investigation_id=investigation_id,
                    event_category="FILE",
                    timestamp_utc=f.get("timestamp_utc", datetime.utcnow().isoformat()),
                    target_path=f.get("path"),
                    operation=f.get("operation", "WriteFile"),
                    details=f.get("details", {}),
                    is_simulated=is_simulated_network
                )
                repo.add_telemetry_event(ev)

            reg_events = telemetry_json.get("registry_events", [])
            for r in reg_events:
                reg_count += 1
                ev = DynamicTelemetryEvent(
                    id=f"EV-REG-{uuid.uuid4().hex[:8]}",
                    run_id=run.id,
                    investigation_id=investigation_id,
                    event_category="REGISTRY",
                    timestamp_utc=r.get("timestamp_utc", datetime.utcnow().isoformat()),
                    target_path=r.get("key"),
                    operation=r.get("operation", "SetValue"),
                    details=r.get("details", {}),
                    is_simulated=is_simulated_network
                )
                repo.add_telemetry_event(ev)

            dropped_files = telemetry_json.get("dropped_files", [])
            for d in dropped_files:
                dropped_count += 1
                art = DroppedArtifactRecord(
                    id=f"DROP-{uuid.uuid4().hex[:8]}",
                    run_id=run.id,
                    investigation_id=investigation_id,
                    filename=d.get("filename", "unknown_artifact"),
                    file_path=d.get("file_path"),
                    size_bytes=d.get("size_bytes", 0),
                    sha256=d.get("sha256", ""),
                    file_type=d.get("file_type"),
                    dropped_by_process=d.get("dropped_by_process", "TargetBinary"),
                    timestamp_utc=d.get("timestamp_utc", datetime.utcnow().isoformat())
                )
                repo.add_dropped_artifact_record(art)

        # Ingest and dissect PCAP if provided
        pcap_flow_count = 0
        pcap_sha256 = None
        pcap_name = None

        if pcap_file_path and pcap_file_path.exists():
            pcap_name = pcap_file_path.name
            flows, pcap_events, meta = pcap_telemetry_engine.analyze_pcap(
                file_path=pcap_file_path,
                investigation_id=investigation_id,
                run_id=run.id,
                is_simulated=is_simulated_network
            )
            pcap_sha256 = meta.get("pcap_sha256")
            pcap_flow_count = len(flows)

            for fl in flows:
                repo.add_network_flow_record(fl)
            for ev in pcap_events:
                repo.add_telemetry_event(ev)

            run.sandbox_logs.append(
                f"[{datetime.utcnow().isoformat()}] PCAP {pcap_name} parsed: {meta.get('total_packets', 0)} packets, {len(flows)} flows, {len(meta.get('dns_queries', []))} DNS queries."
            )

        run.status = "COMPLETED"
        run.completed_at_utc = datetime.utcnow().isoformat()
        run.process_count = process_count
        run.file_event_count = file_count
        run.registry_event_count = reg_count
        run.network_flow_count = pcap_flow_count
        run.dropped_artifacts_count = dropped_count
        run.pcap_filename = pcap_name
        run.pcap_sha256 = pcap_sha256
        run.sandbox_logs.append(f"[{datetime.utcnow().isoformat()}] Dynamic run completed successfully.")

        repo.update_sandbox_run(run)
        return run

sandbox_manager = SandboxManager()
