import uuid
import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple

from backend.app.core.models import (
    DynamicSandboxRun,
    DynamicTelemetryEvent,
    NetworkFlowRecord,
    DroppedArtifactRecord,
    DynamicObservation
)
from backend.app.database.repository import repo
from backend.app.analyzers.dynamic.sandbox_policy import sandbox_policy

logger = logging.getLogger(__name__)

class TelemetryCollector:
    """
    Ingests, normalizes, and persists runtime behavioral telemetry events
    across processes, filesystem, registry, and network.
    """

    def ingest_bundle(
        self,
        run: DynamicSandboxRun,
        telemetry_data: Dict[str, Any]
    ) -> Dict[str, int]:
        """
        Normalizes and persists a complete telemetry bundle from a sandbox provider.
        Returns counts of ingested items.
        """
        counts = {
            "processes": 0,
            "files": 0,
            "registry": 0,
            "network": 0,
            "observations": 0
        }

        # 1. Process Events
        proc_list = telemetry_data.get("processes", [])
        for p in proc_list:
            ev_id = f"EV-PROC-{uuid.uuid4().hex[:8]}"
            ev = DynamicTelemetryEvent(
                id=ev_id,
                run_id=run.id,
                investigation_id=run.investigation_id,
                event_category="PROCESS",
                timestamp_utc=p.get("timestamp_utc", datetime.utcnow().isoformat()),
                process_id=p.get("pid") or p.get("process_id"),
                process_name=p.get("name") or p.get("process_name"),
                parent_process_id=p.get("ppid") or p.get("parent_pid") or p.get("parent_process_id"),
                parent_process_name=p.get("parent_name") or p.get("parent_process_name"),
                command_line=p.get("cmdline") or p.get("command_line"),
                operation=p.get("operation", "ProcessCreate"),
                details=p.get("details", {}),
                is_simulated=run.is_simulated_network
            )
            repo.add_telemetry_event(ev)
            counts["processes"] += 1

        # 2. File Events
        file_list = telemetry_data.get("file_events") or telemetry_data.get("files") or []
        for f in file_list:
            ev_id = f"EV-FILE-{uuid.uuid4().hex[:8]}"
            details_dict = f.get("details", {})
            if not details_dict:
                details_dict = {k: v for k, v in f.items() if k not in ("path", "target_path", "action", "operation", "timestamp_utc")}
            ev = DynamicTelemetryEvent(
                id=ev_id,
                run_id=run.id,
                investigation_id=run.investigation_id,
                event_category="FILE",
                timestamp_utc=f.get("timestamp_utc", datetime.utcnow().isoformat()),
                target_path=f.get("path") or f.get("target_path"),
                operation=f.get("action") or f.get("operation", "WriteFile"),
                details=details_dict,
                is_simulated=run.is_simulated_network
            )
            repo.add_telemetry_event(ev)
            counts["files"] += 1

        # 3. Registry Events
        reg_list = telemetry_data.get("registry_events") or telemetry_data.get("registry") or []
        for r in reg_list:
            ev_id = f"EV-REG-{uuid.uuid4().hex[:8]}"
            details_dict = r.get("details", {})
            if not details_dict:
                details_dict = {k: v for k, v in r.items() if k not in ("key", "target_path", "action", "operation", "timestamp_utc")}
            ev = DynamicTelemetryEvent(
                id=ev_id,
                run_id=run.id,
                investigation_id=run.investigation_id,
                event_category="REGISTRY",
                timestamp_utc=r.get("timestamp_utc", datetime.utcnow().isoformat()),
                target_path=r.get("key") or r.get("target_path"),
                operation=r.get("action") or r.get("operation", "SetValue"),
                details=details_dict,
                is_simulated=run.is_simulated_network
            )
            repo.add_telemetry_event(ev)
            counts["registry"] += 1

        # 4. Network Flows
        net_list = telemetry_data.get("network_flows") or telemetry_data.get("network") or []
        for net in net_list:
            flow_id = f"FLOW-{uuid.uuid4().hex[:8]}"
            if "src_ip" in net:
                src_ip = net["src_ip"]
                src_port = int(net.get("src_port", 0))
                dst_ip = net.get("dst_ip", "127.0.0.1")
                dst_port = int(net.get("dst_port", 0))
            else:
                src_ip, src_port = self._parse_ip_port(net.get("local", "127.0.0.1:0"))
                dst_ip, dst_port = self._parse_ip_port(net.get("foreign", "127.0.0.1:0"))

            flow = NetworkFlowRecord(
                id=flow_id,
                run_id=run.id,
                investigation_id=run.investigation_id,
                timestamp_utc=net.get("timestamp_utc", datetime.utcnow().isoformat()),
                src_ip=src_ip,
                src_port=src_port,
                dst_ip=dst_ip,
                dst_port=dst_port,
                protocol=net.get("protocol") or net.get("proto", "TCP").upper(),
                direction="OUTBOUND",
                dns_hostname=net.get("dns_hostname"),
                tls_sni=net.get("tls_sni"),
                http_method=net.get("http_method"),
                http_status=net.get("http_status"),
                packet_count=net.get("packets", 1),
                byte_count=net.get("bytes", 0),
                is_simulated=net.get("is_simulated", run.is_simulated_network)
            )
            repo.add_network_flow_record(flow)
            counts["network"] += 1

        # Update run aggregates
        run.process_count += counts["processes"]
        run.file_event_count += counts["files"]
        run.registry_event_count += counts["registry"]
        run.network_flow_count += counts["network"]
        repo.update_sandbox_run(run)

        return counts

    def _parse_ip_port(self, endpoint_str: str) -> Tuple[str, int]:
        try:
            if ":" in endpoint_str:
                ip, port = endpoint_str.rsplit(":", 1)
                return ip.strip(), int(port) if port.isdigit() else 0
        except Exception:
            pass
        return "127.0.0.1", 0

telemetry_collector = TelemetryCollector()
