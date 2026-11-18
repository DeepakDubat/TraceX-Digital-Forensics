import logging
from typing import Dict, Any, List, Optional
from pathlib import Path

from backend.app.core.models import NetworkFlowRecord, DynamicObservation
from backend.app.database.repository import repo
from backend.app.analyzers.network.pcap_telemetry_engine import pcap_telemetry_engine

logger = logging.getLogger(__name__)

class DynamicNetworkMonitor:
    """
    Monitors, parses, and analyzes network flows, DNS resolutions, and TLS handshakes
    captured during sandbox execution.
    """

    SUSPICIOUS_PORTS = {4444, 1337, 8888, 9999, 5555, 6667, 7777, 31337, 8080}

    def analyze_network_telemetry(self, investigation_id: str, run_id: Optional[str] = None) -> List[Dict[str, Any]]:
        """Analyzes recorded flows and flags suspicious traffic patterns."""
        flows = repo.list_network_flow_records(investigation_id, run_id=run_id)
        findings = []

        for flow in flows:
            # Check suspicious port
            if flow.dst_port in self.SUSPICIOUS_PORTS:
                findings.append({
                    "type": "SUSPICIOUS_PORT_CONNECTION",
                    "severity": "HIGH",
                    "title": f"Connection to Common Malware / Backdoor Port {flow.dst_port}",
                    "details": f"Outbound {flow.protocol} flow to {flow.dst_ip}:{flow.dst_port}",
                    "flow_id": flow.id
                })

            # Check direct IP HTTP connection (bypassing DNS)
            if not flow.dns_hostname and flow.dst_ip not in ("127.0.0.1", "0.0.0.0") and flow.dst_port in (80, 8080, 8000):
                findings.append({
                    "type": "DIRECT_IP_HTTP_REQUEST",
                    "severity": "MEDIUM",
                    "title": f"Direct IP HTTP Request ({flow.dst_ip})",
                    "details": "Malware frequently connects directly to C2 servers via raw IP to avoid DNS logging.",
                    "flow_id": flow.id
                })

        return findings

    def parse_pcap_capture(self, pcap_path: Path) -> List[Dict[str, Any]]:
        """Dissects a PCAP capture file using TraceX's pure-Python PCAP engine."""
        if not pcap_path.exists():
            return []
        try:
            return pcap_telemetry_engine.dissect_pcap(pcap_path)
        except Exception as e:
            logger.error(f"PCAP parsing failed for {pcap_path}: {e}")
            return []

dynamic_network_monitor = DynamicNetworkMonitor()
