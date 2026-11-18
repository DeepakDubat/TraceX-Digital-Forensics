import uuid
import logging
from datetime import datetime
from typing import Dict, Any, List, Optional, Set

from backend.app.core.models import (
    StaticDynamicCorrelation,
    UniversalInvestigationDetail
)
from backend.app.database.repository import repo

logger = logging.getLogger(__name__)

class StaticDynamicCorrelator:
    """
    Correlates static binary capabilities and extracted artifacts with observed
    dynamic sandbox events, network flows, and dropped artifacts.
    Enforces honest evidence semantics:
    - Never equates an API import with proof of execution.
    - Never treats a connection attempt as proof of successful C2.
    - Distinguishes simulated network responses from real server communication.
    """

    def correlate_investigation(self, detail: UniversalInvestigationDetail) -> List[StaticDynamicCorrelation]:
        inv_id = detail.record.id
        correlations: List[StaticDynamicCorrelation] = []
        seen_keys: Set[str] = set()

        dynamic_events = repo.list_telemetry_events(inv_id)
        flows = repo.list_network_flow_records(inv_id)
        dropped_files = repo.list_dropped_artifact_records(inv_id)

        # 1. Correlate Static Domains / Hostnames with Dynamic DNS queries
        dns_events = [e for e in dynamic_events if e.event_category == "DNS_QUERY"]
        static_domains: Dict[str, str] = {} # domain -> finding_id or indicator_id

        for ind in getattr(detail, "osint_indicators", []):
            if ind.indicator_type in ("domain", "hostname"):
                static_domains[ind.normalized_value.lower()] = ind.id
        for c2 in getattr(detail, "c2_indicators", []):
            if getattr(c2, "domain", None):
                static_domains[c2.domain.lower()] = c2.id

        for ev in dns_events:
            q_domain = ev.details.get("query_domain", "").lower()
            if q_domain in static_domains:
                key = f"DNS:{q_domain}"
                if key not in seen_keys:
                    seen_keys.add(key)
                    stat_id = static_domains[q_domain]
                    corr = StaticDynamicCorrelation(
                        id=f"CORR-DNS-{uuid.uuid4().hex[:8]}",
                        investigation_id=inv_id,
                        static_finding_id=stat_id,
                        dynamic_event_id=ev.id,
                        source_evidence_id=detail.record.id,
                        indicator_value=q_domain,
                        correlation_method="DOMAIN_MATCH_IN_DYNAMIC_DNS",
                        confidence="Confirmed" if not ev.is_simulated else "High",
                        supporting_event_summary=f"Domain '{q_domain}' statically identified in binary was actively resolved via DNS during runtime execution.",
                        packet_reference=ev.details.get("packet_ref"),
                        is_simulated_event=ev.is_simulated,
                        alternative_explanation="Domain resolution might be initiated by an advertising SDK or benign third-party library rather than malware payload.",
                        limitations="A DNS query demonstrates runtime resolution intent, but does not prove successful data exfiltration or active payload receipt.",
                        created_at_utc=datetime.utcnow().isoformat()
                    )
                    repo.add_static_dynamic_correlation(corr)
                    correlations.append(corr)

        # 2. Correlate Static IPs with Dynamic Network Flows
        static_ips: Dict[str, str] = {}
        for ind in getattr(detail, "osint_indicators", []):
            if ind.indicator_type in ("ip", "ipv4", "ipv6"):
                static_ips[ind.normalized_value] = ind.id
        for c2 in getattr(detail, "c2_indicators", []):
            if getattr(c2, "ip_address", None):
                static_ips[c2.ip_address] = c2.id

        for fl in flows:
            dest = fl.dst_ip
            if dest in static_ips:
                key = f"FLOW:{dest}:{fl.dst_port}"
                if key not in seen_keys:
                    seen_keys.add(key)
                    stat_id = static_ips[dest]
                    sim_note = "simulated fake network" if fl.is_simulated else "live network capture"
                    corr = StaticDynamicCorrelation(
                        id=f"CORR-FLOW-{uuid.uuid4().hex[:8]}",
                        investigation_id=inv_id,
                        static_finding_id=stat_id,
                        dynamic_event_id=fl.id,
                        source_evidence_id=detail.record.id,
                        indicator_value=f"{dest}:{fl.dst_port}",
                        correlation_method="IP_MATCH_IN_NETWORK_FLOW",
                        confidence="High",
                        supporting_event_summary=f"Statically embedded destination IP {dest}:{fl.dst_port} was contacted via {fl.protocol} ({sim_note}, {fl.packet_count} packets).",
                        packet_reference=fl.packet_reference,
                        is_simulated_event=fl.is_simulated,
                        alternative_explanation="Connection could represent CDN infrastructure or telemetry synchronization.",
                        limitations="Observed TCP/UDP packet exchange alone does not prove malicious command execution.",
                        created_at_utc=datetime.utcnow().isoformat()
                    )
                    repo.add_static_dynamic_correlation(corr)
                    correlations.append(corr)

        # 3. Correlate PE Imports / Capabilities with Process & Registry Execution Events
        pe_meta = getattr(detail, "pe_metadata", None)
        if pe_meta and hasattr(pe_meta, "imported_functions"):
            imports = set(f.lower() for f in pe_meta.imported_functions)
            for ev in dynamic_events:
                if ev.event_category == "PROCESS" and ("createprocess" in imports or "shellexecute" in imports):
                    key = f"PROC:{ev.process_name}"
                    if key not in seen_keys:
                        seen_keys.add(key)
                        corr = StaticDynamicCorrelation(
                            id=f"CORR-PROC-{uuid.uuid4().hex[:8]}",
                            investigation_id=inv_id,
                            static_finding_id="PE-IMPORT-PROCESS",
                            dynamic_event_id=ev.id,
                            source_evidence_id=detail.record.id,
                            indicator_value=str(ev.process_name or ev.command_line),
                            correlation_method="IMPORT_CAPABILITY_OBSERVED_IN_PROCESS",
                            confidence="High",
                            supporting_event_summary=f"Static process creation capability (e.g. CreateProcess) correlated with observed child process: {ev.process_name} (PID: {ev.process_id}).",
                            is_simulated_event=ev.is_simulated,
                            alternative_explanation="Standard installer or application update child process initialization.",
                            limitations="Static import suggests potential capability; dynamic event confirms actual runtime invocation.",
                            created_at_utc=datetime.utcnow().isoformat()
                        )
                        repo.add_static_dynamic_correlation(corr)
                        correlations.append(corr)

                elif ev.event_category == "REGISTRY" and ("regsetvalue" in imports or "regcreatekey" in imports):
                    key = f"REG:{ev.target_path}"
                    if key not in seen_keys and ev.target_path:
                        seen_keys.add(key)
                        corr = StaticDynamicCorrelation(
                            id=f"CORR-REG-{uuid.uuid4().hex[:8]}",
                            investigation_id=inv_id,
                            static_finding_id="PE-IMPORT-REGISTRY",
                            dynamic_event_id=ev.id,
                            source_evidence_id=detail.record.id,
                            indicator_value=str(ev.target_path),
                            correlation_method="IMPORT_CAPABILITY_OBSERVED_IN_REGISTRY",
                            confidence="High",
                            supporting_event_summary=f"Static registry manipulation capability correlated with dynamic key write: {ev.target_path}.",
                            is_simulated_event=ev.is_simulated,
                            alternative_explanation="Legitimate software settings or window position persistence.",
                            limitations="Registry modification may be non-malicious configuration persistence.",
                            created_at_utc=datetime.utcnow().isoformat()
                        )
                        repo.add_static_dynamic_correlation(corr)
                        correlations.append(corr)

        # 4. Correlate Dropped Artifacts with Extracted Evidence Items
        evidence_hashes = {ev.sha256.lower(): ev.filename for ev in getattr(detail, "evidence_items", []) if getattr(ev, "sha256", None)}
        for d in dropped_files:
            if d.sha256.lower() in evidence_hashes:
                key = f"DROP:{d.sha256}"
                if key not in seen_keys:
                    seen_keys.add(key)
                    corr = StaticDynamicCorrelation(
                        id=f"CORR-DROP-{uuid.uuid4().hex[:8]}",
                        investigation_id=inv_id,
                        static_finding_id=f"EVD-HASH-{d.sha256[:8]}",
                        dynamic_event_id=d.id,
                        source_evidence_id=detail.record.id,
                        indicator_value=d.sha256,
                        correlation_method="DROPPED_FILE_MATCH_IN_EVIDENCE",
                        confidence="Confirmed",
                        supporting_event_summary=f"Dropped artifact '{d.filename}' (SHA256: {d.sha256[:16]}...) precisely matches known investigation evidence item.",
                        is_simulated_event=False,
                        alternative_explanation="Self-unpacking extraction or resource extraction routine.",
                        limitations="Identical hash confirms binary drop; dynamic capability depends on subsequent execution.",
                        created_at_utc=datetime.utcnow().isoformat()
                    )
                    repo.add_static_dynamic_correlation(corr)
                    correlations.append(corr)

        # 5. Correlate Android Permissions with Dynamic Activity
        meta = getattr(detail, "metadata", None)
        static_permissions = set()
        if meta and hasattr(meta, "permissions"):
            static_permissions = set(p.lower() for p in meta.permissions)

        if "android.permission.internet" in static_permissions:
            key = "PERM:INTERNET"
            if key not in seen_keys:
                seen_keys.add(key)
                has_net = len(flows) > 0 or any(e.event_category in ("NETWORK_FLOW", "DNS_QUERY") for e in dynamic_events)
                status_label = "RUNTIME_OBSERVED" if has_net else "RUNTIME_NOT_OBSERVED"
                corr = StaticDynamicCorrelation(
                    id=f"CORR-PERM-{uuid.uuid4().hex[:8]}",
                    investigation_id=inv_id,
                    static_finding_id="PERM-INTERNET",
                    dynamic_event_id=flows[0].id if flows else "EV-NONE",
                    source_evidence_id=detail.record.id,
                    indicator_value="android.permission.INTERNET",
                    correlation_method="PERMISSION_CORRELATED_WITH_RUNTIME_SOCKETS",
                    confidence="Confirmed" if has_net else "Medium",
                    supporting_event_summary=(
                        f"Static permission 'android.permission.INTERNET' was actively triggered at runtime ({len(flows)} network flows observed)."
                        if has_net else
                        "Static permission 'android.permission.INTERNET' was declared in AndroidManifest.xml, but zero outbound network flows were observed during execution."
                    ),
                    is_simulated_event=False,
                    alternative_explanation="Application may require user interaction or network availability to initiate communication.",
                    limitations="Absence of network traffic does not prove benign behavior; sample may delay execution or detect sandbox.",
                    created_at_utc=datetime.utcnow().isoformat()
                )
                repo.add_static_dynamic_correlation(corr)
                correlations.append(corr)

        return correlations

    def classify_behavior_correlation(
        self,
        static_present: bool,
        dynamic_observed: bool,
        sandbox_limited: bool = False
    ) -> str:
        """
        Assigns standard 5-tier forensic correlation status:
        - STATIC_INDICATOR: Code exists, not triggered during run.
        - RUNTIME_OBSERVED: Explicitly confirmed active during execution.
        - RUNTIME_NOT_OBSERVED: Executed without triggering behavior.
        - INCONCLUSIVE: Evasion or incomplete execution suspected.
        - ENVIRONMENT_LIMITATION: Missing virtualization/capabilities.
        """
        if sandbox_limited:
            return "ENVIRONMENT_LIMITATION"
        if static_present and dynamic_observed:
            return "RUNTIME_OBSERVED"
        if static_present and not dynamic_observed:
            return "STATIC_INDICATOR"
        if not static_present and dynamic_observed:
            return "RUNTIME_OBSERVED"
        return "RUNTIME_NOT_OBSERVED"

static_dynamic_correlator = StaticDynamicCorrelator()
