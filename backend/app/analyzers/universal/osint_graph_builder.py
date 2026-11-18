import uuid
from typing import Dict, Any, List, Set, Tuple, Optional
from backend.app.core.models import (
    OSINTGraphNode,
    OSINTGraphEdge,
    OSINTIndicator,
    OSINTObservation,
    SecretExposureFinding,
    UniversalInvestigationDetail
)

class OSINTGraphBuilder:
    """
    Constructs an interactive OSINT Evidence Graph with explicit node types
    and 16 forensic relationship edge types for visual analysis.
    """

    def build_graph(self, detail: UniversalInvestigationDetail) -> Tuple[List[OSINTGraphNode], List[OSINTGraphEdge]]:
        nodes_dict: Dict[str, OSINTGraphNode] = {}
        edges: List[OSINTGraphEdge] = []
        seen_edges: Set[str] = set()

        def add_node(node: OSINTGraphNode):
            if node.id not in nodes_dict:
                nodes_dict[node.id] = node

        def add_edge(edge: OSINTGraphEdge):
            key = f"{edge.source}->{edge.target}:{edge.relationship_type}"
            if key not in seen_edges:
                seen_edges.add(key)
                edges.append(edge)

        # 1. Add Evidence Files as root nodes
        for ev in detail.evidence_items:
            ev_node_id = f"node_evd_{ev.id}"
            add_node(OSINTGraphNode(
                id=ev_node_id,
                node_type="evidence_file",
                label=ev.filename,
                entity_value=ev.sha256[:16] + "...",
                provenance="Direct Evidence",
                severity="Informational",
                data={
                    "file_size": ev.file_size,
                    "format": ev.detected_format,
                    "sha256": ev.sha256
                }
            ))

        # 2. Add Indicators as Nodes and link to Evidence Files
        for ind in detail.osint_indicators:
            ind_node_id = f"node_ind_{ind.id}"
            node_type = self._map_indicator_node_type(ind.indicator_type)
            label = ind.masked_value if ind.is_sensitive_secret else ind.value

            # Truncate long labels for clean UI display
            display_label = label if len(label) <= 30 else label[:27] + "..."

            add_node(OSINTGraphNode(
                id=ind_node_id,
                node_type=node_type,
                label=display_label,
                entity_value=ind.normalized_value,
                provenance="Direct Evidence" if ind.pivot_depth == 0 else f"Derived Pivot (Depth {ind.pivot_depth})",
                severity="Critical" if ind.is_sensitive_secret else ("High" if ind.indicator_type in ("ip", "c2_url") else "Informational"),
                data={
                    "indicator_type": ind.indicator_type,
                    "pivot_depth": ind.pivot_depth,
                    "extractor": ind.extractor_or_provider
                }
            ))

            # Edge from Evidence to Indicator
            if ind.evidence_id:
                ev_node_id = f"node_evd_{ind.evidence_id}"
                if ev_node_id in nodes_dict:
                    add_edge(OSINTGraphEdge(
                        id=f"edge_{uuid.uuid4().hex[:8]}",
                        source=ev_node_id,
                        target=ind_node_id,
                        relationship_type="EXTRACTED_FROM",
                        provider_or_tool=ind.extractor_or_provider,
                        confidence=ind.confidence
                    ))

            # Edge from Parent Indicator to Child Indicator (Pivots)
            if ind.parent_indicator_id:
                parent_node_id = f"node_ind_{ind.parent_indicator_id}"
                if parent_node_id in nodes_dict:
                    add_edge(OSINTGraphEdge(
                        id=f"edge_{uuid.uuid4().hex[:8]}",
                        source=parent_node_id,
                        target=ind_node_id,
                        relationship_type="PARENT_INDICATOR",
                        provider_or_tool="RecursivePivotEngine",
                        confidence="High"
                    ))

        # 3. Add Observations & Inter-Indicator Relationships
        for obs in detail.osint_observations:
            if obs.status != "SUCCESS" or not obs.normalized_data:
                continue

            ind_node_id = f"node_ind_{obs.indicator_id}"
            if ind_node_id not in nodes_dict:
                continue

            data = obs.normalized_data

            # A. DNS: Domain -> Resolves to IP
            if obs.provider == "DNS" and "resolved_ips" in data:
                for ip in data.get("resolved_ips", []):
                    # Check if IP exists as a node
                    target_ip_node = self._find_node_by_value(nodes_dict, ip)
                    if not target_ip_node:
                        target_id = f"node_dyn_ip_{uuid.uuid4().hex[:8]}"
                        target_ip_node = OSINTGraphNode(
                            id=target_id,
                            node_type="ip",
                            label=ip,
                            entity_value=ip,
                            provenance="OSINT Provider",
                            severity="Informational"
                        )
                        add_node(target_ip_node)

                    add_edge(OSINTGraphEdge(
                        id=f"edge_{uuid.uuid4().hex[:8]}",
                        source=ind_node_id,
                        target=target_ip_node.id,
                        relationship_type="RESOLVES_TO",
                        provider_or_tool="DNS",
                        confidence="High",
                        limitations="Current DNS resolution"
                    ))

            # B. Reverse DNS: IP -> Reverse Resolves to Hostname
            elif obs.provider == "ReverseDNS" and "resolved_hostnames" in data:
                for host in data.get("resolved_hostnames", []):
                    target_h_node = self._find_node_by_value(nodes_dict, host)
                    if not target_h_node:
                        target_id = f"node_dyn_dom_{uuid.uuid4().hex[:8]}"
                        target_h_node = OSINTGraphNode(
                            id=target_id,
                            node_type="domain",
                            label=host,
                            entity_value=host,
                            provenance="OSINT Provider",
                            severity="Informational"
                        )
                        add_node(target_h_node)

                    add_edge(OSINTGraphEdge(
                        id=f"edge_{uuid.uuid4().hex[:8]}",
                        source=ind_node_id,
                        target=target_h_node.id,
                        relationship_type="REVERSE_RESOLVES_TO",
                        provider_or_tool="ReverseDNS",
                        confidence="High"
                    ))

            # C. Network Intelligence: IP -> ASN & Organization
            elif obs.provider == "NetworkInfo":
                asn = data.get("asn")
                as_org = data.get("as_org")
                if asn:
                    asn_node_id = f"node_asn_{asn.replace(' ', '_')}"
                    add_node(OSINTGraphNode(
                        id=asn_node_id,
                        node_type="asn",
                        label=str(asn),
                        entity_value=str(asn),
                        provenance="OSINT Provider",
                        severity="Informational"
                    ))
                    add_edge(OSINTGraphEdge(
                        id=f"edge_{uuid.uuid4().hex[:8]}",
                        source=ind_node_id,
                        target=asn_node_id,
                        relationship_type="ASSIGNED_TO_NETWORK",
                        provider_or_tool="NetworkInfo",
                        confidence="High"
                    ))

                if as_org:
                    org_node_id = f"node_org_{uuid.uuid4().hex[:8]}"
                    add_node(OSINTGraphNode(
                        id=org_node_id,
                        node_type="organization",
                        label=str(as_org)[:25],
                        entity_value=str(as_org),
                        provenance="OSINT Provider",
                        severity="Informational"
                    ))
                    add_edge(OSINTGraphEdge(
                        id=f"edge_{uuid.uuid4().hex[:8]}",
                        source=ind_node_id,
                        target=org_node_id,
                        relationship_type="HOSTED_BY",
                        provider_or_tool="NetworkInfo",
                        confidence="High"
                    ))

            # D. Certificate Transparency: Domain -> Hostname in Certificate
            elif obs.provider == "CertTransparency" and "discovered_subdomains" in data:
                for sub in data.get("discovered_subdomains", [])[:8]:
                    sub_node = self._find_node_by_value(nodes_dict, sub)
                    if not sub_node:
                        sub_node_id = f"node_sub_{uuid.uuid4().hex[:8]}"
                        sub_node = OSINTGraphNode(
                            id=sub_node_id,
                            node_type="domain",
                            label=sub,
                            entity_value=sub,
                            provenance="CertTransparency",
                            severity="Informational"
                        )
                        add_node(sub_node)

                    add_edge(OSINTGraphEdge(
                        id=f"edge_{uuid.uuid4().hex[:8]}",
                        source=ind_node_id,
                        target=sub_node.id,
                        relationship_type="CERTIFICATE_LISTS_HOSTNAME",
                        provider_or_tool="crt.sh",
                        confidence="High"
                    ))

        # 4. Add Secret Exposure Findings
        for sec in detail.secret_exposure_findings:
            sec_node_id = f"node_sec_{sec.id}"
            add_node(OSINTGraphNode(
                id=sec_node_id,
                node_type="secret_exposure",
                label=sec.masked_token,
                entity_value=sec.secret_type,
                provenance="Direct Evidence",
                severity="Critical",
                data={"risk": sec.risk_level, "safety": sec.safety_attestation}
            ))

            # Link to evidence
            ev_node_id = f"node_evd_{sec.evidence_id}"
            if ev_node_id in nodes_dict:
                add_edge(OSINTGraphEdge(
                    id=f"edge_{uuid.uuid4().hex[:8]}",
                    source=ev_node_id,
                    target=sec_node_id,
                    relationship_type="EXTRACTED_FROM",
                    provider_or_tool="SecretCorrelationEngine",
                    confidence="Confirmed"
                ))

            # Link to any correlated public identities
            for ident in sec.independently_found_public_identities:
                ident_node = self._find_node_by_value(nodes_dict, ident)
                if not ident_node:
                    ident_node_id = f"node_tg_user_{uuid.uuid4().hex[:8]}"
                    ident_node = OSINTGraphNode(
                        id=ident_node_id,
                        node_type="telegram_username",
                        label=ident,
                        entity_value=ident,
                        provenance="Direct Evidence",
                        severity="High"
                    )
                    add_node(ident_node)

                add_edge(OSINTGraphEdge(
                    id=f"edge_{uuid.uuid4().hex[:8]}",
                    source=sec_node_id,
                    target=ident_node.id,
                    relationship_type="POSSIBLE_RELATIONSHIP",
                    provider_or_tool="SecretCorrelationEngine",
                    confidence="Medium",
                    limitations="Co-located in same evidence binary; public channel/handle"
                ))

        return list(nodes_dict.values()), edges

    def _map_indicator_node_type(self, ind_type: str) -> str:
        mapping = {
            "ip": "ip",
            "ipv4": "ip",
            "ipv6": "ip",
            "domain": "domain",
            "hostname": "domain",
            "url": "url",
            "hash": "file_hash",
            "telegram_username": "telegram_username",
            "telegram_bot_token": "secret_exposure",
            "email": "organization"
        }
        return mapping.get(ind_type.lower(), "domain")

    def _find_node_by_value(self, nodes_dict: Dict[str, OSINTGraphNode], val: str) -> Optional[OSINTGraphNode]:
        clean_v = val.strip().lower()
        for node in nodes_dict.values():
            if node.entity_value.strip().lower() == clean_v:
                return node
        return None

osint_graph_builder = OSINTGraphBuilder()
