import logging
import uuid
from datetime import datetime
from typing import List, Dict, Any, Optional, Set
from backend.app.core.models import (
    OSINTIndicator,
    OSINTObservation,
    RecursivePivotJob
)
from backend.app.database.repository import repo
from backend.app.integrations.osint.osint_service import osint_service

logger = logging.getLogger(__name__)

class RecursivePivotEngine:
    """
    Bounded Recursive Evidence Pivot Engine.
    Discovers infrastructure links by pivoting across DNS, Reverse DNS,
    Certificate Transparency subdomains, and RDAP records.
    Strictly bounded by maximum depth, query budgets, and local caching.
    """

    def run_recursive_pivot(
        self,
        investigation_id: str,
        max_depth: int = 3,
        budget_limit_queries: int = 50,
        seed_indicator_ids: Optional[List[str]] = None
    ) -> RecursivePivotJob:
        job_id = f"PIVOT-{uuid.uuid4().hex[:8]}"
        job = RecursivePivotJob(
            id=job_id,
            investigation_id=investigation_id,
            status="running",
            max_depth=max(1, min(max_depth, 5)), # Bound between 1 and 5
            current_depth=0,
            budget_limit_queries=max(5, min(budget_limit_queries, 100)),
            started_at_utc=datetime.utcnow().isoformat()
        )
        repo.create_or_update_pivot_job(job)

        try:
            # 1. Load indicators
            all_indicators = repo.list_osint_indicators(investigation_id)
            if seed_indicator_ids:
                active_seeds = [ind for ind in all_indicators if ind.id in seed_indicator_ids]
            else:
                active_seeds = [ind for ind in all_indicators if ind.pivot_depth == 0]

            evaluated_values: Set[str] = set()
            for ind in all_indicators:
                if ind.pivot_depth > 0:
                    evaluated_values.add(ind.normalized_value.lower())

            current_frontier: List[OSINTIndicator] = active_seeds
            total_evaluated = 0
            total_discovered = 0
            total_queries = 0

            for depth in range(1, job.max_depth + 1):
                if not current_frontier:
                    break

                job.current_depth = depth
                next_frontier: List[OSINTIndicator] = []

                for parent_ind in current_frontier:
                    if total_queries >= job.budget_limit_queries:
                        job.status = "stopped_budget"
                        break

                    # Skip sensitive secrets from being pivoted
                    if parent_ind.is_sensitive_secret or parent_ind.indicator_type == "telegram_bot_token":
                        continue

                    norm_val = parent_ind.normalized_value.lower()
                    evaluated_values.add(norm_val)
                    total_evaluated += 1

                    # Run OSINT enrichment for this indicator
                    observations = osint_service.enrich_indicator(parent_ind)
                    total_queries += len(observations)

                    # Extract derived indicators from observations
                    child_indicators = self._derive_child_indicators(parent_ind, observations, depth, evaluated_values)
                    for child in child_indicators:
                        evaluated_values.add(child.normalized_value.lower())
                        repo.create_osint_indicator(child)
                        next_frontier.append(child)
                        total_discovered += 1

                if job.status == "stopped_budget":
                    break

                current_frontier = next_frontier

            if job.status != "stopped_budget":
                job.status = "completed"

            job.total_indicators_evaluated = total_evaluated
            job.total_new_indicators_discovered = total_discovered
            job.total_provider_queries = total_queries
            job.completed_at_utc = datetime.utcnow().isoformat()

        except Exception as e:
            logger.error(f"Error during recursive pivot: {e}", exc_info=True)
            job.status = "failed"
            job.errors.append(str(e))
            job.completed_at_utc = datetime.utcnow().isoformat()

        repo.create_or_update_pivot_job(job)
        return job

    def _derive_child_indicators(
        self,
        parent: OSINTIndicator,
        observations: List[OSINTObservation],
        current_depth: int,
        seen_values: Set[str]
    ) -> List[OSINTIndicator]:
        derived: List[OSINTIndicator] = []

        for obs in observations:
            if obs.status != "SUCCESS" or not obs.normalized_data:
                continue

            data = obs.normalized_data

            # 1. DNS: Domain -> Resolved IPs
            if obs.provider == "DNS" and "resolved_ips" in data:
                for ip in data.get("resolved_ips", []):
                    clean_ip = ip.strip()
                    if clean_ip.lower() not in seen_values:
                        derived.append(OSINTIndicator(
                            id=f"IND-PIV-IP-{uuid.uuid4().hex[:8]}",
                            investigation_id=parent.investigation_id,
                            indicator_type="ip",
                            value=clean_ip,
                            normalized_value=clean_ip.lower(),
                            provenance_type="PIVOT_DERIVED",
                            extractor_or_provider="DNSResolver",
                            confidence="High",
                            pivot_depth=current_depth,
                            parent_indicator_id=parent.id,
                            limitations=f"Derived from DNS resolution of parent domain {parent.value}"
                        ))

            # 2. Reverse DNS: IP -> Hostnames
            if obs.provider == "ReverseDNS" and "resolved_hostnames" in data:
                for host in data.get("resolved_hostnames", []):
                    clean_h = host.strip().lower()
                    if clean_h and clean_h not in seen_values:
                        derived.append(OSINTIndicator(
                            id=f"IND-PIV-DOM-{uuid.uuid4().hex[:8]}",
                            investigation_id=parent.investigation_id,
                            indicator_type="domain",
                            value=clean_h,
                            normalized_value=clean_h,
                            provenance_type="PIVOT_DERIVED",
                            extractor_or_provider="ReverseDNS",
                            confidence="Medium",
                            pivot_depth=current_depth,
                            parent_indicator_id=parent.id,
                            limitations=f"Derived from Reverse DNS PTR record of IP {parent.value}"
                        ))

            # 3. Certificate Transparency: Domain -> Discovered Subdomains
            if obs.provider == "CertTransparency" and "discovered_subdomains" in data:
                # Cap subdomains to avoid explosion
                for sub in data.get("discovered_subdomains", [])[:10]:
                    clean_sub = sub.strip().lower()
                    if clean_sub and clean_sub not in seen_values:
                        derived.append(OSINTIndicator(
                            id=f"IND-PIV-SUB-{uuid.uuid4().hex[:8]}",
                            investigation_id=parent.investigation_id,
                            indicator_type="domain",
                            value=clean_sub,
                            normalized_value=clean_sub,
                            provenance_type="PIVOT_DERIVED",
                            extractor_or_provider="CertTransparency",
                            confidence="High",
                            pivot_depth=current_depth,
                            parent_indicator_id=parent.id,
                            limitations=f"Discovered via Certificate Transparency logs of {parent.value}"
                        ))

            # 4. RDAP: Domain -> Nameservers & Registrant Emails
            if obs.provider == "RDAP":
                if "nameservers" in data:
                    for ns in data.get("nameservers", [])[:4]:
                        clean_ns = ns.strip().lower()
                        if clean_ns and clean_ns not in seen_values:
                            derived.append(OSINTIndicator(
                                id=f"IND-PIV-NS-{uuid.uuid4().hex[:8]}",
                                investigation_id=parent.investigation_id,
                                indicator_type="domain",
                                value=clean_ns,
                                normalized_value=clean_ns,
                                provenance_type="PIVOT_DERIVED",
                                extractor_or_provider="RDAPProvider",
                                confidence="Medium",
                                pivot_depth=current_depth,
                                parent_indicator_id=parent.id,
                                limitations=f"Authoritative nameserver for domain {parent.value}"
                            ))
                if "emails" in data:
                    for em in data.get("emails", [])[:3]:
                        clean_em = em.strip().lower()
                        if clean_em and clean_em not in seen_values:
                            derived.append(OSINTIndicator(
                                id=f"IND-PIV-EML-{uuid.uuid4().hex[:8]}",
                                investigation_id=parent.investigation_id,
                                indicator_type="email",
                                value=clean_em,
                                normalized_value=clean_em,
                                provenance_type="PIVOT_DERIVED",
                                extractor_or_provider="RDAPProvider",
                                confidence="Medium",
                                pivot_depth=current_depth,
                                parent_indicator_id=parent.id,
                                limitations=f"Contact email registered with domain {parent.value}"
                            ))

            # 5. NetworkInfo / IPinfo: IP -> Autonomous System (ASN)
            if obs.provider in ("NetworkInfo", "IPinfo"):
                asn = data.get("asn")
                if asn and str(asn).strip():
                    clean_asn = str(asn).strip().upper()
                    if not clean_asn.startswith("AS"):
                        clean_asn = f"AS{clean_asn}"
                    if clean_asn.lower() not in seen_values:
                        derived.append(OSINTIndicator(
                            id=f"IND-PIV-ASN-{uuid.uuid4().hex[:8]}",
                            investigation_id=parent.investigation_id,
                            indicator_type="asn",
                            value=clean_asn,
                            normalized_value=clean_asn.lower(),
                            provenance_type="PIVOT_DERIVED",
                            extractor_or_provider=obs.provider,
                            confidence="High",
                            pivot_depth=current_depth,
                            parent_indicator_id=parent.id,
                            limitations=f"Autonomous system for routed IP {parent.value}"
                        ))

            # 6. CertTransparency: Domain -> Certificate Fingerprint
            if obs.provider == "CertTransparency" and "fingerprints" in data:
                for fp in data.get("fingerprints", [])[:3]:
                    clean_fp = fp.strip().lower()
                    if clean_fp and clean_fp not in seen_values:
                        derived.append(OSINTIndicator(
                            id=f"IND-PIV-CERT-{uuid.uuid4().hex[:8]}",
                            investigation_id=parent.investigation_id,
                            indicator_type="certificate_fingerprint",
                            value=clean_fp,
                            normalized_value=clean_fp,
                            provenance_type="PIVOT_DERIVED",
                            extractor_or_provider="CertTransparencyProvider",
                            confidence="High",
                            pivot_depth=current_depth,
                            parent_indicator_id=parent.id,
                            limitations=f"Certificate observed in CT logs for {parent.value}"
                        ))

        return derived

recursive_pivot_engine = RecursivePivotEngine()
