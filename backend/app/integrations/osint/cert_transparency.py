import httpx
import uuid
from typing import Dict, Any, List, Optional, Set
from backend.app.config import settings
from backend.app.core.models import OSINTObservation

class CertTransparencyClient:
    """
    Passive Certificate Transparency (CT) search client querying crt.sh logs.
    Identifies historical and active TLS certificates, Subject Alternative Names (SANs),
    and reveals hidden subdomains and related infrastructure without any direct network scans.
    """

    def __init__(self, local_only_mode: Optional[bool] = None, timeout: float = 8.0):
        self.local_only_mode = settings.LOCAL_ONLY_MODE if local_only_mode is None else local_only_mode
        self.timeout = timeout

    def search_domain(self, domain: str, investigation_id: str, indicator_id: str) -> OSINTObservation:
        clean_domain = domain.strip().lower()

        if self.local_only_mode:
            return OSINTObservation(
                id=f"OBS-CT-{uuid.uuid4().hex[:8]}",
                investigation_id=investigation_id,
                indicator_id=indicator_id,
                provider="CertTransparency",
                indicator_type="domain",
                indicator_value=clean_domain,
                status="SKIPPED_LOCAL_ONLY",
                normalized_data={},
                limitations="Certificate Transparency search skipped because local-only mode is active."
            )

        try:
            with httpx.Client(timeout=self.timeout, follow_redirects=True) as client:
                url = f"https://crt.sh/?q={clean_domain}&output=json"
                resp = client.get(url, headers={"User-Agent": "UniversalForensics-OSINT/1.0"})

                if resp.status_code == 200:
                    try:
                        raw_entries = resp.json()
                    except Exception:
                        return OSINTObservation(
                            id=f"OBS-CT-{uuid.uuid4().hex[:8]}",
                            investigation_id=investigation_id,
                            indicator_id=indicator_id,
                            provider="CertTransparency",
                            indicator_type="domain",
                            indicator_value=clean_domain,
                            status="NO_DATA",
                            error_message="crt.sh returned non-JSON response."
                        )

                    if not raw_entries or not isinstance(raw_entries, list):
                        return OSINTObservation(
                            id=f"OBS-CT-{uuid.uuid4().hex[:8]}",
                            investigation_id=investigation_id,
                            indicator_id=indicator_id,
                            provider="CertTransparency",
                            indicator_type="domain",
                            indicator_value=clean_domain,
                            status="NO_DATA",
                            normalized_data={"certificates": [], "discovered_subdomains": []},
                            permalink=f"https://crt.sh/?q={clean_domain}",
                            data_freshness="Live"
                        )

                    # Deduplicate and extract subdomains & cert summaries
                    discovered_subdomains: Set[str] = set()
                    certs_summary: List[Dict[str, Any]] = []

                    for entry in raw_entries[:50]: # Cap at 50 records
                        name_value = entry.get("name_value", "")
                        common_name = entry.get("common_name", "")
                        issuer_name = entry.get("issuer_name", "")
                        not_before = entry.get("not_before")
                        not_after = entry.get("not_after")
                        serial = entry.get("serial_number")

                        # Split multi-name values (newline separated in crt.sh)
                        for n in name_value.split("\n"):
                            cleaned_sub = n.strip().lower()
                            if cleaned_sub.startswith("*."):
                                cleaned_sub = cleaned_sub[2:]
                            if cleaned_sub and cleaned_sub != clean_domain and clean_domain in cleaned_sub:
                                discovered_subdomains.add(cleaned_sub)

                        if len(certs_summary) < 15:
                            certs_summary.append({
                                "common_name": common_name,
                                "issuer": issuer_name.split(",")[0] if issuer_name else "Unknown",
                                "not_before": not_before,
                                "not_after": not_after,
                                "serial_number": str(serial) if serial else None
                            })

                    return OSINTObservation(
                        id=f"OBS-CT-{uuid.uuid4().hex[:8]}",
                        investigation_id=investigation_id,
                        indicator_id=indicator_id,
                        provider="CertTransparency",
                        indicator_type="domain",
                        indicator_value=clean_domain,
                        status="SUCCESS",
                        normalized_data={
                            "total_logged_certificates": len(raw_entries),
                            "discovered_subdomains": sorted(list(discovered_subdomains)),
                            "recent_certificates": certs_summary
                        },
                        permalink=f"https://crt.sh/?q={clean_domain}",
                        data_freshness="Live",
                        limitations="Certificate logs record issuance, not whether domains or subdomains are currently hosted or active."
                    )
                elif resp.status_code in (502, 503, 504):
                    return OSINTObservation(
                        id=f"OBS-CT-{uuid.uuid4().hex[:8]}",
                        investigation_id=investigation_id,
                        indicator_id=indicator_id,
                        provider="CertTransparency",
                        indicator_type="domain",
                        indicator_value=clean_domain,
                        status="UNAVAILABLE",
                        error_message="crt.sh service temporarily unavailable."
                    )
                else:
                    return OSINTObservation(
                        id=f"OBS-CT-{uuid.uuid4().hex[:8]}",
                        investigation_id=investigation_id,
                        indicator_id=indicator_id,
                        provider="CertTransparency",
                        indicator_type="domain",
                        indicator_value=clean_domain,
                        status="PARTIAL",
                        error_message=f"HTTP {resp.status_code}"
                    )
        except httpx.TimeoutException:
            return OSINTObservation(
                id=f"OBS-CT-{uuid.uuid4().hex[:8]}",
                investigation_id=investigation_id,
                indicator_id=indicator_id,
                provider="CertTransparency",
                indicator_type="domain",
                indicator_value=clean_domain,
                status="TIMEOUT",
                error_message="crt.sh search timed out."
            )
        except Exception as e:
            return OSINTObservation(
                id=f"OBS-CT-{uuid.uuid4().hex[:8]}",
                investigation_id=investigation_id,
                indicator_id=indicator_id,
                provider="CertTransparency",
                indicator_type="domain",
                indicator_value=clean_domain,
                status="NETWORK_ERROR",
                error_message=str(e)
            )
