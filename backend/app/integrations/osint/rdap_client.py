import httpx
import uuid
from typing import Dict, Any, List, Optional
from backend.app.config import settings
from backend.app.core.models import OSINTObservation

class RDAPClient:
    """
    Passive RDAP (Registration Data Access Protocol) Client.
    Queries open RDAP aggregators (e.g., rdap.org) for domain and IP ownership data.
    Never submits proprietary evidence or contacts the target infrastructure directly.
    """

    def __init__(self, local_only_mode: Optional[bool] = None, timeout: float = 6.0):
        self.local_only_mode = settings.LOCAL_ONLY_MODE if local_only_mode is None else local_only_mode
        self.timeout = timeout
        self.base_url = "https://rdap.org"

    def query_domain(self, domain: str, investigation_id: str, indicator_id: str) -> OSINTObservation:
        clean_domain = domain.strip().lower()

        if self.local_only_mode:
            return OSINTObservation(
                id=f"OBS-RDAP-{uuid.uuid4().hex[:8]}",
                investigation_id=investigation_id,
                indicator_id=indicator_id,
                provider="RDAP",
                indicator_type="domain",
                indicator_value=clean_domain,
                status="SKIPPED_LOCAL_ONLY",
                normalized_data={},
                limitations="RDAP query skipped because local-only mode is active."
            )

        try:
            with httpx.Client(timeout=self.timeout, follow_redirects=True) as client:
                resp = client.get(
                    f"{self.base_url}/domain/{clean_domain}",
                    headers={"Accept": "application/rdap+json"}
                )

                if resp.status_code == 200:
                    data = resp.json()
                    parsed = self._parse_domain_rdap(data)
                    return OSINTObservation(
                        id=f"OBS-RDAP-{uuid.uuid4().hex[:8]}",
                        investigation_id=investigation_id,
                        indicator_id=indicator_id,
                        provider="RDAP",
                        indicator_type="domain",
                        indicator_value=clean_domain,
                        status="SUCCESS",
                        normalized_data=parsed,
                        permalink=f"https://rdap.org/domain/{clean_domain}",
                        data_freshness="Live",
                        limitations="Whois/RDAP records may be protected by privacy proxies or GDPR redaction."
                    )
                elif resp.status_code == 404:
                    return OSINTObservation(
                        id=f"OBS-RDAP-{uuid.uuid4().hex[:8]}",
                        investigation_id=investigation_id,
                        indicator_id=indicator_id,
                        provider="RDAP",
                        indicator_type="domain",
                        indicator_value=clean_domain,
                        status="NOT_FOUND",
                        normalized_data={"message": "Domain record not found in authoritative RDAP registry."},
                        data_freshness="Live"
                    )
                elif resp.status_code == 429:
                    return OSINTObservation(
                        id=f"OBS-RDAP-{uuid.uuid4().hex[:8]}",
                        investigation_id=investigation_id,
                        indicator_id=indicator_id,
                        provider="RDAP",
                        indicator_type="domain",
                        indicator_value=clean_domain,
                        status="RATE_LIMITED",
                        error_message="RDAP registry rate limit encountered."
                    )
                else:
                    return OSINTObservation(
                        id=f"OBS-RDAP-{uuid.uuid4().hex[:8]}",
                        investigation_id=investigation_id,
                        indicator_id=indicator_id,
                        provider="RDAP",
                        indicator_type="domain",
                        indicator_value=clean_domain,
                        status="PARTIAL",
                        error_message=f"RDAP query returned HTTP {resp.status_code}"
                    )
        except httpx.TimeoutException:
            return OSINTObservation(
                id=f"OBS-RDAP-{uuid.uuid4().hex[:8]}",
                investigation_id=investigation_id,
                indicator_id=indicator_id,
                provider="RDAP",
                indicator_type="domain",
                indicator_value=clean_domain,
                status="TIMEOUT",
                error_message="RDAP request timed out."
            )
        except Exception as e:
            return OSINTObservation(
                id=f"OBS-RDAP-{uuid.uuid4().hex[:8]}",
                investigation_id=investigation_id,
                indicator_id=indicator_id,
                provider="RDAP",
                indicator_type="domain",
                indicator_value=clean_domain,
                status="NETWORK_ERROR",
                error_message=str(e)
            )

    def query_ip(self, ip_address: str, investigation_id: str, indicator_id: str) -> OSINTObservation:
        clean_ip = ip_address.strip()

        if self.local_only_mode:
            return OSINTObservation(
                id=f"OBS-RDAP-{uuid.uuid4().hex[:8]}",
                investigation_id=investigation_id,
                indicator_id=indicator_id,
                provider="RDAP",
                indicator_type="ip",
                indicator_value=clean_ip,
                status="SKIPPED_LOCAL_ONLY",
                normalized_data={},
                limitations="RDAP query skipped because local-only mode is active."
            )

        try:
            with httpx.Client(timeout=self.timeout, follow_redirects=True) as client:
                resp = client.get(
                    f"{self.base_url}/ip/{clean_ip}",
                    headers={"Accept": "application/rdap+json"}
                )

                if resp.status_code == 200:
                    data = resp.json()
                    parsed = self._parse_ip_rdap(data)
                    return OSINTObservation(
                        id=f"OBS-RDAP-{uuid.uuid4().hex[:8]}",
                        investigation_id=investigation_id,
                        indicator_id=indicator_id,
                        provider="RDAP",
                        indicator_type="ip",
                        indicator_value=clean_ip,
                        status="SUCCESS",
                        normalized_data=parsed,
                        permalink=f"https://rdap.org/ip/{clean_ip}",
                        data_freshness="Live",
                        limitations="Regional internet registry allocations describe the parent netblock, not necessarily the current occupant."
                    )
                elif resp.status_code == 404:
                    return OSINTObservation(
                        id=f"OBS-RDAP-{uuid.uuid4().hex[:8]}",
                        investigation_id=investigation_id,
                        indicator_id=indicator_id,
                        provider="RDAP",
                        indicator_type="ip",
                        indicator_value=clean_ip,
                        status="NOT_FOUND",
                        normalized_data={"message": "IP netblock not found in RIR registry."}
                    )
                elif resp.status_code == 429:
                    return OSINTObservation(
                        id=f"OBS-RDAP-{uuid.uuid4().hex[:8]}",
                        investigation_id=investigation_id,
                        indicator_id=indicator_id,
                        provider="RDAP",
                        indicator_type="ip",
                        indicator_value=clean_ip,
                        status="RATE_LIMITED",
                        error_message="RDAP registry rate limit encountered."
                    )
                else:
                    return OSINTObservation(
                        id=f"OBS-RDAP-{uuid.uuid4().hex[:8]}",
                        investigation_id=investigation_id,
                        indicator_id=indicator_id,
                        provider="RDAP",
                        indicator_type="ip",
                        indicator_value=clean_ip,
                        status="PARTIAL",
                        error_message=f"RDAP query returned HTTP {resp.status_code}"
                    )
        except httpx.TimeoutException:
            return OSINTObservation(
                id=f"OBS-RDAP-{uuid.uuid4().hex[:8]}",
                investigation_id=investigation_id,
                indicator_id=indicator_id,
                provider="RDAP",
                indicator_type="ip",
                indicator_value=clean_ip,
                status="TIMEOUT",
                error_message="RDAP request timed out."
            )
        except Exception as e:
            return OSINTObservation(
                id=f"OBS-RDAP-{uuid.uuid4().hex[:8]}",
                investigation_id=investigation_id,
                indicator_id=indicator_id,
                provider="RDAP",
                indicator_type="ip",
                indicator_value=clean_ip,
                status="NETWORK_ERROR",
                error_message=str(e)
            )

    def _parse_domain_rdap(self, data: Dict[str, Any]) -> Dict[str, Any]:
        handle = data.get("handle", "")
        status = data.get("status", [])
        
        events = {}
        for ev in data.get("events", []):
            action = ev.get("eventAction")
            date = ev.get("eventDate")
            if action and date:
                events[action] = date

        # Entities (Registrar, Registrant)
        registrar = None
        registrant = None
        for ent in data.get("entities", []):
            roles = ent.get("roles", [])
            vcard = ent.get("vcardArray", [])
            ent_name = self._extract_vcard_fn(vcard) or ent.get("handle")
            if "registrar" in roles:
                registrar = ent_name
            elif "registrant" in roles:
                registrant = ent_name

        # Name servers
        nameservers = []
        for ns in data.get("nameservers", []):
            ns_name = ns.get("ldhName")
            if ns_name:
                nameservers.append(ns_name.lower())

        return {
            "handle": handle,
            "status": status,
            "registration_date": events.get("registration"),
            "expiration_date": events.get("expiration"),
            "last_changed_date": events.get("last changed"),
            "registrar": registrar or "Redacted / Privacy Protected",
            "registrant": registrant or "Redacted / Privacy Protected",
            "nameservers": nameservers
        }

    def _parse_ip_rdap(self, data: Dict[str, Any]) -> Dict[str, Any]:
        handle = data.get("handle", "")
        start_addr = data.get("startAddress", "")
        end_addr = data.get("endAddress", "")
        ip_version = data.get("ipVersion", "")
        name = data.get("name", "")
        country = data.get("country", "")

        # Entities
        org = None
        for ent in data.get("entities", []):
            roles = ent.get("roles", [])
            if "registrant" in roles or "administrative" in roles or not org:
                vcard = ent.get("vcardArray", [])
                fn = self._extract_vcard_fn(vcard)
                if fn:
                    org = fn

        return {
            "handle": handle,
            "netblock_name": name,
            "start_address": start_addr,
            "end_address": end_addr,
            "ip_version": ip_version,
            "country": country,
            "organization": org or "Unknown Organization"
        }

    def _extract_vcard_fn(self, vcard_array: Any) -> Optional[str]:
        if not isinstance(vcard_array, list) or len(vcard_array) < 2:
            return None
        entries = vcard_array[1]
        if not isinstance(entries, list):
            return None
        for item in entries:
            if isinstance(item, list) and len(item) >= 4 and item[0] == "fn":
                return item[3]
        return None
