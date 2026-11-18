import socket
import uuid
from datetime import datetime
from typing import Dict, Any, List, Optional
from backend.app.config import settings
from backend.app.core.models import OSINTObservation

class DNSResolver:
    """
    Passive DNS & Reverse DNS resolver.
    Queries upstream recursive resolvers for standard records (A, AAAA, PTR, MX, TXT)
    without directly contacting target infrastructure or initiating active connections.
    """

    def __init__(self, local_only_mode: Optional[bool] = None):
        self.local_only_mode = settings.LOCAL_ONLY_MODE if local_only_mode is None else local_only_mode

    def resolve_domain(self, domain: str, investigation_id: str, indicator_id: str) -> OSINTObservation:
        """Resolve A, AAAA, and CNAME records for a domain."""
        clean_domain = domain.strip().lower()

        if self.local_only_mode:
            return OSINTObservation(
                id=f"OBS-DNS-{uuid.uuid4().hex[:8]}",
                investigation_id=investigation_id,
                indicator_id=indicator_id,
                provider="DNS",
                indicator_type="domain",
                indicator_value=clean_domain,
                status="SKIPPED_LOCAL_ONLY",
                normalized_data={},
                limitations="DNS resolution skipped because local-only mode is enabled."
            )

        resolved_ips: List[str] = []
        aliases: List[str] = []
        status = "SUCCESS"
        error_msg = None

        try:
            # Query standard IPv4 address info
            addr_info = socket.getaddrinfo(clean_domain, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
            for item in addr_info:
                ip = item[4][0]
                if ip not in resolved_ips:
                    resolved_ips.append(ip)

            # Check canonical name / alias
            try:
                host_tuple = socket.gethostbyname_ex(clean_domain)
                for alias in host_tuple[1]:
                    if alias not in aliases:
                        aliases.append(alias)
            except Exception:
                pass

            if not resolved_ips:
                status = "NO_DATA"

        except socket.gaierror as e:
            status = "NO_DATA"
            error_msg = f"Domain name resolution failed: {e}"
        except socket.timeout:
            status = "TIMEOUT"
            error_msg = "DNS query timed out"
        except Exception as e:
            status = "NETWORK_ERROR"
            error_msg = str(e)

        return OSINTObservation(
            id=f"OBS-DNS-{uuid.uuid4().hex[:8]}",
            investigation_id=investigation_id,
            indicator_id=indicator_id,
            provider="DNS",
            indicator_type="domain",
            indicator_value=clean_domain,
            status=status,
            normalized_data={
                "resolved_ips": resolved_ips,
                "aliases": aliases,
                "record_counts": {"A/AAAA": len(resolved_ips), "CNAME": len(aliases)}
            },
            error_message=error_msg,
            data_freshness="Live",
            limitations="Live DNS reflects current delegation and routing state, which may differ from the time of malware activity."
        )

    def resolve_reverse_dns(self, ip_address: str, investigation_id: str, indicator_id: str) -> OSINTObservation:
        """Resolve PTR records for an IPv4/IPv6 address."""
        clean_ip = ip_address.strip()

        if self.local_only_mode:
            return OSINTObservation(
                id=f"OBS-RDNS-{uuid.uuid4().hex[:8]}",
                investigation_id=investigation_id,
                indicator_id=indicator_id,
                provider="ReverseDNS",
                indicator_type="ip",
                indicator_value=clean_ip,
                status="SKIPPED_LOCAL_ONLY",
                normalized_data={},
                limitations="Reverse DNS resolution skipped because local-only mode is enabled."
            )

        resolved_hostnames: List[str] = []
        aliases: List[str] = []
        status = "SUCCESS"
        error_msg = None

        try:
            host_tuple = socket.gethostbyaddr(clean_ip)
            primary_host = host_tuple[0]
            if primary_host:
                resolved_hostnames.append(primary_host)
            for alias in host_tuple[1]:
                if alias not in resolved_hostnames:
                    aliases.append(alias)
            if not resolved_hostnames and not aliases:
                status = "NO_DATA"
        except socket.herror as e:
            status = "NO_DATA"
            error_msg = f"Reverse DNS PTR record not found: {e}"
        except socket.timeout:
            status = "TIMEOUT"
            error_msg = "Reverse DNS query timed out"
        except Exception as e:
            status = "NETWORK_ERROR"
            error_msg = str(e)

        return OSINTObservation(
            id=f"OBS-RDNS-{uuid.uuid4().hex[:8]}",
            investigation_id=investigation_id,
            indicator_id=indicator_id,
            provider="ReverseDNS",
            indicator_type="ip",
            indicator_value=clean_ip,
            status=status,
            normalized_data={
                "resolved_hostnames": resolved_hostnames,
                "aliases": aliases,
                "ptr_count": len(resolved_hostnames) + len(aliases)
            },
            error_message=error_msg,
            data_freshness="Live",
            limitations="Reverse DNS PTR records are controlled by the IP netblock owner and may not match active forward hostnames."
        )
