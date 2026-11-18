import socket
from datetime import datetime
from typing import Dict, Any, List, Optional
from backend.app.core.models import OSINTObservation
from backend.app.integrations.osint.dns_resolver import DNSResolver
from backend.app.integrations.osint.providers.base_provider import (
    BaseOSINTProvider,
    STATUS_SUCCESS,
    STATUS_NO_DATA,
    STATUS_TIMEOUT,
    STATUS_NETWORK_ERROR,
    STATUS_SKIPPED_LOCAL_ONLY,
    STATUS_INVALID_INDICATOR
)

class DNSProvider(BaseOSINTProvider):
    provider_id = "dns"
    provider_name = "DNS"
    supported_types = ["domain", "hostname", "ip", "ipv4", "ipv6"]
    requires_credentials = False
    endpoint_display = "Upstream Recursive System Resolvers"
    rate_limits = "Unrestricted / Local cache friendly"
    known_limitations = "Reflects current live DNS records; may not represent historical resolution at time of malware activity."
    privacy_implications = "Passive recursive lookup through configured DNS resolvers. Does not send traffic directly to target authoritative server."

    def is_configured(self) -> bool:
        return True

    def query(
        self,
        indicator_type: str,
        value: str,
        investigation_id: str,
        indicator_id: str,
        local_only: bool = False,
        timeout: float = 8.0
    ) -> OSINTObservation:
        resolver = DNSResolver(local_only)
        if indicator_type in ("domain", "hostname"):
            return resolver.resolve_domain(value, investigation_id, indicator_id)
        elif indicator_type in ("ip", "ipv4", "ipv6"):
            return resolver.resolve_reverse_dns(value, investigation_id, indicator_id)
        else:
            return self.create_observation(
                investigation_id, indicator_id, indicator_type, value,
                STATUS_INVALID_INDICATOR,
                error_message=f"DNS provider does not support indicator type: {indicator_type}"
            )

    def test_connection(self) -> Dict[str, Any]:
        try:
            socket.gethostbyname("dns.google")
            return {
                "status": "Connected",
                "connected": True,
                "provider": self.provider_name,
                "rate_limit": self.rate_limits
            }
        except Exception as e:
            return {"status": "Network error", "connected": False, "provider": self.provider_name, "error": str(e)}
