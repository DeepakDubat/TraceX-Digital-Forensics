import httpx
from datetime import datetime
from typing import Dict, Any, List, Optional
from backend.app.core.models import OSINTObservation
from backend.app.integrations.osint.rdap_client import RDAPClient
from backend.app.integrations.osint.providers.base_provider import (
    BaseOSINTProvider,
    STATUS_SUCCESS,
    STATUS_NOT_FOUND,
    STATUS_TIMEOUT,
    STATUS_NETWORK_ERROR,
    STATUS_SKIPPED_LOCAL_ONLY,
    STATUS_INVALID_INDICATOR
)

class RDAPProvider(BaseOSINTProvider):
    provider_id = "rdap"
    provider_name = "RDAP"
    supported_types = ["domain", "hostname", "ip", "ipv4", "ipv6"]
    requires_credentials = False
    endpoint_display = "https://rdap.org/"
    rate_limits = "Public Aggregator: Fair use"
    known_limitations = "Registration data frequently redacted for privacy (GDPR / proxy services)."
    privacy_implications = "Passive registration directory query. Does not interact with target hosts."

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
        client = RDAPClient(local_only, timeout=timeout)
        if indicator_type in ("domain", "hostname"):
            return client.query_domain(value, investigation_id, indicator_id)
        elif indicator_type in ("ip", "ipv4", "ipv6"):
            return client.query_ip(value, investigation_id, indicator_id)
        else:
            return self.create_observation(
                investigation_id, indicator_id, indicator_type, value,
                STATUS_INVALID_INDICATOR,
                error_message=f"RDAP provider does not support indicator type: {indicator_type}"
            )

    def test_connection(self) -> Dict[str, Any]:
        try:
            with httpx.Client(timeout=5.0, follow_redirects=True) as client:
                resp = client.get("https://rdap.org/domain/example.com", headers={"Accept": "application/rdap+json"})
                if resp.status_code == 200:
                    return {
                        "status": "Connected",
                        "connected": True,
                        "provider": self.provider_name,
                        "rate_limit": self.rate_limits
                    }
                else:
                    return {"status": f"HTTP {resp.status_code}", "connected": False, "provider": self.provider_name}
        except httpx.TimeoutException:
            return {"status": "Timeout", "connected": False, "provider": self.provider_name}
        except Exception as e:
            return {"status": "Network error", "connected": False, "provider": self.provider_name, "error": str(e)}
