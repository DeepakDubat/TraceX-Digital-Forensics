import httpx
from datetime import datetime
from typing import Dict, Any, List, Optional
from backend.app.core.models import OSINTObservation
from backend.app.integrations.osint.cert_transparency import CertTransparencyClient
from backend.app.integrations.osint.providers.base_provider import (
    BaseOSINTProvider,
    STATUS_SUCCESS,
    STATUS_NOT_FOUND,
    STATUS_TIMEOUT,
    STATUS_NETWORK_ERROR,
    STATUS_SKIPPED_LOCAL_ONLY,
    STATUS_INVALID_INDICATOR
)

class CertTransparencyProvider(BaseOSINTProvider):
    provider_id = "cert_transparency"
    provider_name = "CertTransparency"
    supported_types = ["domain", "hostname"]
    requires_credentials = False
    endpoint_display = "https://crt.sh/?output=json"
    rate_limits = "Public crt.sh DB: Intermittent heavy load during peak hours"
    known_limitations = "Shows historically issued certificates; certificate presence does not guarantee the domain or host is currently online."
    privacy_implications = "Passive search of public append-only CT logs. Zero network probes to target domain."

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
        client = CertTransparencyClient(local_only, timeout=timeout)
        if indicator_type in ("domain", "hostname"):
            return client.search_domain(value, investigation_id, indicator_id)
        else:
            return self.create_observation(
                investigation_id, indicator_id, indicator_type, value,
                STATUS_INVALID_INDICATOR,
                error_message=f"Certificate Transparency provider only supports domain/hostname indicators, got '{indicator_type}'."
            )

    def test_connection(self) -> Dict[str, Any]:
        try:
            with httpx.Client(timeout=5.0) as client:
                resp = client.get("https://crt.sh/?q=example.com&output=json")
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
