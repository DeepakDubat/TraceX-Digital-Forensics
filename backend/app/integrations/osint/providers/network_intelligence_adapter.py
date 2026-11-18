import httpx
from datetime import datetime
from typing import Dict, Any, List, Optional
from backend.app.core.models import OSINTObservation
from backend.app.integrations.osint.network_intelligence import NetworkIntelligence
from backend.app.integrations.osint.providers.base_provider import (
    BaseOSINTProvider,
    STATUS_SUCCESS,
    STATUS_INVALID_INDICATOR
)

class NetworkIntelligenceProvider(BaseOSINTProvider):
    provider_id = "network_info"
    provider_name = "NetworkInfo"
    supported_types = ["ip", "ipv4", "ipv6"]
    requires_credentials = False
    endpoint_display = "https://ipapi.co/ (or local RFC1918 evaluation)"
    rate_limits = "Free GeoIP API: 1,000 requests/day"
    known_limitations = "Geolocation is approximate and based on BGP announcements; does not represent physical device location."
    privacy_implications = "Passive IP query. Flags RFC 1918 private subnets without transmitting to internet."

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
        net_intel = NetworkIntelligence(local_only, timeout=timeout)
        if indicator_type in ("ip", "ipv4", "ipv6"):
            return net_intel.query_ip(value, investigation_id, indicator_id)
        else:
            return self.create_observation(
                investigation_id, indicator_id, indicator_type, value,
                STATUS_INVALID_INDICATOR,
                error_message=f"NetworkInfo provider only supports IP addresses, got '{indicator_type}'."
            )

    def test_connection(self) -> Dict[str, Any]:
        try:
            with httpx.Client(timeout=5.0) as client:
                resp = client.get("https://ipapi.co/8.8.8.8/json/")
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
