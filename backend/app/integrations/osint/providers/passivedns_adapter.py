import httpx
from datetime import datetime
from typing import Dict, Any, List, Optional
from backend.app.core.models import OSINTObservation
from backend.app.integrations.osint.providers.base_provider import (
    BaseOSINTProvider,
    STATUS_SUCCESS,
    STATUS_NOT_FOUND,
    STATUS_TIMEOUT,
    STATUS_NETWORK_ERROR,
    STATUS_SKIPPED_LOCAL_ONLY,
    STATUS_INVALID_INDICATOR
)

class PassiveDNSProvider(BaseOSINTProvider):
    provider_id = "passive_dns"
    provider_name = "PassiveDNS"
    supported_types = ["domain", "hostname", "ip", "ipv4"]
    requires_credentials = False
    endpoint_display = "https://api.hackertarget.com/dnslookup/"
    rate_limits = "Public endpoint: 50 queries/day free tier"
    known_limitations = "Historical passive DNS mapping; dependent on public sensor sightings."
    privacy_implications = "Passive lookup. No active queries sent to target nameserver."

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
        clean_val = value.strip().lower()
        if local_only:
            return self.create_observation(
                investigation_id, indicator_id, indicator_type, clean_val,
                STATUS_SKIPPED_LOCAL_ONLY,
                error_message="Query blocked: Local-Only mode is active."
            )

        if indicator_type in ("domain", "hostname"):
            url = f"https://api.hackertarget.com/dnslookup/?q={clean_val}"
            permalink = f"https://hackertarget.com/dns-lookup/?q={clean_val}"
        elif indicator_type in ("ip", "ipv4"):
            url = f"https://api.hackertarget.com/reverseiplookup/?q={clean_val}"
            permalink = f"https://hackertarget.com/reverse-ip-lookup/?q={clean_val}"
        else:
            return self.create_observation(
                investigation_id, indicator_id, indicator_type, clean_val,
                STATUS_INVALID_INDICATOR,
                error_message=f"PassiveDNS only supports domains and IP addresses, got '{indicator_type}'."
            )

        try:
            with httpx.Client(timeout=timeout) as client:
                resp = client.get(url)
                if resp.status_code == 200:
                    text = resp.text.strip()
                    if "error" in text.lower() or "no records" in text.lower() or "input invalid" in text.lower():
                        return self.create_observation(
                            investigation_id, indicator_id, indicator_type, clean_val,
                            STATUS_NOT_FOUND,
                            permalink=permalink,
                            error_message="No passive DNS records found."
                        )
                    lines = [line.strip() for line in text.splitlines() if line.strip()]
                    normalized = {
                        "records_count": len(lines),
                        "records": lines[:15],
                        "raw_sample": "\n".join(lines[:5])
                    }
                    return self.create_observation(
                        investigation_id, indicator_id, indicator_type, clean_val,
                        STATUS_SUCCESS,
                        normalized_data=normalized,
                        permalink=permalink
                    )
                else:
                    return self.create_observation(
                        investigation_id, indicator_id, indicator_type, clean_val,
                        STATUS_NETWORK_ERROR,
                        permalink=permalink,
                        error_message=f"PassiveDNS HTTP {resp.status_code}"
                    )
        except httpx.TimeoutException:
            return self.create_observation(
                investigation_id, indicator_id, indicator_type, clean_val,
                STATUS_TIMEOUT,
                permalink=permalink,
                error_message="PassiveDNS request timed out."
            )
        except Exception as e:
            return self.create_observation(
                investigation_id, indicator_id, indicator_type, clean_val,
                STATUS_NETWORK_ERROR,
                permalink=permalink,
                error_message=f"PassiveDNS connection error: {str(e)}"
            )

    def test_connection(self) -> Dict[str, Any]:
        try:
            with httpx.Client(timeout=5.0) as client:
                resp = client.get("https://api.hackertarget.com/dnslookup/?q=example.com")
                if resp.status_code == 200 and "error" not in resp.text.lower():
                    return {
                        "status": "Connected",
                        "connected": True,
                        "provider": self.provider_name,
                        "rate_limit": self.rate_limits
                    }
                else:
                    return {"status": "Service Unavailable", "connected": False, "provider": self.provider_name}
        except httpx.TimeoutException:
            return {"status": "Timeout", "connected": False, "provider": self.provider_name}
        except Exception as e:
            return {"status": "Network error", "connected": False, "provider": self.provider_name, "error": str(e)}
