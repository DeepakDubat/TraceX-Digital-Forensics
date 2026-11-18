import httpx
from datetime import datetime
from typing import Dict, Any, List, Optional
from backend.app.config import settings
from backend.app.core.models import OSINTObservation
from backend.app.database.repository import repo
from backend.app.integrations.osint.providers.base_provider import (
    BaseOSINTProvider,
    STATUS_SUCCESS,
    STATUS_NOT_FOUND,
    STATUS_RATE_LIMITED,
    STATUS_UNAUTHORIZED,
    STATUS_TIMEOUT,
    STATUS_NETWORK_ERROR,
    STATUS_UNAVAILABLE,
    STATUS_SKIPPED_LOCAL_ONLY,
    STATUS_INVALID_INDICATOR
)

class IPinfoProvider(BaseOSINTProvider):
    provider_id = "ipinfo"
    provider_name = "IPinfo"
    supported_types = ["ip", "ipv4", "ipv6"]
    requires_credentials = True
    endpoint_display = "https://ipinfo.io/"
    rate_limits = "Free Tier: 50,000 requests/month with token"
    known_limitations = "VPN/Proxy detection requires standard paid subscription."
    privacy_implications = "Passive IP query. Never exposes analyst location or evidence binaries."

    def is_configured(self) -> bool:
        key = repo.get_setting("ipinfo_api_key") or settings.IPINFO_API_KEY
        return bool(key and not key.startswith("•••"))

    def _get_api_key(self) -> str:
        key = repo.get_setting("ipinfo_api_key") or settings.IPINFO_API_KEY
        return key if key and not key.startswith("•••") else ""

    def query(
        self,
        indicator_type: str,
        value: str,
        investigation_id: str,
        indicator_id: str,
        local_only: bool = False,
        timeout: float = 8.0
    ) -> OSINTObservation:
        clean_val = value.strip()
        if local_only:
            return self.create_observation(
                investigation_id, indicator_id, indicator_type, clean_val,
                STATUS_SKIPPED_LOCAL_ONLY,
                error_message="Query blocked: Local-Only mode is active."
            )

        if indicator_type not in ("ip", "ipv4", "ipv6"):
            return self.create_observation(
                investigation_id, indicator_id, indicator_type, clean_val,
                STATUS_INVALID_INDICATOR,
                error_message="IPinfo only supports IP addresses."
            )

        api_key = self._get_api_key()
        if not api_key:
            return self.create_observation(
                investigation_id, indicator_id, indicator_type, clean_val,
                STATUS_UNAVAILABLE,
                error_message="IPinfo API key is not configured."
            )

        url = f"https://ipinfo.io/{clean_val}/json"
        headers = {"Authorization": f"Bearer {api_key}"}
        permalink = f"https://ipinfo.io/{clean_val}"

        try:
            with httpx.Client(timeout=timeout) as client:
                resp = client.get(url, headers=headers)
                if resp.status_code == 200:
                    data = resp.json()
                    org = data.get("org", "")
                    asn = org.split()[0] if org.startswith("AS") else None
                    as_name = org[len(asn)+1:] if asn else org

                    normalized = {
                        "ip": data.get("ip"),
                        "hostname": data.get("hostname"),
                        "city": data.get("city"),
                        "region": data.get("region"),
                        "country": data.get("country"),
                        "loc": data.get("loc"),
                        "org": org,
                        "asn": asn,
                        "as_name": as_name,
                        "postal": data.get("postal"),
                        "timezone": data.get("timezone")
                    }
                    return self.create_observation(
                        investigation_id, indicator_id, indicator_type, clean_val,
                        STATUS_SUCCESS,
                        normalized_data=normalized,
                        permalink=permalink
                    )
                elif resp.status_code == 429:
                    return self.create_observation(
                        investigation_id, indicator_id, indicator_type, clean_val,
                        STATUS_RATE_LIMITED,
                        permalink=permalink,
                        error_message="IPinfo monthly rate limit reached."
                    )
                elif resp.status_code in (401, 403):
                    return self.create_observation(
                        investigation_id, indicator_id, indicator_type, clean_val,
                        STATUS_UNAUTHORIZED,
                        permalink=permalink,
                        error_message="IPinfo token authentication failed."
                    )
                elif resp.status_code == 404:
                    return self.create_observation(
                        investigation_id, indicator_id, indicator_type, clean_val,
                        STATUS_NOT_FOUND,
                        permalink=permalink,
                        error_message="IP address not found in IPinfo."
                    )
                else:
                    return self.create_observation(
                        investigation_id, indicator_id, indicator_type, clean_val,
                        STATUS_NETWORK_ERROR,
                        permalink=permalink,
                        error_message=f"IPinfo HTTP {resp.status_code}"
                    )
        except httpx.TimeoutException:
            return self.create_observation(
                investigation_id, indicator_id, indicator_type, clean_val,
                STATUS_TIMEOUT,
                permalink=permalink,
                error_message="IPinfo query timed out."
            )
        except Exception as e:
            return self.create_observation(
                investigation_id, indicator_id, indicator_type, clean_val,
                STATUS_NETWORK_ERROR,
                permalink=permalink,
                error_message=f"IPinfo error: {str(e)}"
            )

    def test_connection(self) -> Dict[str, Any]:
        api_key = self._get_api_key()
        if not api_key:
            return {"status": "Not configured", "connected": False, "provider": self.provider_name}
        try:
            headers = {"Authorization": f"Bearer {api_key}"}
            with httpx.Client(timeout=5.0) as client:
                resp = client.get("https://ipinfo.io/json", headers=headers)
                if resp.status_code == 200:
                    return {
                        "status": "Connected",
                        "connected": True,
                        "provider": self.provider_name,
                        "rate_limit": self.rate_limits
                    }
                elif resp.status_code in (401, 403):
                    return {"status": "Invalid credentials", "connected": False, "provider": self.provider_name}
                elif resp.status_code == 429:
                    return {"status": "Rate limited", "connected": False, "provider": self.provider_name}
                else:
                    return {"status": f"HTTP {resp.status_code}", "connected": False, "provider": self.provider_name}
        except httpx.TimeoutException:
            return {"status": "Timeout", "connected": False, "provider": self.provider_name}
        except Exception as e:
            return {"status": "Network error", "connected": False, "provider": self.provider_name, "error": str(e)}
