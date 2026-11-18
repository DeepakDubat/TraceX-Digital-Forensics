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

class GreyNoiseProvider(BaseOSINTProvider):
    provider_id = "greynoise"
    provider_name = "GreyNoise"
    supported_types = ["ip", "ipv4"]
    requires_credentials = True
    endpoint_display = "https://api.greynoise.io/v3/community/"
    rate_limits = "Community API: Rate limits apply"
    known_limitations = "Identifies mass scanners, worms, and benign services (RIOT); does not track targeted single-target C2."
    privacy_implications = "Passive IP query to GreyNoise sensor network."

    def is_configured(self) -> bool:
        key = repo.get_setting("greynoise_api_key") or settings.GREYNOISE_API_KEY
        return bool(key and not key.startswith("•••"))

    def _get_api_key(self) -> str:
        key = repo.get_setting("greynoise_api_key") or settings.GREYNOISE_API_KEY
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

        if indicator_type not in ("ip", "ipv4"):
            return self.create_observation(
                investigation_id, indicator_id, indicator_type, clean_val,
                STATUS_INVALID_INDICATOR,
                error_message="GreyNoise only supports IPv4 addresses."
            )

        api_key = self._get_api_key()
        if not api_key:
            return self.create_observation(
                investigation_id, indicator_id, indicator_type, clean_val,
                STATUS_UNAVAILABLE,
                error_message="GreyNoise API key is not configured."
            )

        url = f"https://api.greynoise.io/v3/community/{clean_val}"
        headers = {"key": api_key, "Accept": "application/json"}
        permalink = f"https://viz.greynoise.io/ip/{clean_val}"

        try:
            with httpx.Client(timeout=timeout) as client:
                resp = client.get(url, headers=headers)
                if resp.status_code == 200:
                    data = resp.json()
                    noise = data.get("noise", False)
                    riot = data.get("riot", False)
                    classification = data.get("classification", "unknown")
                    normalized = {
                        "ip": data.get("ip", clean_val),
                        "noise": noise,
                        "riot": riot,
                        "classification": classification,
                        "name": data.get("name"),
                        "link": data.get("link"),
                        "last_seen": data.get("last_seen"),
                        "message": data.get("message")
                    }
                    return self.create_observation(
                        investigation_id, indicator_id, indicator_type, clean_val,
                        STATUS_SUCCESS,
                        normalized_data=normalized,
                        permalink=permalink,
                        provider_timestamp_utc=data.get("last_seen")
                    )
                elif resp.status_code == 404:
                    return self.create_observation(
                        investigation_id, indicator_id, indicator_type, clean_val,
                        STATUS_NOT_FOUND,
                        permalink=permalink,
                        error_message="IP not observed scanning by GreyNoise (clean / unobserved)."
                    )
                elif resp.status_code == 429:
                    return self.create_observation(
                        investigation_id, indicator_id, indicator_type, clean_val,
                        STATUS_RATE_LIMITED,
                        permalink=permalink,
                        error_message="GreyNoise rate limit exceeded."
                    )
                elif resp.status_code in (401, 403):
                    return self.create_observation(
                        investigation_id, indicator_id, indicator_type, clean_val,
                        STATUS_UNAUTHORIZED,
                        permalink=permalink,
                        error_message="GreyNoise authorization failed."
                    )
                else:
                    return self.create_observation(
                        investigation_id, indicator_id, indicator_type, clean_val,
                        STATUS_NETWORK_ERROR,
                        permalink=permalink,
                        error_message=f"GreyNoise HTTP {resp.status_code}"
                    )
        except httpx.TimeoutException:
            return self.create_observation(
                investigation_id, indicator_id, indicator_type, clean_val,
                STATUS_TIMEOUT,
                permalink=permalink,
                error_message="GreyNoise query timed out."
            )
        except Exception as e:
            return self.create_observation(
                investigation_id, indicator_id, indicator_type, clean_val,
                STATUS_NETWORK_ERROR,
                permalink=permalink,
                error_message=f"GreyNoise error: {str(e)}"
            )

    def test_connection(self) -> Dict[str, Any]:
        api_key = self._get_api_key()
        if not api_key:
            return {"status": "Not configured", "connected": False, "provider": self.provider_name}
        try:
            # Query known benign DNS 8.8.8.8
            headers = {"key": api_key, "Accept": "application/json"}
            with httpx.Client(timeout=5.0) as client:
                resp = client.get("https://api.greynoise.io/v3/community/8.8.8.8", headers=headers)
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
