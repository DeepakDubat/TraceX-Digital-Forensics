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

class CensysProvider(BaseOSINTProvider):
    provider_id = "censys"
    provider_name = "Censys"
    supported_types = ["ip", "domain", "certificate_fingerprint"]
    requires_credentials = True
    endpoint_display = "https://search.censys.io/api/v2/"
    rate_limits = "Community: Rate limits per API ID/Secret pair"
    known_limitations = "API v2 requires both API ID and API Secret."
    privacy_implications = "Passive search against Censys internet scan datasets."

    def is_configured(self) -> bool:
        api_id = repo.get_setting("censys_api_id") or settings.CENSYS_API_ID
        api_secret = repo.get_setting("censys_api_secret") or settings.CENSYS_API_SECRET
        return bool(api_id and api_secret and not api_id.startswith("•••"))

    def _get_credentials(self):
        api_id = repo.get_setting("censys_api_id") or settings.CENSYS_API_ID
        api_secret = repo.get_setting("censys_api_secret") or settings.CENSYS_API_SECRET
        return api_id, api_secret

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

        api_id, api_secret = self._get_credentials()
        if not api_id or not api_secret:
            return self.create_observation(
                investigation_id, indicator_id, indicator_type, clean_val,
                STATUS_UNAVAILABLE,
                error_message="Censys API ID / Secret not configured."
            )

        if indicator_type in ("ip", "ipv4"):
            url = f"https://search.censys.io/api/v2/hosts/{clean_val}"
            permalink = f"https://search.censys.io/hosts/{clean_val}"
        elif indicator_type in ("domain", "hostname"):
            url = f"https://search.censys.io/api/v2/hosts/search?q={clean_val}&per_page=1"
            permalink = f"https://search.censys.io/hosts?q={clean_val}"
        elif indicator_type in ("certificate_fingerprint", "cert_fingerprint"):
            url = f"https://search.censys.io/api/v2/certificates/{clean_val}"
            permalink = f"https://search.censys.io/certificates/{clean_val}"
        else:
            return self.create_observation(
                investigation_id, indicator_id, indicator_type, clean_val,
                STATUS_INVALID_INDICATOR,
                error_message=f"Censys does not support indicator type '{indicator_type}'."
            )

        try:
            with httpx.Client(timeout=timeout, auth=(api_id, api_secret)) as client:
                resp = client.get(url)
                if resp.status_code == 200:
                    data = resp.json().get("result", {})
                    services = data.get("services", [])
                    observed_ports = [s.get("port") for s in services if s.get("port")]
                    normalized = {
                        "ip": data.get("ip", clean_val),
                        "autonomous_system": data.get("autonomous_system", {}),
                        "location": data.get("location", {}),
                        "observed_ports": observed_ports,
                        "services_count": len(services),
                        "last_updated_at": data.get("last_updated_at")
                    }
                    return self.create_observation(
                        investigation_id, indicator_id, indicator_type, clean_val,
                        STATUS_SUCCESS,
                        normalized_data=normalized,
                        permalink=permalink,
                        provider_timestamp_utc=data.get("last_updated_at")
                    )
                elif resp.status_code == 404:
                    return self.create_observation(
                        investigation_id, indicator_id, indicator_type, clean_val,
                        STATUS_NOT_FOUND,
                        permalink=permalink,
                        error_message="Indicator not found in Censys dataset."
                    )
                elif resp.status_code == 429:
                    return self.create_observation(
                        investigation_id, indicator_id, indicator_type, clean_val,
                        STATUS_RATE_LIMITED,
                        permalink=permalink,
                        error_message="Censys rate limit exceeded."
                    )
                elif resp.status_code in (401, 403):
                    return self.create_observation(
                        investigation_id, indicator_id, indicator_type, clean_val,
                        STATUS_UNAUTHORIZED,
                        permalink=permalink,
                        error_message="Censys credentials invalid or unauthorized."
                    )
                else:
                    return self.create_observation(
                        investigation_id, indicator_id, indicator_type, clean_val,
                        STATUS_NETWORK_ERROR,
                        permalink=permalink,
                        error_message=f"Censys HTTP {resp.status_code}"
                    )
        except httpx.TimeoutException:
            return self.create_observation(
                investigation_id, indicator_id, indicator_type, clean_val,
                STATUS_TIMEOUT,
                permalink=permalink,
                error_message="Censys query timed out."
            )
        except Exception as e:
            return self.create_observation(
                investigation_id, indicator_id, indicator_type, clean_val,
                STATUS_NETWORK_ERROR,
                permalink=permalink,
                error_message=f"Censys error: {str(e)}"
            )

    def test_connection(self) -> Dict[str, Any]:
        api_id, api_secret = self._get_credentials()
        if not api_id or not api_secret:
            return {"status": "Not configured", "connected": False, "provider": self.provider_name}
        try:
            with httpx.Client(timeout=5.0, auth=(api_id, api_secret)) as client:
                resp = client.get("https://search.censys.io/api/v1/account")
                if resp.status_code == 200:
                    info = resp.json()
                    return {
                        "status": "Connected",
                        "connected": True,
                        "provider": self.provider_name,
                        "email": info.get("email", "Authenticated"),
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
