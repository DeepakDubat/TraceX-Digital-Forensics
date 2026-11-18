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
    STATUS_FORBIDDEN,
    STATUS_TIMEOUT,
    STATUS_NETWORK_ERROR,
    STATUS_UNAVAILABLE,
    STATUS_SKIPPED_LOCAL_ONLY,
    STATUS_INVALID_INDICATOR
)

class AlienVaultOTXProvider(BaseOSINTProvider):
    provider_id = "alienvault_otx"
    provider_name = "AlienVault OTX"
    supported_types = ["hash", "ip", "domain", "url"]
    requires_credentials = True
    endpoint_display = "https://otx.alienvault.com/api/v1/"
    rate_limits = "Community API: 10,000 requests/day"
    known_limitations = "Pulse indicators are crowdsourced and may vary in quality and freshness."
    privacy_implications = "Passive indicators are checked against existing community pulses without creating new public threat pulses."

    def is_configured(self) -> bool:
        byok = self.get_byok_credential()
        if byok and byok.get("api_key") and not byok["api_key"].startswith("****"):
            return True
        key = repo.get_setting("alienvault_api_key") or settings.ALIENVAULT_OTX_API_KEY
        return bool(key and not key.startswith("•••") and not key.startswith("****"))

    def _get_api_key(self) -> str:
        byok = self.get_byok_credential()
        if byok and byok.get("api_key") and not byok["api_key"].startswith("****"):
            return byok["api_key"]
        key = repo.get_setting("alienvault_api_key") or settings.ALIENVAULT_OTX_API_KEY
        return key if key and not key.startswith("•••") and not key.startswith("****") else ""

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

        api_key = self._get_api_key()
        if not api_key:
            return self.create_observation(
                investigation_id, indicator_id, indicator_type, clean_val,
                STATUS_UNAVAILABLE,
                error_message="AlienVault OTX API key is not configured."
            )

        headers = {"X-OTX-API-KEY": api_key}
        endpoint = None
        permalink = None

        if indicator_type in ("hash", "sha256", "md5", "sha1"):
            endpoint = f"https://otx.alienvault.com/api/v1/indicators/file/{clean_val}/general"
            permalink = f"https://otx.alienvault.com/indicator/file/{clean_val}"
        elif indicator_type in ("ip", "ipv4"):
            endpoint = f"https://otx.alienvault.com/api/v1/indicators/IPv4/{clean_val}/general"
            permalink = f"https://otx.alienvault.com/indicator/ip/{clean_val}"
        elif indicator_type == "ipv6":
            endpoint = f"https://otx.alienvault.com/api/v1/indicators/IPv6/{clean_val}/general"
            permalink = f"https://otx.alienvault.com/indicator/ip/{clean_val}"
        elif indicator_type in ("domain", "hostname"):
            endpoint = f"https://otx.alienvault.com/api/v1/indicators/domain/{clean_val}/general"
            permalink = f"https://otx.alienvault.com/indicator/domain/{clean_val}"
        elif indicator_type == "url":
            endpoint = f"https://otx.alienvault.com/api/v1/indicators/url/{clean_val}/general"
            permalink = f"https://otx.alienvault.com/indicator/url/{clean_val}"
        else:
            return self.create_observation(
                investigation_id, indicator_id, indicator_type, clean_val,
                STATUS_INVALID_INDICATOR,
                error_message=f"Unsupported indicator type: {indicator_type}"
            )

        try:
            with httpx.Client(timeout=timeout) as client:
                resp = client.get(endpoint, headers=headers)
                if resp.status_code == 200:
                    data = resp.json()
                    pulse_info = data.get("pulse_info", {})
                    pulse_count = pulse_info.get("count", 0)
                    pulses = pulse_info.get("pulses", [])[:5]
                    pulse_titles = [p.get("name") for p in pulses if p.get("name")]
                    tags = list(set([t for p in pulses for t in p.get("tags", [])]))[:8]

                    normalized = {
                        "pulse_count": pulse_count,
                        "pulse_titles": pulse_titles,
                        "tags": tags,
                        "adversary": list(set([p.get("adversary") for p in pulses if p.get("adversary")]))[:3],
                        "asn": data.get("asn"),
                        "city": data.get("city"),
                        "country_name": data.get("country_name")
                    }
                    status = STATUS_SUCCESS if pulse_count > 0 else STATUS_NOT_FOUND
                    return self.create_observation(
                        investigation_id, indicator_id, indicator_type, clean_val,
                        status,
                        normalized_data=normalized,
                        permalink=permalink
                    )
                elif resp.status_code == 404:
                    return self.create_observation(
                        investigation_id, indicator_id, indicator_type, clean_val,
                        STATUS_NOT_FOUND,
                        permalink=permalink,
                        error_message="Indicator not found in AlienVault OTX."
                    )
                elif resp.status_code == 429:
                    return self.create_observation(
                        investigation_id, indicator_id, indicator_type, clean_val,
                        STATUS_RATE_LIMITED,
                        error_message="AlienVault OTX API rate limit exceeded."
                    )
                elif resp.status_code in (401, 403):
                    return self.create_observation(
                        investigation_id, indicator_id, indicator_type, clean_val,
                        STATUS_UNAUTHORIZED,
                        error_message="AlienVault OTX authorization failed."
                    )
                else:
                    return self.create_observation(
                        investigation_id, indicator_id, indicator_type, clean_val,
                        STATUS_NETWORK_ERROR,
                        error_message=f"AlienVault OTX HTTP {resp.status_code}"
                    )
        except httpx.TimeoutException:
            return self.create_observation(
                investigation_id, indicator_id, indicator_type, clean_val,
                STATUS_TIMEOUT,
                error_message="AlienVault OTX query timed out."
            )
        except Exception as e:
            return self.create_observation(
                investigation_id, indicator_id, indicator_type, clean_val,
                STATUS_NETWORK_ERROR,
                error_message=f"AlienVault OTX connection error: {str(e)}"
            )

    def test_connection(self) -> Dict[str, Any]:
        api_key = self._get_api_key()
        if not api_key:
            return {"status": "Not configured", "connected": False, "provider": self.provider_name}
        try:
            headers = {"X-OTX-API-KEY": api_key}
            with httpx.Client(timeout=5.0) as client:
                resp = client.get("https://otx.alienvault.com/api/v1/user/me", headers=headers)
                if resp.status_code == 200:
                    data = resp.json()
                    return {
                        "status": "Connected",
                        "connected": True,
                        "provider": self.provider_name,
                        "user": data.get("username", "Authenticated OTX User"),
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
