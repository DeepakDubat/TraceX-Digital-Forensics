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
    STATUS_SKIPPED_PRIVACY_POLICY,
    STATUS_INVALID_INDICATOR
)

class VirusTotalProvider(BaseOSINTProvider):
    provider_id = "virustotal"
    provider_name = "VirusTotal"
    supported_types = ["hash", "ip", "domain", "url"]
    requires_credentials = True
    endpoint_display = "https://www.virustotal.com/api/v3/"
    rate_limits = "Free Public API: 4 requests/min, 500 requests/day"
    known_limitations = "Free tier does not support live behavioral sandbox execution logs or bulk feeds."
    privacy_implications = "Indicator metadata submitted to VirusTotal becomes publicly searchable by enterprise subscribers. Hash-only lookups preserve binary confidentiality; never upload raw binary."

    def is_configured(self) -> bool:
        byok = self.get_byok_credential()
        if byok and byok.get("api_key") and not byok["api_key"].startswith("****"):
            return True
        key = repo.get_setting("virustotal_api_key") or settings.VIRUSTOTAL_API_KEY
        return bool(key and not key.startswith("•••") and not key.startswith("****"))

    def _get_api_key(self) -> str:
        byok = self.get_byok_credential()
        if byok and byok.get("api_key") and not byok["api_key"].startswith("****"):
            return byok["api_key"]
        key = repo.get_setting("virustotal_api_key") or settings.VIRUSTOTAL_API_KEY
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
        norm_type = indicator_type.lower()
        if norm_type not in ("hash", "sha256", "md5", "sha1", "ip", "ipv4", "ipv6", "domain", "url"):
            return self.create_observation(
                investigation_id, indicator_id, indicator_type, clean_val,
                STATUS_INVALID_INDICATOR,
                error_message=f"VirusTotal does not support indicator type '{indicator_type}'."
            )

        if local_only:
            return self.create_observation(
                investigation_id, indicator_id, indicator_type, clean_val,
                STATUS_SKIPPED_LOCAL_ONLY,
                error_message="Query blocked: Local-Only mode is enabled."
            )

        api_key = self._get_api_key()
        if not api_key:
            return self.create_observation(
                investigation_id, indicator_id, indicator_type, clean_val,
                STATUS_UNAVAILABLE,
                error_message="VirusTotal API key is not configured."
            )

        headers = {"x-apikey": api_key}
        endpoint = None
        permalink = None

        if indicator_type in ("hash", "sha256", "md5", "sha1"):
            endpoint = f"https://www.virustotal.com/api/v3/files/{clean_val}"
            permalink = f"https://www.virustotal.com/gui/file/{clean_val}"
        elif indicator_type in ("ip", "ipv4", "ipv6"):
            endpoint = f"https://www.virustotal.com/api/v3/ip_addresses/{clean_val}"
            permalink = f"https://www.virustotal.com/gui/ip-address/{clean_val}"
        elif indicator_type in ("domain", "hostname"):
            endpoint = f"https://www.virustotal.com/api/v3/domains/{clean_val}"
            permalink = f"https://www.virustotal.com/gui/domain/{clean_val}"
        elif indicator_type == "url":
            import base64
            url_id = base64.urlsafe_b64encode(clean_val.encode()).decode().strip("=")
            endpoint = f"https://www.virustotal.com/api/v3/urls/{url_id}"
            permalink = f"https://www.virustotal.com/gui/url/{url_id}"
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
                    data = resp.json().get("data", {}).get("attributes", {})
                    stats = data.get("last_analysis_stats", {})
                    obs_time = None
                    if data.get("last_analysis_date"):
                        obs_time = datetime.utcfromtimestamp(data["last_analysis_date"]).isoformat()

                    normalized = {
                        "malicious_count": stats.get("malicious", 0),
                        "suspicious_count": stats.get("suspicious", 0),
                        "harmless_count": stats.get("harmless", 0),
                        "undetected_count": stats.get("undetected", 0),
                        "total_engines": sum(stats.values()),
                        "reputation": data.get("reputation", 0),
                        "popular_threat_category": data.get("popular_threat_classification", {}).get("suggested_threat_label"),
                        "meaningful_name": data.get("meaningful_name"),
                        "names": data.get("names", [])[:5]
                    }
                    return self.create_observation(
                        investigation_id, indicator_id, indicator_type, clean_val,
                        STATUS_SUCCESS,
                        normalized_data=normalized,
                        permalink=permalink,
                        provider_timestamp_utc=obs_time
                    )
                elif resp.status_code == 404:
                    return self.create_observation(
                        investigation_id, indicator_id, indicator_type, clean_val,
                        STATUS_NOT_FOUND,
                        permalink=permalink,
                        error_message="Indicator not found in VirusTotal database (NO_DATA / NOT_FOUND)."
                    )
                elif resp.status_code == 429:
                    return self.create_observation(
                        investigation_id, indicator_id, indicator_type, clean_val,
                        STATUS_RATE_LIMITED,
                        error_message="VirusTotal API quota exceeded (HTTP 429 Rate Limited)."
                    )
                elif resp.status_code in (401, 403):
                    return self.create_observation(
                        investigation_id, indicator_id, indicator_type, clean_val,
                        STATUS_UNAUTHORIZED,
                        error_message=f"VirusTotal authentication failure (HTTP {resp.status_code})."
                    )
                else:
                    return self.create_observation(
                        investigation_id, indicator_id, indicator_type, clean_val,
                        STATUS_NETWORK_ERROR,
                        error_message=f"VirusTotal HTTP {resp.status_code}: {resp.text[:200]}"
                    )
        except httpx.TimeoutException:
            return self.create_observation(
                investigation_id, indicator_id, indicator_type, clean_val,
                STATUS_TIMEOUT,
                error_message="VirusTotal query timed out."
            )
        except Exception as e:
            return self.create_observation(
                investigation_id, indicator_id, indicator_type, clean_val,
                STATUS_NETWORK_ERROR,
                error_message=f"VirusTotal connection error: {str(e)}"
            )

    def test_connection(self) -> Dict[str, Any]:
        api_key = self._get_api_key()
        if not api_key:
            return {"status": "Not configured", "connected": False, "provider": self.provider_name}
        try:
            headers = {"x-apikey": api_key}
            with httpx.Client(timeout=5.0) as client:
                resp = client.get("https://www.virustotal.com/api/v3/users/current", headers=headers)
                if resp.status_code == 200:
                    user_data = resp.json().get("data", {}).get("attributes", {})
                    return {
                        "status": "Connected",
                        "connected": True,
                        "provider": self.provider_name,
                        "user": user_data.get("username", "Authenticated User"),
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
