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

class AbuseIPDBProvider(BaseOSINTProvider):
    provider_id = "abuseipdb"
    provider_name = "AbuseIPDB"
    supported_types = ["ip", "ipv4", "ipv6"]
    requires_credentials = True
    endpoint_display = "https://api.abuseipdb.com/api/v2/check"
    rate_limits = "Free Tier: 1,000 queries/day"
    known_limitations = "Limited to IP addresses. Does not provide domain or file reputation."
    privacy_implications = "Passive IP check endpoint does NOT file an abuse report. Queries are anonymous to target host."

    def is_configured(self) -> bool:
        byok = self.get_byok_credential()
        if byok and byok.get("api_key") and not byok["api_key"].startswith("****"):
            return True
        key = repo.get_setting("abuseipdb_api_key") or settings.ABUSEIPDB_API_KEY
        return bool(key and not key.startswith("•••") and not key.startswith("****"))

    def _get_api_key(self) -> str:
        byok = self.get_byok_credential()
        if byok and byok.get("api_key") and not byok["api_key"].startswith("****"):
            return byok["api_key"]
        key = repo.get_setting("abuseipdb_api_key") or settings.ABUSEIPDB_API_KEY
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

        if indicator_type not in ("ip", "ipv4", "ipv6"):
            return self.create_observation(
                investigation_id, indicator_id, indicator_type, clean_val,
                STATUS_INVALID_INDICATOR,
                error_message="AbuseIPDB only supports IP addresses."
            )

        api_key = self._get_api_key()
        if not api_key:
            return self.create_observation(
                investigation_id, indicator_id, indicator_type, clean_val,
                STATUS_UNAVAILABLE,
                error_message="AbuseIPDB API key is not configured."
            )

        headers = {
            "Key": api_key,
            "Accept": "application/json"
        }
        params = {
            "ipAddress": clean_val,
            "maxAgeInDays": 90,
            "verbose": True
        }
        permalink = f"https://www.abuseipdb.com/check/{clean_val}"

        try:
            with httpx.Client(timeout=timeout) as client:
                resp = client.get("https://api.abuseipdb.com/api/v2/check", headers=headers, params=params)
                if resp.status_code == 200:
                    data = resp.json().get("data", {})
                    score = data.get("abuseConfidenceScore", 0)
                    total_reports = data.get("totalReports", 0)
                    last_reported = data.get("lastReportedAt")

                    normalized = {
                        "abuse_confidence_score": score,
                        "total_reports": total_reports,
                        "distinct_users": data.get("numDistinctUsers", 0),
                        "country_code": data.get("countryCode"),
                        "usage_type": data.get("usageType"),
                        "isp": data.get("isp"),
                        "domain": data.get("domain"),
                        "is_whitelisted": data.get("isWhitelisted", False),
                        "is_tor": data.get("isTor", False)
                    }
                    status = STATUS_SUCCESS if total_reports > 0 else STATUS_NOT_FOUND
                    return self.create_observation(
                        investigation_id, indicator_id, indicator_type, clean_val,
                        status,
                        normalized_data=normalized,
                        permalink=permalink,
                        provider_timestamp_utc=last_reported
                    )
                elif resp.status_code == 429:
                    return self.create_observation(
                        investigation_id, indicator_id, indicator_type, clean_val,
                        STATUS_RATE_LIMITED,
                        permalink=permalink,
                        error_message="AbuseIPDB rate limit exceeded (1000/day)."
                    )
                elif resp.status_code in (401, 403):
                    return self.create_observation(
                        investigation_id, indicator_id, indicator_type, clean_val,
                        STATUS_UNAUTHORIZED,
                        permalink=permalink,
                        error_message="AbuseIPDB authorization failed."
                    )
                elif resp.status_code == 404:
                    return self.create_observation(
                        investigation_id, indicator_id, indicator_type, clean_val,
                        STATUS_NOT_FOUND,
                        permalink=permalink,
                        error_message="IP address not found in AbuseIPDB."
                    )
                else:
                    return self.create_observation(
                        investigation_id, indicator_id, indicator_type, clean_val,
                        STATUS_NETWORK_ERROR,
                        permalink=permalink,
                        error_message=f"AbuseIPDB HTTP {resp.status_code}"
                    )
        except httpx.TimeoutException:
            return self.create_observation(
                investigation_id, indicator_id, indicator_type, clean_val,
                STATUS_TIMEOUT,
                permalink=permalink,
                error_message="AbuseIPDB request timed out."
            )
        except Exception as e:
            return self.create_observation(
                investigation_id, indicator_id, indicator_type, clean_val,
                STATUS_NETWORK_ERROR,
                permalink=permalink,
                error_message=f"AbuseIPDB error: {str(e)}"
            )

    def test_connection(self) -> Dict[str, Any]:
        api_key = self._get_api_key()
        if not api_key:
            return {"status": "Not configured", "connected": False, "provider": self.provider_name}
        try:
            # Query standard public DNS 1.1.1.1 to verify auth
            headers = {"Key": api_key, "Accept": "application/json"}
            params = {"ipAddress": "1.1.1.1", "maxAgeInDays": 1}
            with httpx.Client(timeout=5.0) as client:
                resp = client.get("https://api.abuseipdb.com/api/v2/check", headers=headers, params=params)
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
