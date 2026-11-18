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

class ShodanProvider(BaseOSINTProvider):
    provider_id = "shodan"
    provider_name = "Shodan"
    supported_types = ["ip", "ipv4", "ipv6"]
    requires_credentials = True
    endpoint_display = "https://api.shodan.io/shodan/host/"
    rate_limits = "1 request/sec, API query credits apply"
    known_limitations = "Shows internet-wide scanned open ports and banners. May be stale if host recently changed configuration."
    privacy_implications = "Passive lookup against Shodan search index. Zero packets sent to target host."

    def is_configured(self) -> bool:
        key = repo.get_setting("shodan_api_key") or settings.SHODAN_API_KEY
        return bool(key and not key.startswith("•••"))

    def _get_api_key(self) -> str:
        key = repo.get_setting("shodan_api_key") or settings.SHODAN_API_KEY
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
                error_message="Shodan host lookup only supports IP addresses."
            )

        api_key = self._get_api_key()
        if not api_key:
            return self.create_observation(
                investigation_id, indicator_id, indicator_type, clean_val,
                STATUS_UNAVAILABLE,
                error_message="Shodan API key is not configured."
            )

        url = f"https://api.shodan.io/shodan/host/{clean_val}"
        params = {"key": api_key, "minify": "true"}
        permalink = f"https://www.shodan.io/host/{clean_val}"

        try:
            with httpx.Client(timeout=timeout) as client:
                resp = client.get(url, params=params)
                if resp.status_code == 200:
                    data = resp.json()
                    ports = data.get("ports", [])
                    vulns = list(data.get("vulns", {}).keys()) if isinstance(data.get("vulns"), dict) else data.get("vulns", [])
                    tags = data.get("tags", [])

                    normalized = {
                        "ip": data.get("ip_str", clean_val),
                        "ports": ports,
                        "open_ports_count": len(ports),
                        "os": data.get("os"),
                        "org": data.get("org"),
                        "isp": data.get("isp"),
                        "asn": data.get("asn"),
                        "city": data.get("city"),
                        "country_name": data.get("country_name"),
                        "vulns": vulns[:10],
                        "tags": tags,
                        "last_update": data.get("last_update")
                    }
                    return self.create_observation(
                        investigation_id, indicator_id, indicator_type, clean_val,
                        STATUS_SUCCESS,
                        normalized_data=normalized,
                        permalink=permalink,
                        provider_timestamp_utc=data.get("last_update")
                    )
                elif resp.status_code == 404:
                    return self.create_observation(
                        investigation_id, indicator_id, indicator_type, clean_val,
                        STATUS_NOT_FOUND,
                        permalink=permalink,
                        error_message="No information available for that IP in Shodan."
                    )
                elif resp.status_code == 429:
                    return self.create_observation(
                        investigation_id, indicator_id, indicator_type, clean_val,
                        STATUS_RATE_LIMITED,
                        permalink=permalink,
                        error_message="Shodan rate limit exceeded."
                    )
                elif resp.status_code in (401, 403):
                    return self.create_observation(
                        investigation_id, indicator_id, indicator_type, clean_val,
                        STATUS_UNAUTHORIZED,
                        permalink=permalink,
                        error_message="Shodan invalid API key or account restricted."
                    )
                else:
                    return self.create_observation(
                        investigation_id, indicator_id, indicator_type, clean_val,
                        STATUS_NETWORK_ERROR,
                        permalink=permalink,
                        error_message=f"Shodan HTTP {resp.status_code}"
                    )
        except httpx.TimeoutException:
            return self.create_observation(
                investigation_id, indicator_id, indicator_type, clean_val,
                STATUS_TIMEOUT,
                permalink=permalink,
                error_message="Shodan request timed out."
            )
        except Exception as e:
            return self.create_observation(
                investigation_id, indicator_id, indicator_type, clean_val,
                STATUS_NETWORK_ERROR,
                permalink=permalink,
                error_message=f"Shodan error: {str(e)}"
            )

    def test_connection(self) -> Dict[str, Any]:
        api_key = self._get_api_key()
        if not api_key:
            return {"status": "Not configured", "connected": False, "provider": self.provider_name}
        try:
            with httpx.Client(timeout=5.0) as client:
                resp = client.get(f"https://api.shodan.io/api-info?key={api_key}")
                if resp.status_code == 200:
                    info = resp.json()
                    return {
                        "status": "Connected",
                        "connected": True,
                        "provider": self.provider_name,
                        "query_credits": info.get("query_credits", 0),
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
