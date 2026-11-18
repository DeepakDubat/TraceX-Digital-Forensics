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

class MISPProvider(BaseOSINTProvider):
    provider_id = "misp"
    provider_name = "MISP"
    supported_types = ["hash", "ip", "domain", "url"]
    requires_credentials = True
    endpoint_display = "Self-hosted / Partner MISP Instance"
    rate_limits = "Configured per instance policy"
    known_limitations = "Requires network visibility to an internal or partner MISP instance."
    privacy_implications = "Queries are directed to internal/trusted instance; ensures confidential investigations stay within authorized trust group."

    def is_configured(self) -> bool:
        url = repo.get_setting("misp_url") or settings.MISP_URL
        key = repo.get_setting("misp_api_key") or settings.MISP_API_KEY
        return bool(url and key and not key.startswith("•••"))

    def _get_config(self):
        url = repo.get_setting("misp_url") or settings.MISP_URL
        key = repo.get_setting("misp_api_key") or settings.MISP_API_KEY
        return url, key

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

        misp_url, misp_key = self._get_config()
        if not misp_url or not misp_key:
            return self.create_observation(
                investigation_id, indicator_id, indicator_type, clean_val,
                STATUS_UNAVAILABLE,
                error_message="MISP instance URL or API key is not configured."
            )

        headers = {
            "Authorization": misp_key,
            "Accept": "application/json",
            "Content-Type": "application/json"
        }
        search_endpoint = f"{misp_url.rstrip('/')}/attributes/restSearch"
        payload = {"value": clean_val, "limit": 5}
        permalink = f"{misp_url.rstrip('/')}/attributes/search/value:{clean_val}"

        try:
            with httpx.Client(timeout=timeout, verify=False) as client:
                resp = client.post(search_endpoint, json=payload, headers=headers)
                if resp.status_code == 200:
                    data = resp.json().get("response", {}).get("Attribute", [])
                    if data:
                        first = data[0]
                        events = list(set([a.get("event_id") for a in data if a.get("event_id")]))
                        categories = list(set([a.get("category") for a in data if a.get("category")]))
                        normalized = {
                            "matches_count": len(data),
                            "event_ids": events,
                            "categories": categories,
                            "type": first.get("type"),
                            "comment": first.get("comment"),
                            "to_ids": first.get("to_ids", False),
                            "timestamp": first.get("timestamp")
                        }
                        return self.create_observation(
                            investigation_id, indicator_id, indicator_type, clean_val,
                            STATUS_SUCCESS,
                            normalized_data=normalized,
                            permalink=permalink,
                            provider_timestamp_utc=first.get("timestamp")
                        )
                    else:
                        return self.create_observation(
                            investigation_id, indicator_id, indicator_type, clean_val,
                            STATUS_NOT_FOUND,
                            permalink=permalink,
                            error_message="No matching attributes found in MISP."
                        )
                elif resp.status_code in (401, 403):
                    return self.create_observation(
                        investigation_id, indicator_id, indicator_type, clean_val,
                        STATUS_UNAUTHORIZED,
                        permalink=permalink,
                        error_message="MISP authentication failure."
                    )
                else:
                    return self.create_observation(
                        investigation_id, indicator_id, indicator_type, clean_val,
                        STATUS_NETWORK_ERROR,
                        permalink=permalink,
                        error_message=f"MISP HTTP {resp.status_code}"
                    )
        except httpx.TimeoutException:
            return self.create_observation(
                investigation_id, indicator_id, indicator_type, clean_val,
                STATUS_TIMEOUT,
                permalink=permalink,
                error_message="MISP request timed out."
            )
        except Exception as e:
            return self.create_observation(
                investigation_id, indicator_id, indicator_type, clean_val,
                STATUS_NETWORK_ERROR,
                permalink=permalink,
                error_message=f"MISP connection error: {str(e)}"
            )

    def test_connection(self) -> Dict[str, Any]:
        misp_url, misp_key = self._get_config()
        if not misp_url or not misp_key:
            return {"status": "Not configured", "connected": False, "provider": self.provider_name}
        try:
            headers = {"Authorization": misp_key, "Accept": "application/json"}
            with httpx.Client(timeout=5.0, verify=False) as client:
                resp = client.get(f"{misp_url.rstrip('/')}/servers/getVersion", headers=headers)
                if resp.status_code == 200:
                    info = resp.json()
                    return {
                        "status": "Connected",
                        "connected": True,
                        "provider": self.provider_name,
                        "version": info.get("version", "Unknown MISP Version"),
                        "rate_limit": self.rate_limits
                    }
                elif resp.status_code in (401, 403):
                    return {"status": "Invalid credentials", "connected": False, "provider": self.provider_name}
                else:
                    return {"status": f"HTTP {resp.status_code}", "connected": False, "provider": self.provider_name}
        except httpx.TimeoutException:
            return {"status": "Timeout", "connected": False, "provider": self.provider_name}
        except Exception as e:
            return {"status": "Network error", "connected": False, "provider": self.provider_name, "error": str(e)}
