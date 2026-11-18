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
    STATUS_TIMEOUT,
    STATUS_NETWORK_ERROR,
    STATUS_SKIPPED_LOCAL_ONLY,
    STATUS_INVALID_INDICATOR
)

class URLhausProvider(BaseOSINTProvider):
    provider_id = "urlhaus"
    provider_name = "URLhaus"
    supported_types = ["domain", "url", "host"]
    requires_credentials = False
    endpoint_display = "https://urlhaus-api.abuse.ch/v1/"
    rate_limits = "Community API: Fair use (generally unthrottled for single queries)"
    known_limitations = "Specialized in malicious malware distribution sites, does not cover clean enterprise domains."
    privacy_implications = "Passive lookup. No active HTTP probing is directed at the malicious site."

    def is_configured(self) -> bool:
        return True # Public read-only endpoint

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

        endpoint = None
        form_data = {}
        permalink = None

        if indicator_type in ("domain", "hostname", "host"):
            endpoint = "https://urlhaus-api.abuse.ch/v1/host/"
            form_data = {"host": clean_val}
            permalink = f"https://urlhaus.abuse.ch/browse.php?search={clean_val}"
        elif indicator_type == "url":
            endpoint = "https://urlhaus-api.abuse.ch/v1/url/"
            form_data = {"url": clean_val}
            permalink = f"https://urlhaus.abuse.ch/browse.php?search={clean_val}"
        else:
            return self.create_observation(
                investigation_id, indicator_id, indicator_type, clean_val,
                STATUS_INVALID_INDICATOR,
                error_message="URLhaus only supports domain, host, and url indicators."
            )

        api_key = repo.get_setting("urlhaus_api_key") or settings.URLHAUS_API_KEY
        headers = {}
        if api_key and not api_key.startswith("•••"):
            headers["Auth-Key"] = api_key

        try:
            with httpx.Client(timeout=timeout) as client:
                resp = client.post(endpoint, data=form_data, headers=headers)
                if resp.status_code == 200:
                    data = resp.json()
                    query_status = data.get("query_status")
                    if query_status == "ok":
                        urls = data.get("urls", [])
                        malicious_urls_count = len(urls)
                        tags = list(set([t for u in urls for t in u.get("tags", []) if t]))[:8]
                        threats = list(set([u.get("threat") for u in urls if u.get("threat")]))

                        normalized = {
                            "query_status": query_status,
                            "malicious_urls_count": malicious_urls_count,
                            "tags": tags,
                            "threats": threats,
                            "first_seen": data.get("firstseen"),
                            "urlhaus_reference": data.get("urlhaus_reference")
                        }
                        return self.create_observation(
                            investigation_id, indicator_id, indicator_type, clean_val,
                            STATUS_SUCCESS,
                            normalized_data=normalized,
                            permalink=permalink,
                            provider_timestamp_utc=data.get("firstseen")
                        )
                    elif query_status in ("no_results", "not_found"):
                        return self.create_observation(
                            investigation_id, indicator_id, indicator_type, clean_val,
                            STATUS_NOT_FOUND,
                            permalink=permalink,
                            error_message="Indicator not listed in URLhaus active threat database."
                        )
                    else:
                        return self.create_observation(
                            investigation_id, indicator_id, indicator_type, clean_val,
                            STATUS_NOT_FOUND,
                            permalink=permalink,
                            error_message=f"URLhaus status: {query_status}"
                        )
                elif resp.status_code == 429:
                    return self.create_observation(
                        investigation_id, indicator_id, indicator_type, clean_val,
                        STATUS_RATE_LIMITED,
                        permalink=permalink,
                        error_message="URLhaus rate limit encountered."
                    )
                else:
                    return self.create_observation(
                        investigation_id, indicator_id, indicator_type, clean_val,
                        STATUS_NETWORK_ERROR,
                        permalink=permalink,
                        error_message=f"URLhaus HTTP {resp.status_code}"
                    )
        except httpx.TimeoutException:
            return self.create_observation(
                investigation_id, indicator_id, indicator_type, clean_val,
                STATUS_TIMEOUT,
                permalink=permalink,
                error_message="URLhaus query timed out."
            )
        except Exception as e:
            return self.create_observation(
                investigation_id, indicator_id, indicator_type, clean_val,
                STATUS_NETWORK_ERROR,
                permalink=permalink,
                error_message=f"URLhaus error: {str(e)}"
            )

    def test_connection(self) -> Dict[str, Any]:
        try:
            # Query safe domain example.com
            with httpx.Client(timeout=5.0) as client:
                resp = client.post("https://urlhaus-api.abuse.ch/v1/host/", data={"host": "example.com"})
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
