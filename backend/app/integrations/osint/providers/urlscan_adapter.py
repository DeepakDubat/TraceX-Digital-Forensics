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

class URLScanProvider(BaseOSINTProvider):
    provider_id = "urlscan"
    provider_name = "urlscan.io"
    supported_types = ["domain", "ip", "hash", "url"]
    requires_credentials = False
    endpoint_display = "https://urlscan.io/api/v1/search/"
    rate_limits = "Public Search API: Rate limited per IP address"
    known_limitations = "Historical scan data only; does NOT trigger active urlscan crawls."
    privacy_implications = "Passive historical search does not submit the URL for new public scanning or indexing."

    def is_configured(self) -> bool:
        return True # Historical search is public

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

        if indicator_type in ("domain", "hostname"):
            q = f"domain:{clean_val}"
        elif indicator_type in ("ip", "ipv4", "ipv6"):
            q = f"ip:{clean_val}"
        elif indicator_type in ("hash", "sha256"):
            q = f"files.sha256:{clean_val}"
        elif indicator_type == "url":
            q = f"page.url:\"{clean_val}\""
        else:
            return self.create_observation(
                investigation_id, indicator_id, indicator_type, clean_val,
                STATUS_INVALID_INDICATOR,
                error_message=f"Unsupported indicator type: {indicator_type}"
            )

        search_url = "https://urlscan.io/api/v1/search/"
        params = {"q": q, "size": 5}
        permalink = f"https://urlscan.io/search/#{q}"

        try:
            with httpx.Client(timeout=timeout) as client:
                resp = client.get(search_url, params=params)
                if resp.status_code == 200:
                    data = resp.json()
                    total = data.get("total", 0)
                    results = data.get("results", [])
                    if total > 0 and results:
                        first = results[0]
                        page = first.get("page", {})
                        task = first.get("task", {})
                        normalized = {
                            "total_historical_scans": total,
                            "latest_url": page.get("url"),
                            "latest_domain": page.get("domain"),
                            "latest_ip": page.get("ip"),
                            "server": page.get("server"),
                            "country": page.get("country"),
                            "screenshot_url": task.get("screenshotURL"),
                            "report_url": task.get("reportURL")
                        }
                        return self.create_observation(
                            investigation_id, indicator_id, indicator_type, clean_val,
                            STATUS_SUCCESS,
                            normalized_data=normalized,
                            permalink=permalink,
                            provider_timestamp_utc=task.get("time")
                        )
                    else:
                        return self.create_observation(
                            investigation_id, indicator_id, indicator_type, clean_val,
                            STATUS_NOT_FOUND,
                            permalink=permalink,
                            error_message="No historical scans recorded on urlscan.io."
                        )
                elif resp.status_code == 429:
                    return self.create_observation(
                        investigation_id, indicator_id, indicator_type, clean_val,
                        STATUS_RATE_LIMITED,
                        permalink=permalink,
                        error_message="urlscan.io rate limit encountered."
                    )
                else:
                    return self.create_observation(
                        investigation_id, indicator_id, indicator_type, clean_val,
                        STATUS_NETWORK_ERROR,
                        permalink=permalink,
                        error_message=f"urlscan.io HTTP {resp.status_code}"
                    )
        except httpx.TimeoutException:
            return self.create_observation(
                investigation_id, indicator_id, indicator_type, clean_val,
                STATUS_TIMEOUT,
                permalink=permalink,
                error_message="urlscan.io search timed out."
            )
        except Exception as e:
            return self.create_observation(
                investigation_id, indicator_id, indicator_type, clean_val,
                STATUS_NETWORK_ERROR,
                permalink=permalink,
                error_message=f"urlscan.io error: {str(e)}"
            )

    def test_connection(self) -> Dict[str, Any]:
        try:
            with httpx.Client(timeout=5.0) as client:
                resp = client.get("https://urlscan.io/api/v1/search/", params={"q": "domain:example.com", "size": 1})
                if resp.status_code == 200:
                    return {
                        "status": "Connected",
                        "connected": True,
                        "provider": self.provider_name,
                        "rate_limit": self.rate_limits
                    }
                elif resp.status_code == 429:
                    return {"status": "Rate limited", "connected": False, "provider": self.provider_name}
                else:
                    return {"status": f"HTTP {resp.status_code}", "connected": False, "provider": self.provider_name}
        except httpx.TimeoutException:
            return {"status": "Timeout", "connected": False, "provider": self.provider_name}
        except Exception as e:
            return {"status": "Network error", "connected": False, "provider": self.provider_name, "error": str(e)}
