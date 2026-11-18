import httpx
import uuid
from typing import Dict, Any, List, Optional
from backend.app.config import settings
from backend.app.core.models import OSINTObservation

class URLScanClient:
    """
    Passive urlscan.io search client.
    Searches historical, publicly indexed website scans without submitting new live scans.
    This guarantees 100% passive forensics with zero outbound traffic to target servers.
    """

    def __init__(self, local_only_mode: Optional[bool] = None, timeout: float = 6.0):
        self.local_only_mode = settings.LOCAL_ONLY_MODE if local_only_mode is None else local_only_mode
        self.timeout = timeout
        self.api_key = getattr(settings, "URLSCAN_API_KEY", None)

    def search_indicator(self, indicator_type: str, value: str, investigation_id: str, indicator_id: str) -> OSINTObservation:
        clean_val = value.strip()

        if self.local_only_mode:
            return OSINTObservation(
                id=f"OBS-USCAN-{uuid.uuid4().hex[:8]}",
                investigation_id=investigation_id,
                indicator_id=indicator_id,
                provider="urlscan.io",
                indicator_type=indicator_type,
                indicator_value=clean_val,
                status="SKIPPED_LOCAL_ONLY",
                normalized_data={},
                limitations="urlscan.io historical search skipped because local-only mode is active."
            )

        # Build search query without active submission
        if indicator_type in ("domain", "hostname"):
            query_str = f"domain:{clean_val}"
        elif indicator_type in ("ip", "ipv4", "ipv6"):
            query_str = f"ip:{clean_val}"
        elif indicator_type == "hash":
            query_str = f"hash:{clean_val}"
        elif indicator_type == "url":
            # Sanitize URL for search query
            query_str = f'page.url:"{clean_val}"'
        else:
            query_str = clean_val

        headers = {"User-Agent": "UniversalForensics-OSINT/1.0"}
        if self.api_key:
            headers["API-Key"] = self.api_key

        try:
            with httpx.Client(timeout=self.timeout, follow_redirects=True) as client:
                resp = client.get(
                    "https://urlscan.io/api/v1/search/",
                    params={"q": query_str, "size": 10},
                    headers=headers
                )

                if resp.status_code == 200:
                    data = resp.json()
                    total = data.get("total", 0)
                    results = data.get("results", [])

                    parsed_results = []
                    for r in results[:5]:
                        page = r.get("page", {})
                        stats = r.get("stats", {})
                        task = r.get("task", {})
                        parsed_results.append({
                            "scan_id": r.get("_id"),
                            "scan_time": task.get("time"),
                            "url": page.get("url"),
                            "domain": page.get("domain"),
                            "ip": page.get("ip"),
                            "asn": page.get("asn"),
                            "asn_name": page.get("asnname"),
                            "country": page.get("country"),
                            "server": page.get("server"),
                            "title": page.get("title"),
                            "screenshot": r.get("screenshot"),
                            "result_url": r.get("result")
                        })

                    status = "SUCCESS" if total > 0 else "NO_DATA"
                    permalink = f"https://urlscan.io/search/#{query_str}"

                    return OSINTObservation(
                        id=f"OBS-USCAN-{uuid.uuid4().hex[:8]}",
                        investigation_id=investigation_id,
                        indicator_id=indicator_id,
                        provider="urlscan.io",
                        indicator_type=indicator_type,
                        indicator_value=clean_val,
                        status=status,
                        normalized_data={
                            "total_scans_found": total,
                            "query": query_str,
                            "recent_scans": parsed_results
                        },
                        permalink=permalink,
                        data_freshness="Historical",
                        limitations="Historical urlscan.io captures represent past scans conducted by third parties, not real-time target status."
                    )
                elif resp.status_code == 429:
                    return OSINTObservation(
                        id=f"OBS-USCAN-{uuid.uuid4().hex[:8]}",
                        investigation_id=investigation_id,
                        indicator_id=indicator_id,
                        provider="urlscan.io",
                        indicator_type=indicator_type,
                        indicator_value=clean_val,
                        status="RATE_LIMITED",
                        error_message="urlscan.io search rate limit encountered."
                    )
                else:
                    return OSINTObservation(
                        id=f"OBS-USCAN-{uuid.uuid4().hex[:8]}",
                        investigation_id=investigation_id,
                        indicator_id=indicator_id,
                        provider="urlscan.io",
                        indicator_type=indicator_type,
                        indicator_value=clean_val,
                        status="PARTIAL",
                        error_message=f"HTTP {resp.status_code}"
                    )
        except httpx.TimeoutException:
            return OSINTObservation(
                id=f"OBS-USCAN-{uuid.uuid4().hex[:8]}",
                investigation_id=investigation_id,
                indicator_id=indicator_id,
                provider="urlscan.io",
                indicator_type=indicator_type,
                indicator_value=clean_val,
                status="TIMEOUT",
                error_message="urlscan.io search timed out."
            )
        except Exception as e:
            return OSINTObservation(
                id=f"OBS-USCAN-{uuid.uuid4().hex[:8]}",
                investigation_id=investigation_id,
                indicator_id=indicator_id,
                provider="urlscan.io",
                indicator_type=indicator_type,
                indicator_value=clean_val,
                status="NETWORK_ERROR",
                error_message=str(e)
            )
