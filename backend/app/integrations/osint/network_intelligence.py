import ipaddress
import httpx
import uuid
from typing import Dict, Any, Optional
from backend.app.config import settings
from backend.app.core.models import OSINTObservation

class NetworkIntelligence:
    """
    Passive IP, ASN, and Network Operator intelligence client.
    Resolves BGP Autonomous System Number (ASN), AS Organization, and approximate GeoIP.
    Preserves passive security: never queries target machines directly and flags private RFC 1918 addresses.
    """

    def __init__(self, local_only_mode: Optional[bool] = None, timeout: float = 6.0):
        self.local_only_mode = settings.LOCAL_ONLY_MODE if local_only_mode is None else local_only_mode
        self.timeout = timeout

    def query_ip(self, ip_address: str, investigation_id: str, indicator_id: str) -> OSINTObservation:
        clean_ip = ip_address.strip()

        # 1. Check for RFC1918 / Loopback / Multicast / Reserved addresses
        try:
            ip_obj = ipaddress.ip_address(clean_ip)
            if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_reserved or ip_obj.is_link_local:
                return OSINTObservation(
                    id=f"OBS-NET-{uuid.uuid4().hex[:8]}",
                    investigation_id=investigation_id,
                    indicator_id=indicator_id,
                    provider="NetworkInfo",
                    indicator_type="ip",
                    indicator_value=clean_ip,
                    status="SUCCESS",
                    normalized_data={
                        "is_private": True,
                        "network_type": "RFC 1918 / Private / Loopback",
                        "asn": None,
                        "as_org": None,
                        "country": "Local / Internal Network",
                        "isp": "Local Infrastructure"
                    },
                    limitations="Address is a non-routable private/local IP. External OSINT providers cannot resolve routing for private subnets."
                )
        except ValueError:
            return OSINTObservation(
                id=f"OBS-NET-{uuid.uuid4().hex[:8]}",
                investigation_id=investigation_id,
                indicator_id=indicator_id,
                provider="NetworkInfo",
                indicator_type="ip",
                indicator_value=clean_ip,
                status="INVALID_INDICATOR",
                error_message=f"Value '{clean_ip}' is not a valid IPv4 or IPv6 address."
            )

        if self.local_only_mode:
            return OSINTObservation(
                id=f"OBS-NET-{uuid.uuid4().hex[:8]}",
                investigation_id=investigation_id,
                indicator_id=indicator_id,
                provider="NetworkInfo",
                indicator_type="ip",
                indicator_value=clean_ip,
                status="SKIPPED_LOCAL_ONLY",
                normalized_data={},
                limitations="Network and ASN lookup skipped because local-only mode is active."
            )

        try:
            with httpx.Client(timeout=self.timeout) as client:
                url = f"http://ip-api.com/json/{clean_ip}?fields=status,message,country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,as,asname,query"
                resp = client.get(url)

                if resp.status_code == 200:
                    data = resp.json()
                    if data.get("status") == "success":
                        # Extract AS number and name
                        raw_as = data.get("as", "")
                        asn = None
                        if raw_as and raw_as.startswith("AS"):
                            parts = raw_as.split(" ", 1)
                            asn = parts[0]

                        return OSINTObservation(
                            id=f"OBS-NET-{uuid.uuid4().hex[:8]}",
                            investigation_id=investigation_id,
                            indicator_id=indicator_id,
                            provider="NetworkInfo",
                            indicator_type="ip",
                            indicator_value=clean_ip,
                            status="SUCCESS",
                            normalized_data={
                                "is_private": False,
                                "asn": asn or data.get("asname"),
                                "as_org": data.get("org") or data.get("asname"),
                                "isp": data.get("isp"),
                                "country": data.get("country"),
                                "country_code": data.get("countryCode"),
                                "city": data.get("city"),
                                "region": data.get("regionName"),
                                "approx_latitude": data.get("lat"),
                                "approx_longitude": data.get("lon"),
                                "timezone": data.get("timezone")
                            },
                            data_freshness="Live",
                            limitations="Geolocation data is approximate at the city/region level and represents IP routing registration, not physical adversary coordinates."
                        )
                    else:
                        return OSINTObservation(
                            id=f"OBS-NET-{uuid.uuid4().hex[:8]}",
                            investigation_id=investigation_id,
                            indicator_id=indicator_id,
                            provider="NetworkInfo",
                            indicator_type="ip",
                            indicator_value=clean_ip,
                            status="NO_DATA",
                            error_message=data.get("message", "IP information not found.")
                        )
                elif resp.status_code == 429:
                    return OSINTObservation(
                        id=f"OBS-NET-{uuid.uuid4().hex[:8]}",
                        investigation_id=investigation_id,
                        indicator_id=indicator_id,
                        provider="NetworkInfo",
                        indicator_type="ip",
                        indicator_value=clean_ip,
                        status="RATE_LIMITED",
                        error_message="IP network intelligence rate limit exceeded."
                    )
                else:
                    return OSINTObservation(
                        id=f"OBS-NET-{uuid.uuid4().hex[:8]}",
                        investigation_id=investigation_id,
                        indicator_id=indicator_id,
                        provider="NetworkInfo",
                        indicator_type="ip",
                        indicator_value=clean_ip,
                        status="PARTIAL",
                        error_message=f"HTTP {resp.status_code}"
                    )
        except httpx.TimeoutException:
            return OSINTObservation(
                id=f"OBS-NET-{uuid.uuid4().hex[:8]}",
                investigation_id=investigation_id,
                indicator_id=indicator_id,
                provider="NetworkInfo",
                indicator_type="ip",
                indicator_value=clean_ip,
                status="TIMEOUT",
                error_message="Network intelligence query timed out."
            )
        except Exception as e:
            return OSINTObservation(
                id=f"OBS-NET-{uuid.uuid4().hex[:8]}",
                investigation_id=investigation_id,
                indicator_id=indicator_id,
                provider="NetworkInfo",
                indicator_type="ip",
                indicator_value=clean_ip,
                status="NETWORK_ERROR",
                error_message=str(e)
            )
