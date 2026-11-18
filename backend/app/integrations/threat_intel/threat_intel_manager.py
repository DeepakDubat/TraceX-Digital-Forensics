import httpx
from datetime import datetime
from typing import Dict, Any, List, Optional
from backend.app.config import settings
from backend.app.core.models import ThreatIntelResult

class ThreatIntelManager:
    """
    Manages passive threat-intelligence enrichment across authorized providers:
    VirusTotal, AbuseIPDB, AlienVault OTX, URLhaus, and MalwareBazaar.
    Strictly passive: Never submits APK binaries or recovered secret tokens.
    """

    def __init__(self, local_only_mode: Optional[bool] = None):
        self._explicit_local_only = local_only_mode

    @property
    def local_only_mode(self) -> bool:
        if self._explicit_local_only is not None:
            return self._explicit_local_only
        return getattr(settings, "LOCAL_ONLY_MODE", True)

    def _get_key(self, provider_id: str, default: str = "") -> str:
        try:
            from backend.app.core.credential_manager import credential_manager
            c = credential_manager.get_credential(provider_id)
            if c and c.get("api_key") and not c["api_key"].startswith("****") and not c["api_key"].startswith("•••"):
                return c["api_key"]
        except Exception:
            pass
        return default if default and not default.startswith("****") and not default.startswith("•••") else ""

    def check_hash(self, sha256_hash: str, inv_id: str) -> List[ThreatIntelResult]:
        """Query VirusTotal, AlienVault OTX, and MalwareBazaar for a SHA-256 hash."""
        results: List[ThreatIntelResult] = []
        if self.local_only_mode:
            results.append(self._skipped_result(inv_id, "All Providers", sha256_hash, "hash", "Local-Only Mode is active."))
            return results

        # 1. VirusTotal Hash Check
        results.append(self._query_virustotal_hash(sha256_hash, inv_id))

        # 2. MalwareBazaar Hash Check (No API key strictly required for public hash queries)
        results.append(self._query_malwarebazaar_hash(sha256_hash, inv_id))

        # 3. AlienVault OTX Hash Check
        results.append(self._query_alienvault_hash(sha256_hash, inv_id))

        return [r for r in results if r is not None]

    def check_ip(self, ip_address: str, inv_id: str) -> List[ThreatIntelResult]:
        """Query AbuseIPDB and VirusTotal for an IP address."""
        results: List[ThreatIntelResult] = []
        if self.local_only_mode:
            results.append(self._skipped_result(inv_id, "All Providers", ip_address, "ip", "Local-Only Mode is active."))
            return results

        results.append(self._query_abuseipdb(ip_address, inv_id))
        results.append(self._query_virustotal_ip(ip_address, inv_id))
        return [r for r in results if r is not None]

    def check_domain(self, domain: str, inv_id: str) -> List[ThreatIntelResult]:
        """Query URLhaus and VirusTotal for a domain."""
        results: List[ThreatIntelResult] = []
        if self.local_only_mode:
            results.append(self._skipped_result(inv_id, "All Providers", domain, "domain", "Local-Only Mode is active."))
            return results

        results.append(self._query_urlhaus_domain(domain, inv_id))
        results.append(self._query_virustotal_domain(domain, inv_id))
        return [r for r in results if r is not None]

    # --- VirusTotal ---
    def _query_virustotal_hash(self, sha256_hash: str, inv_id: str) -> ThreatIntelResult:
        api_key = self._get_key("virustotal", settings.VIRUSTOTAL_API_KEY)
        if not api_key:
            return self._skipped_result(inv_id, "VirusTotal", sha256_hash, "hash", "VirusTotal API key not configured.")
        try:
            headers = {"x-apikey": api_key}
            with httpx.Client(timeout=8.0) as client:
                resp = client.get(f"https://www.virustotal.com/api/v3/files/{sha256_hash}", headers=headers)
                if resp.status_code == 200:
                    data = resp.json().get("data", {}).get("attributes", {})
                    stats = data.get("last_analysis_stats", {})
                    malicious = stats.get("malicious", 0)
                    total = sum(stats.values())
                    status = "malicious" if malicious > 3 else ("suspicious" if malicious > 0 else "clean")
                    return ThreatIntelResult(
                        id=f"TI-VT-{sha256_hash[:8]}",
                        provider="VirusTotal",
                        indicator=sha256_hash,
                        indicator_type="hash",
                        status=status,
                        detections=malicious,
                        total_engines=total,
                        details={"stats": stats, "names": data.get("names", [])[:5]}
                    )
                elif resp.status_code == 404:
                    return ThreatIntelResult(
                        id=f"TI-VT-{sha256_hash[:8]}",
                        provider="VirusTotal",
                        indicator=sha256_hash,
                        indicator_type="hash",
                        status="not_found",
                        detections=0,
                        total_engines=0,
                        details={"message": "Hash not found in VirusTotal database."}
                    )
                elif resp.status_code == 429:
                    return self._rate_limited_result(inv_id, "VirusTotal", sha256_hash, "hash")
                else:
                    return self._error_result(inv_id, "VirusTotal", sha256_hash, "hash", f"HTTP {resp.status_code}")
        except Exception as e:
            return self._error_result(inv_id, "VirusTotal", sha256_hash, "hash", str(e))

    def _query_virustotal_ip(self, ip_address: str, inv_id: str) -> ThreatIntelResult:
        api_key = self._get_key("virustotal", settings.VIRUSTOTAL_API_KEY)
        if not api_key:
            return self._skipped_result(inv_id, "VirusTotal", ip_address, "ip", "VirusTotal API key not configured.")
        try:
            headers = {"x-apikey": api_key}
            with httpx.Client(timeout=8.0) as client:
                resp = client.get(f"https://www.virustotal.com/api/v3/ip_addresses/{ip_address}", headers=headers)
                if resp.status_code == 200:
                    data = resp.json().get("data", {}).get("attributes", {})
                    stats = data.get("last_analysis_stats", {})
                    malicious = stats.get("malicious", 0)
                    total = sum(stats.values())
                    status = "malicious" if malicious > 2 else ("suspicious" if malicious > 0 else "clean")
                    return ThreatIntelResult(
                        id=f"TI-VT-IP-{ip_address}",
                        provider="VirusTotal",
                        indicator=ip_address,
                        indicator_type="ip",
                        status=status,
                        detections=malicious,
                        total_engines=total,
                        details={"as_owner": data.get("as_owner"), "country": data.get("country")}
                    )
                elif resp.status_code == 429:
                    return self._rate_limited_result(inv_id, "VirusTotal", ip_address, "ip")
                else:
                    return self._error_result(inv_id, "VirusTotal", ip_address, "ip", f"HTTP {resp.status_code}")
        except Exception as e:
            return self._error_result(inv_id, "VirusTotal", ip_address, "ip", str(e))

    def _query_virustotal_domain(self, domain: str, inv_id: str) -> ThreatIntelResult:
        api_key = self._get_key("virustotal", settings.VIRUSTOTAL_API_KEY)
        if not api_key:
            return self._skipped_result(inv_id, "VirusTotal", domain, "domain", "VirusTotal API key not configured.")
        try:
            headers = {"x-apikey": api_key}
            with httpx.Client(timeout=8.0) as client:
                resp = client.get(f"https://www.virustotal.com/api/v3/domains/{domain}", headers=headers)
                if resp.status_code == 200:
                    data = resp.json().get("data", {}).get("attributes", {})
                    stats = data.get("last_analysis_stats", {})
                    malicious = stats.get("malicious", 0)
                    total = sum(stats.values())
                    status = "malicious" if malicious > 2 else ("suspicious" if malicious > 0 else "clean")
                    return ThreatIntelResult(
                        id=f"TI-VT-DOM-{domain}",
                        provider="VirusTotal",
                        indicator=domain,
                        indicator_type="domain",
                        status=status,
                        detections=malicious,
                        total_engines=total,
                        details={"registrar": data.get("registrar"), "categories": data.get("categories", {})}
                    )
                elif resp.status_code == 429:
                    return self._rate_limited_result(inv_id, "VirusTotal", domain, "domain")
                else:
                    return self._error_result(inv_id, "VirusTotal", domain, "domain", f"HTTP {resp.status_code}")
        except Exception as e:
            return self._error_result(inv_id, "VirusTotal", domain, "domain", str(e))

    # --- AbuseIPDB ---
    def _query_abuseipdb(self, ip_address: str, inv_id: str) -> ThreatIntelResult:
        api_key = self._get_key("abuseipdb", settings.ABUSEIPDB_API_KEY)
        if not api_key:
            return self._skipped_result(inv_id, "AbuseIPDB", ip_address, "ip", "AbuseIPDB API key not configured.")
        try:
            headers = {"Key": api_key, "Accept": "application/json"}
            params = {"ipAddress": ip_address, "maxAgeInDays": 90}
            with httpx.Client(timeout=8.0) as client:
                resp = client.get("https://api.abuseipdb.com/api/v2/check", headers=headers, params=params)
                if resp.status_code == 200:
                    data = resp.json().get("data", {})
                    score = data.get("abuseConfidenceScore", 0)
                    total_reports = data.get("totalReports", 0)
                    status = "malicious" if score >= 50 else ("suspicious" if score > 0 else "clean")
                    return ThreatIntelResult(
                        id=f"TI-ABUSE-{ip_address}",
                        provider="AbuseIPDB",
                        indicator=ip_address,
                        indicator_type="ip",
                        status=status,
                        detections=score,
                        total_engines=100,
                        details={
                            "abuseConfidenceScore": score,
                            "totalReports": total_reports,
                            "countryCode": data.get("countryCode"),
                            "isp": data.get("isp"),
                            "domain": data.get("domain")
                        }
                    )
                elif resp.status_code == 429:
                    return self._rate_limited_result(inv_id, "AbuseIPDB", ip_address, "ip")
                else:
                    return self._error_result(inv_id, "AbuseIPDB", ip_address, "ip", f"HTTP {resp.status_code}")
        except Exception as e:
            return self._error_result(inv_id, "AbuseIPDB", ip_address, "ip", str(e))

    # --- MalwareBazaar ---
    def _query_malwarebazaar_hash(self, sha256_hash: str, inv_id: str) -> ThreatIntelResult:
        try:
            headers = {"Auth-KEY": settings.MALWAREBAZAAR_API_KEY} if settings.MALWAREBAZAAR_API_KEY else {}
            data = {"query": "get_info", "hash": sha256_hash}
            with httpx.Client(timeout=8.0) as client:
                resp = client.post("https://mb-api.abuse.ch/api/v1/", data=data, headers=headers)
                if resp.status_code == 200:
                    json_res = resp.json()
                    query_status = json_res.get("query_status")
                    if query_status == "ok":
                        info = json_res.get("data", [{}])[0]
                        signature = info.get("signature", "Unknown Malware")
                        return ThreatIntelResult(
                            id=f"TI-MB-{sha256_hash[:8]}",
                            provider="MalwareBazaar",
                            indicator=sha256_hash,
                            indicator_type="hash",
                            status="malicious",
                            detections=1,
                            total_engines=1,
                            details={
                                "signature": signature,
                                "file_type": info.get("file_type"),
                                "tags": info.get("tags", [])
                            }
                        )
                    else:
                        return ThreatIntelResult(
                            id=f"TI-MB-{sha256_hash[:8]}",
                            provider="MalwareBazaar",
                            indicator=sha256_hash,
                            indicator_type="hash",
                            status="not_found",
                            detections=0,
                            total_engines=1,
                            details={"message": "Hash not recorded in MalwareBazaar."}
                        )
                else:
                    return self._error_result(inv_id, "MalwareBazaar", sha256_hash, "hash", f"HTTP {resp.status_code}")
        except Exception as e:
            return self._error_result(inv_id, "MalwareBazaar", sha256_hash, "hash", str(e))

    # --- URLhaus ---
    def _query_urlhaus_domain(self, domain: str, inv_id: str) -> ThreatIntelResult:
        try:
            with httpx.Client(timeout=8.0) as client:
                resp = client.get(f"https://urlhaus-api.abuse.ch/v1/host/{domain}/")
                if resp.status_code == 200:
                    json_res = resp.json()
                    query_status = json_res.get("query_status")
                    if query_status == "ok":
                        url_count = json_res.get("url_count", 0)
                        status = "malicious" if url_count > 0 else "clean"
                        return ThreatIntelResult(
                            id=f"TI-UH-{domain}",
                            provider="URLhaus",
                            indicator=domain,
                            indicator_type="domain",
                            status=status,
                            detections=url_count,
                            total_engines=url_count if url_count > 0 else 1,
                            details={"url_count": url_count, "threat": json_res.get("threat")}
                        )
                    else:
                        return ThreatIntelResult(
                            id=f"TI-UH-{domain}",
                            provider="URLhaus",
                            indicator=domain,
                            indicator_type="domain",
                            status="clean",
                            detections=0,
                            total_engines=1,
                            details={"message": "Host not listed in URLhaus dataset."}
                        )
                else:
                    return self._error_result(inv_id, "URLhaus", domain, "domain", f"HTTP {resp.status_code}")
        except Exception as e:
            return self._error_result(inv_id, "URLhaus", domain, "domain", str(e))

    # --- AlienVault OTX ---
    def _query_alienvault_hash(self, sha256_hash: str, inv_id: str) -> ThreatIntelResult:
        api_key = self._get_key("alienvault_otx", settings.ALIENVAULT_OTX_API_KEY)
        if not api_key:
            return self._skipped_result(inv_id, "AlienVault OTX", sha256_hash, "hash", "AlienVault OTX API key not configured.")
        try:
            headers = {"X-OTX-API-KEY": api_key}
            with httpx.Client(timeout=8.0) as client:
                resp = client.get(f"https://otx.alienvault.com/api/v1/indicators/file/{sha256_hash}/general", headers=headers)
                if resp.status_code == 200:
                    data = resp.json()
                    pulse_count = data.get("pulse_info", {}).get("count", 0)
                    status = "malicious" if pulse_count > 0 else "clean"
                    return ThreatIntelResult(
                        id=f"TI-OTX-{sha256_hash[:8]}",
                        provider="AlienVault OTX",
                        indicator=sha256_hash,
                        indicator_type="hash",
                        status=status,
                        detections=pulse_count,
                        total_engines=pulse_count if pulse_count > 0 else 1,
                        details={"pulse_count": pulse_count, "references": data.get("pulse_info", {}).get("pulses", [])[:3]}
                    )
                elif resp.status_code == 429:
                    return self._rate_limited_result(inv_id, "AlienVault OTX", sha256_hash, "hash")
                else:
                    return self._error_result(inv_id, "AlienVault OTX", sha256_hash, "hash", f"HTTP {resp.status_code}")
        except Exception as e:
            return self._error_result(inv_id, "AlienVault OTX", sha256_hash, "hash", str(e))

    # Helper result constructors
    def _skipped_result(self, inv_id: str, provider: str, ind: str, itype: str, reason: str) -> ThreatIntelResult:
        return ThreatIntelResult(
            id=f"TI-SKIP-{provider[:3]}-{ind[:8]}",
            provider=provider,
            indicator=ind,
            indicator_type=itype,
            status="skipped",
            detections=0,
            total_engines=0,
            details={"reason": reason}
        )

    def _rate_limited_result(self, inv_id: str, provider: str, ind: str, itype: str) -> ThreatIntelResult:
        return ThreatIntelResult(
            id=f"TI-RATELIMIT-{provider[:3]}-{ind[:8]}",
            provider=provider,
            indicator=ind,
            indicator_type=itype,
            status="rate_limited",
            detections=0,
            total_engines=0,
            error_message="Provider rate limit reached (HTTP 429). Indicator status remains unverified."
        )

    def _error_result(self, inv_id: str, provider: str, ind: str, itype: str, err: str) -> ThreatIntelResult:
        return ThreatIntelResult(
            id=f"TI-ERR-{provider[:3]}-{ind[:8]}",
            provider=provider,
            indicator=ind,
            indicator_type=itype,
            status="error",
            detections=0,
            total_engines=0,
            error_message=err
        )

    def test_alienvault_connection(self, api_key: Optional[str] = None) -> Dict[str, Any]:
        """
        Safely tests AlienVault OTX credentials by calling the read-only user endpoint:
        GET https://otx.alienvault.com/api/v1/user/me
        Supports exact states: Connected, Invalid credentials, Rate limited, Provider unavailable, Network error, Not configured.
        """
        key = api_key if api_key is not None else self._get_key("alienvault_otx", settings.ALIENVAULT_OTX_API_KEY)
        if not key or key.startswith("•••"):
            return {
                "status": "Not configured",
                "connected": False,
                "message": "AlienVault OTX API key is not configured."
            }
        try:
            headers = {"X-OTX-API-KEY": key}
            with httpx.Client(timeout=8.0) as client:
                resp = client.get("https://otx.alienvault.com/api/v1/user/me", headers=headers)
                if resp.status_code == 200:
                    data = resp.json()
                    username = data.get("username", "Authenticated User")
                    return {
                        "status": "Connected",
                        "connected": True,
                        "message": f"Successfully authenticated with AlienVault OTX (User: {username})."
                    }
                elif resp.status_code in (401, 403):
                    return {
                        "status": "Invalid credentials",
                        "connected": False,
                        "message": "Authentication failed. The provided AlienVault OTX API key is invalid or expired."
                    }
                elif resp.status_code == 429:
                    return {
                        "status": "Rate limited",
                        "connected": False,
                        "message": "AlienVault OTX API rate limit exceeded."
                    }
                elif resp.status_code >= 500:
                    return {
                        "status": "Provider unavailable",
                        "connected": False,
                        "message": f"AlienVault OTX service error (HTTP {resp.status_code})."
                    }
                else:
                    return {
                        "status": "Provider unavailable",
                        "connected": False,
                        "message": f"Unexpected response from AlienVault OTX (HTTP {resp.status_code})."
                    }
        except httpx.TimeoutException:
            return {
                "status": "Network error",
                "connected": False,
                "message": "Connection timed out while reaching AlienVault OTX service."
            }
        except Exception as e:
            return {
                "status": "Network error",
                "connected": False,
                "message": f"Network communication error: {str(e)}"
            }

threat_intel = ThreatIntelManager()
