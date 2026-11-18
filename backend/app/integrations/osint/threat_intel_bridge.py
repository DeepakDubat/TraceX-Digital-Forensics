import uuid
from typing import Dict, Any, List, Optional
from backend.app.config import settings
from backend.app.core.models import OSINTObservation, ThreatIntelResult
from backend.app.integrations.threat_intel.threat_intel_manager import ThreatIntelManager

class ThreatIntelBridge:
    """
    Bridges existing threat intelligence providers (VirusTotal, AbuseIPDB, AlienVault OTX,
    URLhaus, and MalwareBazaar) into the unified OSINT observation data contract.
    """

    def __init__(self, local_only_mode: Optional[bool] = None):
        self.local_only_mode = settings.LOCAL_ONLY_MODE if local_only_mode is None else local_only_mode
        self.ti_manager = ThreatIntelManager()
        self.ti_manager.local_only_mode = self.local_only_mode

    def query_indicator(self, indicator_type: str, value: str, investigation_id: str, indicator_id: str) -> List[OSINTObservation]:
        """Queries all relevant threat intelligence feeds for the given indicator."""
        results: List[OSINTObservation] = []
        clean_val = value.strip()

        if self.local_only_mode:
            results.append(OSINTObservation(
                id=f"OBS-TI-{uuid.uuid4().hex[:8]}",
                investigation_id=investigation_id,
                indicator_id=indicator_id,
                provider="ThreatIntelManager",
                indicator_type=indicator_type,
                indicator_value=clean_val,
                status="SKIPPED_LOCAL_ONLY",
                normalized_data={},
                limitations="Threat intelligence enrichment skipped because local-only mode is active."
            ))
            return results

        raw_ti_results: List[ThreatIntelResult] = []

        if indicator_type == "hash":
            raw_ti_results = self.ti_manager.check_hash(clean_val, investigation_id)
        elif indicator_type in ("ip", "ipv4", "ipv6"):
            raw_ti_results = self.ti_manager.check_ip(clean_val, investigation_id)
        elif indicator_type in ("domain", "hostname"):
            raw_ti_results = self.ti_manager.check_domain(clean_val, investigation_id)
        elif indicator_type == "url":
            # For URL, check URLhaus and VT domain if possible
            from urllib.parse import urlparse
            try:
                parsed = urlparse(clean_val)
                if parsed.netloc:
                    domain = parsed.netloc.split(":")[0]
                    raw_ti_results = self.ti_manager.check_domain(domain, investigation_id)
            except Exception:
                pass

        for ti in raw_ti_results:
            obs = self._convert_threat_intel_result(ti, investigation_id, indicator_id)
            results.append(obs)

        return results

    def _convert_threat_intel_result(self, ti: ThreatIntelResult, inv_id: str, ind_id: str) -> OSINTObservation:
        # Map status string
        status_map = {
            "clean": "SUCCESS",
            "suspicious": "SUCCESS",
            "malicious": "SUCCESS",
            "not_found": "NOT_FOUND",
            "rate_limited": "RATE_LIMITED",
            "skipped": "SKIPPED_LOCAL_ONLY" if "local" in (ti.error_message or "").lower() else "UNAVAILABLE",
            "error": "NETWORK_ERROR"
        }
        mapped_status = status_map.get(ti.status.lower(), "SUCCESS")

        permalink = None
        if ti.provider == "VirusTotal":
            if ti.indicator_type == "hash":
                permalink = f"https://www.virustotal.com/gui/file/{ti.indicator}"
            elif ti.indicator_type == "ip":
                permalink = f"https://www.virustotal.com/gui/ip-address/{ti.indicator}"
            elif ti.indicator_type == "domain":
                permalink = f"https://www.virustotal.com/gui/domain/{ti.indicator}"
        elif ti.provider == "AbuseIPDB":
            permalink = f"https://www.abuseipdb.com/check/{ti.indicator}"
        elif ti.provider == "AlienVault OTX":
            permalink = f"https://otx.alienvault.com/indicator/{ti.indicator_type}/{ti.indicator}"
        elif ti.provider == "URLhaus":
            permalink = f"https://urlhaus.abuse.ch/browse.php?search={ti.indicator}"
        elif ti.provider == "MalwareBazaar":
            permalink = f"https://bazaar.abuse.ch/sample/{ti.indicator}/"

        return OSINTObservation(
            id=f"OBS-{ti.provider[:3].upper()}-{uuid.uuid4().hex[:8]}",
            investigation_id=inv_id,
            indicator_id=ind_id,
            provider=ti.provider,
            indicator_type=ti.indicator_type,
            indicator_value=ti.indicator,
            query_timestamp_utc=ti.query_time.isoformat() if hasattr(ti.query_time, "isoformat") else str(ti.query_time),
            status=mapped_status,
            normalized_data={
                "verdict": ti.status,
                "detections": ti.detections,
                "total_engines": ti.total_engines,
                "detection_ratio": f"{ti.detections}/{ti.total_engines}" if ti.total_engines > 0 else "0/0",
                "details": ti.details
            },
            permalink=permalink,
            data_freshness="Live" if mapped_status == "SUCCESS" else "Cached",
            error_message=ti.error_message,
            limitations="Third-party reputation scores reflect aggregated vendor signatures and may have false positives or negatives."
        )
