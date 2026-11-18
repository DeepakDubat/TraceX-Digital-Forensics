"""
TraceX IP Details & Comprehensive Intelligence API Routes
Universal Digital Forensics & Cyber Investigation Suite v2.0.0

Endpoints:
- GET  /api/investigations/{id}/ip-details: Discovers and enriches all IPs found in APK analysis
- GET  /api/investigations/{id}/ip-details/{ip}: Deep WHOIS/RDAP, ASN, and Threat detail for a specific IP
- POST /api/investigations/{id}/ip-details/{ip}/export: Exports individual IP report (PDF, HTML, TXT, JSON) to %USERPROFILE%\\Documents\\TraceX\\IP Reports\\<ID>\\<IP>\\
- POST /api/investigations/{id}/ip-details/export-all: Exports complete investigation IP dossier (PDF, HTML, TXT, JSON)
- GET  /api/investigations/{id}/ip-details/{ip}/saved-files: Lists verified on-disk reports for an IP
"""

from typing import Dict, Any, Optional
from datetime import datetime
from pydantic import BaseModel
from fastapi import APIRouter, HTTPException, Query, Depends

from backend.app.database.repository import repo
from backend.app.core.user_auth import get_current_user
from backend.app.models.ip_details import (
    IPDetailRecord,
    InvestigationIPsSummary
)
from backend.app.analyzers.ip_evidence_extractor import (
    extract_all_ips_from_investigation,
    classify_ip_network
)
from backend.app.analyzers.ip_intelligence_engine import (
    build_ip_intelligence_record,
    get_current_network_mode
)
from backend.app.reporting.ip_report_generator import (
    export_individual_ip_report_to_disk,
    export_all_ips_report_to_disk,
    list_saved_reports_for_ip
)

router = APIRouter(prefix="/api", tags=["IP Details"])

class IPReportExportRequest(BaseModel):
    format: str = "pdf" # pdf, html, txt, json
    overwrite: bool = True

@router.get("/investigations/{investigation_id}/ip-details", response_model=InvestigationIPsSummary)
def get_investigation_ip_details(
    investigation_id: str,
    refresh: bool = Query(False),
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """
    Extracts all IP addresses from APK artifacts (Manifest, DEX, resources, native, URLs, endpoints).
    Deduplicates identical IPs while aggregating all evidence references.
    Enriches with authoritative RDAP, Geolocation, ASN, and Threat intelligence per Network Mode.
    """
    detail = repo.get_investigation_detail(investigation_id, include_raw_secrets=False)
    if not detail:
        raise HTTPException(status_code=404, detail="Investigation record not found.")

    raw_extracted = extract_all_ips_from_investigation(detail)
    mode = get_current_network_mode()
    now_utc = datetime.utcnow().isoformat() + "Z"

    ip_records: list[IPDetailRecord] = []
    ipv4_cnt = 0
    ipv6_cnt = 0
    pub_cnt = 0
    priv_cnt = 0
    cloud_cnt = 0
    mal_cnt = 0
    susp_cnt = 0
    clean_cnt = 0
    unk_cnt = 0

    for ip_str, item in raw_extracted.items():
        try:
            rec = build_ip_intelligence_record(
                investigation_id=investigation_id,
                ip_str=ip_str,
                ip_version=item["ip_version"],
                evidence_references=item["evidence_references"],
                associated_urls=item["associated_urls"],
                associated_domains=item["associated_domains"],
                force_refresh=refresh
            )
        except Exception as e:
            logger.error(f"Failed to build IP intelligence for {ip_str} in {investigation_id}: {e}", exc_info=True)
            # Resilient fallback: preserve IP and its evidence references
            rec = IPDetailRecord(
                id=f"IP-{ip_str.replace('.', '-').replace(':', '_')}",
                investigation_id=investigation_id,
                ip_address=ip_str,
                ip_version=item["ip_version"],
                canonical_ip=ip_str,
                evidence_references=item["evidence_references"],
                lookup_status="FAILED",
                created_at_utc=now_utc,
                lookup_timestamp=now_utc
            )
            rec.classification = classify_ip_network(ip_str)

        ip_records.append(rec)

        # Counters
        if rec.ip_version == "IPv4":
            ipv4_cnt += 1
        else:
            ipv6_cnt += 1

        if rec.classification.is_private or rec.classification.is_loopback:
            priv_cnt += 1
        else:
            pub_cnt += 1

        if rec.classification.is_cloud:
            cloud_cnt += 1

        status = rec.threat_info.threat_status.upper()
        if status == "MALICIOUS":
            mal_cnt += 1
        elif status == "SUSPICIOUS":
            susp_cnt += 1
        elif status == "CLEAN":
            clean_cnt += 1
        else:
            unk_cnt += 1

    # Sort: Malicious/Suspicious first, then Public IPs, then Private IPs
    def sort_key(r: IPDetailRecord):
        threat_rank = 0 if r.threat_info.threat_status == "MALICIOUS" else (1 if r.threat_info.threat_status == "SUSPICIOUS" else 2)
        scope_rank = 0 if not (r.classification.is_private or r.classification.is_loopback) else 1
        return (threat_rank, scope_rank, r.ip_address)

    ip_records.sort(key=sort_key)

    return InvestigationIPsSummary(
        investigation_id=investigation_id,
        total_unique_ips=len(ip_records),
        ipv4_count=ipv4_cnt,
        ipv6_count=ipv6_cnt,
        public_ip_count=pub_cnt,
        private_ip_count=priv_cnt,
        cloud_ip_count=cloud_cnt,
        malicious_ip_count=mal_cnt,
        suspicious_ip_count=susp_cnt,
        clean_ip_count=clean_cnt,
        unknown_ip_count=unk_cnt,
        network_mode=mode,
        extraction_timestamp_utc=now_utc,
        ips=ip_records
    )

@router.get("/investigations/{investigation_id}/ip-details/{ip_address}", response_model=IPDetailRecord)
def get_single_ip_details(
    investigation_id: str,
    ip_address: str,
    refresh: bool = Query(False),
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """
    Returns full individual IP report detail for a specific IP.
    """
    clean_ip = ip_address.strip()
    detail = repo.get_investigation_detail(investigation_id, include_raw_secrets=False)
    if not detail:
        raise HTTPException(status_code=404, detail="Investigation record not found.")

    raw_extracted = extract_all_ips_from_investigation(detail)
    evidence_refs = []
    associated_urls = []
    associated_domains = []

    if clean_ip in raw_extracted:
        evidence_refs = raw_extracted[clean_ip]["evidence_references"]
        associated_urls = raw_extracted[clean_ip]["associated_urls"]
        associated_domains = raw_extracted[clean_ip]["associated_domains"]
        ip_version = raw_extracted[clean_ip]["ip_version"]
    else:
        # Standalone lookup for an IP within the investigation context
        ip_version = "IPv6" if ":" in clean_ip else "IPv4"

    try:
        return build_ip_intelligence_record(
            investigation_id=investigation_id,
            ip_str=clean_ip,
            ip_version=ip_version,
            evidence_references=evidence_refs,
            associated_urls=associated_urls,
            associated_domains=associated_domains,
            force_refresh=refresh
        )
    except Exception as e:
        logger.error(f"Failed to build single IP intelligence for {clean_ip}: {e}", exc_info=True)
        rec = IPDetailRecord(
            id=f"IP-{clean_ip.replace('.', '-').replace(':', '_')}",
            investigation_id=investigation_id,
            ip_address=clean_ip,
            ip_version=ip_version,
            canonical_ip=clean_ip,
            evidence_references=evidence_refs,
            lookup_status="FAILED",
            created_at_utc=datetime.utcnow().isoformat() + "Z",
            lookup_timestamp=datetime.utcnow().isoformat() + "Z"
        )
        rec.classification = classify_ip_network(clean_ip)
        return rec

@router.post("/investigations/{investigation_id}/ip-details/{ip_address}/export")
def export_single_ip_report(
    investigation_id: str,
    ip_address: str,
    req: IPReportExportRequest,
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """
    Generates and saves individual IP report directly to:
    %USERPROFILE%\\Documents\\TraceX\\IP Reports\\<INVESTIGATION_ID>\\<SAFE_IP>\\
    Formats: pdf, html, txt, json.
    """
    rec = get_single_ip_details(investigation_id, ip_address, refresh=False, current_user=current_user)
    result = export_individual_ip_report_to_disk(
        record=rec,
        format_type=req.format,
        overwrite=req.overwrite
    )
    if result.get("status") != "success":
        raise HTTPException(status_code=500, detail=result.get("error", "Failed to export IP report."))
    return result

@router.post("/investigations/{investigation_id}/ip-details/export-all")
def export_all_ips_report(
    investigation_id: str,
    req: IPReportExportRequest,
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """
    Generates and saves the complete investigation IP dossier to:
    %USERPROFILE%\\Documents\\TraceX\\IP Reports\\<INVESTIGATION_ID>\\
    Formats: pdf, html, txt, json.
    """
    summary = get_investigation_ip_details(investigation_id, refresh=False, current_user=current_user)
    result = export_all_ips_report_to_disk(
        summary=summary,
        format_type=req.format,
        overwrite=req.overwrite
    )
    if result.get("status") != "success":
        raise HTTPException(status_code=500, detail=result.get("error", "Failed to export all-IP dossier."))
    return result

@router.get("/investigations/{investigation_id}/ip-details/{ip_address}/saved-files")
def get_saved_reports_for_ip_endpoint(
    investigation_id: str,
    ip_address: str,
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """
    Returns list of verified on-disk reports saved for this IP in:
    %USERPROFILE%\\Documents\\TraceX\\IP Reports\\<INVESTIGATION_ID>\\<SAFE_IP>\\
    """
    return list_saved_reports_for_ip(investigation_id, ip_address)
