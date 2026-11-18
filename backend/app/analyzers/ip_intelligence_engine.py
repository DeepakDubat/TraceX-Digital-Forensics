"""
TraceX Comprehensive IP Intelligence Engine
Universal Digital Forensics & Cyber Investigation Suite v2.0.0

Performs deep, structured, authoritative IP intelligence lookups:
1. Special / Reserved / RFC 1918 / Loopback classification
2. Authoritative Regional Internet Registry (RIR) RDAP & WHOIS data:
   - ARIN, RIPE NCC, APNIC, LACNIC, AFRINIC
   - Automatic referral tracking
   - NetRange, CIDR, NetName, NetHandle, Parent, NetType, OriginAS
   - Organization name, address, official technical & abuse contacts
3. Geolocation Intelligence (with required approximate disclaimer)
4. Network & ASN Routing Intelligence
5. Server & Cloud Hosting Provider Detection (AWS, Azure, GCP, Cloudflare, OVH, etc.)
6. Domain & DNS PTR Intelligence (Reverse DNS via PTR)
7. Multi-Engine Threat Intelligence (VirusTotal, AbuseIPDB, OTX, GreyNoise)
8. Network Classification (VPN, Proxy, Tor, CDN, Public DNS, Cloud)
9. Network Mode Privacy Enforcement:
   - LOCAL_ONLY: Zero outbound network calls, local evidence and offline metadata only.
   - HYBRID: Minimum necessary indicator queries with timeouts and in-memory caching.
"""

import os
import json
import socket
import logging
import ipaddress
import urllib.request
import urllib.error
from datetime import datetime
from typing import Dict, Any, Optional, List, Tuple

from backend.app.config import settings
from backend.app.models.ip_details import (
    IPDetailRecord,
    IPClassificationInfo,
    IPNetworkInfo,
    IPOrganizationInfo,
    IPGeolocationInfo,
    IPRoutingASNInfo,
    IPHostingServerInfo,
    IPDomainDnsInfo,
    IPThreatReputationInfo,
    IPEvidenceReference,
    SourceReference
)
from backend.app.analyzers.ip_evidence_extractor import (
    classify_ip_network,
    detect_cloud_infrastructure,
    PUBLIC_DNS_SERVERS,
    KNOWN_CLOUD_PROVIDERS
)

logger = logging.getLogger("tracex.ip_intelligence")

# In-memory session cache for fast deduplicated lookups
_IP_INTELLIGENCE_CACHE: Dict[str, IPDetailRecord] = {}

# Authoritative RDAP Bootstrap Endpoints
RDAP_BOOTSTRAP_URL = "https://rdap.arin.net/registry/ip/{ip}"

def get_current_network_mode() -> str:
    """Retrieves authoritative network mode from environment or configuration."""
    from backend.app.core.network_mode import get_network_mode
    try:
        return get_network_mode().value
    except Exception:
        return "LOCAL_ONLY" if getattr(settings, "LOCAL_ONLY_MODE", True) else "HYBRID"

def resolve_reverse_dns(ip_str: str, timeout: float = 2.0) -> Optional[str]:
    """Performs reverse DNS PTR lookup with strict socket timeout."""
    try:
        # Temporarily set default socket timeout for PTR query
        orig_timeout = socket.getdefaulttimeout()
        socket.setdefaulttimeout(timeout)
        try:
            hostname, _, _ = socket.gethostbyaddr(ip_str)
            return hostname
        finally:
            socket.setdefaulttimeout(orig_timeout)
    except Exception:
        return None

def resolve_forward_dns(hostname: str, timeout: float = 2.0) -> List[str]:
    """Resolves A/AAAA records for a hostname."""
    ips = []
    try:
        orig_timeout = socket.getdefaulttimeout()
        socket.setdefaulttimeout(timeout)
        try:
            addr_info = socket.getaddrinfo(hostname, None)
            for item in addr_info:
                sockaddr = item[4]
                if sockaddr and sockaddr[0] not in ips:
                    ips.append(sockaddr[0])
        finally:
            socket.setdefaulttimeout(orig_timeout)
    except Exception:
        pass
    return ips

def parse_rdap_vcard(vcard_array: Any) -> Dict[str, Any]:
    """Extracts structured organization, address, and contact info from RDAP vCard (jCard format)."""
    result = {
        "fn": None,
        "org": None,
        "adr": None,
        "email": None,
        "tel": None
    }
    if not isinstance(vcard_array, list) or len(vcard_array) < 2:
        return result

    properties = vcard_array[1]
    if not isinstance(properties, list):
        return result

    for prop in properties:
        if not isinstance(prop, list) or len(prop) < 4:
            continue
        p_name = prop[0].lower()
        p_val = prop[3]

        if p_name == "fn" and not result["fn"]:
            result["fn"] = str(p_val)
        elif p_name == "org" and not result["org"]:
            result["org"] = str(p_val)
        elif p_name == "email" and not result["email"]:
            result["email"] = str(p_val)
        elif p_name == "tel" and not result["tel"]:
            result["tel"] = str(p_val)
        elif p_name == "adr" and isinstance(p_val, list):
            # jCard ADR: [pobox, ext, street, locality, region, code, country]
            parts = [str(x) for x in p_val if x]
            if parts:
                result["adr"] = ", ".join(parts)

    return result

def query_authoritative_rdap(ip_str: str, timeout: float = 3.5) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
    """
    Queries authoritative Regional Internet Registry via RDAP bootstrap.
    Follows HTTP 302/307 redirects across ARIN, RIPE NCC, APNIC, LACNIC, and AFRINIC.
    Returns (rdap_json, authoritative_url).
    """
    target_url = RDAP_BOOTSTRAP_URL.format(ip=ip_str)
    req = urllib.request.Request(
        target_url,
        headers={
            "User-Agent": "TraceX-Forensics/2.0 (Digital Forensics & OSINT Suite; Read-Only)",
            "Accept": "application/rdap+json, application/json"
        }
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            if resp.status == 200:
                raw_bytes = resp.read()
                data = json.loads(raw_bytes.decode("utf-8", errors="replace"))
                actual_url = resp.geturl()
                return data, actual_url
    except Exception as e:
        logger.debug(f"RDAP query failed for {ip_str}: {e}")
        return None, None
    return None, None

def query_public_geoip_fallback(ip_str: str, timeout: float = 3.0) -> Optional[Dict[str, Any]]:
    """Secondary passive GeoIP lookup using standard free API when in HYBRID mode."""
    url = f"http://ip-api.com/json/{ip_str}?fields=status,message,country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,as,asname,query"
    req = urllib.request.Request(url, headers={"User-Agent": "TraceX-Forensics/2.0"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            if resp.status == 200:
                data = json.loads(resp.read().decode("utf-8", errors="replace"))
                if data.get("status") == "success":
                    return data
    except Exception:
        pass
    return None

def build_ip_intelligence_record(
    investigation_id: str,
    ip_str: str,
    ip_version: str,
    evidence_references: List[IPEvidenceReference],
    associated_urls: List[str] = None,
    associated_domains: List[str] = None,
    force_refresh: bool = False
) -> IPDetailRecord:
    """
    Main orchestrator for comprehensive IP intelligence compilation.
    Checks cache, respects LOCAL_ONLY / HYBRID network mode, extracts authoritative RDAP,
    PTR, DNS, Geolocation, ASN, Cloud, and Threat intelligence.
    """
    associated_urls = associated_urls or []
    associated_domains = associated_domains or []

    cache_key = f"{investigation_id}:{ip_str}"
    if not force_refresh and cache_key in _IP_INTELLIGENCE_CACHE:
        cached = _IP_INTELLIGENCE_CACHE[cache_key]
        # Update references if any new ones arrived
        cached.evidence_references = evidence_references
        return cached

    now_utc = datetime.utcnow().isoformat() + "Z"
    safe_id = f"IP-{ip_str.replace('.', '-').replace(':', '_')}"

    # Initialize Record
    record = IPDetailRecord(
        id=safe_id,
        investigation_id=investigation_id,
        ip_address=ip_str,
        ip_version=ip_version,
        canonical_ip=ip_str,
        evidence_references=evidence_references,
        created_at_utc=now_utc,
        lookup_timestamp=now_utc
    )

    # 1. Base Subnet & Network Classification (Instant & Offline)
    classification = classify_ip_network(ip_str)
    record.classification = classification

    # Check Cloud Provider ranges
    cloud_name, cloud_class = detect_cloud_infrastructure(ip_str, associated_domains)
    if cloud_name:
        record.classification.is_cloud = True
        record.hosting_server_info.cloud_provider = cloud_name
        record.hosting_server_info.hosting_provider = cloud_name
        record.hosting_server_info.server_classification = "Cloud / Hosting Infrastructure"
        record.hosting_server_info.evidence_basis = f"IP range matches documented {cloud_name} Autonomous System prefix."

    # Associate extracted URLs and Domains
    record.domain_dns_info.associated_urls = associated_urls
    record.domain_dns_info.associated_domains = associated_domains

    # Check network privacy mode
    network_mode = get_current_network_mode()

    # IF LOCAL_ONLY OR PRIVATE/LOOPBACK: Operate purely offline
    if network_mode == "LOCAL_ONLY" or classification.is_private or classification.is_loopback or classification.is_reserved or classification.is_link_local:
        if network_mode == "LOCAL_ONLY" and not (classification.is_private or classification.is_loopback):
            record.lookup_status = "SKIPPED_LOCAL_ONLY"
            comment = "External RDAP and threat intelligence lookup skipped: LOCAL_ONLY privacy mode active. Network communication strictly disabled."
        else:
            record.lookup_status = "OFFLINE_ONLY"
            comment = f"Special non-routable address ({classification.classification_label}). Local forensic processing only."

        record.network_info = IPNetworkInfo(
            net_name=classification.classification_label,
            cidr="32" if ip_version == "IPv4" else "128",
            net_type="LOCAL_SUBNET",
            comment=comment
        )
        record.organization_info = IPOrganizationInfo(
            organization="Private / Internal Network",
            country="Local Subnet"
        )
        record.geolocation_info = IPGeolocationInfo(
            country="Local / Internal Network",
            region="Private Address Space",
            data_source="RFC 1918 / RFC 4193 Definition",
            confidence="Deterministic Offline Standard"
        )
        record.routing_asn_info = IPRoutingASNInfo(
            asn_name="Non-Routable Autonomous Space",
            isp="Internal / Loopback / Air-Gapped Network"
        )
        if classification.is_public_dns:
            threat_st = "CLEAN"
            bl_st = "Public DNS Resolver (Known Safe)"
        elif classification.is_private or classification.is_loopback:
            threat_st = "CLEAN"
            bl_st = "Internal Subnet (Not Routable on Internet)"
        else:
            threat_st = "UNKNOWN"
            bl_st = "Not Evaluated (External Queries Skipped in LOCAL_ONLY Mode)"

        record.threat_info = IPThreatReputationInfo(
            threat_status=threat_st,
            blacklist_status=bl_st
        )
        record.source_references.append(SourceReference(
            provider="TraceX Local Forensic Engine",
            query_timestamp=now_utc,
            lookup_status=record.lookup_status,
            confidence="High"
        ))

        _IP_INTELLIGENCE_CACHE[cache_key] = record
        return record

    # ==========================================================================
    # HYBRID MODE: LIVE AUTHORITATIVE RDAP, PTR, AND GEOLOCATION ENRICHMENT
    # ==========================================================================
    record.lookup_status = "ENRICHED"

    # Step A: Reverse DNS PTR lookup
    ptr_hostname = resolve_reverse_dns(ip_str)
    if ptr_hostname:
        record.domain_dns_info.reverse_dns = ptr_hostname
        record.domain_dns_info.hostname = ptr_hostname
        record.source_references.append(SourceReference(
            provider="Authoritative DNS In-Addr.ARPA PTR",
            query_timestamp=now_utc,
            lookup_status="SUCCESS",
            confidence="High"
        ))

    # Step B: Query Authoritative RDAP
    rdap_data, auth_url = query_authoritative_rdap(ip_str)
    if rdap_data:
        record.source_references.append(SourceReference(
            provider="Regional Internet Registry RDAP",
            query_timestamp=now_utc,
            source_url=auth_url,
            lookup_status="SUCCESS",
            confidence="Authoritative"
        ))

        # 1. Network Info
        start_addr = rdap_data.get("startAddress")
        end_addr = rdap_data.get("endAddress")
        net_range_str = f"{start_addr} - {end_addr}" if start_addr and end_addr else None
        
        # Derive CIDR from cidr0_cidrs if present
        cidrs = rdap_data.get("cidr0_cidrs", [])
        cidr_str = None
        if cidrs and isinstance(cidrs, list):
            cidr_entry = cidrs[0]
            if isinstance(cidr_entry, dict):
                cidr_str = f"{cidr_entry.get('v4prefix', cidr_entry.get('v6prefix', ''))}/{cidr_entry.get('length', '')}"

        # Detect RIR
        rir_name = "ARIN"
        if auth_url:
            if "ripe.net" in auth_url:
                rir_name = "RIPE NCC"
            elif "apnic.net" in auth_url:
                rir_name = "APNIC"
            elif "lacnic.net" in auth_url:
                rir_name = "LACNIC"
            elif "afrinic.net" in auth_url:
                rir_name = "AFRINIC"

        remarks = rdap_data.get("remarks", [])
        comment_text = None
        if remarks and isinstance(remarks, list):
            desc_lines = []
            for rem in remarks:
                for d in rem.get("description", []):
                    desc_lines.append(str(d))
            if desc_lines:
                comment_text = "\n".join(desc_lines[:6])

        # Self resource link
        self_link = None
        for link in rdap_data.get("links", []):
            if link.get("rel") == "self":
                self_link = link.get("href")
                break

        record.network_info = IPNetworkInfo(
            net_range=net_range_str,
            cidr=cidr_str or (f"{start_addr}/24" if start_addr else None),
            net_name=rdap_data.get("name"),
            net_handle=rdap_data.get("handle"),
            parent_handle=rdap_data.get("parentHandle"),
            net_type=rdap_data.get("type"),
            rir=rir_name,
            registration_status=rdap_data.get("status", ["active"])[0] if isinstance(rdap_data.get("status"), list) else rdap_data.get("status"),
            resource_link=self_link or auth_url,
            referral_server=auth_url,
            comment=comment_text
        )

        # Parse Organization & Entities
        entities = rdap_data.get("entities", [])
        for ent in entities:
            roles = ent.get("roles", [])
            vcard = parse_rdap_vcard(ent.get("vcardArray"))

            # Primary Org Entity
            if ("registrant" in roles or "administrative" in roles or not record.organization_info.organization) and vcard.get("org"):
                record.organization_info.organization = vcard.get("org") or vcard.get("fn")
                record.organization_info.org_id = ent.get("handle")
                record.organization_info.address = vcard.get("adr")
                record.organization_info.country = rdap_data.get("country")

            # Abuse Contact
            if "abuse" in roles:
                record.organization_info.abuse_contact_name = vcard.get("fn") or ent.get("handle")
                record.organization_info.abuse_contact_email = vcard.get("email")
                record.organization_info.abuse_contact_phone = vcard.get("tel")

            # Technical Contact
            if "technical" in roles:
                record.organization_info.tech_contact_name = vcard.get("fn") or ent.get("handle")
                record.organization_info.tech_contact_email = vcard.get("email")
                record.organization_info.tech_contact_phone = vcard.get("tel")

        # Routing ASN info from RDAP
        record.routing_asn_info.network_prefix = cidr_str or net_range_str
        record.routing_asn_info.network_owner = record.organization_info.organization
        record.routing_asn_info.rir = rir_name

    # Step C: GeoIP & ASN Routing Enrichment (Secondary passive provider)
    geo_data = query_public_geoip_fallback(ip_str)
    if geo_data:
        record.source_references.append(SourceReference(
            provider="BGP Routing & GeoIP Provider",
            query_timestamp=now_utc,
            source_url="http://ip-api.com",
            lookup_status="SUCCESS",
            confidence="Approximate"
        ))

        # Geolocation
        record.geolocation_info.country = geo_data.get("country") or record.geolocation_info.country
        record.geolocation_info.country_code = geo_data.get("countryCode")
        record.geolocation_info.region = geo_data.get("regionName")
        record.geolocation_info.city = geo_data.get("city")
        record.geolocation_info.postal_code = geo_data.get("zip")
        record.geolocation_info.latitude = geo_data.get("lat")
        record.geolocation_info.longitude = geo_data.get("lon")
        record.geolocation_info.timezone = geo_data.get("timezone")
        record.geolocation_info.data_source = "BGP Routing & Public Registry"

        # ASN & ISP
        raw_as = geo_data.get("as", "")
        asn_code = None
        if raw_as and raw_as.startswith("AS"):
            parts = raw_as.split(" ", 1)
            asn_code = parts[0]

        record.routing_asn_info.asn = asn_code or record.routing_asn_info.asn
        record.routing_asn_info.asn_name = geo_data.get("asname") or record.routing_asn_info.asn_name
        record.routing_asn_info.as_organization = geo_data.get("org") or record.routing_asn_info.as_organization
        record.routing_asn_info.isp = geo_data.get("isp") or record.routing_asn_info.isp

        # Fallback Org if RDAP didn't populate it
        if not record.organization_info.organization:
            record.organization_info.organization = geo_data.get("org") or geo_data.get("isp")
            record.organization_info.country = geo_data.get("country")
            record.organization_info.city = geo_data.get("city")

    # Step D: Infrastructure / Hosting Provider Refinement
    hosting_candidate = (
        record.routing_asn_info.as_organization or
        record.routing_asn_info.isp or
        record.organization_info.organization or
        ""
    ).lower()

    if not record.hosting_server_info.cloud_provider:
        for p_name, p_keys in KNOWN_CLOUD_PROVIDERS:
            for k in p_keys:
                if k in hosting_candidate:
                    record.hosting_server_info.cloud_provider = p_name
                    record.hosting_server_info.hosting_provider = p_name
                    record.hosting_server_info.server_classification = "Cloud / Hosting Infrastructure"
                    record.hosting_server_info.evidence_basis = f"ASN Organization matches {p_name}."
                    record.classification.is_cloud = True
                    break

    # Step E: Threat Reputation Check
    # Verify against configured threat providers or provide clean baseline
    try:
        from backend.app.database.repository import repo
        existing_ti = repo.get_threat_intel_results(investigation_id)
        ti_for_ip = [t for t in existing_ti if t.indicator == ip_str]
        if ti_for_ip:
            total_mal = sum(t.detections for t in ti_for_ip if t.status in ("malicious", "suspicious"))
            if total_mal > 0 or any(t.status == "malicious" for t in ti_for_ip):
                record.threat_info.threat_status = "MALICIOUS"
                record.threat_info.malicious_count = total_mal
                record.threat_info.blacklist_status = f"Flagged by threat intelligence providers ({total_mal} detections)"
            elif any(t.status == "suspicious" for t in ti_for_ip):
                record.threat_info.threat_status = "SUSPICIOUS"
                record.threat_info.blacklist_status = "Suspicious reputation observed"
            elif any(t.status == "clean" for t in ti_for_ip):
                record.threat_info.threat_status = "CLEAN"
                record.threat_info.blacklist_status = "Clean (No malicious detections recorded)"
            else:
                record.threat_info.threat_status = "UNKNOWN"
                record.threat_info.blacklist_status = "Not Evaluated / Inconclusive"
            
            record.threat_info.provider_results = {
                t.provider.lower(): {"status": t.status.upper(), "detections": t.detections, "total_engines": t.total_engines}
                for t in ti_for_ip
            }
        else:
            if record.classification.is_public_dns:
                record.threat_info.threat_status = "CLEAN"
                record.threat_info.blacklist_status = "Public DNS Resolver (Known Safe)"
            elif record.classification.is_private or record.classification.is_loopback:
                record.threat_info.threat_status = "CLEAN"
                record.threat_info.blacklist_status = "Internal / Private Subnet"
            else:
                record.threat_info.threat_status = "UNKNOWN"
                record.threat_info.blacklist_status = "Not Evaluated (No External Threat Queries Conducted)"
    except Exception as e:
        logger.debug(f"Threat intel check error for {ip_str}: {e}")
        record.threat_info.threat_status = "UNKNOWN"
        record.threat_info.blacklist_status = "Not Evaluated"

    _IP_INTELLIGENCE_CACHE[cache_key] = record
    return record
