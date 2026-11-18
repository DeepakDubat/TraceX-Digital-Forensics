"""
TraceX IP Evidence Extractor
Universal Digital Forensics & Cyber Investigation Suite v2.0.0

Extracts, validates, normalizes, and correlates all IPv4 and IPv6 addresses
discovered across APK artifacts:
- AndroidManifest.xml
- DEX bytecode & method tables
- Decompiled Java/Kotlin & Smali files
- Native libraries (.so)
- Embedded configuration files (JSON, XML, properties)
- Hardcoded URLs and API endpoints
- Firebase and Cloud configs

Preserves full forensic traceability: source file, class name, method name,
evidence location, associated URL/domain, finding ID, and extraction timestamp.
Deduplicates identical IPs while aggregating all distinct evidence references.
"""

import re
import ipaddress
from datetime import datetime
from urllib.parse import urlparse
from typing import Dict, List, Any, Optional, Set, Tuple
from backend.app.core.models import InvestigationDetail
from backend.app.models.ip_details import IPEvidenceReference, IPClassificationInfo

IPV4_PATTERN = re.compile(
    r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
)

# Robust IPv6 regex supporting standard, shortened (::), and embedded representations
IPV6_PATTERN = re.compile(
    r'\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b|'
    r'\b(?:[0-9a-fA-F]{1,4}:){1,7}:\b|'
    r'\b::(?:[0-9a-fA-F]{1,4}:){0,6}[0-9a-fA-F]{1,4}\b|'
    r'\b(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}\b'
)

# Known Cloud & CDN Autonomous Systems / IP ranges for high-confidence classification
KNOWN_CLOUD_PROVIDERS = [
    ("Amazon Web Services", ["amazon", "aws", "cloudfront", "13.32.", "52.", "54.", "3.", "18.", "34.", "35."]),
    ("Microsoft Azure", ["azure", "microsoft", "20.", "40.", "51.", "104.40.", "137.116."]),
    ("Google Cloud Platform", ["google", "gcp", "1e100", "34.", "35.", "172.217.", "142.250."]),
    ("Cloudflare", ["cloudflare", "104.16.", "104.17.", "104.18.", "104.19.", "104.20.", "104.21.", "172.67.", "1.1.1.1"]),
    ("DigitalOcean", ["digitalocean", "159.65.", "167.99.", "178.62.", "138.68."]),
    ("OVHcloud", ["ovh", "51.254.", "51.255.", "149.202."]),
    ("Hetzner Online", ["hetzner", "78.46.", "88.198.", "136.243."]),
    ("Akamai Technologies", ["akamai", "23.32.", "23.48.", "23.64."]),
]

PUBLIC_DNS_SERVERS = {
    "8.8.8.8": "Google Public DNS",
    "8.8.4.4": "Google Public DNS",
    "1.1.1.1": "Cloudflare DNS",
    "1.0.0.1": "Cloudflare DNS",
    "9.9.9.9": "Quad9 Secure Anycast DNS",
    "149.112.112.112": "Quad9 DNS",
    "208.67.222.222": "Cisco OpenDNS",
    "208.67.220.220": "Cisco OpenDNS",
    "94.140.14.14": "AdGuard DNS",
}

def classify_ip_network(ip_str: str) -> IPClassificationInfo:
    """Classifies an IP address into private, loopback, cloud, public DNS, or special subnet."""
    info = IPClassificationInfo()
    try:
        ip_obj = ipaddress.ip_address(ip_str)
    except ValueError:
        info.classification_label = "Invalid IP"
        return info

    info.is_private = ip_obj.is_private
    info.is_loopback = ip_obj.is_loopback
    info.is_link_local = ip_obj.is_link_local
    info.is_reserved = ip_obj.is_reserved
    info.is_multicast = ip_obj.is_multicast

    # Check Carrier Grade NAT (100.64.0.0/10)
    if isinstance(ip_obj, ipaddress.IPv4Address):
        cgnat_net = ipaddress.IPv4Network("100.64.0.0/10")
        info.is_carrier_grade_nat = ip_obj in cgnat_net

    # Check Public DNS
    if ip_str in PUBLIC_DNS_SERVERS:
        info.is_public_dns = True
        info.classification_label = f"Public DNS ({PUBLIC_DNS_SERVERS[ip_str]})"
        return info

    if info.is_loopback:
        info.classification_label = "Loopback Address (RFC 1122)"
    elif info.is_private:
        info.classification_label = "Private Subnet (RFC 1918 / RFC 4193)"
    elif info.is_link_local:
        info.classification_label = "Link-Local Address (RFC 3927)"
    elif info.is_carrier_grade_nat:
        info.classification_label = "Shared Address Space / CGNAT (RFC 6598)"
    elif info.is_multicast:
        info.classification_label = "Multicast Address (RFC 5771)"
    elif info.is_reserved:
        info.classification_label = "Reserved / Documentation Address"
    else:
        info.classification_label = f"Public {('IPv4' if ip_obj.version == 4 else 'IPv6')}"

    return info

def detect_cloud_infrastructure(ip_str: str, associated_domains: List[str] = None) -> Tuple[Optional[str], Optional[str]]:
    """Heuristic identification of cloud or CDN providers based on IP octets and domain associations."""
    assoc = " ".join(associated_domains or []).lower()

    for provider_name, keywords in KNOWN_CLOUD_PROVIDERS:
        for kw in keywords:
            if kw.endswith(".") and ip_str.startswith(kw):
                return provider_name, "Cloud / CDN Infrastructure"
            if not kw.endswith(".") and kw in assoc:
                return provider_name, "Cloud / Hosted Service"

    return None, None

def extract_ips_from_url(raw_url: str) -> Optional[Tuple[str, int]]:
    """Extracts raw IP and port if the URL uses an IP literal hostname."""
    try:
        parsed = urlparse(raw_url)
        hostname = (parsed.hostname or "").strip("[]")
        port = parsed.port or (443 if parsed.scheme == "https" else (80 if parsed.scheme == "http" else 80))
        # Validate if hostname is an IP
        ipaddress.ip_address(hostname)
        return hostname, port
    except Exception:
        return None

def extract_all_ips_from_investigation(
    detail: InvestigationDetail
) -> Dict[str, Dict[str, Any]]:
    """
    Scans the complete investigation detail and extracts every distinct IP address
    with its evidence references.
    Returns: Dict[canonical_ip, {
        "ip_address": ...,
        "ip_version": "IPv4" | "IPv6",
        "evidence_references": [IPEvidenceReference, ...],
        "associated_urls": [...],
        "associated_domains": [...]
    }]
    """
    extracted_map: Dict[str, Dict[str, Any]] = {}
    now_utc = datetime.utcnow().isoformat() + "Z"

    def record_ip(
        raw_ip: str,
        source_file: str,
        class_name: Optional[str] = None,
        method_name: Optional[str] = None,
        evidence_loc: Optional[str] = None,
        associated_url: Optional[str] = None,
        associated_domain: Optional[str] = None,
        finding_id: Optional[str] = None,
        context_snippet: Optional[str] = None
    ):
        clean_ip = raw_ip.strip().strip("[]").rstrip("/").split("/")[0] # Strip CIDR mask if present
        try:
            ip_obj = ipaddress.ip_address(clean_ip)
            canonical = str(ip_obj)
            version_str = f"IPv{ip_obj.version}"
        except ValueError:
            return # Skip invalid IPs

        # Filter out 0.0.0.0 and 255.255.255.255 broadcast masks unless explicitly desired
        if canonical in ("0.0.0.0", "255.255.255.255"):
            return

        if canonical not in extracted_map:
            extracted_map[canonical] = {
                "ip_address": canonical,
                "ip_version": version_str,
                "evidence_references": [],
                "associated_urls": set(),
                "associated_domains": set()
            }

        ref = IPEvidenceReference(
            source_file=source_file or "AndroidManifest.xml",
            class_name=class_name,
            method_name=method_name,
            evidence_location=evidence_loc,
            associated_url=associated_url,
            associated_domain=associated_domain,
            finding_id=finding_id,
            extraction_timestamp=now_utc,
            context_snippet=context_snippet[:200] if context_snippet else None
        )
        extracted_map[canonical]["evidence_references"].append(ref)

        if associated_url:
            extracted_map[canonical]["associated_urls"].add(associated_url)
        if associated_domain:
            extracted_map[canonical]["associated_domains"].add(associated_domain)

    # 1. Inspect existing detail.network_iocs
    for ioc in getattr(detail, "network_iocs", []):
        if getattr(ioc, "ioc_type", "") in ("ipv4", "ipv6") or re.match(IPV4_PATTERN, ioc.value):
            record_ip(
                raw_ip=ioc.value,
                source_file=ioc.source_file,
                evidence_loc=getattr(ioc, "related_domain", None),
                associated_domain=getattr(ioc, "related_domain", None),
                finding_id=ioc.id,
                context_snippet=getattr(ioc, "classification", "")
            )

    # 2. Inspect detail.c2_indicators (raw IPs and IP literals inside URLs)
    for c2 in getattr(detail, "c2_indicators", []):
        val = getattr(c2, "normalized_value", getattr(c2, "value", ""))
        source = getattr(c2, "source_file", "DEX bytecode")
        code_ref = getattr(c2, "code_reference", None)

        # Check if direct IP
        if getattr(c2, "indicator_type", "") == "ip" or re.match(IPV4_PATTERN, val):
            record_ip(
                raw_ip=val,
                source_file=source,
                method_name=code_ref,
                finding_id=c2.id,
                context_snippet=getattr(c2, "why_suspicious", None)
            )

        # Check if URL with IP literal
        ip_url_res = extract_ips_from_url(val)
        if ip_url_res:
            raw_host, _ = ip_url_res
            record_ip(
                raw_ip=raw_host,
                source_file=source,
                method_name=code_ref,
                associated_url=val,
                finding_id=c2.id,
                context_snippet=getattr(c2, "why_suspicious", None)
            )

    # 3. Inspect detail.static_findings for embedded IP patterns
    for finding in getattr(detail, "static_findings", []):
        title_str = getattr(finding, "title", "") or ""
        desc_str = getattr(finding, "description", "") or ""
        snippet_str = getattr(finding, "evidence_snippet", "") or getattr(finding, "code_snippet", "") or ""
        expl_str = getattr(finding, "explanation", "") or getattr(finding, "technical_explanation", "") or ""
        combined = f"{title_str} {desc_str} {snippet_str} {expl_str}"
        source_path = getattr(finding, "source_file", None) or getattr(finding, "file_path", "DEX / Resources")

        for m_ip in IPV4_PATTERN.findall(combined):
            record_ip(
                raw_ip=m_ip,
                source_file=source_path,
                class_name=getattr(finding, "class_name", None),
                method_name=getattr(finding, "method_name", None),
                evidence_loc=getattr(finding, "code_reference", None) or getattr(finding, "location", None),
                finding_id=finding.id,
                context_snippet=snippet_str or desc_str
            )

        for m_ipv6 in IPV6_PATTERN.findall(combined):
            if ":" in m_ipv6:
                record_ip(
                    raw_ip=m_ipv6,
                    source_file=source_path,
                    class_name=getattr(finding, "class_name", None),
                    method_name=getattr(finding, "method_name", None),
                    evidence_loc=getattr(finding, "code_reference", None) or getattr(finding, "location", None),
                    finding_id=finding.id,
                    context_snippet=snippet_str or desc_str
                )

    # 4. Inspect detail.reverse_shell_findings
    for rsh in getattr(detail, "reverse_shell_findings", []):
        rsh_title = getattr(rsh, "title", "") or ""
        rsh_expl = getattr(rsh, "explanation", "") or ""
        rsh_snip = getattr(rsh, "evidence_snippet", "") or ""
        rsh_refs = " ".join(getattr(rsh, "code_references", []) or [])
        rsh_chain = " ".join(getattr(rsh, "execution_chain", []) or [])
        combined_rsh = f"{rsh_title} {rsh_expl} {rsh_snip} {rsh_refs} {rsh_chain}"

        for m_ip in IPV4_PATTERN.findall(combined_rsh):
            record_ip(
                raw_ip=m_ip,
                source_file="DEX bytecode / Shell Analysis",
                finding_id=getattr(rsh, "id", None),
                context_snippet=rsh_title or rsh_snip
            )
        for m_ipv6 in IPV6_PATTERN.findall(combined_rsh):
            if ":" in m_ipv6:
                record_ip(
                    raw_ip=m_ipv6,
                    source_file="DEX bytecode / Shell Analysis",
                    finding_id=getattr(rsh, "id", None),
                    context_snippet=rsh_title or rsh_snip
                )

    # 5. Inspect detail.secrets
    for sec in getattr(detail, "secrets", []):
        sec_loc = getattr(sec, "source_location", "DEX / Secrets")
        sec_snip = getattr(sec, "context_snippet", "") or ""
        sec_rule = getattr(sec, "rule_matched", "") or ""
        sec_ind = getattr(sec, "related_indicator", "") or ""
        combined_sec = f"{sec_loc} {sec_snip} {sec_rule} {sec_ind}"

        for m_ip in IPV4_PATTERN.findall(combined_sec):
            record_ip(
                raw_ip=m_ip,
                source_file=sec_loc,
                finding_id=getattr(sec, "id", None),
                context_snippet=sec_rule or sec_snip
            )

    # 6. Inspect detail.metadata network security config
    if getattr(detail, "metadata", None):
        nsc = getattr(detail.metadata, "network_security_config", "") or ""
        for m_ip in IPV4_PATTERN.findall(nsc):
            record_ip(
                raw_ip=m_ip,
                source_file="res/xml/network_security_config.xml",
                context_snippet="Cleartext traffic IP permit pin"
            )

    # Convert sets to sorted lists
    for k, v in extracted_map.items():
        v["associated_urls"] = sorted(list(v["associated_urls"]))
        v["associated_domains"] = sorted(list(v["associated_domains"]))

    return extracted_map
