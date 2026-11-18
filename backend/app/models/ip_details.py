"""
TraceX IP Details Data Models
Universal Digital Forensics & Cyber Investigation Suite v2.0.0

Structured Pydantic models for Comprehensive IP Intelligence Reports:
- Automatic IP Evidence Extraction Traceability
- WHOIS & RDAP Authoritative Registry Data
- Geolocation Intelligence (with approximate location disclaimer)
- Network & ASN Routing Intelligence
- Cloud & Hosting Infrastructure Detection
- Domain & DNS PTR Intelligence
- Contact & Organization Data (Privacy-Preserving)
- Multi-Engine Threat Intelligence & Reputation
- Network Classification (Cloud, CDN, Tor, VPN, RFC 1918)
- Source Attributions
"""

from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field

class IPEvidenceReference(BaseModel):
    """Traceability record linking an extracted IP to its origin in the APK."""
    source_file: str = "Unknown"
    class_name: Optional[str] = None
    method_name: Optional[str] = None
    evidence_location: Optional[str] = None
    associated_url: Optional[str] = None
    associated_domain: Optional[str] = None
    finding_id: Optional[str] = None
    extraction_timestamp: str = ""
    context_snippet: Optional[str] = None

class SourceReference(BaseModel):
    """Source attribution for every data point."""
    provider: str
    query_timestamp: str
    source_url: Optional[str] = None
    lookup_status: str = "SUCCESS" # SUCCESS, CACHED, SKIPPED_LOCAL_ONLY, FAILED
    confidence: str = "High"

class IPNetworkInfo(BaseModel):
    """[1] IP Network Information from authoritative RDAP / WHOIS."""
    net_range: Optional[str] = None
    cidr: Optional[str] = None
    net_name: Optional[str] = None
    net_handle: Optional[str] = None
    parent_handle: Optional[str] = None
    net_type: Optional[str] = None
    origin_as: Optional[str] = None
    rir: Optional[str] = None # ARIN, RIPE NCC, APNIC, LACNIC, AFRINIC
    registration_status: Optional[str] = None
    reg_date: Optional[str] = None
    updated_date: Optional[str] = None
    resource_link: Optional[str] = None
    referral_server: Optional[str] = None
    comment: Optional[str] = None

class IPOrganizationInfo(BaseModel):
    """[2] Organization & Official Contact Information."""
    organization: Optional[str] = None
    org_id: Optional[str] = None
    address: Optional[str] = None
    city: Optional[str] = None
    state_prov: Optional[str] = None
    postal_code: Optional[str] = None
    country: Optional[str] = None
    official_website: Optional[str] = None
    # Official Organizational & Abuse Contacts (No personal individual PII)
    tech_contact_name: Optional[str] = None
    tech_contact_email: Optional[str] = None
    tech_contact_phone: Optional[str] = None
    abuse_contact_name: Optional[str] = None
    abuse_contact_email: Optional[str] = None
    abuse_contact_phone: Optional[str] = None
    admin_contact_name: Optional[str] = None

class IPGeolocationInfo(BaseModel):
    """[3] Geolocation Intelligence with approximate location disclaimer."""
    country: Optional[str] = None
    country_code: Optional[str] = None
    region: Optional[str] = None
    state: Optional[str] = None
    city: Optional[str] = None
    postal_code: Optional[str] = None
    latitude: Optional[float] = None
    longitude: Optional[float] = None
    timezone: Optional[str] = None
    continent: Optional[str] = None
    confidence: str = "Approximate"
    data_source: Optional[str] = "BGP / Registry Allocation"
    disclaimer: str = "Notice: IP geolocation is approximate and reflects network routing/allocation. It does not identify the physical location of an individual, device, or premise."

class IPRoutingASNInfo(BaseModel):
    """[4] Network Owner and ASN Intelligence."""
    asn: Optional[str] = None
    asn_name: Optional[str] = None
    as_organization: Optional[str] = None
    origin_as: Optional[str] = None
    network_prefix: Optional[str] = None
    cidr: Optional[str] = None
    network_owner: Optional[str] = None
    isp: Optional[str] = None
    internet_transit_provider: Optional[str] = None
    upstream_provider: Optional[str] = None
    peering_info: Optional[str] = None
    bgp_routing_info: Optional[str] = None
    rir: Optional[str] = None

class IPHostingServerInfo(BaseModel):
    """[5] Hosting, Cloud, and Server Infrastructure Classification."""
    hosting_provider: Optional[str] = None
    cloud_provider: Optional[str] = None # AWS, Microsoft Azure, Google Cloud, Cloudflare, etc.
    datacenter: Optional[str] = None
    vps_provider: Optional[str] = None
    cdn_provider: Optional[str] = None
    server_classification: str = "Standard Network" # Cloud, CDN, Data Centre, Residential, Enterprise, Educational, Government
    classification_confidence: str = "Medium"
    evidence_basis: Optional[str] = None

class IPDomainDnsInfo(BaseModel):
    """[6] Domain and DNS Intelligence."""
    reverse_dns: Optional[str] = None # PTR record
    hostname: Optional[str] = None
    associated_domains: List[str] = Field(default_factory=list)
    associated_urls: List[str] = Field(default_factory=list)
    a_records: List[str] = Field(default_factory=list)
    aaaa_records: List[str] = Field(default_factory=list)
    cname_records: List[str] = Field(default_factory=list)
    mx_records: List[str] = Field(default_factory=list)
    ns_records: List[str] = Field(default_factory=list)
    txt_records: List[str] = Field(default_factory=list)
    dns_provider: Optional[str] = None
    resolution_timestamp: Optional[str] = None

class IPThreatReputationInfo(BaseModel):
    """[8] Multi-Engine Threat Intelligence and Reputation."""
    threat_status: str = "CLEAN" # MALICIOUS, SUSPICIOUS, CLEAN, UNKNOWN, NOT FOUND, LOOKUP FAILED
    malicious_count: int = 0
    suspicious_count: int = 0
    total_security_engines: int = 0
    abuse_confidence_score: Optional[int] = None
    threat_categories: List[str] = Field(default_factory=list)
    known_malware_associations: List[str] = Field(default_factory=list)
    known_botnet_associations: List[str] = Field(default_factory=list)
    scanner_activity: Optional[str] = None
    suspicious_network_behaviour: Optional[str] = None
    known_c2_associations: bool = False
    blacklist_status: str = "Not Listed"
    last_reported_date: Optional[str] = None
    first_seen_date: Optional[str] = None
    last_seen_date: Optional[str] = None
    provider_results: Dict[str, Any] = Field(default_factory=dict) # e.g. {"virustotal": ..., "abuseipdb": ...}

class IPClassificationInfo(BaseModel):
    """[10] VPN, Proxy, Tor, and Special Subnet Classification."""
    is_private: bool = False
    is_loopback: bool = False
    is_link_local: bool = False
    is_reserved: bool = False
    is_multicast: bool = False
    is_carrier_grade_nat: bool = False
    is_cloud: bool = False
    is_cdn: bool = False
    is_vpn: bool = False
    is_proxy: bool = False
    is_tor_exit_node: bool = False
    is_public_dns: bool = False
    classification_label: str = "Public IPv4"
    classification_confidence: str = "High"

class IPDetailRecord(BaseModel):
    """Complete individual IP report record."""
    id: str # unique identifier e.g. IP-8-8-8-8
    investigation_id: str
    ip_address: str
    ip_version: str # IPv4 or IPv6
    canonical_ip: str
    classification: IPClassificationInfo = Field(default_factory=IPClassificationInfo)
    network_info: IPNetworkInfo = Field(default_factory=IPNetworkInfo)
    organization_info: IPOrganizationInfo = Field(default_factory=IPOrganizationInfo)
    geolocation_info: IPGeolocationInfo = Field(default_factory=IPGeolocationInfo)
    routing_asn_info: IPRoutingASNInfo = Field(default_factory=IPRoutingASNInfo)
    hosting_server_info: IPHostingServerInfo = Field(default_factory=IPHostingServerInfo)
    domain_dns_info: IPDomainDnsInfo = Field(default_factory=IPDomainDnsInfo)
    threat_info: IPThreatReputationInfo = Field(default_factory=IPThreatReputationInfo)
    evidence_references: List[IPEvidenceReference] = Field(default_factory=list)
    source_references: List[SourceReference] = Field(default_factory=list)
    lookup_status: str = "PENDING" # ENRICHED, SKIPPED_LOCAL_ONLY, CACHED, OFFLINE_ONLY, FAILED
    lookup_timestamp: str = ""
    created_at_utc: str = ""

class InvestigationIPsSummary(BaseModel):
    """Aggregated summary of all IPs extracted for an investigation."""
    investigation_id: str
    total_unique_ips: int
    ipv4_count: int
    ipv6_count: int
    public_ip_count: int
    private_ip_count: int
    cloud_ip_count: int
    malicious_ip_count: int
    suspicious_ip_count: int
    clean_ip_count: int
    unknown_ip_count: int
    network_mode: str # LOCAL_ONLY or HYBRID
    extraction_timestamp_utc: str
    ips: List[IPDetailRecord] = Field(default_factory=list)
