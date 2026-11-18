"""
TraceX IP Intelligence Report Generator
Universal Digital Forensics & Cyber Investigation Suite v2.0.0

Generates dedicated, comprehensive, law-enforcement grade IP Intelligence Reports:
- Individual IP Report: PDF, HTML, TXT, JSON
- Complete Investigation IP Report: PDF, HTML, TXT, JSON
- Dedicated storage location: %USERPROFILE%\\Documents\\TraceX\\IP Reports\\<INV_ID>\\<SAFE_IP>\\
- Safe Windows filesystem naming for IPv4 and IPv6 addresses
- Native PyMuPDF vector PDF generation (zero headless browser dependency)
- Verification of on-disk existence and non-zero byte size before returning success
"""

import os
import re
import json
import uuid
import logging
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple

import fitz # PyMuPDF
from backend.app.models.ip_details import (
    IPDetailRecord,
    InvestigationIPsSummary
)

logger = logging.getLogger("tracex.ip_report_generator")

def get_ip_reports_root_dir() -> Path:
    """Returns %USERPROFILE%\\Documents\\TraceX\\IP Reports."""
    user_profile = os.environ.get("USERPROFILE") or str(Path.home())
    root = Path(user_profile) / "Documents" / "TraceX" / "IP Reports"
    root.mkdir(parents=True, exist_ok=True)
    return root.resolve()

def sanitize_ip_for_path(ip_str: str) -> str:
    """Replaces characters forbidden in Windows directories (e.g. ':' in IPv6)."""
    # Replace colons and invalid chars with underscores
    safe = re.sub(r'[:\\/*?"<>|]', '_', ip_str.strip())
    return safe or "unknown_ip"

def get_individual_ip_storage_dir(investigation_id: str, ip_str: str) -> Path:
    """
    Returns %USERPROFILE%\\Documents\\TraceX\\IP Reports\\<INV_ID>\\<SAFE_IP>\\
    """
    safe_inv = re.sub(r'[:\\/*?"<>|]', '_', investigation_id.strip())
    safe_ip = sanitize_ip_for_path(ip_str)
    target_dir = get_ip_reports_root_dir() / safe_inv / safe_ip
    target_dir.mkdir(parents=True, exist_ok=True)
    return target_dir.resolve()

def get_all_ips_storage_dir(investigation_id: str) -> Path:
    """
    Returns %USERPROFILE%\\Documents\\TraceX\\IP Reports\\<INV_ID>\\
    """
    safe_inv = re.sub(r'[:\\/*?"<>|]', '_', investigation_id.strip())
    target_dir = get_ip_reports_root_dir() / safe_inv
    target_dir.mkdir(parents=True, exist_ok=True)
    return target_dir.resolve()

# ==============================================================================
# TXT REPORT GENERATION
# ==============================================================================

def generate_individual_ip_txt(record: IPDetailRecord) -> str:
    """Generates standard WHOIS/RDAP plain text intelligence report."""
    nl = "\n"
    lines = [
        "=" * 60,
        "TRACEX – IP INTELLIGENCE REPORT",
        "=" * 60,
        f"IP Address           : {record.ip_address}",
        f"IP Version           : {record.ip_version}",
        f"Investigation ID     : {record.investigation_id}",
        f"Classification       : {record.classification.classification_label}",
        f"Lookup Status        : {record.lookup_status}",
        f"Timestamp UTC        : {record.lookup_timestamp or datetime.utcnow().isoformat() + 'Z'}",
        "=" * 60,
        "",
        "[1] IP NETWORK INFORMATION",
        "-" * 40,
        f"NetRange             : {record.network_info.net_range or 'Not Available'}",
        f"CIDR                 : {record.network_info.cidr or 'Not Available'}",
        f"NetName              : {record.network_info.net_name or 'Not Available'}",
        f"NetHandle            : {record.network_info.net_handle or 'Not Available'}",
        f"Parent               : {record.network_info.parent_handle or 'Not Available'}",
        f"NetType              : {record.network_info.net_type or 'Not Available'}",
        f"OriginAS             : {record.network_info.origin_as or record.routing_asn_info.asn or 'Not Available'}",
        f"RIR                  : {record.network_info.rir or 'Not Available'}",
        f"Registration Status  : {record.network_info.registration_status or 'Not Available'}",
        f"Comment              : {record.network_info.comment or 'None'}",
        "",
        "[2] ORGANIZATION INFORMATION",
        "-" * 40,
        f"Organization         : {record.organization_info.organization or 'Not Available'}",
        f"OrgId                : {record.organization_info.org_id or 'Not Available'}",
        f"Address              : {record.organization_info.address or 'Not Available'}",
        f"City                 : {record.organization_info.city or 'Not Available'}",
        f"State/Province       : {record.organization_info.state_prov or 'Not Available'}",
        f"Postal Code          : {record.organization_info.postal_code or 'Not Available'}",
        f"Country              : {record.organization_info.country or 'Not Available'}",
        f"Official Website     : {record.organization_info.official_website or 'Not Available'}",
        "",
        "[3] GEOLOCATION INFORMATION",
        "-" * 40,
        f"Country              : {record.geolocation_info.country or 'Not Available'} ({record.geolocation_info.country_code or 'N/A'})",
        f"Region / State       : {record.geolocation_info.region or record.geolocation_info.state or 'Not Available'}",
        f"City                 : {record.geolocation_info.city or 'Not Available'}",
        f"Coordinates          : {record.geolocation_info.latitude or 'N/A'}, {record.geolocation_info.longitude or 'N/A'}",
        f"Timezone             : {record.geolocation_info.timezone or 'Not Available'}",
        f"Data Source          : {record.geolocation_info.data_source or 'Registry / BGP'}",
        f"Confidence           : {record.geolocation_info.confidence}",
        f"Legal Disclaimer     : {record.geolocation_info.disclaimer}",
        "",
        "[4] NETWORK AND ASN INFORMATION",
        "-" * 40,
        f"ASN                  : {record.routing_asn_info.asn or 'Not Available'}",
        f"ASN Name             : {record.routing_asn_info.asn_name or 'Not Available'}",
        f"ASN Organization     : {record.routing_asn_info.as_organization or 'Not Available'}",
        f"ISP                  : {record.routing_asn_info.isp or 'Not Available'}",
        f"Network Owner        : {record.routing_asn_info.network_owner or 'Not Available'}",
        f"Network Prefix       : {record.routing_asn_info.network_prefix or 'Not Available'}",
        f"RIR                  : {record.routing_asn_info.rir or record.network_info.rir or 'Not Available'}",
        "",
        "[5] HOSTING AND SERVER INFORMATION",
        "-" * 40,
        f"Hosting Provider     : {record.hosting_server_info.hosting_provider or 'Standard Host / Non-Cloud'}",
        f"Cloud Provider       : {record.hosting_server_info.cloud_provider or 'None Detected'}",
        f"Data Centre          : {record.hosting_server_info.datacenter or 'Not Available'}",
        f"CDN Provider         : {record.hosting_server_info.cdn_provider or 'None'}",
        f"Classification       : {record.hosting_server_info.server_classification}",
        f"Evidence Basis       : {record.hosting_server_info.evidence_basis or 'Prefix & ASN Heuristics'}",
        "",
        "[6] DOMAIN AND DNS INFORMATION",
        "-" * 40,
        f"Reverse DNS (PTR)    : {record.domain_dns_info.reverse_dns or 'No PTR Record'}",
        f"Hostname             : {record.domain_dns_info.hostname or 'Not Available'}",
        f"Associated Domains   : {', '.join(record.domain_dns_info.associated_domains) if record.domain_dns_info.associated_domains else 'None'}",
        f"Associated URLs      : {', '.join(record.domain_dns_info.associated_urls) if record.domain_dns_info.associated_urls else 'None'}",
        "",
        "[7] CONTACT INFORMATION (ORGANIZATIONAL ONLY)",
        "-" * 40,
        f"Technical Contact    : {record.organization_info.tech_contact_name or 'Not Available'}",
        f"Technical Email      : {record.organization_info.tech_contact_email or 'Not Available'}",
        f"Technical Phone      : {record.organization_info.tech_contact_phone or 'Not Available'}",
        f"Abuse Contact        : {record.organization_info.abuse_contact_name or 'Not Available'}",
        f"Abuse Email          : {record.organization_info.abuse_contact_email or 'Not Available'}",
        f"Abuse Phone          : {record.organization_info.abuse_contact_phone or 'Not Available'}",
        "",
        "[8] THREAT INTELLIGENCE AND REPUTATION",
        "-" * 40,
        f"Threat Classification: {record.threat_info.threat_status}",
        f"Blacklist Status     : {record.threat_info.blacklist_status}",
        f"Malicious Detections : {record.threat_info.malicious_count} / {record.threat_info.total_security_engines or 72}",
        f"Suspicious Detections: {record.threat_info.suspicious_count}",
        f"Abuse Score          : {record.threat_info.abuse_confidence_score if record.threat_info.abuse_confidence_score is not None else 'N/A'}",
        "",
        "[9] EVIDENCE TRACEABILITY (ORIGIN IN APPLICATION)",
        "-" * 40
    ]

    if record.evidence_references:
        for idx, ref in enumerate(record.evidence_references, 1):
            lines.append(f"  Reference #{idx}:")
            lines.append(f"    Source File    : {ref.source_file}")
            if ref.class_name:
                lines.append(f"    Class Name     : {ref.class_name}")
            if ref.method_name:
                lines.append(f"    Method / Member: {ref.method_name}")
            if ref.evidence_location:
                lines.append(f"    Location       : {ref.evidence_location}")
            if ref.associated_url:
                lines.append(f"    Embedded URL   : {ref.associated_url}")
            if ref.context_snippet:
                lines.append(f"    Context Snippet: {ref.context_snippet.strip()}")
            lines.append("")
    else:
        lines.append("  No direct static code references recorded.")
        lines.append("")

    lines.extend([
        "[10] SOURCE REFERENCES & ATTRIBUTION",
        "-" * 40
    ])

    if record.source_references:
        for s in record.source_references:
            lines.append(f"  Provider       : {s.provider}")
            lines.append(f"  Timestamp      : {s.query_timestamp}")
            lines.append(f"  Lookup Status  : {s.lookup_status}")
            lines.append(f"  Confidence     : {s.confidence}")
            if s.source_url:
                lines.append(f"  Source URL     : {s.source_url}")
            lines.append("")
    else:
        lines.append("  Internal Forensic Heuristics & Local Configuration")
        lines.append("")

    lines.append("=" * 60)
    lines.append("END OF TRACEX IP INTELLIGENCE REPORT")
    lines.append("=" * 60)
    return nl.join(lines)

def generate_all_ips_txt(summary: InvestigationIPsSummary) -> str:
    """Generates complete plain-text intelligence dossier across all extracted IPs."""
    nl = "\n"
    lines = [
        "=" * 72,
        "TRACEX – COMPLETE INVESTIGATION IP INTELLIGENCE DOSSIER",
        "=" * 72,
        f"Investigation ID     : {summary.investigation_id}",
        f"Total Unique IPs     : {summary.total_unique_ips}",
        f"IPv4 Addresses       : {summary.ipv4_count}",
        f"IPv6 Addresses       : {summary.ipv6_count}",
        f"Public Routable IPs  : {summary.public_ip_count}",
        f"Private / RFC Subnets: {summary.private_ip_count}",
        f"Cloud Infrastructure : {summary.cloud_ip_count}",
        f"Threat Reputations   : {summary.malicious_ip_count} Malicious | {summary.suspicious_ip_count} Suspicious | {summary.clean_ip_count} Clean",
        f"Network Privacy Mode : {summary.network_mode}",
        f"Timestamp UTC        : {summary.extraction_timestamp_utc}",
        "=" * 72,
        ""
    ]

    for idx, ip_rec in enumerate(summary.ips, 1):
        lines.append(f"--- IP RECORD {idx}/{summary.total_unique_ips}: {ip_rec.ip_address} ---")
        lines.append(generate_individual_ip_txt(ip_rec))
        lines.append("\n" + "=" * 72 + "\n")

    return nl.join(lines)

# ==============================================================================
# HTML REPORT GENERATION
# ==============================================================================

def generate_individual_ip_html(record: IPDetailRecord) -> str:
    """Generates clean, responsive, dark-mode ready HTML IP Intelligence report."""
    # Badge colors
    status_bg = "#10b981" if record.threat_info.threat_status == "CLEAN" else ("#ef4444" if record.threat_info.threat_status == "MALICIOUS" else "#f59e0b")

    evidence_rows = ""
    for idx, ref in enumerate(record.evidence_references, 1):
        evidence_rows += f"""
        <tr>
            <td style="padding: 8px 12px; border: 1px solid #334155; font-family: monospace;">#{idx}</td>
            <td style="padding: 8px 12px; border: 1px solid #334155; font-family: monospace;">{ref.source_file}</td>
            <td style="padding: 8px 12px; border: 1px solid #334155; font-family: monospace;">{ref.class_name or ref.method_name or 'N/A'}</td>
            <td style="padding: 8px 12px; border: 1px solid #334155; font-size: 11px;">{ref.associated_url or ref.context_snippet or 'Static String'}</td>
        </tr>
        """

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>TraceX IP Intelligence Report - {record.ip_address}</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background-color: #0b0f19; color: #f1f5f9; margin: 0; padding: 24px; line-height: 1.5; }}
        .container {{ max-width: 960px; margin: 0 auto; }}
        .header {{ border-bottom: 2px solid #06b6d4; padding-bottom: 16px; margin-bottom: 24px; display: flex; justify-content: space-between; align-items: flex-start; }}
        .title {{ font-size: 24px; font-weight: bold; color: #38bdf8; margin: 0; }}
        .subtitle {{ font-size: 13px; color: #94a3b8; margin-top: 4px; font-family: monospace; }}
        .badge {{ display: inline-block; padding: 4px 10px; border-radius: 6px; font-size: 12px; font-weight: bold; color: #ffffff; background-color: {status_bg}; }}
        .card {{ background-color: #111827; border: 1px solid #1e293b; border-radius: 12px; padding: 20px; margin-bottom: 20px; }}
        .card-title {{ font-size: 14px; font-weight: bold; color: #06b6d4; text-transform: uppercase; letter-spacing: 0.05em; margin-bottom: 14px; border-bottom: 1px solid #1e293b; padding-bottom: 8px; }}
        .grid {{ display: grid; grid-template-columns: repeat(2, 1fr); gap: 12px 24px; font-size: 13px; }}
        .field-label {{ color: #64748b; font-family: monospace; font-size: 11px; text-transform: uppercase; }}
        .field-value {{ color: #e2e8f0; font-family: monospace; font-weight: 500; word-break: break-all; margin-top: 2px; }}
        .disclaimer {{ background-color: #1e1b4b; border-left: 4px solid #6366f1; padding: 12px; border-radius: 4px; font-size: 11px; color: #c7d2fe; margin-top: 14px; }}
        table {{ width: 100%; border-collapse: collapse; margin-top: 8px; font-size: 12px; }}
        th {{ background-color: #1e293b; color: #94a3b8; text-align: left; padding: 8px 12px; border: 1px solid #334155; font-size: 11px; text-transform: uppercase; }}
        @media print {{ body {{ background: #fff; color: #000; }} .card {{ border: 1px solid #ccc; background: #fff; }} .field-value {{ color: #000; }} }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <div>
                <h1 class="title">TRACEX IP INTELLIGENCE REPORT</h1>
                <div class="subtitle">IP: {record.ip_address} ({record.ip_version}) • Investigation: {record.investigation_id}</div>
            </div>
            <div>
                <span class="badge">{record.threat_info.threat_status}</span>
            </div>
        </div>

        <!-- [1] Network Information -->
        <div class="card">
            <div class="card-title">[1] IP Network Information (Authoritative RDAP)</div>
            <div class="grid">
                <div><div class="field-label">NetRange</div><div class="field-value">{record.network_info.net_range or 'Not Available'}</div></div>
                <div><div class="field-label">CIDR</div><div class="field-value">{record.network_info.cidr or 'Not Available'}</div></div>
                <div><div class="field-label">NetName</div><div class="field-value">{record.network_info.net_name or 'Not Available'}</div></div>
                <div><div class="field-label">NetHandle</div><div class="field-value">{record.network_info.net_handle or 'Not Available'}</div></div>
                <div><div class="field-label">Origin AS</div><div class="field-value">{record.network_info.origin_as or record.routing_asn_info.asn or 'Not Available'}</div></div>
                <div><div class="field-label">Registry (RIR)</div><div class="field-value">{record.network_info.rir or 'Not Available'}</div></div>
            </div>
        </div>

        <!-- [2] Organization & Location -->
        <div class="card">
            <div class="card-title">[2] Organization & Geolocation Intelligence</div>
            <div class="grid">
                <div><div class="field-label">Organization</div><div class="field-value">{record.organization_info.organization or 'Not Available'}</div></div>
                <div><div class="field-label">Country</div><div class="field-value">{record.geolocation_info.country or 'Not Available'} ({record.geolocation_info.country_code or 'N/A'})</div></div>
                <div><div class="field-label">Region / City</div><div class="field-value">{record.geolocation_info.region or 'N/A'}, {record.geolocation_info.city or 'N/A'}</div></div>
                <div><div class="field-label">Coordinates</div><div class="field-value">{record.geolocation_info.latitude or 'N/A'}, {record.geolocation_info.longitude or 'N/A'}</div></div>
                <div><div class="field-label">ISP / Transit</div><div class="field-value">{record.routing_asn_info.isp or 'Not Available'}</div></div>
                <div><div class="field-label">Timezone</div><div class="field-value">{record.geolocation_info.timezone or 'Not Available'}</div></div>
            </div>
            <div class="disclaimer">
                {record.geolocation_info.disclaimer}
            </div>
        </div>

        <!-- [3] Hosting & Infrastructure -->
        <div class="card">
            <div class="card-title">[3] Infrastructure & Classification</div>
            <div class="grid">
                <div><div class="field-label">Cloud Provider</div><div class="field-value">{record.hosting_server_info.cloud_provider or 'None Detected'}</div></div>
                <div><div class="field-label">Classification</div><div class="field-value">{record.hosting_server_info.server_classification}</div></div>
                <div><div class="field-label">Reverse DNS (PTR)</div><div class="field-value">{record.domain_dns_info.reverse_dns or 'No PTR Record'}</div></div>
                <div><div class="field-label">Network Type</div><div class="field-value">{record.classification.classification_label}</div></div>
            </div>
        </div>

        <!-- [4] Contact Information -->
        <div class="card">
            <div class="card-title">[4] Official Contacts (Organizational & Abuse)</div>
            <div class="grid">
                <div><div class="field-label">Abuse Contact Email</div><div class="field-value">{record.organization_info.abuse_contact_email or 'Not Available'}</div></div>
                <div><div class="field-label">Abuse Phone</div><div class="field-value">{record.organization_info.abuse_contact_phone or 'Not Available'}</div></div>
                <div><div class="field-label">Technical Contact Email</div><div class="field-value">{record.organization_info.tech_contact_email or 'Not Available'}</div></div>
                <div><div class="field-label">Technical Phone</div><div class="field-value">{record.organization_info.tech_contact_phone or 'Not Available'}</div></div>
            </div>
        </div>

        <!-- [5] Threat Intelligence -->
        <div class="card">
            <div class="card-title">[5] Threat Intelligence & Reputation</div>
            <div class="grid">
                <div><div class="field-label">Threat Classification</div><div class="field-value">{record.threat_info.threat_status}</div></div>
                <div><div class="field-label">Blacklist Status</div><div class="field-value">{record.threat_info.blacklist_status}</div></div>
                <div><div class="field-label">Security Engines</div><div class="field-value">{record.threat_info.malicious_count} flagged malicious</div></div>
                <div><div class="field-label">Lookup Status</div><div class="field-value">{record.lookup_status}</div></div>
            </div>
        </div>

        <!-- [6] Evidence Traceability -->
        <div class="card">
            <div class="card-title">[6] Evidence Traceability ({len(record.evidence_references)} static reference(s) in APK)</div>
            <table>
                <thead>
                    <tr><th>#</th><th>Source File</th><th>Class / Method</th><th>Details</th></tr>
                </thead>
                <tbody>
                    {evidence_rows if evidence_rows else '<tr><td colspan="4" style="padding: 12px; text-align: center; color: #64748b;">No direct code references found.</td></tr>'}
                </tbody>
            </table>
        </div>
    </div>
</body>
</html>
"""
    return html

def generate_all_ips_html(summary: InvestigationIPsSummary) -> str:
    """Generates complete aggregated HTML IP report across all discovered IPs."""
    ip_cards = ""
    for rec in summary.ips:
        ip_cards += f"""
        <div style="background-color: #111827; border: 1px solid #1e293b; border-radius: 12px; padding: 18px; margin-bottom: 16px;">
            <div style="display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid #1e293b; padding-bottom: 10px; margin-bottom: 12px;">
                <div>
                    <span style="font-size: 16px; font-weight: bold; font-family: monospace; color: #38bdf8;">{rec.ip_address}</span>
                    <span style="font-size: 11px; margin-left: 8px; color: #94a3b8; font-family: monospace;">{rec.ip_version}</span>
                </div>
                <span style="padding: 3px 8px; border-radius: 4px; font-size: 11px; font-weight: bold; background-color: {'#10b981' if rec.threat_info.threat_status == 'CLEAN' else '#ef4444'}; color: #fff;">{rec.threat_info.threat_status}</span>
            </div>
            <div style="display: grid; grid-template-columns: repeat(3, 1fr); gap: 10px; font-size: 12px; font-family: monospace;">
                <div><span style="color: #64748b;">Org:</span> {rec.organization_info.organization or 'N/A'}</div>
                <div><span style="color: #64748b;">Country:</span> {rec.geolocation_info.country or 'N/A'}</div>
                <div><span style="color: #64748b;">ASN:</span> {rec.routing_asn_info.asn or 'N/A'}</div>
                <div><span style="color: #64748b;">PTR:</span> {rec.domain_dns_info.reverse_dns or 'None'}</div>
                <div><span style="color: #64748b;">Cloud:</span> {rec.hosting_server_info.cloud_provider or 'None'}</div>
                <div><span style="color: #64748b;">References:</span> {len(rec.evidence_references)} location(s) in APK</div>
            </div>
        </div>
        """

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>TraceX Investigation IP Dossier - {summary.investigation_id}</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background-color: #0b0f19; color: #f1f5f9; margin: 0; padding: 24px; }}
        .container {{ max-width: 1040px; margin: 0 auto; }}
        .header {{ border-bottom: 2px solid #06b6d4; padding-bottom: 16px; margin-bottom: 24px; }}
        .title {{ font-size: 26px; font-weight: bold; color: #38bdf8; margin: 0; }}
        .stats-grid {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 12px; margin-bottom: 24px; }}
        .stat-card {{ background-color: #111827; border: 1px solid #1e293b; border-radius: 8px; padding: 12px; text-align: center; }}
        .stat-val {{ font-size: 20px; font-weight: bold; color: #38bdf8; font-family: monospace; }}
        .stat-lbl {{ font-size: 11px; color: #94a3b8; text-transform: uppercase; margin-top: 4px; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1 class="title">COMPLETE INVESTIGATION IP DOSSIER</h1>
            <div style="font-family: monospace; font-size: 13px; color: #94a3b8; margin-top: 4px;">
                Investigation: {summary.investigation_id} • Total Unique IPs Discovered: {summary.total_unique_ips} • Mode: {summary.network_mode}
            </div>
        </div>

        <div class="stats-grid">
            <div class="stat-card"><div class="stat-val">{summary.total_unique_ips}</div><div class="stat-lbl">Total IPs</div></div>
            <div class="stat-card"><div class="stat-val">{summary.public_ip_count}</div><div class="stat-lbl">Public Routable</div></div>
            <div class="stat-card"><div class="stat-val">{summary.private_ip_count}</div><div class="stat-lbl">Private / Local</div></div>
            <div class="stat-card"><div class="stat-val">{summary.cloud_ip_count}</div><div class="stat-lbl">Cloud Hosted</div></div>
        </div>

        {ip_cards if ip_cards else '<div style="text-align: center; padding: 40px; color: #64748b;">No external or local IP addresses extracted during analysis.</div>'}
    </div>
</body>
</html>
"""
    return html

# ==============================================================================
# PDF REPORT GENERATION (NATIVE PYMUPDF)
# ==============================================================================

def generate_individual_ip_pdf(record: IPDetailRecord) -> bytes:
    """Generates crisp multi-page vector PDF report using native PyMuPDF."""
    doc = fitz.open()
    page = doc.new_page(width=595, height=842) # Standard A4 (595 x 842 pt)

    # Margins
    margin_x = 40
    current_y = 45

    def check_page_break(needed_pt: float):
        nonlocal page, current_y
        if current_y + needed_pt > 780:
            # Draw running footer on current page
            page.draw_line(fitz.Point(margin_x, 790), fitz.Point(555, 790), color=(0.7, 0.7, 0.7), width=0.5)
            page.insert_text(fitz.Point(margin_x, 805), f"TraceX IP Intelligence Report • IP: {record.ip_address}", fontsize=8, color=(0.5, 0.5, 0.5))
            page.insert_text(fitz.Point(480, 805), f"Page {len(doc)}", fontsize=8, color=(0.5, 0.5, 0.5))

            page = doc.new_page(width=595, height=842)
            current_y = 50

    # Top Banner Header
    page.draw_rect(fitz.Rect(margin_x, current_y, 555, current_y + 40), color=None, fill=(0.04, 0.08, 0.15))
    page.insert_text(fitz.Point(margin_x + 10, current_y + 24), "TRACEX – IP INTELLIGENCE REPORT", fontsize=13, fontname="helv", color=(0.2, 0.8, 0.95))
    current_y += 50

    # Summary Metadata Box
    page.draw_rect(fitz.Rect(margin_x, current_y, 555, current_y + 70), color=(0.8, 0.85, 0.9), fill=(0.96, 0.98, 1.0), width=0.8)
    page.insert_text(fitz.Point(margin_x + 12, current_y + 18), f"IP Address : {record.ip_address} ({record.ip_version})", fontsize=10, fontname="helv", color=(0.05, 0.15, 0.3))
    page.insert_text(fitz.Point(margin_x + 12, current_y + 34), f"Network    : {record.classification.classification_label}", fontsize=9, fontname="helv", color=(0.2, 0.25, 0.35))
    page.insert_text(fitz.Point(margin_x + 12, current_y + 50), f"Case ID    : {record.investigation_id}", fontsize=9, fontname="helv", color=(0.2, 0.25, 0.35))
    page.insert_text(fitz.Point(340, current_y + 18), f"Threat Status : {record.threat_info.threat_status}", fontsize=10, fontname="helv", color=(0.1, 0.6, 0.3) if record.threat_info.threat_status == "CLEAN" else (0.8, 0.1, 0.1))
    page.insert_text(fitz.Point(340, current_y + 34), f"Lookup Status : {record.lookup_status}", fontsize=9, fontname="helv", color=(0.2, 0.25, 0.35))
    page.insert_text(fitz.Point(340, current_y + 50), f"Timestamp UTC : {record.lookup_timestamp[:19] if record.lookup_timestamp else 'N/A'}", fontsize=8, fontname="helv", color=(0.4, 0.4, 0.4))
    current_y += 85

    def draw_section_header(title: str):
        nonlocal current_y
        check_page_break(40)
        page.draw_rect(fitz.Rect(margin_x, current_y, 555, current_y + 20), color=None, fill=(0.92, 0.95, 0.98))
        page.draw_line(fitz.Point(margin_x, current_y + 20), fitz.Point(555, current_y + 20), color=(0.15, 0.6, 0.8), width=1.5)
        page.insert_text(fitz.Point(margin_x + 8, current_y + 14), title, fontsize=9, fontname="helv", color=(0.05, 0.2, 0.4))
        current_y += 28

    def draw_key_value_grid(items: List[Tuple[str, str]]):
        nonlocal current_y
        for label, val in items:
            check_page_break(18)
            page.insert_text(fitz.Point(margin_x + 6, current_y), f"{label}:", fontsize=8.5, fontname="helv", color=(0.4, 0.45, 0.5))
            page.insert_text(fitz.Point(margin_x + 140, current_y), str(val or 'Not Available')[:75], fontsize=8.5, fontname="courier", color=(0.1, 0.15, 0.2))
            current_y += 14
        current_y += 6

    # 1. Network Information
    draw_section_header("1. AUTHORITATIVE NETWORK REGISTRY (RDAP / WHOIS)")
    draw_key_value_grid([
        ("NetRange", record.network_info.net_range),
        ("CIDR Subnet", record.network_info.cidr),
        ("NetName", record.network_info.net_name),
        ("NetHandle", record.network_info.net_handle),
        ("Parent Handle", record.network_info.parent_handle),
        ("Origin AS", record.network_info.origin_as or record.routing_asn_info.asn),
        ("Registry (RIR)", record.network_info.rir),
        ("Registration Status", record.network_info.registration_status),
    ])

    # 2. Organization & Location
    draw_section_header("2. ORGANIZATION & GEOLOCATION INTELLIGENCE")
    draw_key_value_grid([
        ("Organization", record.organization_info.organization),
        ("Country / Code", f"{record.geolocation_info.country or 'N/A'} ({record.geolocation_info.country_code or 'N/A'})"),
        ("Region / City", f"{record.geolocation_info.region or 'N/A'}, {record.geolocation_info.city or 'N/A'}"),
        ("Coordinates", f"{record.geolocation_info.latitude or 'N/A'}, {record.geolocation_info.longitude or 'N/A'}"),
        ("Timezone", record.geolocation_info.timezone),
        ("ISP / Transit", record.routing_asn_info.isp),
    ])

    # Disclaimer note
    check_page_break(25)
    page.draw_rect(fitz.Rect(margin_x, current_y, 555, current_y + 20), color=None, fill=(0.96, 0.96, 0.98))
    page.insert_text(fitz.Point(margin_x + 6, current_y + 13), record.geolocation_info.disclaimer[:98], fontsize=7, fontname="helv", color=(0.4, 0.4, 0.55))
    current_y += 28

    # 3. Server & Infrastructure
    draw_section_header("3. SERVER & CLOUD HOSTING INFRASTRUCTURE")
    draw_key_value_grid([
        ("Cloud Provider", record.hosting_server_info.cloud_provider),
        ("Server Classification", record.hosting_server_info.server_classification),
        ("Reverse DNS (PTR)", record.domain_dns_info.reverse_dns),
        ("Network Classification", record.classification.classification_label),
    ])

    # 4. Official Contacts
    draw_section_header("4. OFFICIAL REGISTRY CONTACTS")
    draw_key_value_grid([
        ("Abuse Email", record.organization_info.abuse_contact_email),
        ("Abuse Phone", record.organization_info.abuse_contact_phone),
        ("Tech Email", record.organization_info.tech_contact_email),
        ("Tech Phone", record.organization_info.tech_contact_phone),
    ])

    # 5. Evidence Traceability
    draw_section_header(f"5. EVIDENCE TRACEABILITY IN APK ({len(record.evidence_references)} REFERENCE(S))")
    for idx, ref in enumerate(record.evidence_references[:10], 1):
        check_page_break(32)
        page.insert_text(fitz.Point(margin_x + 6, current_y), f"#{idx} Source : {ref.source_file}", fontsize=8, fontname="helv", color=(0.05, 0.25, 0.45))
        current_y += 11
        detail_loc = ref.class_name or ref.method_name or ref.associated_url or "Embedded String"
        page.insert_text(fitz.Point(margin_x + 20, current_y), f"Ref   : {detail_loc[:80]}", fontsize=7.5, fontname="courier", color=(0.3, 0.35, 0.4))
        current_y += 14

    # Final Footer
    page.draw_line(fitz.Point(margin_x, 790), fitz.Point(555, 790), color=(0.7, 0.7, 0.7), width=0.5)
    page.insert_text(fitz.Point(margin_x, 805), f"TraceX IP Intelligence Report • IP: {record.ip_address} • Case: {record.investigation_id}", fontsize=8, color=(0.5, 0.5, 0.5))
    page.insert_text(fitz.Point(480, 805), f"Page {len(doc)} of {len(doc)}", fontsize=8, color=(0.5, 0.5, 0.5))

    pdf_bytes = doc.tobytes()
    doc.close()
    return pdf_bytes

def generate_all_ips_pdf(summary: InvestigationIPsSummary) -> bytes:
    """Generates complete aggregated PDF dossier for all IPs in the investigation."""
    doc = fitz.open()

    # Cover / Overview Page
    page = doc.new_page(width=595, height=842)
    margin_x = 40
    current_y = 50

    # Title box
    page.draw_rect(fitz.Rect(margin_x, current_y, 555, current_y + 50), color=None, fill=(0.04, 0.08, 0.15))
    page.insert_text(fitz.Point(margin_x + 12, current_y + 25), "TRACEX – INVESTIGATION IP DOSSIER", fontsize=14, fontname="helv", color=(0.2, 0.8, 0.95))
    page.insert_text(fitz.Point(margin_x + 12, current_y + 40), f"Case Reference: {summary.investigation_id} • Discovered IPs: {summary.total_unique_ips}", fontsize=9, fontname="helv", color=(0.7, 0.8, 0.9))
    current_y += 65

    # Summary Stats
    page.draw_rect(fitz.Rect(margin_x, current_y, 555, current_y + 60), color=(0.8, 0.85, 0.9), fill=(0.97, 0.98, 1.0), width=0.8)
    page.insert_text(fitz.Point(margin_x + 14, current_y + 20), f"Total Extracted IPs  : {summary.total_unique_ips}", fontsize=9.5, fontname="helv", color=(0.1, 0.2, 0.35))
    page.insert_text(fitz.Point(margin_x + 14, current_y + 36), f"IPv4 / IPv6 Breakdown: {summary.ipv4_count} IPv4, {summary.ipv6_count} IPv6", fontsize=9, fontname="helv", color=(0.3, 0.35, 0.45))
    page.insert_text(fitz.Point(margin_x + 14, current_y + 50), f"Network Routing Scope: {summary.public_ip_count} Public Routable, {summary.private_ip_count} Private/Local", fontsize=9, fontname="helv", color=(0.3, 0.35, 0.45))
    page.insert_text(fitz.Point(340, current_y + 20), f"Network Privacy Mode : {summary.network_mode}", fontsize=9.5, fontname="helv", color=(0.1, 0.5, 0.6))
    page.insert_text(fitz.Point(340, current_y + 36), f"Threat Classifications: {summary.clean_ip_count} Clean, {summary.suspicious_ip_count} Suspicious", fontsize=9, fontname="helv", color=(0.3, 0.35, 0.45))
    current_y += 75

    # IP Inventory Table
    page.draw_rect(fitz.Rect(margin_x, current_y, 555, current_y + 20), color=None, fill=(0.15, 0.25, 0.35))
    page.insert_text(fitz.Point(margin_x + 8, current_y + 14), "DISCOVERED IP ADDRESS INVENTORY", fontsize=9, fontname="helv", color=(1.0, 1.0, 1.0))
    current_y += 24

    for rec in summary.ips:
        if current_y > 780:
            page = doc.new_page(width=595, height=842)
            current_y = 50

        page.draw_rect(fitz.Rect(margin_x, current_y, 555, current_y + 28), color=(0.85, 0.88, 0.92), fill=(0.98, 0.99, 1.0), width=0.5)
        page.insert_text(fitz.Point(margin_x + 6, current_y + 12), f"{rec.ip_address} ({rec.ip_version})", fontsize=8.5, fontname="courier", color=(0.05, 0.2, 0.4))
        page.insert_text(fitz.Point(margin_x + 200, current_y + 12), f"Org: {(rec.organization_info.organization or 'N/A')[:35]}", fontsize=7.5, fontname="helv", color=(0.2, 0.25, 0.3))
        page.insert_text(fitz.Point(margin_x + 440, current_y + 12), f"Status: {rec.threat_info.threat_status}", fontsize=8, fontname="helv", color=(0.1, 0.6, 0.3) if rec.threat_info.threat_status == "CLEAN" else (0.8, 0.1, 0.1))

        sub_info = f"Geo: {rec.geolocation_info.country or 'N/A'} • ASN: {rec.routing_asn_info.asn or 'N/A'} • Cloud: {rec.hosting_server_info.cloud_provider or 'None'} • References: {len(rec.evidence_references)}"
        page.insert_text(fitz.Point(margin_x + 6, current_y + 24), sub_info, fontsize=7, fontname="helv", color=(0.4, 0.45, 0.5))
        current_y += 32

    # Running footers across all pages
    for p_no in range(len(doc)):
        p = doc[p_no]
        p.draw_line(fitz.Point(margin_x, 790), fitz.Point(555, 790), color=(0.7, 0.7, 0.7), width=0.5)
        p.insert_text(fitz.Point(margin_x, 805), f"TraceX Complete IP Dossier • Case: {summary.investigation_id}", fontsize=8, color=(0.5, 0.5, 0.5))
        p.insert_text(fitz.Point(480, 805), f"Page {p_no + 1} of {len(doc)}", fontsize=8, color=(0.5, 0.5, 0.5))

    pdf_bytes = doc.tobytes()
    doc.close()
    return pdf_bytes

# ==============================================================================
# DISK EXPORT & VERIFICATION MANAGER
# ==============================================================================

def export_individual_ip_report_to_disk(
    record: IPDetailRecord,
    format_type: str,
    overwrite: bool = True
) -> Dict[str, Any]:
    """
    Saves individual IP report to:
    %USERPROFILE%\\Documents\\TraceX\\IP Reports\\<INV_ID>\\<SAFE_IP>\\
    Verifies existence and size > 0 on disk.
    """
    request_id = f"IPEXP-{uuid.uuid4().hex[:8].upper()}"
    norm_format = format_type.strip().lower()
    target_dir = get_individual_ip_storage_dir(record.investigation_id, record.ip_address)
    safe_ip = sanitize_ip_for_path(record.ip_address)

    base_name = f"IP_Intelligence_Report_{safe_ip}.{norm_format}"
    dest_path = target_dir / base_name

    try:
        content_bytes: bytes = b""

        if norm_format == "pdf":
            content_bytes = generate_individual_ip_pdf(record)
        elif norm_format == "html":
            content_bytes = generate_individual_ip_html(record).encode("utf-8")
        elif norm_format == "txt":
            content_bytes = generate_individual_ip_txt(record).encode("utf-8")
        elif norm_format == "json":
            content_bytes = record.model_dump_json(indent=2).encode("utf-8")
        else:
            raise ValueError(f"Unsupported IP report format: {format_type}")

        # Atomic write
        temp_dest = dest_path.with_suffix(dest_path.suffix + f".tmp_{uuid.uuid4().hex[:6]}")
        with open(temp_dest, "wb") as f:
            f.write(content_bytes)
            f.flush()
            os.fsync(f.fileno())

        if dest_path.exists() and overwrite:
            dest_path.unlink()
        temp_dest.replace(dest_path)

    except Exception as e:
        logger.error(f"[{request_id}] Failed writing IP report for {record.ip_address}: {e}")
        return {
            "status": "failed",
            "request_id": request_id,
            "ip_address": record.ip_address,
            "error": str(e)
        }

    # Strict filesystem verification
    if not dest_path.exists() or dest_path.stat().st_size <= 0:
        return {
            "status": "failed",
            "request_id": request_id,
            "ip_address": record.ip_address,
            "error": "Filesystem verification failed: Report file does not exist or has 0 bytes."
        }

    file_size = dest_path.stat().st_size
    formatted_size = f"{file_size / 1024:.1f} KB" if file_size >= 1024 else f"{file_size} B"

    logger.info(f"[{request_id}] Successfully exported IP report: {dest_path} ({file_size} bytes)")

    return {
        "status": "success",
        "request_id": request_id,
        "investigation_id": record.investigation_id,
        "ip_address": record.ip_address,
        "format": norm_format,
        "filename": dest_path.name,
        "filepath": str(dest_path.resolve()),
        "directory": str(target_dir.resolve()),
        "file_size": file_size,
        "file_size_formatted": formatted_size,
        "created_at": datetime.utcnow().isoformat() + "Z"
    }

def export_all_ips_report_to_disk(
    summary: InvestigationIPsSummary,
    format_type: str,
    overwrite: bool = True
) -> Dict[str, Any]:
    """
    Saves complete investigation IP dossier to:
    %USERPROFILE%\\Documents\\TraceX\\IP Reports\\<INV_ID>\\
    Verifies existence and size > 0 on disk.
    """
    request_id = f"ALLIP-{uuid.uuid4().hex[:8].upper()}"
    norm_format = format_type.strip().lower()
    target_dir = get_all_ips_storage_dir(summary.investigation_id)

    safe_inv = re.sub(r'[:\\/*?"<>|]', '_', summary.investigation_id.strip())
    base_name = f"All_IPs_Intelligence_Dossier_{safe_inv}.{norm_format}"
    dest_path = target_dir / base_name

    try:
        content_bytes: bytes = b""

        if norm_format == "pdf":
            content_bytes = generate_all_ips_pdf(summary)
        elif norm_format == "html":
            content_bytes = generate_all_ips_html(summary).encode("utf-8")
        elif norm_format == "txt":
            content_bytes = generate_all_ips_txt(summary).encode("utf-8")
        elif norm_format == "json":
            content_bytes = summary.model_dump_json(indent=2).encode("utf-8")
        else:
            raise ValueError(f"Unsupported dossier format: {format_type}")

        temp_dest = dest_path.with_suffix(dest_path.suffix + f".tmp_{uuid.uuid4().hex[:6]}")
        with open(temp_dest, "wb") as f:
            f.write(content_bytes)
            f.flush()
            os.fsync(f.fileno())

        if dest_path.exists() and overwrite:
            dest_path.unlink()
        temp_dest.replace(dest_path)

    except Exception as e:
        logger.error(f"[{request_id}] Failed writing all-IP dossier: {e}")
        return {
            "status": "failed",
            "request_id": request_id,
            "error": str(e)
        }

    if not dest_path.exists() or dest_path.stat().st_size <= 0:
        return {
            "status": "failed",
            "request_id": request_id,
            "error": "Filesystem verification failed: Dossier does not exist or has 0 bytes."
        }

    file_size = dest_path.stat().st_size
    formatted_size = f"{file_size / 1024:.1f} KB" if file_size >= 1024 else f"{file_size} B"

    logger.info(f"[{request_id}] Successfully exported all-IP dossier: {dest_path} ({file_size} bytes)")

    return {
        "status": "success",
        "request_id": request_id,
        "investigation_id": summary.investigation_id,
        "format": norm_format,
        "filename": dest_path.name,
        "filepath": str(dest_path.resolve()),
        "directory": str(target_dir.resolve()),
        "file_size": file_size,
        "file_size_formatted": formatted_size,
        "created_at": datetime.utcnow().isoformat() + "Z"
    }

def list_saved_reports_for_ip(investigation_id: str, ip_str: str) -> List[Dict[str, Any]]:
    """Lists verified report files for an IP in Documents\\TraceX\\IP Reports\\<INV>\\<SAFE_IP>\\."""
    target_dir = get_individual_ip_storage_dir(investigation_id, ip_str)
    if not target_dir.exists():
        return []

    reports = []
    for item in target_dir.iterdir():
        if item.is_file() and not item.name.endswith(".tmp"):
            try:
                st = item.stat()
                if st.st_size > 0:
                    reports.append({
                        "filename": item.name,
                        "filepath": str(item.resolve()),
                        "directory": str(target_dir.resolve()),
                        "file_size": st.st_size,
                        "file_size_formatted": f"{st.st_size / 1024:.1f} KB" if st.st_size >= 1024 else f"{st.st_size} B",
                        "format": item.suffix.lstrip(".").lower(),
                        "modified_at": datetime.fromtimestamp(st.st_mtime).isoformat() + "Z"
                    })
            except Exception:
                pass
    reports.sort(key=lambda x: x.get("modified_at", ""), reverse=True)
    return reports
