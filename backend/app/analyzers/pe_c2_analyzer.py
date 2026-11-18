import re
from typing import List, Dict, Any, Optional
from urllib.parse import urlparse
from backend.app.core.models import C2Indicator

SUSPICIOUS_TLDS = {".ru", ".cn", ".cc", ".top", ".xyz", ".club", ".tk", ".pw", ".onion", ".biz"}
KNOWN_BENIGN_DOMAINS = {
    "microsoft.com", "windows.com", "google.com", "github.com",
    "digicert.com", "verisign.com", "sectigo.com", "w3.org", "schema.org"
}
DYNAMIC_DNS_DOMAINS = ["duckdns.org", "no-ip.com", "ngrok.io", "serveo.net", "ddns.net", "hopto.org"]

def is_potential_dga(domain: str) -> bool:
    """Heuristic test for algorithmic domain names (high consonant/number ratios or randomness)."""
    parts = domain.split('.')
    if len(parts) < 2:
        return False
    sld = parts[0].lower()
    if len(sld) >= 12:
        consonants = len(re.findall(r'[bcdfghjklmnpqrstvwxyz0-9]', sld))
        ratio = consonants / len(sld)
        if ratio > 0.85:
            return True
    return False

def analyze_pe_c2_infrastructure(
    urls: List[Dict[str, Any]],
    ips: List[Dict[str, Any]],
    domains: List[Dict[str, Any]],
    decoded_items: List[Dict[str, Any]],
    imported_apis: List[str]
) -> List[C2Indicator]:
    """
    Reconstruct and classify potential C2 destinations from PE strings,
    decoded artifacts, and correlate with imported network APIs.
    """
    indicators: List[C2Indicator] = []
    seen_values = set()
    counter = 1

    has_network_apis = any(api in imported_apis for api in [
        "InternetOpenUrlA", "InternetOpenUrlW", "InternetConnectA", "InternetConnectW",
        "WinHttpSendRequest", "connect", "send", "WSAStartup", "URLDownloadToFileA", "URLDownloadToFileW"
    ])

    # 1. Evaluate URLs
    for u in urls:
        raw_url = u["url"]
        if raw_url in seen_values:
            continue
        seen_values.add(raw_url)

        try:
            parsed = urlparse(raw_url)
            host = parsed.hostname or ""
            port = parsed.port or (443 if parsed.scheme == "https" else 80)
            proto = parsed.scheme
        except Exception:
            host, port, proto = "", None, "http"

        is_ddns = any(ddns in host.lower() for ddns in DYNAMIC_DNS_DOMAINS)
        is_benign = any(b in host.lower() for b in KNOWN_BENIGN_DOMAINS)

        # Classification logic
        if is_ddns or (port not in [80, 443, 8080] and port is not None):
            classification = "potential_c2"
            why_suspicious = f"Embedded URL references Dynamic DNS or non-standard communication port ({port})."
            confidence = "High" if has_network_apis else "Medium"
        elif is_benign:
            classification = "third_party"
            why_suspicious = "Known public infrastructure or OS vendor verification endpoint."
            confidence = "Low"
        elif any(host.lower().endswith(tld) for tld in SUSPICIOUS_TLDS):
            classification = "potential_c2"
            why_suspicious = f"URL host uses high-risk TLD commonly observed in bulletproof hosting."
            confidence = "Medium"
        else:
            classification = "suspicious_destination" if has_network_apis else "embedded_unclassified"
            why_suspicious = f"Embedded URL located in PE section '{u.get('section', 'Unknown')}'."
            confidence = "Medium"

        indicators.append(C2Indicator(
            id=f"PE-C2-URL-{counter:03d}",
            indicator_type="url",
            value=raw_url,
            normalized_value=raw_url.lower(),
            source_file=f"PE Section: {u.get('section', 'Unknown')}",
            code_reference=f"Offset 0x{u.get('offset', 0):08X}",
            port=port,
            protocol=proto,
            classification=classification,
            why_suspicious=why_suspicious,
            confidence=confidence,
            threat_intel_status="Unchecked",
            recommended_validation="Query passive threat intelligence for domain reputation; do not connect directly."
        ))
        counter += 1

    # 2. Evaluate Public and Suspicious IPs
    for ip_item in ips:
        ip = ip_item["ip"]
        if ip in seen_values:
            continue
        seen_values.add(ip)

        is_priv = ip_item.get("is_private", False)
        if is_priv:
            classification = "private_ip"
            why = "RFC1918 / Loopback address."
            conf = "Low"
        else:
            classification = "potential_c2" if has_network_apis else "embedded_unclassified"
            why = f"Hardcoded routable public IPv4 address located at offset 0x{ip_item.get('offset', 0):08X}."
            conf = "Medium"

        indicators.append(C2Indicator(
            id=f"PE-C2-IP-{counter:03d}",
            indicator_type="ip",
            value=ip,
            normalized_value=ip,
            source_file=f"PE Section: {ip_item.get('section', 'Unknown')}",
            code_reference=f"Offset 0x{ip_item.get('offset', 0):08X}",
            classification=classification,
            why_suspicious=why,
            confidence=conf,
            threat_intel_status="Unchecked",
            recommended_validation="Perform passive ASN and reputation lookup; do not send active probes."
        ))
        counter += 1

    # 3. Evaluate Domains
    for d in domains:
        dom = d["domain"]
        if dom in seen_values:
            continue
        seen_values.add(dom)

        is_dga = is_potential_dga(dom)
        is_ddns = d.get("is_ddns", False)
        is_benign = any(b in dom for b in KNOWN_BENIGN_DOMAINS)

        if is_dga:
            classification = "potential_c2"
            why = "High consonant/entropy ratio conforms to Domain Generation Algorithm (DGA) characteristics."
            conf = "High"
        elif is_ddns:
            classification = "potential_c2"
            why = "Dynamic DNS service frequently utilized to conceal C2 IP infrastructure changes."
            conf = "High"
        elif is_benign:
            classification = "third_party"
            why = "Legitimate software vendor or platform endpoint."
            conf = "Low"
        else:
            classification = "suspicious_destination" if has_network_apis else "embedded_unclassified"
            why = f"Extracted domain string in section '{d.get('section', 'Unknown')}'."
            conf = "Medium"

        indicators.append(C2Indicator(
            id=f"PE-C2-DOM-{counter:03d}",
            indicator_type="domain",
            value=dom,
            normalized_value=dom,
            source_file=f"PE Section: {d.get('section', 'Unknown')}",
            code_reference=f"Offset 0x{d.get('offset', 0):08X}",
            classification=classification,
            why_suspicious=why,
            confidence=conf,
            threat_intel_status="Unchecked",
            recommended_validation="Check WHOIS creation dates and passive DNS resolution history."
        ))
        counter += 1

    # 4. Decoded Items (if they contain URLs or IPs)
    for dec in decoded_items:
        dec_val = dec["decoded"]
        if ("http://" in dec_val or "https://" in dec_val) and dec_val not in seen_values:
            seen_values.add(dec_val)
            indicators.append(C2Indicator(
                id=f"PE-C2-DEC-{counter:03d}",
                indicator_type="url",
                value=dec_val,
                normalized_value=dec_val.lower(),
                source_file=f"PE Section: {dec.get('section', 'Unknown')}",
                code_reference=f"Offset 0x{dec.get('offset', 0):08X}",
                encoding_steps=f"{dec.get('transformation')} decoded offline from '{dec.get('original')[:30]}...'",
                classification="potential_c2",
                why_suspicious="Obfuscated / encoded network URL extracted via offline decoding.",
                confidence="High",
                threat_intel_status="Unchecked",
                recommended_validation="Examine associated decryption routine in disassembly."
            ))
            counter += 1

    return indicators
