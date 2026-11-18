import re
import math
from typing import List, Dict, Any, Optional
from urllib.parse import urlparse
from backend.app.core.models import C2Indicator
from backend.app.analyzers.string_analyzer import is_private_ip, DYNAMIC_DNS_DOMAINS, KNOWN_DOH_SERVERS, BENIGN_DOMAINS_WHITELIST

SUSPICIOUS_C2_PORTS = {4444, 1337, 8888, 8088, 9001, 9999, 5555, 6666, 7777, 31337, 8443, 8000, 8080, 27017, 587}
SUSPICIOUS_PATHS = [
    "/gate.php", "/panel", "/admin", "/c2", "/bot", "/api/v1/ping",
    "/beacon", "/task", "/command", "/connect", "/heartbeat", "/checkin",
    "/upload", "/download", "/shell", "/exec", "/login.php", "/sync"
]

def calculate_shannon_entropy(data: str) -> float:
    """Calculate the Shannon entropy of a string (useful for DGA domain detection)."""
    if not data:
        return 0.0
    entropy = 0.0
    for x in set(data):
        p_x = float(data.count(x)) / len(data)
        entropy += - p_x * math.log2(p_x)
    return entropy

def is_potential_dga(domain: str) -> bool:
    """Heuristic check for Domain Generation Algorithm (DGA) characteristics."""
    parts = domain.split('.')
    if not parts:
        return False
    sub = parts[0]
    # DGA domains typically have long random alphanumeric labels with high entropy
    if len(sub) >= 12 and calculate_shannon_entropy(sub) > 3.4:
        # Check digit count
        digit_count = sum(c.isdigit() for c in sub)
        if digit_count >= 2 or not any(v in sub for v in 'aeiou'):
            return True
    return False

def analyze_c2_infrastructure(
    urls: List[Dict[str, Any]],
    ips: List[Dict[str, Any]],
    domains: List[Dict[str, Any]],
    decoded_strings: List[Dict[str, Any]],
    dex_methods: List[str]
) -> List[C2Indicator]:
    """
    Forensically evaluates extracted network indicators and reconstructs
    potential Command-and-Control (C2) configurations without active interaction.
    """
    indicators: List[C2Indicator] = []
    seen_normalized = set()
    counter = 1

    # 1. Process URLs
    for item in urls:
        raw_url = item["url"]
        source = item["source"]
        try:
            parsed = urlparse(raw_url)
            hostname = (parsed.hostname or "").lower()
            port = parsed.port or (443 if parsed.scheme == "https" else (80 if parsed.scheme == "http" else None))
            path = parsed.path or ""
        except Exception:
            hostname = ""
            port = None
            path = ""

        if not hostname:
            continue

        normalized = f"{parsed.scheme}://{hostname}{f':{port}' if port and port not in (80, 443) else ''}{path}"
        if normalized in seen_normalized:
            continue
        seen_normalized.add(normalized)

        # Classification heuristics
        classification = "embedded_unclassified"
        why_suspicious = "Embedded URL found within application code or resources."
        confidence = "Low"
        recommended_val = "Verify domain ownership and passive DNS records via authorized threat intelligence."

        # Check Telegram Bot C2
        if "api.telegram.org" in hostname or "t.me" in hostname:
            classification = "potential_c2"
            why_suspicious = "Telegram API / bot channel endpoint utilized for C2 communication or exfiltration."
            confidence = "High"
            recommended_val = "Extract bot token and chat ID to query bot profile and channels via read-only API."

        # Check for Cloud Storage Buckets (S3, Firebase, CloudFront)
        elif any(ext in hostname for ext in ("s3.amazonaws.com", "s3.ap-south-1.amazonaws.com", "firebaseio.com", "firebaseapp.com", "cloudfront.net")):
            classification = "cloud_exfiltration_bucket"
            why_suspicious = f"Cloud bucket or staging infrastructure ({hostname}) used for asset/credential exfiltration."
            confidence = "High"
            recommended_val = "Audit permissions and access policies on cloud storage bucket."

        # Whitelist check
        elif any(hostname == b or hostname.endswith(f".{b}") for b in BENIGN_DOMAINS_WHITELIST):
            classification = "third_party"
            why_suspicious = "Standard third-party or platform destination (Google, Android, Apache, Github)."
            confidence = "Low"
            recommended_val = "Verify if benign API is utilized for legitimate analytics or dead-drop C2."

        # Check for Dynamic DNS
        elif any(hostname.endswith(dd) for dd in DYNAMIC_DNS_DOMAINS):
            classification = "potential_c2"
            why_suspicious = f"Uses dynamic DNS service ({hostname}), frequently leveraged by threat actors for agile C2 redirection."
            confidence = "High"
            recommended_val = "Investigate DNS resolution history for threat actor IP hosting history."

        # Check for DGA
        elif is_potential_dga(hostname):
            classification = "potential_c2"
            why_suspicious = "Hostname exhibits high Shannon entropy and pseudo-random characteristics consistent with Domain Generation Algorithms (DGA)."
            confidence = "Medium"
            recommended_val = "Query passive DNS to observe whether the domain has ever been registered or sinkholed."

        # Check for Suspicious C2 Port
        elif port in SUSPICIOUS_C2_PORTS:
            classification = "potential_c2"
            why_suspicious = f"Configured with non-standard service port ({port}), typical for custom C2 agents and reverse shells."
            confidence = "High"
            recommended_val = "Examine DEX methods invoking this endpoint for socket or HTTP command processing loops."

        # Check for Suspicious C2 Path
        elif any(path.lower().startswith(p) or path.lower() == p for p in SUSPICIOUS_PATHS):
            classification = "potential_c2"
            why_suspicious = f"URL path '{path}' matches common botnet check-in, beaconing, or panel endpoints."
            confidence = "High"
            recommended_val = "Correlate with methods handling HTTP POST request payloads."

        # Check if hostname is raw IP
        elif re.match(r'^(?:\d{1,3}\.){3}\d{1,3}$', hostname):
            if is_private_ip(hostname):
                classification = "private_ip"
                why_suspicious = "RFC 1918 private/local IP address."
                confidence = "Low"
            else:
                classification = "suspicious_destination"
                why_suspicious = "Direct raw public IP communication without DNS hostname resolution."
                confidence = "Medium"

        # Check for DoH
        elif hostname in KNOWN_DOH_SERVERS:
            classification = "suspicious_destination"
            why_suspicious = "DNS-over-HTTPS (DoH) resolver endpoint, often abused by modern malware to evade corporate DNS monitoring."
            confidence = "Medium"
            recommended_val = "Inspect whether application constructs custom DoH queries to resolve hidden C2 hostnames."

        # Reconstruct association with DEX methods
        associated_method = None
        for m in dex_methods:
            if hostname in m or (path and len(path) > 3 and path in m):
                associated_method = m[:120]
                break

        indicators.append(C2Indicator(
            id=f"C2-IND-{counter:03d}",
            indicator_type="url",
            value=raw_url,
            normalized_value=normalized,
            source_file=source,
            code_reference=associated_method,
            port=port,
            protocol=parsed.scheme or "http",
            classification=classification,
            why_suspicious=why_suspicious,
            confidence=confidence,
            recommended_validation=recommended_val
        ))
        counter += 1

    # 2. Process Raw IPs not part of URLs
    for ip_item in ips:
        ip = ip_item["ip"]
        source = ip_item["source"]
        if ip in seen_normalized:
            continue
        seen_normalized.add(ip)

        is_priv = ip_item.get("is_private", is_private_ip(ip))
        if is_priv:
            classification = "private_ip"
            why = "RFC 1918 internal/loopback IP address embedded in artifact."
            conf = "Low"
        else:
            classification = "embedded_unclassified"
            why = "Extracted public IP address embedded in application strings."
            conf = "Medium"

        # Correlate with methods
        assoc = next((m[:120] for m in dex_methods if ip in m), None)

        indicators.append(C2Indicator(
            id=f"C2-IND-{counter:03d}",
            indicator_type="ip",
            value=ip,
            normalized_value=ip,
            source_file=source,
            code_reference=assoc,
            classification=classification,
            why_suspicious=why,
            confidence=conf,
            recommended_validation="Cross-reference IP with AbuseIPDB and VirusTotal to check for prior malware hosting reports."
        ))
        counter += 1

    # 3. Process Decoded Items (Recovered from Base64 or Hex)
    for dec in decoded_strings:
        val = dec["decoded"]
        # Check if decoded string is URL or Domain
        if "http://" in val or "https://" in val or any(val.lower().endswith(d) for d in DYNAMIC_DNS_DOMAINS):
            indicators.append(C2Indicator(
                id=f"C2-IND-{counter:03d}",
                indicator_type="decoded_c2",
                value=dec["original"],
                normalized_value=val,
                source_file=dec["source"],
                encoding_steps=f"Obfuscation reversed via {dec['transformation']}",
                classification="potential_c2",
                why_suspicious=f"De-obfuscated network endpoint recovered from encoded string: {val}",
                confidence="High",
                recommended_validation="Examine routines that call Base64/Hex decoding functions to identify when this address is invoked."
            ))
            counter += 1

    return indicators
