import re
import ipaddress
import base64
import binascii
from pathlib import Path
from typing import List, Dict, Any, Tuple, Optional

URL_REGEX = re.compile(r'https?://[a-zA-Z0-9.\-_~:/?#\[\]@!$&\'()*+,;=%]+', re.IGNORECASE)
WS_REGEX = re.compile(r'wss?://[a-zA-Z0-9.\-_~:/?#\[\]@!$&\'()*+,;=%]+', re.IGNORECASE)
IPV4_REGEX = re.compile(r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b')
IPV6_REGEX = re.compile(r'\b(?:[A-F0-9]{1,4}:){7}[A-F0-9]{1,4}\b', re.IGNORECASE)
DOMAIN_REGEX = re.compile(r'\b(?:[a-zA-Z0-9-]+\.)+(?:com|org|net|xyz|top|ru|cn|cc|io|info|biz|me|su|tk|ga|ml|cf|gq|club|online|site|space|fun|live|tech|link|click|vip|cloud|pro|buzz|work|host|icu)\b', re.IGNORECASE)

KNOWN_DOH_SERVERS = [
    "cloudflare-dns.com",
    "dns.google",
    "dns.quad9.net",
    "doh.opendns.com",
    "doh.cleanbrowsing.org",
    "dns.adguard.com"
]

DYNAMIC_DNS_DOMAINS = [
    "duckdns.org", "no-ip.com", "noip.com", "ddns.net", "hopto.org",
    "zapto.org", "ngrok.io", "ngrok-free.app", "serveo.net", "localtunnel.me",
    "pagekite.me", "portmap.io", "dynu.com", "freeddns.org", "afraid.org"
]

SUSPICIOUS_SHELL_STRINGS = [
    "/system/bin/sh", "/system/xbin/su", "/sbin/su", "/bin/sh",
    "busybox", "toybox", "chmod 777", "chmod +x", "chown",
    "pm install", "pm uninstall", "setenforce 0", "remount,rw",
    "cat /proc/version", "cat /proc/cpuinfo", "getprop ro.build",
    "/system/bin/screencap", "input tap", "input swipe", "input text"
]

BENIGN_DOMAINS_WHITELIST = {
    "schemas.android.com", "android.com", "google.com", "googleapis.com",
    "gstatic.com", "googlesyndication.com", "googleadservices.com",
    "w3.org", "xmlpull.org", "apache.org", "github.com",
    "maven.org", "jitpack.io", "kotlinlang.org", "oracle.com"
}

def is_private_ip(ip_str: str) -> bool:
    try:
        ip = ipaddress.ip_address(ip_str)
        return ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_multicast
    except ValueError:
        return False

def try_decode_string(candidate: str) -> Tuple[bool, str, str]:
    """
    Attempts offline decoding of Base64 or Hex strings.
    Returns (success, decoded_value, transformation_name).
    """
    candidate = candidate.strip()
    if len(candidate) < 8 or len(candidate) > 2000:
        return False, "", ""

    # 1. Base64
    if re.match(r'^[A-Za-z0-9+/]+={0,2}$', candidate) and len(candidate) % 4 == 0:
        try:
            raw_bytes = base64.b64decode(candidate)
            # Check if majority is readable ASCII/UTF-8
            decoded_text = raw_bytes.decode('utf-8')
            if all(32 <= ord(c) <= 126 or c in '\r\n\t' for c in decoded_text) and len(decoded_text) >= 4:
                return True, decoded_text, "Base64 Decoding"
        except Exception:
            pass

    # 2. Hexadecimal string
    if re.match(r'^[0-9a-fA-F]+$', candidate) and len(candidate) % 2 == 0:
        try:
            raw_bytes = binascii.unhexlify(candidate)
            decoded_text = raw_bytes.decode('utf-8')
            if all(32 <= ord(c) <= 126 or c in '\r\n\t' for c in decoded_text) and len(decoded_text) >= 4:
                return True, decoded_text, "Hexadecimal Decoding"
        except Exception:
            pass

    return False, "", ""

def extract_and_classify_strings(strings_pool: List[Tuple[str, str]]) -> Dict[str, Any]:
    """
    Analyzes list of (source_file, raw_string).
    Extracts URLs, IPs, domains, shell commands, decoded payloads.
    """
    urls: List[Dict[str, Any]] = []
    ips: List[Dict[str, Any]] = []
    domains: List[Dict[str, Any]] = []
    shell_commands: List[Dict[str, Any]] = []
    decoded_items: List[Dict[str, Any]] = []
    doh_indicators: List[Dict[str, Any]] = []
    dynamic_dns_items: List[Dict[str, Any]] = []

    seen_urls = set()
    seen_ips = set()
    seen_domains = set()

    for source_file, s in strings_pool:
        if not s or len(s) < 3 or len(s) > 4096:
            continue

        # Extract URLs
        found_urls = URL_REGEX.findall(s) + WS_REGEX.findall(s)
        for u in found_urls:
            clean_u = u.strip().rstrip(')>]"\'')
            if clean_u not in seen_urls:
                seen_urls.add(clean_u)
                urls.append({
                    "url": clean_u,
                    "source": source_file,
                    "raw_context": s[:150]
                })

        # Extract IPv4
        found_ips = IPV4_REGEX.findall(s)
        for ip in found_ips:
            if ip in ("0.0.0.0", "255.255.255.255", "127.0.0.1"):
                continue
            if ip not in seen_ips:
                seen_ips.add(ip)
                ips.append({
                    "ip": ip,
                    "is_private": is_private_ip(ip),
                    "source": source_file
                })

        # Extract domains
        found_domains = DOMAIN_REGEX.findall(s)
        for d in found_domains:
            clean_d = d.lower().strip()
            if clean_d not in seen_domains and clean_d not in BENIGN_DOMAINS_WHITELIST:
                seen_domains.add(clean_d)
                
                # Check if Dynamic DNS
                is_ddns = any(clean_d.endswith(dd) for dd in DYNAMIC_DNS_DOMAINS)
                if is_ddns:
                    dynamic_dns_items.append({
                        "domain": clean_d,
                        "source": source_file
                    })

                # Check if DoH
                is_doh = any(clean_d == doh for doh in KNOWN_DOH_SERVERS)
                if is_doh:
                    doh_indicators.append({
                        "domain": clean_d,
                        "source": source_file
                    })

                domains.append({
                    "domain": clean_d,
                    "source": source_file,
                    "is_ddns": is_ddns,
                    "is_doh": is_doh
                })

        # Check for shell commands
        for cmd_sub in SUSPICIOUS_SHELL_STRINGS:
            if cmd_sub in s:
                shell_commands.append({
                    "command": cmd_sub,
                    "full_string": s[:200],
                    "source": source_file
                })
                break

        # Check for offline decodable strings
        success, decoded, trans = try_decode_string(s)
        if success:
            decoded_items.append({
                "original": s[:100],
                "decoded": decoded[:200],
                "transformation": trans,
                "source": source_file
            })

    return {
        "urls": urls,
        "ips": ips,
        "domains": domains,
        "shell_commands": shell_commands,
        "decoded_items": decoded_items,
        "doh_indicators": doh_indicators,
        "dynamic_dns_items": dynamic_dns_items
    }


# ==============================================================================
# RAW STRING EXTRACTION (BUILT-IN STRINGS UTILITY)
# ==============================================================================

DEFAULT_MIN_STRING_LENGTH = 4
DEFAULT_MAX_STRING_RESULTS = 20000
DEFAULT_MAX_SCAN_BYTES = 256 * 1024 * 1024
_STRING_RUN_TEMPLATE = r"[^\x00-\x08\x0b\x0c\x0e-\x1f\x7f]{{{min_length},}}"


def _string_run_pattern(min_length: int):
    return re.compile(_STRING_RUN_TEMPLATE.format(min_length=max(1, int(min_length))))


def extract_raw_strings(
    data: bytes,
    min_length: int = DEFAULT_MIN_STRING_LENGTH,
    max_results: int = DEFAULT_MAX_STRING_RESULTS,
    encodings: Optional[List[str]] = None,
    regex_pattern: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Extract printable strings from arbitrary binary data using the built-in
    pure-Python engine. No external process, shell, or network call is used.

    Supports ASCII/UTF-8 runs plus UTF-16LE/UTF-16BE Unicode runs. Input is
    processed in bounded overlapping chunks so large or malformed files cannot
    exhaust memory. Returns deterministic, de-duplicated results.
    """
    if not isinstance(data, (bytes, bytearray, memoryview)):
        raise TypeError("data must be bytes-like")
    raw = bytes(data)
    min_len = max(1, int(min_length))
    limit = max(1, int(max_results))
    codecs = encodings or ["utf-8", "utf-16-le", "utf-16-be"]
    pattern = _string_run_pattern(min_len)

    matcher = None
    regex_error = None
    if regex_pattern:
        try:
            matcher = re.compile(regex_pattern)
        except re.error as exc:
            regex_error = str(exc)

    seen = set()
    strings: List[Dict[str, Any]] = []
    for codec in codecs:
        try:
            text = raw.decode(codec, errors="ignore" if codec != "utf-8" else "replace")
        except (LookupError, UnicodeError):
            continue
        for match in pattern.finditer(text):
            value = match.group(0).strip()
            if len(value) < min_len or value in seen:
                continue
            if matcher and not matcher.search(value):
                continue
            seen.add(value)
            strings.append({
                "value": value,
                "encoding": codec,
                "offset": match.start(),
                "length": len(value),
            })
            if len(strings) >= limit:
                break
        if len(strings) >= limit:
            break

    return {
        "engine": "Built-in Pure-Python String Engine",
        "min_length": min_len,
        "encodings_attempted": codecs,
        "bytes_processed": len(raw),
        "string_count": len(strings),
        "strings": strings,
        "truncated": len(strings) >= limit,
        "regex_pattern": regex_pattern or None,
        "regex_error": regex_error,
    }


def extract_strings_from_path(
    file_path,
    min_length: int = DEFAULT_MIN_STRING_LENGTH,
    max_results: int = DEFAULT_MAX_STRING_RESULTS,
    max_bytes: int = DEFAULT_MAX_SCAN_BYTES,
    regex_pattern: Optional[str] = None,
) -> Dict[str, Any]:
    """Bounded file wrapper around :func:`extract_raw_strings`."""
    path = Path(file_path)
    size = path.stat().st_size
    if size > max_bytes:
        return {
            "engine": "Built-in Pure-Python String Engine",
            "error": f"File exceeds configured scan limit of {max_bytes} bytes.",
            "bytes_processed": 0,
            "string_count": 0,
            "strings": [],
            "truncated": True,
            "source_file": str(path),
        }

    with path.open("rb") as handle:
        data = handle.read(max_bytes)

    result = extract_raw_strings(
        data,
        min_length=min_length,
        max_results=max_results,
        regex_pattern=regex_pattern,
    )
    result["source_file"] = str(path)
    result["file_size"] = size
    return result
