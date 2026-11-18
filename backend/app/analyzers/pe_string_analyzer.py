import re
import ipaddress
import base64
import binascii
from typing import List, Dict, Any, Tuple, Optional
from pathlib import Path
import pefile

# Regular Expressions for Forensic Pattern Extraction
URL_REGEX = re.compile(r'https?://[a-zA-Z0-9_\-\.]+(:[0-9]{1,5})?(/[a-zA-Z0-9_.\-~%!$&\'()*+,;=:@/?#]*)?', re.IGNORECASE)
IPV4_REGEX = re.compile(r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b')
IPV6_REGEX = re.compile(r'\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b')
DOMAIN_REGEX = re.compile(r'\b([a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+(?:com|net|org|io|ru|cn|cc|top|xyz|info|biz|club|tk|pw|onion|online|site|live|duckdns\.org|ngrok\.io|serveo\.net)\b', re.IGNORECASE)

REGISTRY_REGEX = re.compile(r'\b(?:HKEY_LOCAL_MACHINE|HKLM|HKEY_CURRENT_USER|HKCU|HKEY_CLASSES_ROOT|HKCR|HKEY_USERS|HKU)\\[a-zA-Z0-9_\-\\]+', re.IGNORECASE)
POWERSHELL_REGEX = re.compile(r'(powershell(?:\.exe)?\s+-[a-zA-Z0-9_\-\s"\'\$\=]+)', re.IGNORECASE)
CMD_REGEX = re.compile(r'(cmd(?:\.exe)?\s+/[ck]\s+[^\r\n"]+)', re.IGNORECASE)
NAMED_PIPE_REGEX = re.compile(r'(\\\\\.\\pipe\\[a-zA-Z0-9_\-\.]+)', re.IGNORECASE)
PDB_PATH_REGEX = re.compile(r'([a-zA-Z]:\\[^\x00\r\n]+\.pdb)', re.IGNORECASE)

KNOWN_DOH_SERVERS = [
    "cloudflare-dns.com", "dns.google", "dns.quad9.net",
    "dns.adguard.com", "doh.opendns.com"
]

def map_offset_to_section(offset: int, pe: Optional[pefile.PE]) -> str:
    """Determine which PE section contains a given physical file offset."""
    if not pe:
        return "Unknown"
    try:
        for section in pe.sections:
            raw_ptr = section.PointerToRawData
            raw_size = section.SizeOfRawData
            if raw_ptr <= offset < (raw_ptr + raw_size):
                return section.Name.decode('utf-8', errors='ignore').strip('\x00')
    except Exception:
        pass
    return "Header/Overlay"

def extract_raw_strings(data: bytes, min_length: int = 4, max_strings: int = 15000) -> List[Dict[str, Any]]:
    """
    Safely extract printable ASCII and UTF-16LE strings from byte buffer,
    preserving exact physical file offsets.
    """
    extracted = []
    
    # 1. ASCII Strings
    ascii_re = re.compile(b'[\x20-\x7E]{' + str(min_length).encode() + b',}')
    for m in ascii_re.finditer(data):
        if len(extracted) >= max_strings:
            break
        text = m.group(0).decode('latin-1', errors='ignore')
        extracted.append({
            "value": text,
            "encoding": "ASCII",
            "offset": m.start(),
            "length": len(text)
        })

    # 2. UTF-16LE (Wide) Strings
    utf16_re = re.compile(b'(?:[\x20-\x7E]\x00){' + str(min_length).encode() + b',}')
    for m in utf16_re.finditer(data):
        if len(extracted) >= max_strings:
            break
        try:
            text = m.group(0).decode('utf-16le', errors='ignore')
            extracted.append({
                "value": text,
                "encoding": "UTF-16LE",
                "offset": m.start(),
                "length": len(text)
            })
        except Exception:
            continue

    return extracted

def is_private_ip(ip_str: str) -> bool:
    """Safely check if an IPv4 or IPv6 address belongs to private/reserved ranges."""
    try:
        ip = ipaddress.ip_address(ip_str)
        return ip.is_private or ip.is_loopback or ip.is_reserved or ip.is_link_local
    except ValueError:
        return False

def try_decode_string(s: str) -> Tuple[bool, Optional[str], Optional[str]]:
    """
    Bounded offline decoding of Base64 and Hexadecimal encoded strings.
    Strict size and recursion limits to prevent buffer bloat or denial of service.
    """
    if len(s) < 8 or len(s) > 1024:
        return False, None, None

    # Base64 Attempt
    if re.fullmatch(r'[A-Za-z0-9+/=]{8,}', s) and (len(s) % 4 == 0):
        try:
            decoded_bytes = base64.b64decode(s, validate=True)
            if len(decoded_bytes) >= 4 and all(0x20 <= b <= 0x7E or b in (9, 10, 13) for b in decoded_bytes):
                decoded_str = decoded_bytes.decode('utf-8', errors='ignore').strip()
                if len(decoded_str) >= 4 and decoded_str != s:
                    return True, decoded_str, "Base64"
        except Exception:
            pass

    # Hexadecimal Attempt
    if re.fullmatch(r'[0-9a-fA-F]{8,}', s) and (len(s) % 2 == 0):
        try:
            decoded_bytes = binascii.unhexlify(s)
            if len(decoded_bytes) >= 4 and all(0x20 <= b <= 0x7E or b in (9, 10, 13) for b in decoded_bytes):
                decoded_str = decoded_bytes.decode('utf-8', errors='ignore').strip()
                if len(decoded_str) >= 4 and decoded_str != s:
                    return True, decoded_str, "Hexadecimal"
        except Exception:
            pass

    return False, None, None

def analyze_pe_strings(file_path: Path, pe: Optional[pefile.PE] = None) -> Dict[str, Any]:
    """
    Extract, classify, and normalize indicators from Windows PE executable strings:
    - URLs, IPs, domains, DoH endpoints
    - Registry persistence paths
    - Shell / PowerShell command fragments
    - Named pipes, Mutex strings, PDB debug paths
    - Decoded Base64 / Hex items
    """
    with open(file_path, "rb") as f:
        file_data = f.read()

    raw_items = extract_raw_strings(file_data)
    
    urls: List[Dict[str, Any]] = []
    ips: List[Dict[str, Any]] = []
    domains: List[Dict[str, Any]] = []
    registry_paths: List[Dict[str, Any]] = []
    shell_commands: List[Dict[str, Any]] = []
    named_pipes: List[Dict[str, Any]] = []
    pdb_paths: List[Dict[str, Any]] = []
    decoded_items: List[Dict[str, Any]] = []

    seen_urls = set()
    seen_ips = set()
    seen_domains = set()
    seen_regs = set()

    for item in raw_items:
        val = item["value"].strip()
        offset = item["offset"]
        section_name = map_offset_to_section(offset, pe)
        
        # 1. URLs
        for m in URL_REGEX.finditer(val):
            url_str = m.group(0).rstrip(')"\'>;,')
            if url_str not in seen_urls:
                seen_urls.add(url_str)
                urls.append({
                    "url": url_str,
                    "offset": offset,
                    "section": section_name,
                    "encoding": item["encoding"]
                })

        # 2. IPv4
        for m in IPV4_REGEX.finditer(val):
            ip_str = m.group(0)
            # Filter broadcast / local mask
            if ip_str not in seen_ips and ip_str not in ("255.255.255.255", "0.0.0.0"):
                seen_ips.add(ip_str)
                ips.append({
                    "ip": ip_str,
                    "is_private": is_private_ip(ip_str),
                    "offset": offset,
                    "section": section_name,
                    "encoding": item["encoding"]
                })

        # 3. Domains
        for m in DOMAIN_REGEX.finditer(val):
            dom_str = m.group(0).lower().rstrip('.')
            if dom_str not in seen_domains and dom_str not in seen_ips:
                seen_domains.add(dom_str)
                is_doh = any(doh in dom_str for doh in KNOWN_DOH_SERVERS)
                is_ddns = any(ddns in dom_str for ddns in ["duckdns.org", "no-ip.com", "ngrok.io", "serveo.net"])
                domains.append({
                    "domain": dom_str,
                    "is_doh": is_doh,
                    "is_ddns": is_ddns,
                    "offset": offset,
                    "section": section_name,
                    "encoding": item["encoding"]
                })

        # 4. Registry Paths
        for m in REGISTRY_REGEX.finditer(val):
            reg_str = m.group(0)
            if reg_str not in seen_regs:
                seen_regs.add(reg_str)
                registry_paths.append({
                    "path": reg_str,
                    "offset": offset,
                    "section": section_name
                })

        # 5. Shell / PowerShell Commands
        ps_match = POWERSHELL_REGEX.search(val)
        if ps_match:
            shell_commands.append({
                "type": "PowerShell",
                "command": ps_match.group(1),
                "offset": offset,
                "section": section_name
            })
        cmd_match = CMD_REGEX.search(val)
        if cmd_match:
            shell_commands.append({
                "type": "Command Prompt",
                "command": cmd_match.group(1),
                "offset": offset,
                "section": section_name
            })

        # 6. Named Pipes
        for m in NAMED_PIPE_REGEX.finditer(val):
            named_pipes.append({
                "pipe": m.group(1),
                "offset": offset,
                "section": section_name
            })

        # 7. PDB Paths
        for m in PDB_PATH_REGEX.finditer(val):
            pdb_paths.append({
                "path": m.group(1),
                "offset": offset,
                "section": section_name
            })

        # 8. Offline decoding
        success, dec_val, trans = try_decode_string(val)
        if success and dec_val:
            decoded_items.append({
                "original": val,
                "decoded": dec_val,
                "transformation": trans,
                "offset": offset,
                "section": section_name
            })

    return {
        "raw_strings": raw_items,
        "raw_strings_count": len(raw_items),
        "raw_strings_sample": raw_items[:200],
        "urls": urls,
        "ips": ips,
        "domains": domains,
        "registry_paths": registry_paths,
        "shell_commands": shell_commands,
        "named_pipes": named_pipes,
        "pdb_paths": pdb_paths,
        "decoded_items": decoded_items
    }
