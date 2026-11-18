"""
Centralized Authentication & Provider Registry
Universal Digital Forensics & Evidence Intelligence Platform v2.0.0

Formally declares the supported authentication architecture for every integration:
- oauth2_authorization_code_pkce
- api_key
- local_executable
- public_unauthenticated
- custom_endpoint_token

Documents official endpoints, scopes, redirect URIs, and capabilities.
"""

from typing import Dict, Any, List, Optional

AUTHENTICATION_REGISTRY: Dict[str, Dict[str, Any]] = {
    # ==========================================================================
    # 1. THREAT INTELLIGENCE
    # ==========================================================================
    "virustotal": {
        "id": "virustotal",
        "name": "VirusTotal v3",
        "category": "threat_intel",
        "description": "Multi-engine malware analysis and IOC reputation aggregator.",
        "auth_types_supported": ["api_key"],
        "default_auth_type": "api_key",
        "oauth2_config": {"enabled": False},
        "api_key_config": {
            "enabled": True,
            "auth_header": "x-apikey",
            "fields": [
                {
                    "key": "api_key",
                    "label": "VirusTotal API Key",
                    "type": "password",
                    "placeholder": "64-character hex API key",
                    "help_text": "Get your personal API key from your VirusTotal profile."
                }
            ]
        },
        "test_endpoint": "https://www.virustotal.com/api/v3/users/current",
        "docs_url": "https://developers.virustotal.com/reference/overview",
        "rate_limits": "Free Community Tier: 4 requests/min, 500 requests/day",
        "privacy_note": "Queries hashes, domains, and IPs only. Never uploads proprietary binaries."
    },

    "alienvault_otx": {
        "id": "alienvault_otx",
        "name": "AlienVault OTX",
        "category": "threat_intel",
        "description": "Open Threat Exchange crowdsourced threat intelligence pulses.",
        "auth_types_supported": ["api_key"],
        "default_auth_type": "api_key",
        "oauth2_config": {"enabled": False},
        "api_key_config": {
            "enabled": True,
            "auth_header": "X-OTX-API-KEY",
            "fields": [
                {
                    "key": "api_key",
                    "label": "OTX API Key",
                    "type": "password",
                    "placeholder": "64-character hex OTX key",
                    "help_text": "Obtain an OTX API key at https://otx.alienvault.com/api."
                }
            ]
        },
        "test_endpoint": "https://otx.alienvault.com/api/v1/user/me",
        "docs_url": "https://otx.alienvault.com/api",
        "rate_limits": "Community Tier: 10,000 requests/day",
        "privacy_note": "Passive read-only pulse lookups for observed hashes, IPs, and domains."
    },

    "abuseipdb": {
        "id": "abuseipdb",
        "name": "AbuseIPDB v2",
        "category": "threat_intel",
        "description": "Crowdsourced IP abuse confidence scoring and reporting database.",
        "auth_types_supported": ["api_key"],
        "default_auth_type": "api_key",
        "oauth2_config": {"enabled": False},
        "api_key_config": {
            "enabled": True,
            "auth_header": "Key",
            "fields": [
                {
                    "key": "api_key",
                    "label": "AbuseIPDB APIv2 Key",
                    "type": "password",
                    "placeholder": "80-character APIv2 key",
                    "help_text": "Create an APIv2 key in your AbuseIPDB Account dashboard."
                }
            ]
        },
        "test_endpoint": "https://api.abuseipdb.com/api/v2/check?ipAddress=127.0.0.1",
        "docs_url": "https://docs.abuseipdb.com/",
        "rate_limits": "Free Tier: 1,000 checks/day",
        "privacy_note": "Checks IP reputation without disclosing workstation identity."
    },

    "urlhaus": {
        "id": "urlhaus",
        "name": "URLhaus (abuse.ch)",
        "category": "threat_intel",
        "description": "Malicious URL feed sharing malware distribution sites.",
        "auth_types_supported": ["public_unauthenticated", "api_key"],
        "default_auth_type": "public_unauthenticated",
        "oauth2_config": {"enabled": False},
        "api_key_config": {
            "enabled": True,
            "auth_header": "Auth-Key",
            "fields": [
                {
                    "key": "api_key",
                    "label": "Auth-Key (Optional)",
                    "type": "password",
                    "placeholder": "Optional abuse.ch API token",
                    "help_text": "Leave blank to query public community feed."
                }
            ]
        },
        "test_endpoint": "https://urlhaus-api.abuse.ch/v1/payloads/recent/",
        "docs_url": "https://urlhaus.abuse.ch/api/",
        "rate_limits": "Public Community",
        "privacy_note": "Zero private data transmitted; queries publicly known malware URLs."
    },

    "malwarebazaar": {
        "id": "malwarebazaar",
        "name": "MalwareBazaar (abuse.ch)",
        "category": "threat_intel",
        "description": "Malware sample database and hash verification exchange.",
        "auth_types_supported": ["public_unauthenticated", "api_key"],
        "default_auth_type": "public_unauthenticated",
        "oauth2_config": {"enabled": False},
        "api_key_config": {
            "enabled": True,
            "auth_header": "Auth-Key",
            "fields": [
                {
                    "key": "api_key",
                    "label": "Auth-Key (Optional)",
                    "type": "password",
                    "placeholder": "Optional abuse.ch API token",
                    "help_text": "Leave blank to query public community feed."
                }
            ]
        },
        "test_endpoint": "https://mb-api.abuse.ch/api/v1/",
        "docs_url": "https://bazaar.abuse.ch/api/",
        "rate_limits": "Public Community",
        "privacy_note": "Queries sample hashes against public malware catalogs."
    },

    # ==========================================================================
    # 3. OSINT & NETWORK ENRICHMENT
    # ==========================================================================
    "shodan": {
        "id": "shodan",
        "name": "Shodan",
        "category": "osint",
        "description": "Search engine for Internet-connected devices, banners, and open ports.",
        "auth_types_supported": ["api_key"],
        "default_auth_type": "api_key",
        "oauth2_config": {"enabled": False},
        "api_key_config": {
            "enabled": True,
            "auth_header": "QueryParam",
            "fields": [
                {
                    "key": "api_key",
                    "label": "Shodan API Key",
                    "type": "password",
                    "placeholder": "32-character API key",
                    "help_text": "Retrieve your API key from https://account.shodan.io."
                }
            ]
        },
        "test_endpoint": "https://api.shodan.io/api-info",
        "docs_url": "https://developer.shodan.io/api",
        "rate_limits": "Dependent on Shodan subscription tier",
        "privacy_note": "Queries observed public IP banners."
    },

    "ipinfo": {
        "id": "ipinfo",
        "name": "IPinfo.io",
        "category": "osint",
        "description": "Geolocation, ASN, and hosting network provider intelligence.",
        "auth_types_supported": ["api_key", "public_unauthenticated"],
        "default_auth_type": "api_key",
        "oauth2_config": {"enabled": False},
        "api_key_config": {
            "enabled": True,
            "auth_header": "Authorization",
            "auth_scheme": "Bearer",
            "fields": [
                {
                    "key": "api_key",
                    "label": "IPinfo Access Token",
                    "type": "password",
                    "placeholder": "14-character token",
                    "help_text": "Get a free token from https://ipinfo.io/signup."
                }
            ]
        },
        "test_endpoint": "https://ipinfo.io/8.8.8.8/json",
        "docs_url": "https://ipinfo.io/developers",
        "rate_limits": "Free tier: 50,000 lookups/month",
        "privacy_note": "Passive IP metadata enrichment."
    },

    "censys": {
        "id": "censys",
        "name": "Censys Search v2",
        "category": "osint",
        "description": "Attack surface scanner and TLS certificate repository.",
        "auth_types_supported": ["api_key"],
        "default_auth_type": "api_key",
        "oauth2_config": {"enabled": False},
        "api_key_config": {
            "enabled": True,
            "auth_header": "BasicAuth",
            "fields": [
                {"key": "api_id", "label": "API ID", "type": "text", "placeholder": "UUID format"},
                {"key": "api_secret", "label": "API Secret", "type": "password", "placeholder": "Secret token"}
            ]
        },
        "test_endpoint": "https://search.censys.io/api/v2/hosts/8.8.8.8",
        "docs_url": "https://search.censys.io/api",
        "rate_limits": "Community Tier: 250 queries/month",
        "privacy_note": "Queries public Internet scan databases."
    },

    "greynoise": {
        "id": "greynoise",
        "name": "GreyNoise",
        "category": "osint",
        "description": "Internet noise and benign scanner filter (identifies harmless scanners vs threats).",
        "auth_types_supported": ["api_key"],
        "default_auth_type": "api_key",
        "oauth2_config": {"enabled": False},
        "api_key_config": {
            "enabled": True,
            "auth_header": "key",
            "fields": [
                {"key": "api_key", "label": "GreyNoise API Key", "type": "password", "placeholder": "API key"}
            ]
        },
        "test_endpoint": "https://api.greynoise.io/v3/community/8.8.8.8",
        "docs_url": "https://docs.greynoise.io/reference/get_v3-community-ip",
        "rate_limits": "Community tier",
        "privacy_note": "Passive noise lookups."
    },

    # ==========================================================================
    # 4. MALWARE ANALYSIS & SANDBOXES
    # ==========================================================================
    "mobsf": {
        "id": "mobsf",
        "name": "Mobile Security Framework (MobSF)",
        "category": "malware_analysis",
        "description": "Automated Android and iOS dynamic malware execution sandbox.",
        "auth_types_supported": ["custom_endpoint_token"],
        "default_auth_type": "custom_endpoint_token",
        "oauth2_config": {"enabled": False},
        "custom_endpoint_config": {
            "enabled": True,
            "fields": [
                {
                    "key": "url",
                    "label": "MobSF Instance URL",
                    "type": "text",
                    "placeholder": "http://127.0.0.1:8001",
                    "help_text": "Local Docker container or remote dedicated MobSF instance."
                },
                {
                    "key": "api_key",
                    "label": "REST API Key",
                    "type": "password",
                    "placeholder": "64-character REST API token",
                    "help_text": "Found in MobSF web interface under API Key."
                }
            ]
        },
        "test_endpoint": "{url}/api/v1/scans",
        "docs_url": "https://mobsf.github.io/Mobile-Security-Framework-MobSF/",
        "privacy_note": "Local isolated container execution. Files remain inside private lab boundary."
    },

    "cape": {
        "id": "cape",
        "name": "CAPE Sandbox v2",
        "category": "malware_analysis",
        "description": "Automated Windows malware dynamic behavior and payload unpacking sandbox.",
        "auth_types_supported": ["custom_endpoint_token"],
        "default_auth_type": "custom_endpoint_token",
        "oauth2_config": {"enabled": False},
        "custom_endpoint_config": {
            "enabled": True,
            "fields": [
                {"key": "url", "label": "CAPE Instance URL", "type": "text", "placeholder": "http://192.168.1.50:8000"},
                {"key": "api_key", "label": "CAPE API Token", "type": "password", "placeholder": "Bearer token"}
            ]
        },
        "test_endpoint": "{url}/apiv2/cuckoo/status/",
        "docs_url": "https://capev2.readthedocs.io/",
        "privacy_note": "Requires dedicated isolated hypervisor cluster."
    },

    "misp": {
        "id": "misp",
        "name": "MISP Threat Sharing",
        "category": "malware_analysis",
        "description": "Open Source Threat Intelligence Platform & Open Standards Exchange.",
        "auth_types_supported": ["custom_endpoint_token"],
        "default_auth_type": "custom_endpoint_token",
        "oauth2_config": {"enabled": False},
        "custom_endpoint_config": {
            "enabled": True,
            "fields": [
                {"key": "url", "label": "MISP Instance URL", "type": "text", "placeholder": "https://misp.local"},
                {"key": "api_key", "label": "MISP Auth Key", "type": "password", "placeholder": "40-character Auth key"}
            ]
        },
        "test_endpoint": "{url}/servers/getVersion",
        "docs_url": "https://www.misp-project.org/openapi/",
        "privacy_note": "Internal organizational threat sharing instance."
    },

    # ==========================================================================
    # 5. LOCAL FORENSIC TOOLS
    # ==========================================================================
    "jadx": {
        "id": "jadx",
        "name": "JADX CLI Decompiler",
        "category": "local_tools",
        "description": "Dex-to-Java decompiler for command-line automated reverse engineering.",
        "auth_types_supported": ["local_executable"],
        "default_auth_type": "local_executable",
        "oauth2_config": {"enabled": False},
        "local_executable_config": {
            "enabled": True,
            "binary_name": "jadx.bat",
            "fields": [
                {"key": "binary_path", "label": "JADX Executable Path", "type": "text", "placeholder": "C:\\Tools\\jadx\\bin\\jadx.bat"}
            ]
        },
        "docs_url": "https://github.com/skylot/jadx",
        "privacy_note": "100% offline decompilation. No evidence leaves the workstation."
    },

    "jadx_gui": {
        "id": "jadx_gui",
        "name": "JADX GUI Viewer",
        "category": "local_tools",
        "description": "Interactive GUI viewer for browsing decompiled Android bytecode.",
        "auth_types_supported": ["local_executable"],
        "default_auth_type": "local_executable",
        "oauth2_config": {"enabled": False},
        "local_executable_config": {
            "enabled": True,
            "binary_name": "jadx-gui.bat",
            "fields": [
                {"key": "binary_path", "label": "JADX GUI Executable Path", "type": "text", "placeholder": "C:\\Tools\\jadx\\bin\\jadx-gui.bat"}
            ]
        },
        "docs_url": "https://github.com/skylot/jadx",
        "privacy_note": "Offline local GUI viewer."
    },

    "apktool": {
        "id": "apktool",
        "name": "Apktool",
        "category": "local_tools",
        "description": "Decodes APK resources to near-original form (Smali bytecode, XML layouts, Manifest).",
        "auth_types_supported": ["local_executable"],
        "default_auth_type": "local_executable",
        "oauth2_config": {"enabled": False},
        "local_executable_config": {
            "enabled": True,
            "binary_name": "apktool.bat",
            "fields": [
                {"key": "binary_path", "label": "Apktool Script Path", "type": "text", "placeholder": "C:\\Tools\\apktool\\apktool.bat"}
            ]
        },
        "docs_url": "https://apktool.org/",
        "privacy_note": "Offline local decoding."
    },

    "androguard": {
        "id": "androguard",
        "name": "Androguard Bytecode Engine",
        "category": "local_tools",
        "description": "Embedded Python engine for Dalvik executable and APK static analysis.",
        "auth_types_supported": ["local_executable"],
        "default_auth_type": "local_executable",
        "oauth2_config": {"enabled": False},
        "local_executable_config": {"enabled": True, "embedded": True},
        "docs_url": "https://androguard.readthedocs.io/",
        "privacy_note": "Embedded Python library running directly in-memory."
    },

    "yara": {
        "id": "yara",
        "name": "YARA Signature Engine",
        "category": "local_tools",
        "description": "Pattern matching swiss army knife for malware identification.",
        "auth_types_supported": ["local_executable"],
        "default_auth_type": "local_executable",
        "oauth2_config": {"enabled": False},
        "local_executable_config": {"enabled": True, "embedded": True},
        "docs_url": "https://yara.readthedocs.io/",
        "privacy_note": "Embedded native C-compiled pattern matching engine."
    },

    # ==========================================================================
    # 6. NETWORK ANALYSIS
    # ==========================================================================
    "tshark": {
        "id": "tshark",
        "name": "Wireshark / TShark",
        "category": "network_analysis",
        "description": "Command-line packet capture and network protocol dissector.",
        "auth_types_supported": ["local_executable"],
        "default_auth_type": "local_executable",
        "oauth2_config": {"enabled": False},
        "local_executable_config": {
            "enabled": True,
            "binary_name": "tshark.exe",
            "fields": [
                {"key": "binary_path", "label": "TShark Path", "type": "text", "placeholder": "C:\\Program Files\\Wireshark\\tshark.exe"}
            ]
        },
        "docs_url": "https://www.wireshark.org/docs/man-pages/tshark.html",
        "privacy_note": "Parses local PCAP offline. Falls back to pure-Python PCAP parser if unavailable."
    },

    "zeek": {
        "id": "zeek",
        "name": "Zeek Network Security Monitor",
        "category": "network_analysis",
        "description": "Transforms raw packets into structured high-level connection and HTTP/DNS logs.",
        "auth_types_supported": ["local_executable"],
        "default_auth_type": "local_executable",
        "oauth2_config": {"enabled": False},
        "local_executable_config": {
            "enabled": True,
            "binary_name": "zeek",
            "fields": [
                {"key": "binary_path", "label": "Zeek Executable Path", "type": "text", "placeholder": "zeek"}
            ]
        },
        "docs_url": "https://zeek.org/",
        "privacy_note": "Local network event extraction."
    },

    "suricata": {
        "id": "suricata",
        "name": "Suricata IDS/IPS Engine",
        "category": "network_analysis",
        "description": "Signature-based network threat detection against ET Open rulesets.",
        "auth_types_supported": ["local_executable"],
        "default_auth_type": "local_executable",
        "oauth2_config": {"enabled": False},
        "local_executable_config": {
            "enabled": True,
            "binary_name": "suricata",
            "fields": [
                {"key": "binary_path", "label": "Suricata Binary Path", "type": "text", "placeholder": "suricata"}
            ]
        },
        "docs_url": "https://suricata.io/",
        "privacy_note": "Evaluates local PCAP captures offline."
    },

    "fakenet": {
        "id": "fakenet",
        "name": "FakeNet-NG",
        "category": "network_analysis",
        "description": "Next-generation dynamic network simulation tool for malware analysis.",
        "auth_types_supported": ["local_executable"],
        "default_auth_type": "local_executable",
        "oauth2_config": {"enabled": False},
        "local_executable_config": {
            "enabled": True,
            "binary_name": "fakenet.exe",
            "fields": [
                {"key": "binary_path", "label": "FakeNet Path", "type": "text", "placeholder": "fakenet"}
            ]
        },
        "docs_url": "https://github.com/mandiant/flare-fakenet-ng",
        "privacy_note": "Simulates DNS, HTTP, and SSL services locally on loopback."
    }
}


def get_auth_registry_item(provider_id: str) -> Optional[Dict[str, Any]]:
    """Retrieves authentication metadata specification for a provider."""
    return AUTHENTICATION_REGISTRY.get(provider_id.lower().strip())


def list_registered_providers() -> List[Dict[str, Any]]:
    """Returns all registered providers in category sequence."""
    return list(AUTHENTICATION_REGISTRY.values())

