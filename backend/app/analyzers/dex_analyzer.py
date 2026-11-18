import re
from typing import List, Dict, Any, Tuple
from pathlib import Path
from backend.app.core.models import StaticFinding

SUSPICIOUS_DEX_PATTERNS = [
    {
        "id": "DEX-001",
        "category": "dynamic_loading",
        "title": "Dynamic Code Loading (DexClassLoader)",
        "pattern": r'(?:dalvik/system/(?:DexClassLoader|PathClassLoader|InMemoryDexClassLoader))',
        "severity": "High",
        "confidence": "High",
        "description": "Application instantiates dynamic Dalvik/ART class loaders to execute external or dropped bytecode.",
        "explanation": "Dynamic class loading is frequently leveraged by Android droppers and banking trojans to fetch and run encrypted secondary payloads from C2, evading static detection.",
        "remediation_advice": "Ensure all code is statically packaged and signed within the base APK unless modular dynamic feature delivery is explicitly documented."
    },
    {
        "id": "DEX-002",
        "category": "reflection",
        "title": "Java Reflection & Method Invocation",
        "pattern": r'(?:java/lang/reflect/Method->invoke|java/lang/Class->forName|java/lang/Class->getMethod)',
        "severity": "Medium",
        "confidence": "Medium",
        "description": "Application dynamically resolves classes and invokes methods via reflection.",
        "explanation": "Reflection can be used legitimately in frameworks, but in malware it often hides invocation of sensitive Android APIs (e.g., hidden telephony, package installation, or runtime shell calls).",
        "remediation_advice": "Audit the resolved class and method strings to ensure sensitive APIs are not obfuscated."
    },
    {
        "id": "DEX-003",
        "category": "process_exec",
        "title": "Runtime Process & Shell Command Execution",
        "pattern": r'(?:java/lang/Runtime->exec|java/lang/ProcessBuilder)',
        "severity": "High",
        "confidence": "Confirmed",
        "description": "Application invokes local operating system binaries or shell interpreters via ProcessBuilder or Runtime.exec.",
        "explanation": "Spawning shell processes enables root privilege escalation, reverse shell pipes, or background command execution on the Linux subsystem.",
        "remediation_advice": "Inspect the argument strings passed to Runtime.exec/ProcessBuilder to verify command boundaries."
    },
    {
        "id": "DEX-004",
        "category": "crypto",
        "title": "Cryptographic Cipher Usage",
        "pattern": r'(?:javax/crypto/Cipher->getInstance)',
        "severity": "Low",
        "confidence": "High",
        "description": "Application performs symmetric or asymmetric cryptographic cipher operations.",
        "explanation": "Cryptographic routines are standard in secure apps, but can also decrypt obfuscated C2 hostnames, strings, or secondary payload DEX files.",
        "remediation_advice": "Cross-reference cipher initialization with nearby string tables and static keys."
    },
    {
        "id": "DEX-005",
        "category": "network",
        "title": "Low-Level TCP/UDP Socket Communication",
        "pattern": r'(?:java/net/Socket|java/net/ServerSocket)',
        "severity": "Medium",
        "confidence": "High",
        "description": "Application opens direct TCP/UDP network sockets.",
        "explanation": "Direct socket communication bypasses HTTP proxies and is frequently utilized in reverse shells and custom binary C2 protocols.",
        "remediation_advice": "Trace socket destination IP/port parameters in the corresponding methods."
    },
    {
        "id": "DEX-006",
        "category": "webview",
        "title": "WebView JavaScript Interface Bridge",
        "pattern": r'(?:android/webkit/WebView->addJavascriptInterface)',
        "severity": "Medium",
        "confidence": "High",
        "description": "Application exposes native Java objects to JavaScript execution context inside a WebView.",
        "explanation": "If untrusted or remote HTML content is loaded into the WebView, exposed JavaScript interfaces can enable remote code execution on older Android platforms or unauthorized local API calls.",
        "remediation_advice": "Ensure only trusted local assets are loaded and ensure targetSdk >= 17 with @JavascriptInterface annotations."
    },
    {
        "id": "DEX-007",
        "category": "anti_analysis",
        "title": "Anti-Analysis & Environment Detection",
        "pattern": r'(?:android/os/Debug->isDebuggerConnected|ro\.kernel\.qemu|generic|goldfish)',
        "severity": "Medium",
        "confidence": "Medium",
        "description": "Application inspects system properties or debugging flags to detect virtual environments or debuggers.",
        "explanation": "Evasion logic halts malicious behavior or exhibits benign decoy behavior when running inside dynamic analysis sandboxes or under forensic debuggers.",
        "remediation_advice": "Examine evasion logic to identify true malicious branches."
    },
    {
        "id": "DEX-008",
        "category": "telephony",
        "title": "Direct SMS Transmission API",
        "pattern": r'(?:android/telephony/SmsManager->sendTextMessage)',
        "severity": "High",
        "confidence": "Confirmed",
        "description": "Application directly transmits SMS messages via SmsManager.",
        "explanation": "Direct SMS transmission without user SMS compose UI is strongly correlated with toll-fraud trojans or remote SMS exfiltration.",
        "remediation_advice": "Identify recipient destination numbers and SMS body templates in DEX bytecode."
    },
    {
        "id": "DEX-009",
        "category": "database_access",
        "title": "Embedded Remote Database Connection Configuration",
        "pattern": r'(?:connectDb|mongodb://|jdbc:|sqlite3_exec|Lcom/.*/connectDb)',
        "severity": "High",
        "confidence": "Confirmed",
        "description": "Application bytecode or strings contain remote database connection configuration methods (e.g. MongoDB URI). Note: Passive static extraction identifies embedded connection strings; active credential verification requires authorized connectivity validation.",
        "explanation": "Directly connecting to remote backend databases (e.g. MongoDB, MySQL) exposes database credentials and infrastructure directly to reverse engineering.",
        "remediation_advice": "Mediate all database operations through authenticated backend REST/gRPC API microservices."
    },
    {
        "id": "DEX-010",
        "category": "c2_channel",
        "title": "Embedded Telegram Bot API Notification Endpoint",
        "pattern": r'(?:notifyViaTelegram|api\.telegram\.org/bot)',
        "severity": "High",
        "confidence": "Confirmed",
        "description": "Application strings or bytecode define Telegram bot notification routines or API endpoints (Candidate C2 / Alerting Channel). Passive static inspection confirms the embedded URL structure; active C2 communication requires corroborating network traffic telemetry.",
        "explanation": "Telegram Bot APIs are frequently leveraged by threat actors as stealthy, encrypted C2 and victim data exfiltration channels.",
        "remediation_advice": "Audit the chat_id, bot_token, and payload parameters being dispatched to Telegram."
    },
    {
        "id": "DEX-011",
        "category": "exfiltration",
        "title": "Automated Photo / Document Upload Routine",
        "pattern": r'(?:uploadPhoto|/api/v1/photos/upload)',
        "severity": "Medium",
        "confidence": "High",
        "description": "Application defines automated media/photo upload handlers directed to remote endpoints.",
        "explanation": "Automated photo or media upload routines are common in spyware and stalkerware harvesting personal media from compromised devices.",
        "remediation_advice": "Verify user authorization and explicit consent prompts preceding media transmission."
    },
    {
        "id": "DEX-012",
        "category": "exfiltration",
        "title": "Direct SMTP Mailer / Email Dispatch Method",
        "pattern": r'(?:sendEmailInvite|javax/mail|smtp\.host)',
        "severity": "Medium",
        "confidence": "High",
        "description": "Bytecode incorporates embedded SMTP mail generation and transmission methods.",
        "explanation": "Direct SMTP mailers can be utilized to send unsolicited spam, exfiltrate stolen credentials, or phish victim contacts without host email client awareness.",
        "remediation_advice": "Inspect SMTP server configuration and recipient email parameters."
    },
    {
        "id": "DEX-013",
        "category": "threat_intel",
        "title": "Embedded Developer Watermark / Handle in Strings (@kodexhacks)",
        "pattern": r'(?:@kodexhacks|kodexhacks)',
        "severity": "Medium",
        "confidence": "Medium",
        "description": "Application strings contain embedded handle or watermark '@kodexhacks'. Note: This represents an embedded developer identifier/watermark and serves as an investigative lead; static string presence alone does not establish legal or definitive threat actor attribution.",
        "explanation": "Watermarks or embedded usernames may indicate developer reuse, open-source template authoring, or deliberate false flags. Attribution requires multi-source corroboration and forensic timeline analysis.",
        "remediation_advice": "Pivot on handle across open-source repositories and forensic databases as an investigative lead without asserting definitive threat actor attribution."
    },
    {
        "id": "DEX-014",
        "category": "credentials",
        "title": "Extracted Static Server Authentication Token",
        "pattern": r'(?:getAdminToken|buildAuthHeader|server\.api_key|server\.api_secret)',
        "severity": "High",
        "confidence": "Confirmed",
        "description": "Application bytecode defines methods referencing static server authentication token strings or headers. Note: Passive static identification; credential validity and authorization cannot be determined solely via static analysis.",
        "explanation": "Hardcoded admin tokens enable attackers to seize control of server APIs and compromise all associated infrastructure.",
        "remediation_advice": "Revoke exposed server API tokens and implement secure token exchange protocols."
    },
    {
        "id": "DEX-015",
        "category": "evasion",
        "title": "Root Privilege & Environment Check",
        "pattern": r'(?:/system/bin/su|/system/xbin/su|Superuser\.apk|magisk|daemonsu)',
        "severity": "Medium",
        "confidence": "Medium",
        "description": "Bytecode contains references to root binary paths or management tools.",
        "explanation": "Used either to detect rooted environments for anti-analysis or to elevate privileges on compromised devices.",
        "remediation_advice": "Audit root-checking methods to verify whether the app requests su access or checks for anti-tamper."
    },
    {
        "id": "DEX-016",
        "category": "telephony",
        "title": "Device Identifier & Telephony Profiling",
        "pattern": r'(?:getDeviceId|getImei|getSubscriberId|getSimSerialNumber)',
        "severity": "Medium",
        "confidence": "High",
        "description": "Application queries unique device identifiers (IMEI, IMSI, SIM Serial Number).",
        "explanation": "Aggressive device fingerprinting is characteristic of spyware and banking trojans tracking unique hardware installations.",
        "remediation_advice": "Migrate to scoped App Set IDs or Android ID in accordance with privacy guidelines."
    }
]

def analyze_dex_content(dex_strings: List[str], dex_methods: List[str], source_file: str = "classes.dex") -> List[StaticFinding]:
    """
    Scans extracted DEX methods, strings, and class references for security indicators.
    """
    findings: List[StaticFinding] = []
    
    # Combined string for fast regex scanning
    all_methods_text = "\n".join(dex_methods)
    all_strings_text = "\n".join(dex_strings)
    
    for rule in SUSPICIOUS_DEX_PATTERNS:
        pattern = re.compile(rule["pattern"])
        matches = pattern.findall(all_methods_text) or pattern.findall(all_strings_text)
        if matches:
            # Find sample matching method or string for evidence snippet
            matching_items = [m for m in dex_methods if pattern.search(m)]
            evidence = matching_items[0] if matching_items else (matches[0] if matches else "")
            
            findings.append(StaticFinding(
                id=rule["id"],
                category=rule["category"],
                severity=rule["severity"],
                confidence=rule["confidence"],
                title=rule["title"],
                description=rule["description"],
                source_file=source_file,
                code_reference=evidence[:150] if evidence else None,
                evidence_snippet=evidence[:120] if evidence else None,
                explanation=rule["explanation"],
                remediation_advice=rule["remediation_advice"]
            ))
            
    return findings
