import re
from typing import List, Dict, Any, Tuple
from backend.app.core.models import PePersistenceFinding

REGISTRY_PERSISTENCE_PATTERNS = [
    (re.compile(r'CurrentVersion\\Run\b', re.IGNORECASE), "Registry Run Key", "High", "Auto-start execution on every user login"),
    (re.compile(r'CurrentVersion\\RunOnce\b', re.IGNORECASE), "Registry RunOnce Key", "High", "Executes once during subsequent reboot/login"),
    (re.compile(r'Winlogon\\Userinit\b', re.IGNORECASE), "Winlogon Userinit Hijack", "Critical", "Hooks Windows user initialization sequence"),
    (re.compile(r'Winlogon\\Shell\b', re.IGNORECASE), "Winlogon Shell Replacement", "Critical", "Replaces or appends to standard Windows Explorer shell"),
    (re.compile(r'Windows\\CurrentVersion\\Policies\\Explorer\\Run\b', re.IGNORECASE), "Explorer Policy Run", "High", "Enterprise policy run key execution"),
    (re.compile(r'Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Shell Folders', re.IGNORECASE), "Shell Folders Query", "Medium", "Locating user startup directory"),
]

EXECUTION_PATTERNS = [
    (re.compile(r'schtasks(?:\.exe)?\s+/create', re.IGNORECASE), "Scheduled Task Creation", "High", "Creates persistent automated scheduled task"),
    (re.compile(r'sc(?:\.exe)?\s+create', re.IGNORECASE), "Service Creation via SC", "High", "Installs Windows service via command line"),
    (re.compile(r'vssadmin(?:\.exe)?\s+delete\s+shadows', re.IGNORECASE), "Ransomware Shadow Copy Deletion", "Critical", "Inhibits system recovery by deleting VSS volume snapshots"),
    (re.compile(r'bcdedit(?:\.exe)?\s+/set.+recoveryenabled\s+no', re.IGNORECASE), "Boot Recovery Invalidation", "Critical", "Disables Windows automatic recovery options"),
    (re.compile(r'powershell.*-(?:enc|encodedcommand|executionpolicy\s+bypass|windowstyle\s+hidden|nop|noprofile)', re.IGNORECASE), "Obfuscated PowerShell Execution", "High", "PowerShell invocation with evasion and bypass flags"),
    (re.compile(r'bitsadmin(?:\.exe)?\s+/(?:transfer|create)', re.IGNORECASE), "BITSAdmin Background Transfer", "High", "Uses Background Intelligent Transfer Service for persistent download"),
    (re.compile(r'certutil(?:\.exe)?\s+-(?:urlcache|decode)', re.IGNORECASE), "CertUtil Payload Download/Decode", "High", "LOLBAS abuse: CertUtil used to fetch or de-obfuscate files"),
    (re.compile(r'CommandLineEventConsumer', re.IGNORECASE), "WMI Event Subscription", "Critical", "WMI persistence executing payload on system events")
]

def analyze_pe_persistence(
    raw_strings: List[Dict[str, Any]],
    imported_apis: List[str]
) -> List[PePersistenceFinding]:
    """
    Examine PE strings, registry references, and API capabilities for Windows
    persistence mechanisms, execution helpers, and privilege escalation patterns.
    """
    findings: List[PePersistenceFinding] = []
    seen_mechanisms = set()
    counter = 1

    all_api_set = set(imported_apis)

    # 1. Registry persistence strings
    for item in raw_strings:
        val = item["value"]
        offset = item.get("offset", 0)
        section = item.get("section", "Unknown")

        for pattern, mech_name, severity, desc in REGISTRY_PERSISTENCE_PATTERNS:
            if pattern.search(val) and mech_name not in seen_mechanisms:
                seen_mechanisms.add(mech_name)
                
                # Check if correlated with registry writing APIs
                has_reg_write = any(api in all_api_set for api in ["RegSetValueExA", "RegSetValueExW", "RegCreateKeyExA", "RegCreateKeyExW"])
                indicator_type = "Correlated Pattern" if has_reg_write else "String Indicator"
                confidence = "High" if has_reg_write else "Medium"
                
                findings.append(PePersistenceFinding(
                    id=f"PE-PERSIST-{counter:03d}",
                    mechanism=mech_name,
                    indicator_type=indicator_type,
                    title=f"Windows Persistence Indicator: {mech_name}",
                    severity=severity,
                    confidence=confidence,
                    source_evidence=f"String in section '{section}' (offset 0x{offset:08X}): {val[:80]}",
                    details=f"{desc}. Correlated with registry write APIs: {has_reg_write}.",
                    limitations="Static analysis verifies presence of the registry target string in the binary; execution is not performed."
                ))
                counter += 1

    # 2. Execution and LOLBAS command strings
    for item in raw_strings:
        val = item["value"]
        offset = item.get("offset", 0)
        section = item.get("section", "Unknown")

        for pattern, exec_name, severity, desc in EXECUTION_PATTERNS:
            if pattern.search(val) and exec_name not in seen_mechanisms:
                seen_mechanisms.add(exec_name)
                findings.append(PePersistenceFinding(
                    id=f"PE-PERSIST-{counter:03d}",
                    mechanism=exec_name,
                    indicator_type="Command Pattern",
                    title=f"Execution / Persistence Command: {exec_name}",
                    severity=severity,
                    confidence="High",
                    source_evidence=f"Found in section '{section}' at offset 0x{offset:08X}: '{val[:100]}'",
                    details=f"{desc}. Matches known LOLBAS or persistence utility invocations.",
                    limitations="Static string pattern analysis; execution is not triggered."
                ))
                counter += 1

    # 3. API-based Windows Service installation
    if ("CreateServiceA" in all_api_set or "CreateServiceW" in all_api_set) and "Service Installation API" not in seen_mechanisms:
        seen_mechanisms.add("Service Installation API")
        findings.append(PePersistenceFinding(
            id=f"PE-PERSIST-{counter:03d}",
            mechanism="Windows Service Installation API",
            indicator_type="API Capability",
            title="Service Installation Capability (CreateService)",
            severity="High",
            confidence="High",
            source_evidence="Import Table: advapi32.dll!CreateService",
            details="Binary imports CreateService Win32 API capable of registering system-level background services for persistent host survivability.",
            limitations="API is present in the import table; service configuration details depend on runtime execution parameters."
        ))
        counter += 1

    # 4. API-based Process Injection chain
    has_injection = (
        ("VirtualAllocEx" in all_api_set or "VirtualProtectEx" in all_api_set) and
        ("WriteProcessMemory" in all_api_set or "NtWriteVirtualMemory" in all_api_set) and
        ("CreateRemoteThread" in all_api_set or "CreateRemoteThreadEx" in all_api_set)
    )
    if has_injection and "Process Injection" not in seen_mechanisms:
        seen_mechanisms.add("Process Injection")
        findings.append(PePersistenceFinding(
            id=f"PE-PERSIST-{counter:03d}",
            mechanism="Process Injection (Remote Thread Creation)",
            indicator_type="Correlated Pattern",
            title="Cross-Process Code Injection Capability",
            severity="Critical",
            confidence="High",
            source_evidence="Import Table: VirtualAllocEx + WriteProcessMemory + CreateRemoteThread",
            details="Binary possesses capability to allocate foreign process memory, write executable shellcode, and spawn remote threads for process evasion.",
            limitations="Static import correlation confirms capability; target process selection occurs at runtime."
        ))
        counter += 1

    return findings
