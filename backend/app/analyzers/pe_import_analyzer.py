from typing import List, Dict, Any, Tuple
import pefile
from backend.app.core.models import ImportedDll, ImportedFunction, StaticFinding

# API Capability Knowledge Base
API_CAPABILITY_CATALOG: Dict[str, Dict[str, Any]] = {
    # 1. Network Communication
    "InternetOpenUrlA": {"category": "Network Communication", "severity": "Medium", "confidence": "Medium", "desc": "Connects to HTTP/FTP URL endpoint."},
    "InternetOpenUrlW": {"category": "Network Communication", "severity": "Medium", "confidence": "Medium", "desc": "Connects to HTTP/FTP URL endpoint."},
    "InternetConnectA": {"category": "Network Communication", "severity": "Medium", "confidence": "Medium", "desc": "Opens connection session with remote server."},
    "InternetConnectW": {"category": "Network Communication", "severity": "Medium", "confidence": "Medium", "desc": "Opens connection session with remote server."},
    "InternetReadFile": {"category": "Network Communication", "severity": "Medium", "confidence": "Medium", "desc": "Reads incoming data from active network request."},
    "InternetWriteFile": {"category": "Network Communication", "severity": "Medium", "confidence": "Medium", "desc": "Sends data over HTTP/FTP network connection."},
    "WinHttpOpen": {"category": "Network Communication", "severity": "Low", "confidence": "Medium", "desc": "Initializes WinHTTP communication session."},
    "WinHttpConnect": {"category": "Network Communication", "severity": "Medium", "confidence": "Medium", "desc": "Specifies initial target server for WinHTTP request."},
    "WinHttpSendRequest": {"category": "Network Communication", "severity": "Medium", "confidence": "Medium", "desc": "Transmits request to HTTP/HTTPS destination."},
    "HttpSendRequestA": {"category": "Network Communication", "severity": "Medium", "confidence": "Medium", "desc": "Transmits HTTP request over WinInet."},
    "HttpSendRequestW": {"category": "Network Communication", "severity": "Medium", "confidence": "Medium", "desc": "Transmits HTTP request over WinInet."},
    "URLDownloadToFileA": {"category": "Network Communication", "severity": "High", "confidence": "High", "desc": "Directly downloads remote URL content to local file (frequent downloader trojan artifact)."},
    "URLDownloadToFileW": {"category": "Network Communication", "severity": "High", "confidence": "High", "desc": "Directly downloads remote URL content to local file (frequent downloader trojan artifact)."},
    "socket": {"category": "Network Communication", "severity": "Medium", "confidence": "Medium", "desc": "Creates raw TCP/UDP network socket."},
    "connect": {"category": "Network Communication", "severity": "Medium", "confidence": "Medium", "desc": "Establishes connection to remote socket host and port."},
    "send": {"category": "Network Communication", "severity": "Medium", "confidence": "Medium", "desc": "Transmits outbound data buffer over active socket."},
    "recv": {"category": "Network Communication", "severity": "Medium", "confidence": "Medium", "desc": "Receives inbound payload or command stream over active socket."},
    "WSAStartup": {"category": "Network Communication", "severity": "Low", "confidence": "Medium", "desc": "Initializes Windows Sockets implementation."},
    "getaddrinfo": {"category": "Network Communication", "severity": "Low", "confidence": "Medium", "desc": "Translates host name or IP address to network address structure."},
    "DnsQuery_A": {"category": "Network Communication", "severity": "Medium", "confidence": "Medium", "desc": "Conducts standard or specialized DNS resolution queries."},
    "DnsQuery_W": {"category": "Network Communication", "severity": "Medium", "confidence": "Medium", "desc": "Conducts standard or specialized DNS resolution queries."},

    # 2. Process Execution
    "CreateProcessA": {"category": "Process Execution", "severity": "Medium", "confidence": "Medium", "desc": "Launches a new application process and its primary thread."},
    "CreateProcessW": {"category": "Process Execution", "severity": "Medium", "confidence": "Medium", "desc": "Launches a new application process and its primary thread."},
    "ShellExecuteA": {"category": "Process Execution", "severity": "Medium", "confidence": "Medium", "desc": "Executes shell command or launches application through Windows Shell."},
    "ShellExecuteW": {"category": "Process Execution", "severity": "Medium", "confidence": "Medium", "desc": "Executes shell command or launches application through Windows Shell."},
    "ShellExecuteExA": {"category": "Process Execution", "severity": "Medium", "confidence": "Medium", "desc": "Extended shell execution supporting elevated execution (runas)."},
    "ShellExecuteExW": {"category": "Process Execution", "severity": "Medium", "confidence": "Medium", "desc": "Extended shell execution supporting elevated execution (runas)."},
    "WinExec": {"category": "Process Execution", "severity": "High", "confidence": "High", "desc": "Legacy API executing command line process (often found in simple droppers)."},
    "CreateProcessInternalW": {"category": "Process Execution", "severity": "High", "confidence": "High", "desc": "Low-level unexported kernel32 routine for process creation."},

    # 3. Memory Manipulation and Possible Injection
    "VirtualAllocEx": {"category": "Memory Manipulation & Injection", "severity": "High", "confidence": "High", "desc": "Allocates virtual memory space within a foreign target process."},
    "WriteProcessMemory": {"category": "Memory Manipulation & Injection", "severity": "High", "confidence": "High", "desc": "Writes data directly into the virtual address space of a target process."},
    "CreateRemoteThread": {"category": "Memory Manipulation & Injection", "severity": "Critical", "confidence": "High", "desc": "Creates a execution thread inside another process (classic DLL/shellcode injection primitive)."},
    "CreateRemoteThreadEx": {"category": "Memory Manipulation & Injection", "severity": "Critical", "confidence": "High", "desc": "Creates an extended execution thread in a foreign process."},
    "VirtualProtectEx": {"category": "Memory Manipulation & Injection", "severity": "High", "confidence": "High", "desc": "Alters page protection (e.g. RW -> RWX) in a foreign target process."},
    "VirtualProtect": {"category": "Memory Manipulation & Injection", "severity": "Medium", "confidence": "Medium", "desc": "Modifies page execution and write protection in local process."},
    "NtWriteVirtualMemory": {"category": "Memory Manipulation & Injection", "severity": "High", "confidence": "High", "desc": "Native system call writing directly into remote process memory."},
    "NtCreateThreadEx": {"category": "Memory Manipulation & Injection", "severity": "Critical", "confidence": "High", "desc": "Undocumented native NT system call used for process injection."},
    "QueueUserAPC": {"category": "Memory Manipulation & Injection", "severity": "High", "confidence": "High", "desc": "Queues Asynchronous Procedure Call to a thread (Early Bird injection)."},
    "SetThreadContext": {"category": "Memory Manipulation & Injection", "severity": "High", "confidence": "High", "desc": "Modifies CPU register context of target thread (used in Process Hollowing)."},
    "GetThreadContext": {"category": "Memory Manipulation & Injection", "severity": "Medium", "confidence": "Medium", "desc": "Retrieves CPU register state for a suspended thread."},
    "ResumeThread": {"category": "Memory Manipulation & Injection", "severity": "Medium", "confidence": "Medium", "desc": "Resumes suspended thread execution after code or context injection."},

    # 4. Persistence-Related APIs
    "RegCreateKeyExA": {"category": "Persistence", "severity": "Medium", "confidence": "Medium", "desc": "Creates or opens Windows Registry subkeys (e.g. Run/RunOnce)."},
    "RegCreateKeyExW": {"category": "Persistence", "severity": "Medium", "confidence": "Medium", "desc": "Creates or opens Windows Registry subkeys (e.g. Run/RunOnce)."},
    "RegSetValueExA": {"category": "Persistence", "severity": "Medium", "confidence": "Medium", "desc": "Writes value data under a registry key (e.g. startup persistence)."},
    "RegSetValueExW": {"category": "Persistence", "severity": "Medium", "confidence": "Medium", "desc": "Writes value data under a registry key (e.g. startup persistence)."},
    "CreateServiceA": {"category": "Persistence", "severity": "High", "confidence": "High", "desc": "Installs and registers a new Windows Service for background persistence."},
    "CreateServiceW": {"category": "Persistence", "severity": "High", "confidence": "High", "desc": "Installs and registers a new Windows Service for background persistence."},
    "StartServiceA": {"category": "Persistence", "severity": "Medium", "confidence": "Medium", "desc": "Starts a registered Windows service executable."},
    "StartServiceW": {"category": "Persistence", "severity": "Medium", "confidence": "Medium", "desc": "Starts a registered Windows service executable."},
    "OpenSCManagerA": {"category": "Persistence", "severity": "Medium", "confidence": "Medium", "desc": "Opens connection to the Service Control Manager on the local or remote computer."},
    "OpenSCManagerW": {"category": "Persistence", "severity": "Medium", "confidence": "Medium", "desc": "Opens connection to the Service Control Manager on the local or remote computer."},

    # 5. Credential and System Access
    "OpenProcessToken": {"category": "Credential & System Access", "severity": "Medium", "confidence": "Medium", "desc": "Retrieves the access token for a target process."},
    "DuplicateTokenEx": {"category": "Credential & System Access", "severity": "High", "confidence": "Medium", "desc": "Duplicates access token for privilege escalation or impersonation."},
    "CryptUnprotectData": {"category": "Credential & System Access", "severity": "High", "confidence": "High", "desc": "Decrypts DPAPI-protected user credentials (browser logins, cookies, wifi passwords)."},
    "CredEnumerateA": {"category": "Credential & System Access", "severity": "High", "confidence": "High", "desc": "Enumerates stored credentials in Windows Credential Vault."},
    "CredEnumerateW": {"category": "Credential & System Access", "severity": "High", "confidence": "High", "desc": "Enumerates stored credentials in Windows Credential Vault."},
    "GetKeyState": {"category": "Credential & System Access", "severity": "Medium", "confidence": "Medium", "desc": "Checks keystroke state (frequently used in simple keylogger loops)."},
    "GetAsyncKeyState": {"category": "Credential & System Access", "severity": "High", "confidence": "High", "desc": "Polls asynchronous keypress states (classic polling keylogger indicator)."},
    "SetWindowsHookExA": {"category": "Credential & System Access", "severity": "High", "confidence": "High", "desc": "Installs application-defined hook procedure (global keyboard/mouse hook keylogging)."},
    "SetWindowsHookExW": {"category": "Credential & System Access", "severity": "High", "confidence": "High", "desc": "Installs application-defined hook procedure (global keyboard/mouse hook keylogging)."},

    # 6. Anti-Analysis and Environment Checks
    "IsDebuggerPresent": {"category": "Anti-Analysis", "severity": "Low", "confidence": "Medium", "desc": "Checks if calling process is running under an active user-mode debugger."},
    "CheckRemoteDebuggerPresent": {"category": "Anti-Analysis", "severity": "Medium", "confidence": "Medium", "desc": "Queries kernel whether debugger is attached to the target process."},
    "NtQueryInformationProcess": {"category": "Anti-Analysis", "severity": "Medium", "confidence": "Medium", "desc": "Queries internal process information (ProcessDebugPort, ProcessDebugFlags)."},
    "QueryPerformanceCounter": {"category": "Anti-Analysis", "severity": "Low", "confidence": "Low", "desc": "High-resolution time counter; frequently used for debugger timing evasion."},
    "GetTickCount": {"category": "Anti-Analysis", "severity": "Low", "confidence": "Low", "desc": "Queries elapsed system milliseconds (often used for anti-sandbox sleep evasion)."},
    "OutputDebugStringA": {"category": "Anti-Analysis", "severity": "Low", "confidence": "Low", "desc": "Sends string to debugger for display; can be used for anti-debugger checks."},
    "Sleep": {"category": "Anti-Analysis", "severity": "Low", "confidence": "Low", "desc": "Suspends thread execution; long sleep calls are often used to evade sandbox timeouts."}
}

def analyze_pe_imports(pe: pefile.PE) -> Tuple[List[ImportedDll], List[StaticFinding], Dict[str, Any]]:
    """
    Parse import directory table and map APIs against forensic capability catalog.
    Returns:
    - Structured list of imported DLLs and their functions
    - List of StaticFinding objects for categorized suspicious capabilities
    - Summary dictionary with category counts
    """
    imported_dlls: List[ImportedDll] = []
    findings: List[StaticFinding] = []
    category_counts: Dict[str, int] = {
        "Network Communication": 0,
        "Process Execution": 0,
        "Memory Manipulation & Injection": 0,
        "Persistence": 0,
        "Credential & System Access": 0,
        "Anti-Analysis": 0
    }

    if not hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
        return imported_dlls, findings, {"total_dlls": 0, "total_apis": 0, "categories": category_counts}

    finding_counter = 1
    total_apis = 0

    for entry in pe.DIRECTORY_ENTRY_IMPORT:
        dll_name = entry.dll.decode('utf-8', errors='ignore') if entry.dll else "Unknown.dll"
        func_list: List[ImportedFunction] = []

        for imp in entry.imports:
            total_apis += 1
            func_name = None
            if imp.name:
                func_name = imp.name.decode('utf-8', errors='ignore')
            elif imp.ordinal:
                func_name = f"Ordinal_{imp.ordinal}"

            if not func_name:
                continue

            # Check in capability catalog
            rule = API_CAPABILITY_CATALOG.get(func_name)
            if rule:
                category = rule["category"]
                severity = rule["severity"]
                confidence = rule["confidence"]
                desc = rule["desc"]

                if category in category_counts:
                    category_counts[category] += 1

                func_list.append(ImportedFunction(
                    name=func_name,
                    ordinal=imp.ordinal if hasattr(imp, 'ordinal') else None,
                    category=category,
                    severity=severity,
                    confidence=confidence,
                    why_relevant=desc
                ))

                # Create forensic static finding
                findings.append(StaticFinding(
                    id=f"FIND-PE-API-{finding_counter:03d}",
                    category="pe_imports",
                    severity=severity,
                    confidence=confidence,
                    title=f"Suspicious API Import: {func_name} ({category})",
                    description=f"Imported from '{dll_name}'. Capability: {desc}",
                    source_file=dll_name,
                    code_reference=f"DLL: {dll_name}!{func_name}",
                    evidence_snippet=f"Import entry address: 0x{imp.address:08X}" if hasattr(imp, 'address') and imp.address else f"Import: {dll_name}!{func_name}",
                    explanation=f"The Windows API '{func_name}' is associated with {category.lower()} behavior. Note: legitimate utilities also invoke these APIs; presence indicates analytical capability rather than definitive malicious verdict.",
                    remediation_advice="Correlate this import with binary strings, cross-references, and persistence indicators."
                ))
                finding_counter += 1
            else:
                func_list.append(ImportedFunction(
                    name=func_name,
                    ordinal=imp.ordinal if hasattr(imp, 'ordinal') else None,
                    category="System / General",
                    severity="Informational",
                    confidence="Medium",
                    why_relevant="Standard platform dependency."
                ))

        imported_dlls.append(ImportedDll(
            dll_name=dll_name,
            functions=func_list
        ))

    # Detect high-risk injection combos (e.g., VirtualAllocEx + WriteProcessMemory + CreateRemoteThread)
    all_func_names = {f.name for dll in imported_dlls for f in dll.functions}
    has_injection_triad = (
        ("VirtualAllocEx" in all_func_names or "VirtualProtectEx" in all_func_names) and
        ("WriteProcessMemory" in all_func_names or "NtWriteVirtualMemory" in all_func_names) and
        ("CreateRemoteThread" in all_func_names or "CreateRemoteThreadEx" in all_func_names or "NtCreateThreadEx" in all_func_names)
    )

    if has_injection_triad:
        findings.append(StaticFinding(
            id="FIND-PE-INJECTION-CHAIN",
            category="pe_imports",
            severity="Critical",
            confidence="High",
            title="Correlated Process Injection API Triad Detected",
            description="The binary imports the classic foreign-process injection chain: Memory Allocation (VirtualAllocEx) + Process Memory Write (WriteProcessMemory) + Remote Thread Creation (CreateRemoteThread).",
            source_file="kernel32.dll / ntdll.dll",
            code_reference="Triad: VirtualAllocEx -> WriteProcessMemory -> CreateRemoteThread",
            evidence_snippet=f"Imported APIs: {[api for api in ['VirtualAllocEx', 'WriteProcessMemory', 'CreateRemoteThread'] if api in all_func_names]}",
            explanation="This specific combination of Win32 memory manipulation APIs is standardly utilized by trojans and rootkits to hollow out legitimate processes (e.g. svchost.exe, explorer.exe) or execute unbacked shellcode.",
            remediation_advice="Inspect disassembly around these call sites to determine target process naming and injected payload payloads."
        ))

    summary = {
        "total_dlls": len(imported_dlls),
        "total_apis": total_apis,
        "categories": category_counts,
        "injection_chain_detected": has_injection_triad
    }

    return imported_dlls, findings, summary
