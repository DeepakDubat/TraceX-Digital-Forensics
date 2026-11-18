import struct
import math
import re
from pathlib import Path
from datetime import datetime
from typing import Dict, Any, List, Tuple, Optional

from backend.app.core.models import ExtractedArtifact, FindingRecord
from backend.app.analyzers.yara_scanner import run_yara_scan

# ELF Machine Architecture Constants
ELF_MACHINES = {
    0: "None / Unknown",
    2: "SPARC",
    3: "x86 / Intel 80386",
    8: "MIPS",
    20: "PowerPC",
    21: "PowerPC 64-bit",
    40: "ARM (32-bit)",
    42: "SuperH",
    50: "IA-64 (Itanium)",
    62: "x86-64 / AMD64",
    183: "AArch64 (ARM 64-bit)",
    243: "RISC-V",
}

# ELF Object File Types
ELF_TYPES = {
    0: "ET_NONE (Unknown)",
    1: "ET_REL (Relocatable object file)",
    2: "ET_EXEC (Executable binary)",
    3: "ET_DYN (Shared object / Position-Independent Executable)",
    4: "ET_CORE (Core dump)",
}

# ELF OS / ABI
ELF_ABIS = {
    0: "UNIX - System V",
    1: "HP-UX",
    2: "NetBSD",
    3: "Linux",
    4: "GNU Hurd",
    6: "Solaris",
    7: "AIX",
    8: "IRIX",
    9: "FreeBSD",
    12: "OpenBSD",
}

# Program Header Segment Types
PT_TYPES = {
    0: "PT_NULL",
    1: "PT_LOAD",
    2: "PT_DYNAMIC",
    3: "PT_INTERP",
    4: "PT_NOTE",
    5: "PT_SHLIB",
    6: "PT_PHDR",
    7: "PT_TLS",
    0x6474e550: "PT_GNU_EH_FRAME",
    0x6474e551: "PT_GNU_STACK",
    0x6474e552: "PT_GNU_RELRO",
}

# Suspicious Linux APIs & System Calls
SUSPICIOUS_ELF_APIS = {
    "ptrace": ("Process Injection / Anti-Debugging", "critical"),
    "process_vm_writev": ("Cross-process Memory Injection", "critical"),
    "process_vm_readv": ("Cross-process Memory Inspection", "high"),
    "memfd_create": ("Fileless In-Memory Binary Execution", "critical"),
    "mprotect": ("Dynamic Memory Permission Modification (W+X)", "high"),
    "execve": ("Direct Binary / Shell Execution", "high"),
    "execvp": ("Subprocess Command Execution", "medium"),
    "system": ("Command Shell Execution", "high"),
    "popen": ("Piped Command Shell Execution", "high"),
    "socket": ("Raw Network Socket Creation", "medium"),
    "connect": ("Outbound Network Connection Establishment", "medium"),
    "bind": ("Network Port Binding / Listening Service", "medium"),
    "dup2": ("Standard I/O Redirection (Reverse Shell Indicator)", "high"),
    "fork": ("Process Spawning / Background Forking", "low"),
    "daemon": ("Background Daemonization", "medium"),
    "dlopen": ("Dynamic Shared Library Ingestion", "medium"),
    "dlsym": ("Dynamic Function Resolution / Evasion", "medium"),
    "chroot": ("Filesystem Root Jail Alteration", "high"),
    "setuid": ("Privilege Escalation / UID Change", "high"),
    "setgid": ("Privilege Escalation / GID Change", "medium"),
}

def _calculate_entropy(data: bytes) -> float:
    """Calculates Shannon entropy of a byte slice (0.0 to 8.0)."""
    if not data:
        return 0.0
    occ = [0] * 256
    for b in data:
        occ[b] += 1
    total = len(data)
    entropy = 0.0
    for count in occ:
        if count > 0:
            p = count / total
            entropy -= p * math.log2(p)
    return round(entropy, 4)

def analyze_elf_evidence(
    file_path: Path,
    evidence_id: str,
    investigation_id: str
) -> Tuple[Dict[str, Any], List[ExtractedArtifact], List[FindingRecord]]:
    """
    Static forensic analysis of Linux ELF executables and shared libraries:
    1. ELF Header parsing (e_ident, architecture, endianness, entry point)
    2. Program Headers (Segments) analysis and W+X / executable stack checks
    3. Section Headers, section entropy, and packer detection
    4. Dynamic segment inspection, interpreter (PT_INTERP), and DT_NEEDED libraries
    5. Symbol table parsing for suspicious Linux system calls & APIs
    6. ASCII/UTF-8 string extraction and network IOC identification
    7. YARA scanning against compiled rules
    Strict Non-Execution Invariant: The binary is strictly parsed as data.
    """
    artifacts: List[ExtractedArtifact] = []
    findings: List[FindingRecord] = []
    metadata: Dict[str, Any] = {
        "format": "elf",
        "bitness": "Unknown",
        "endianness": "Unknown",
        "machine": "Unknown",
        "type": "Unknown",
        "os_abi": "Unknown",
        "entry_point": "0x0",
        "interpreter": None,
        "segments": [],
        "sections": [],
        "dependencies": [],
        "suspicious_apis": [],
        "iocs": [],
        "yara_matches": [],
        "security_flags": {
            "has_wx_segment": False,
            "executable_stack": False,
            "is_pie": False,
            "is_stripped": False,
            "high_entropy_sections": []
        }
    }

    try:
        raw_bytes = file_path.read_bytes()
    except Exception as e:
        metadata["parser_error"] = f"Failed to read file: {str(e)}"
        return metadata, artifacts, findings

    if len(raw_bytes) < 52 or not raw_bytes.startswith(b"\x7fELF"):
        metadata["parser_error"] = "Invalid ELF magic bytes."
        return metadata, artifacts, findings

    # 1. Parse e_ident
    ei_class = raw_bytes[4] # 1 = 32-bit, 2 = 64-bit
    ei_data = raw_bytes[5]  # 1 = Little-endian, 2 = Big-endian
    ei_version = raw_bytes[6]
    ei_osabi = raw_bytes[7]

    is_64bit = (ei_class == 2)
    is_little = (ei_data == 1)
    endian_prefix = "<" if is_little else ">"

    metadata["bitness"] = "64-bit" if is_64bit else "32-bit"
    metadata["endianness"] = "Little-endian" if is_little else "Big-endian"
    metadata["os_abi"] = ELF_ABIS.get(ei_osabi, f"Unknown (0x{ei_osabi:02x})")

    # 2. Parse ELF Header
    try:
        if is_64bit:
            # 64-bit header: 64 bytes
            if len(raw_bytes) < 64:
                raise ValueError("Truncated 64-bit ELF header")
            (e_type, e_machine, e_version, e_entry, e_phoff, e_shoff,
             e_flags, e_ehsize, e_phentsize, e_phnum, e_shentsize, e_shnum, e_shstrndx) = struct.unpack(
                f"{endian_prefix}HHIQQQIHHHHHH", raw_bytes[16:64]
            )
        else:
            # 32-bit header: 52 bytes
            (e_type, e_machine, e_version, e_entry, e_phoff, e_shoff,
             e_flags, e_ehsize, e_phentsize, e_phnum, e_shentsize, e_shnum, e_shstrndx) = struct.unpack(
                f"{endian_prefix}HHIIIIIHHHHHH", raw_bytes[16:52]
            )
    except Exception as e:
        metadata["parser_error"] = f"Header parse error: {str(e)}"
        return metadata, artifacts, findings

    metadata["type"] = ELF_TYPES.get(e_type, f"Unknown ({e_type})")
    metadata["machine"] = ELF_MACHINES.get(e_machine, f"Unknown ({e_machine})")
    metadata["entry_point"] = f"0x{e_entry:X}"
    metadata["security_flags"]["is_pie"] = (e_type == 3)

    # 3. Parse Program Headers (Segments)
    segments = []
    has_wx_seg = False
    exec_stack = False

    if e_phoff > 0 and e_phnum > 0 and e_phoff < len(raw_bytes):
        for i in range(e_phnum):
            off = e_phoff + (i * e_phentsize)
            if off + e_phentsize > len(raw_bytes):
                break
            if is_64bit:
                # Elf64_Phdr: p_type(4), p_flags(4), p_offset(8), p_vaddr(8), p_paddr(8), p_filesz(8), p_memsz(8), p_align(8)
                p_type, p_flags, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_align = struct.unpack(
                    f"{endian_prefix}IIQQQQQQ", raw_bytes[off:off+56]
                )
            else:
                # Elf32_Phdr: p_type(4), p_offset(4), p_vaddr(4), p_paddr(4), p_filesz(4), p_memsz(4), p_flags(4), p_align(4)
                p_type, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_flags, p_align = struct.unpack(
                    f"{endian_prefix}IIIIIIII", raw_bytes[off:off+32]
                )

            type_name = PT_TYPES.get(p_type, f"0x{p_type:X}")
            r = bool(p_flags & 4)
            w = bool(p_flags & 2)
            x = bool(p_flags & 1)
            flag_str = f"{'R' if r else '-'}{'W' if w else '-'}{'X' if x else '-'}"

            # Check W+X
            if w and x and type_name == "PT_LOAD":
                has_wx_seg = True

            # Check Executable Stack
            if type_name == "PT_GNU_STACK" and x:
                exec_stack = True

            # Extract interpreter if PT_INTERP
            if type_name == "PT_INTERP" and p_offset < len(raw_bytes):
                interp_bytes = raw_bytes[p_offset:p_offset + p_filesz].split(b"\x00")[0]
                metadata["interpreter"] = interp_bytes.decode("latin-1", errors="replace")

            segments.append({
                "index": i,
                "type": type_name,
                "flags": flag_str,
                "offset": f"0x{p_offset:X}",
                "vaddr": f"0x{p_vaddr:X}",
                "file_size": p_filesz,
                "mem_size": p_memsz
            })

    metadata["segments"] = segments
    metadata["security_flags"]["has_wx_segment"] = has_wx_seg
    metadata["security_flags"]["executable_stack"] = exec_stack

    if has_wx_seg:
        findings.append(FindingRecord(
            id=f"FND-{investigation_id[-6:]}-ELF-WX",
            investigation_id=investigation_id,
            evidence_id=evidence_id,
            artifact_ids=[],
            title="Writable and Executable (W+X) ELF Segment Detected",
            description="The binary contains an execution segment marked as both writable and executable (W+X). This is a hallmark of unpacked shellcode, self-modifying code, or run-time code generation.",
            observation="Found PT_LOAD program header with flags PF_W | PF_X (RWX permissions).",
            interpretation="Enables arbitrary code generation and memory execution at runtime, characteristic of polymorphic malware or packers.",
            severity="Critical",
            confidence="High",
            analysis_method="Static ELF Program Header Dissection",
            source_location="Program Header Table (PT_LOAD)",
            analyzer_name="ELF Forensics Analyzer",
            analyzer_version="1.0.0"
        ))

    if exec_stack:
        findings.append(FindingRecord(
            id=f"FND-{investigation_id[-6:]}-ELF-STACK",
            investigation_id=investigation_id,
            evidence_id=evidence_id,
            artifact_ids=[],
            title="Executable Stack (NX Disabled) Detected",
            description="The ELF PT_GNU_STACK header specifies executable permissions. Stack execution protection is disabled, rendering the process vulnerable to stack buffer overflow exploitation.",
            observation="Found PT_GNU_STACK segment with PF_X executable flag enabled.",
            interpretation="Process stack is executable, indicating absence of modern exploit mitigation (NX/DEP).",
            severity="High",
            confidence="High",
            analysis_method="Static ELF Mitigation Audit",
            source_location="PT_GNU_STACK Header",
            analyzer_name="ELF Forensics Analyzer",
            analyzer_version="1.0.0"
        ))

    # 4. Parse Section Headers & Section Names
    sections = []
    shstrtab = b""
    if e_shoff > 0 and e_shnum > 0 and e_shstrndx < e_shnum:
        # First locate shstrtab
        shstr_off = e_shoff + (e_shstrndx * e_shentsize)
        if shstr_off + e_shentsize <= len(raw_bytes):
            if is_64bit:
                _, _, _, _, str_off, str_size, _, _, _, _ = struct.unpack(
                    f"{endian_prefix}IIQQQQIIQQ", raw_bytes[shstr_off:shstr_off+64]
                )
            else:
                _, _, _, _, str_off, str_size, _, _, _, _ = struct.unpack(
                    f"{endian_prefix}IIIIIIIIII", raw_bytes[shstr_off:shstr_off+40]
                )
            if str_off + str_size <= len(raw_bytes):
                shstrtab = raw_bytes[str_off:str_off + str_size]

    symtab_data = b""
    strtab_data = b""
    dynsym_data = b""
    dynstr_data = b""
    dynamic_data = b""

    for i in range(e_shnum):
        off = e_shoff + (i * e_shentsize)
        if off + e_shentsize > len(raw_bytes):
            break
        if is_64bit:
            sh_name_idx, sh_type, sh_flags, sh_addr, sh_offset, sh_size, sh_link, sh_info, sh_addralign, sh_entsize = struct.unpack(
                f"{endian_prefix}IIQQQQIIQQ", raw_bytes[off:off+64]
            )
        else:
            sh_name_idx, sh_type, sh_flags, sh_addr, sh_offset, sh_size, sh_link, sh_info, sh_addralign, sh_entsize = struct.unpack(
                f"{endian_prefix}IIIIIIIIII", raw_bytes[off:off+40]
            )

        # Resolve section name
        name = "unknown"
        if shstrtab and sh_name_idx < len(shstrtab):
            name_bytes = shstrtab[sh_name_idx:].split(b"\x00")[0]
            name = name_bytes.decode("latin-1", errors="replace")

        # Slice section content for entropy and inspection
        sec_bytes = b""
        if sh_offset + sh_size <= len(raw_bytes) and sh_type != 8: # 8 = SHT_NOBITS (.bss)
            sec_bytes = raw_bytes[sh_offset:sh_offset + sh_size]

        sec_entropy = _calculate_entropy(sec_bytes) if sec_bytes else 0.0

        # Save symbol/string tables
        if name == ".symtab":
            symtab_data = sec_bytes
        elif name == ".strtab":
            strtab_data = sec_bytes
        elif name == ".dynsym":
            dynsym_data = sec_bytes
        elif name == ".dynstr":
            dynstr_data = sec_bytes
        elif name == ".dynamic":
            dynamic_data = sec_bytes

        # Flags: W (1), A (2), X (4)
        is_w = bool(sh_flags & 1)
        is_a = bool(sh_flags & 2)
        is_x = bool(sh_flags & 4)

        if is_w and is_x and sh_size > 0:
            findings.append(FindingRecord(
                id=f"FND-{investigation_id[-6:]}-SEC-WX-{i}",
                investigation_id=investigation_id,
                evidence_id=evidence_id,
                artifact_ids=[],
                title=f"W+X Section Detected: {name}",
                description=f"Section '{name}' has both write and execute flags (SHF_WRITE | SHF_EXECINSTR). High likelihood of packing or shellcode payload.",
                observation=f"Section '{name}' header attributes specify writable and executable permissions.",
                interpretation="Writable and executable sections allow dynamic code alteration and in-memory shellcode execution.",
                severity="Critical",
                confidence="High",
                analysis_method="Static Section Header Inspection",
                source_location=f"Section Header [{name}]",
                analyzer_name="ELF Forensics Analyzer",
                analyzer_version="1.0.0"
            ))

        if sec_entropy > 7.2 and sh_size > 4096:
            metadata["security_flags"]["high_entropy_sections"].append(name)
            findings.append(FindingRecord(
                id=f"FND-{investigation_id[-6:]}-ENTROPY-{i}",
                investigation_id=investigation_id,
                evidence_id=evidence_id,
                artifact_ids=[],
                title=f"High Entropy Section: {name} ({sec_entropy:.2f})",
                description=f"Section '{name}' exhibits high Shannon entropy ({sec_entropy:.2f}/8.0), indicating encrypted, compressed, or packed binary code.",
                observation=f"Shannon entropy calculated at {sec_entropy:.2f} for {sh_size} bytes in section '{name}'.",
                interpretation="High entropy in executable sections suggests binary obfuscation, compression (e.g. UPX), or encrypted payload staging.",
                severity="Medium",
                confidence="High",
                analysis_method="Shannon Entropy Calculation",
                source_location=f"Section [{name}]",
                analyzer_name="ELF Forensics Analyzer",
                analyzer_version="1.0.0"
            ))

        sections.append({
            "index": i,
            "name": name,
            "type": sh_type,
            "flags": f"{'W' if is_w else '-'}{'A' if is_a else '-'}{'X' if is_x else '-'}",
            "address": f"0x{sh_addr:X}",
            "offset": f"0x{sh_offset:X}",
            "size": sh_size,
            "entropy": sec_entropy
        })

    metadata["sections"] = sections
    metadata["security_flags"]["is_stripped"] = (len(symtab_data) == 0)

    # 5. Extract Dynamic Dependencies (DT_NEEDED) from .dynamic & .dynstr
    dependencies = []
    if dynamic_data and dynstr_data:
        entry_size = 16 if is_64bit else 8
        count = len(dynamic_data) // entry_size
        for idx in range(count):
            e_off = idx * entry_size
            if is_64bit:
                d_tag, d_val = struct.unpack(f"{endian_prefix}QQ", dynamic_data[e_off:e_off+16])
            else:
                d_tag, d_val = struct.unpack(f"{endian_prefix}II", dynamic_data[e_off:e_off+8])

            if d_tag == 0: # DT_NULL
                break
            if d_tag == 1: # DT_NEEDED (offset into dynstr)
                if d_val < len(dynstr_data):
                    dep_name = dynstr_data[d_val:].split(b"\x00")[0].decode("latin-1", errors="replace")
                    if dep_name and dep_name not in dependencies:
                        dependencies.append(dep_name)

    metadata["dependencies"] = dependencies

    # 6. Parse Symbols and Check Suspicious APIs
    detected_suspicious = []
    target_strtab = dynstr_data or strtab_data
    target_symtab = dynsym_data or symtab_data

    if target_symtab and target_strtab:
        sym_size = 24 if is_64bit else 16
        sym_count = len(target_symtab) // sym_size
        for s_idx in range(min(sym_count, 10000)):
            s_off = s_idx * sym_size
            if is_64bit:
                st_name_idx, st_info, st_other, st_shndx, st_value, st_size = struct.unpack(
                    f"{endian_prefix}IBBHQQ", target_symtab[s_off:s_off+24]
                )
            else:
                st_name_idx, st_value, st_size, st_info, st_other, st_shndx = struct.unpack(
                    f"{endian_prefix}IIIBBH", target_symtab[s_off:s_off+16]
                )

            if st_name_idx < len(target_strtab):
                sym_name = target_strtab[st_name_idx:].split(b"\x00")[0].decode("latin-1", errors="replace")
                if sym_name in SUSPICIOUS_ELF_APIS and sym_name not in [d["api"] for d in detected_suspicious]:
                    desc, sev = SUSPICIOUS_ELF_APIS[sym_name]
                    detected_suspicious.append({
                        "api": sym_name,
                        "behavior": desc,
                        "severity": sev
                    })
                    findings.append(FindingRecord(
                        id=f"FND-{investigation_id[-6:]}-ELF-API-{len(detected_suspicious)}",
                        investigation_id=investigation_id,
                        evidence_id=evidence_id,
                        artifact_ids=[],
                        title=f"Suspicious Linux API: {sym_name}",
                        description=f"Imported/referenced symbol '{sym_name}' is commonly associated with: {desc}.",
                        observation=f"Found symbol table entry for syscall/library call '{sym_name}'.",
                        interpretation=f"Capability indicator: {desc}.",
                        severity=sev.capitalize(),
                        confidence="High",
                        analysis_method="Static Symbol Table Analysis",
                        source_location="ELF Symbol Table (.dynsym / .symtab)",
                        analyzer_name="ELF Forensics Analyzer",
                        analyzer_version="1.0.0"
                    ))

    metadata["suspicious_apis"] = detected_suspicious

    # 7. String Extraction & Network IOC Hunting
    extracted_strings = []
    ascii_strings = re.findall(b'[\x20-\x7e]{4,}', raw_bytes)
    for s in ascii_strings[:5000]:
        try:
            s_text = s.decode("ascii")
            extracted_strings.append(s_text)
        except Exception:
            pass

    # Regex hunt for IPv4, URLs, shell commands
    ip_pattern = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
    url_pattern = re.compile(r'https?://[a-zA-Z0-9\.\-_]+(?::\d+)?(?:/[^\s]*)?')
    shell_pattern = re.compile(r'(?:/bin/sh|/bin/bash|/bin/zsh|/dev/tcp/|nc\s+-e|curl\s+|wget\s+)')

    detected_iocs = []
    for s in extracted_strings:
        # Check URLs
        for url in url_pattern.findall(s):
            if url not in [i["value"] for i in detected_iocs]:
                detected_iocs.append({"type": "URL", "value": url})
        # Check IPs
        for ip in ip_pattern.findall(s):
            # Exclude broadcast/invalid
            parts = [int(p) for p in ip.split(".")]
            if all(0 <= p <= 255 for p in parts) and parts[0] not in (0, 127, 255):
                if ip not in [i["value"] for i in detected_iocs]:
                    detected_iocs.append({"type": "IPv4", "value": ip})
        # Check Shell triggers
        if shell_pattern.search(s):
            if s not in [i["value"] for i in detected_iocs]:
                detected_iocs.append({"type": "SHELL_COMMAND", "value": s[:120]})

    metadata["iocs"] = detected_iocs
    for idx, ioc in enumerate(detected_iocs[:20]):
        findings.append(FindingRecord(
            id=f"FND-{investigation_id[-6:]}-IOC-{idx}",
            investigation_id=investigation_id,
            evidence_id=evidence_id,
            artifact_ids=[],
            title=f"Static Network / Execution Indicator: {ioc['type']}",
            description=f"Extracted indicator from binary string tables: {ioc['value']}",
            observation=f"Matched pattern '{ioc['type']}' in binary byte strings.",
            interpretation=f"Hardcoded network indicator or command execution string: {ioc['value']}",
            severity="High" if ioc["type"] in ("SHELL_COMMAND", "URL") else "Medium",
            confidence="High",
            analysis_method="Static String Extraction & Regex Pattern Matching",
            source_location="Binary String Pools",
            analyzer_name="ELF Forensics Analyzer",
            analyzer_version="1.0.0"
        ))

    # 8. YARA Scanning
    try:
        yara_matches = run_yara_scan(file_path)
        metadata["yara_matches"] = yara_matches
        for y_idx, match in enumerate(yara_matches):
            rule_name = match.get("rule", "UnknownRule")
            findings.append(FindingRecord(
                id=f"FND-{investigation_id[-6:]}-YARA-{y_idx}",
                investigation_id=investigation_id,
                evidence_id=evidence_id,
                artifact_ids=[],
                title=f"YARA Detection: {rule_name}",
                description=f"Matched YARA rule '{rule_name}' with tags: {match.get('tags', [])}",
                observation=f"Binary matched compiled YARA rule '{rule_name}'.",
                interpretation=f"Signature match indicates known malware strain, shellcode pattern, or suspicious utility.",
                severity="Critical" if "malware" in rule_name.lower() or "trojan" in rule_name.lower() else "High",
                confidence="Confirmed",
                analysis_method="Compiled YARA Signature Evaluation",
                source_location="Compiled Rule Set",
                analyzer_name="YARA Scanner",
                analyzer_version="4.5.4"
            ))
    except Exception as e:
        metadata["yara_error"] = str(e)

    # 9. Register Extracted Binary Artifact
    artifacts.append(ExtractedArtifact(
        id=f"ART-{investigation_id[-6:]}-ELF-META",
        investigation_id=investigation_id,
        evidence_id=evidence_id,
        artifact_type="elf_metadata",
        source_format="elf",
        source_location="ELF Header & Section Tables",
        value=f"{metadata['bitness']} {metadata['machine']} ({len(sections)} sections, {len(dependencies)} dynamic dependencies)",
        structured_data={"sections": len(sections), "segments": len(segments), "bitness": metadata["bitness"], "machine": metadata["machine"]},
        extractor_name="ELF Forensics Analyzer",
        extracted_at=datetime.utcnow(),
        confidence="Confirmed"
    ))

    return metadata, artifacts, findings
