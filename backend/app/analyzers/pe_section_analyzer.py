import math
from typing import List, Tuple, Dict, Any
import pefile
from backend.app.core.models import PeSection, StaticFinding

KNOWN_STANDARD_SECTIONS = {
    ".text", ".data", ".rdata", ".idata", ".edata", ".rsrc",
    ".reloc", ".pdata", ".tls", ".bss", ".textbss", ".cormeta"
}

KNOWN_PACKER_SECTIONS = {
    "UPX0": "UPX Packer Section 0",
    "UPX1": "UPX Packer Section 1",
    "UPX2": "UPX Packer Section 2",
    ".aspack": "Aspack Packer",
    ".adata": "Aspack / Armadillo",
    "PEC2": "PECompact",
    ".mpress1": "MPRESS Packer",
    ".mpress2": "MPRESS Packer",
    ".themida": "Themida Protection",
    ".vmp0": "VMProtect Section 0",
    ".vmp1": "VMProtect Section 1",
    "FSG!": "FSG Packer"
}

def calculate_entropy(data: bytes) -> float:
    """Calculate standard Shannon entropy for a byte buffer (0.0 to 8.0)."""
    if not data:
        return 0.0
    entropy = 0.0
    length = len(data)
    occurrences = [0] * 256
    for b in data:
        occurrences[b] += 1
    for count in occurrences:
        if count > 0:
            p_x = count / length
            entropy -= p_x * math.log2(p_x)
    return round(entropy, 4)

def analyze_pe_sections(pe: pefile.PE, file_size: int) -> Tuple[List[PeSection], List[StaticFinding], Dict[str, Any]]:
    """
    Examine all PE sections for permissions, entropy, boundary integrity,
    size anomalies, and packer / injection heuristics.
    """
    sections: List[PeSection] = []
    findings: List[StaticFinding] = []
    summary: Dict[str, Any] = {
        "total_sections": len(pe.sections),
        "high_entropy_sections": 0,
        "writable_executable_sections": 0,
        "out_of_bounds_sections": 0,
        "entry_point_in_suspicious_section": False,
        "packer_indicators": []
    }

    entry_point_rva = getattr(pe.OPTIONAL_HEADER, 'AddressOfEntryPoint', 0)
    entry_point_section_name = None

    for idx, section in enumerate(pe.sections):
        raw_name = section.Name.decode('utf-8', errors='ignore').strip('\x00')
        sec_name = raw_name if raw_name else f"Section_{idx}"
        
        va = section.VirtualAddress
        vs = section.Misc_VirtualSize
        raw_offset = section.PointerToRawData
        raw_size = section.SizeOfRawData
        chars = section.Characteristics

        # Check permissions
        is_readable = bool(chars & 0x40000000)
        is_writable = bool(chars & 0x80000000)
        is_executable = bool(chars & 0x20000000)

        # Calculate section entropy
        try:
            sec_data = section.get_data()
            entropy = calculate_entropy(sec_data)
        except Exception:
            entropy = 0.0

        # Boundary checks
        is_oob = (raw_offset + raw_size) > file_size
        suspicious_indicators: List[str] = []

        # Check if entry point is in this section
        if va <= entry_point_rva < (va + max(vs, raw_size)):
            entry_point_section_name = sec_name

        # Heuristic 1: Writable + Executable (W+X)
        if is_writable and is_executable:
            suspicious_indicators.append("Writable and Executable memory permissions (W+X: potential self-modifying code or shellcode execution).")
            summary["writable_executable_sections"] += 1
            findings.append(StaticFinding(
                id=f"FIND-PE-SEC-WX-{idx:02d}",
                category="pe_sections",
                severity="High",
                confidence="High",
                title=f"Writable and Executable Section Detected ({sec_name})",
                description=f"Section '{sec_name}' has both IMAGE_SCN_MEM_WRITE and IMAGE_SCN_MEM_EXECUTE characteristics enabled.",
                source_file=sec_name,
                code_reference=f"RVA: 0x{va:08X}, RawOffset: 0x{raw_offset:08X}",
                evidence_snippet=f"Characteristics: 0x{chars:08X} (R={is_readable}, W={is_writable}, X={is_executable})",
                explanation="Legitimate modern executables strictly separate executable code from writable data (W^X). Having both permissions enables in-memory unpacking, code injection, or runtime hook patching.",
                remediation_advice="Review whether this executable uses an obfuscator, packer, or JIT engine, or whether it exhibits malicious shellcode staging."
            ))

        # Heuristic 2: High Entropy (> 7.2)
        if entropy > 7.2:
            suspicious_indicators.append(f"High Shannon entropy ({entropy:.2f}/8.0): suggests encrypted payload or compressed resources.")
            summary["high_entropy_sections"] += 1
            findings.append(StaticFinding(
                id=f"FIND-PE-SEC-ENTROPY-{idx:02d}",
                category="pe_sections",
                severity="Medium",
                confidence="Medium",
                title=f"High-Entropy Section ({sec_name}: {entropy:.2f})",
                description=f"Section '{sec_name}' contains data with an entropy of {entropy:.2f}, indicating compressed or encrypted content.",
                source_file=sec_name,
                code_reference=f"RawSize: {raw_size} bytes, VirtualSize: {vs} bytes",
                evidence_snippet=f"Entropy: {entropy:.4f}",
                explanation="High entropy is a classic indicator of packed binaries, encrypted shellcode, or embedded ransomware ciphers. However, it can also occur in compressed media or legitimate packed assets.",
                remediation_advice="Inspect strings and cross-reference with packer signatures and import table capability analysis."
            ))

        # Heuristic 3: Packer section names
        clean_name = sec_name.strip()
        if clean_name in KNOWN_PACKER_SECTIONS:
            desc = KNOWN_PACKER_SECTIONS[clean_name]
            suspicious_indicators.append(f"Known packer signature: {desc}")
            summary["packer_indicators"].append(desc)
            findings.append(StaticFinding(
                id=f"FIND-PE-PACKER-{idx:02d}",
                category="pe_sections",
                severity="Medium",
                confidence="High",
                title=f"Known Packer Section Identified ({sec_name})",
                description=f"Section '{sec_name}' corresponds to the signature of {desc}.",
                source_file=sec_name,
                code_reference=f"Section: {sec_name}",
                evidence_snippet=f"Matched packer signature: {desc}",
                explanation="Malware frequently utilizes executable packers to bypass static signature detection and complicate reverse engineering.",
                remediation_advice="Unpack sample using dedicated tools or examine memory dump if dynamic analysis is authorized."
            ))
        elif clean_name.lower() not in KNOWN_STANDARD_SECTIONS and not clean_name.startswith('/'):
            suspicious_indicators.append(f"Non-standard section name: '{clean_name}'")

        # Heuristic 4: Virtual size >> Raw size (Size discrepancy)
        if vs > 0 and raw_size > 0:
            ratio = vs / raw_size
            if ratio > 10.0 and vs > 65536:
                suspicious_indicators.append(f"Disproportionate virtual-to-raw size ratio ({ratio:.1f}x): suggests memory unrolling.")

        # Heuristic 5: Out of bounds
        if is_oob:
            suspicious_indicators.append("Section raw data pointers extend beyond EOF.")
            summary["out_of_bounds_sections"] += 1
            findings.append(StaticFinding(
                id=f"FIND-PE-SEC-OOB-{idx:02d}",
                category="pe_sections",
                severity="High",
                confidence="High",
                title=f"Out-of-Bounds Section Reference ({sec_name})",
                description=f"Section '{sec_name}' specifies raw offset {raw_offset} + raw size {raw_size} ({raw_offset + raw_size}) which exceeds physical file length ({file_size}).",
                source_file=sec_name,
                code_reference=f"Offset: {raw_offset}, Size: {raw_size}, FileSize: {file_size}",
                evidence_snippet="Raw data extends beyond file bounds",
                explanation="Truncated or deliberately malformed section headers are commonly used to crash analysis tools or conceal appended overlay payloads.",
                remediation_advice="Inspect sample in a safe disassembler and check for appended overlay data."
            ))

        char_desc = []
        if is_readable: char_desc.append("READ")
        if is_writable: char_desc.append("WRITE")
        if is_executable: char_desc.append("EXECUTE")

        sections.append(PeSection(
            name=sec_name,
            virtual_address=f"0x{va:08X}",
            virtual_size=vs,
            raw_data_offset=raw_offset,
            raw_data_size=raw_size,
            entropy=entropy,
            characteristics=f"0x{chars:08X} ({', '.join(char_desc) if char_desc else 'NONE'})",
            readable=is_readable,
            writable=is_writable,
            executable=is_executable,
            suspicious_indicators=suspicious_indicators,
            out_of_bounds=is_oob
        ))

    # Check if entry point is outside standard code section
    if entry_point_section_name and entry_point_section_name.lower() not in [".text", "code"]:
        summary["entry_point_in_suspicious_section"] = True
        findings.append(StaticFinding(
            id="FIND-PE-EP-ANOMALY",
            category="pe_sections",
            severity="Medium",
            confidence="Medium",
            title=f"Entry Point in Non-Standard Section ({entry_point_section_name})",
            description=f"The PE AddressOfEntryPoint (0x{entry_point_rva:08X}) is located inside section '{entry_point_section_name}' instead of standard '.text'.",
            source_file=entry_point_section_name,
            code_reference=f"EntryPoint: 0x{entry_point_rva:08X}",
            evidence_snippet=f"Located in: {entry_point_section_name}",
            explanation="Compilers standardly place the initial execution entry point in '.text'. Placing entry points in other sections (e.g. '.data', '.rsrc', or packed sections) strongly indicates packing, crypting, or code injection.",
            remediation_advice="Investigate instructions at the entry point to trace unpacking stub or initial payload execution."
        ))

    return sections, findings, summary
