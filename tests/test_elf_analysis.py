import struct
import tempfile
from pathlib import Path
import pytest
from backend.app.analyzers.universal.elf_analyzer import analyze_elf_evidence
from backend.app.analyzers.universal.file_identifier import identify_file_format

def _build_synthetic_elf64(
    is_wx_segment: bool = False,
    is_exec_stack: bool = False,
    has_high_entropy_section: bool = False,
    embed_ioc: bool = False
) -> bytes:
    """Builds a well-formed synthetic 64-bit ELF binary in memory."""
    # 1. e_ident: \x7fELF, class=2 (64-bit), data=1 (Little-endian), ver=1, osabi=0 (SysV)
    e_ident = b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 8
    
    # Header fields: e_type(2), e_machine(62=x86_64), e_version(1), e_entry(0x401000)
    # e_phoff(64), e_shoff(see below), e_flags(0), e_ehsize(64), e_phentsize(56), e_phnum(2),
    # e_shentsize(64), e_shnum(4), e_shstrndx(1)
    e_type = 2 # ET_EXEC
    e_machine = 62 # x86_64
    e_version = 1
    e_entry = 0x401000
    e_phoff = 64
    e_phentsize = 56
    e_phnum = 2
    
    # Program Headers:
    # Seg 0: PT_LOAD (1), flags (RW=6 or RWX=7)
    seg0_flags = 7 if is_wx_segment else 5 # 7=RWX, 5=RX
    seg0 = struct.pack("<IIQQQQQQ", 1, seg0_flags, 0, 0x400000, 0x400000, 0x1000, 0x1000, 0x1000)
    
    # Seg 1: PT_GNU_STACK (0x6474e551), flags (6=RW or 7=RWX)
    seg1_flags = 7 if is_exec_stack else 6 # 7=RWX, 6=RW
    seg1 = struct.pack("<IIQQQQQQ", 0x6474e551, seg1_flags, 0, 0, 0, 0, 0, 0x10)
    
    ph_data = seg0 + seg1
    
    # Section String Table (.shstrtab)
    shstrtab = b"\x00.shstrtab\x00.text\x00.data\x00"
    
    # .text section payload
    if has_high_entropy_section:
        import os
        text_payload = os.urandom(8192) # High Shannon entropy
    else:
        text_payload = b"\x90" * 512 # NOP sled (Low entropy)
    
    if embed_ioc:
        text_payload += b"\x00http://evil-c2-server.com/beacon\x00198.51.100.45\x00/bin/sh -c 'whoami'\x00"
    
    data_payload = b"Sample data string\x00"
    
    # Offsets layout:
    # 0..64: ELF Header (64 bytes)
    # 64..176: Program Headers (2 * 56 = 112 bytes)
    # 176..176+len(shstrtab): shstrtab
    # align to 16
    off_shstr = 176
    off_text = off_shstr + len(shstrtab)
    off_data = off_text + len(text_payload)
    off_sh = off_data + len(data_payload)
    # Align off_sh
    off_sh = (off_sh + 15) & ~15
    
    e_shoff = off_sh
    e_shentsize = 64
    e_shnum = 4
    e_shstrndx = 1
    
    elf_hdr = struct.pack(
        "<HHIQQQIHHHHHH",
        e_type, e_machine, e_version, e_entry, e_phoff, e_shoff,
        0, 64, e_phentsize, e_phnum, e_shentsize, e_shnum, e_shstrndx
    )
    
    # Section 0: NULL section
    sec0 = struct.pack("<IIQQQQIIQQ", 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
    # Section 1: .shstrtab
    sec1 = struct.pack("<IIQQQQIIQQ", 1, 3, 0, 0, off_shstr, len(shstrtab), 0, 0, 1, 0) # 3 = SHT_STRTAB
    # Section 2: .text (offset 11 into shstrtab)
    sec2_flags = 6 # SHF_ALLOC | SHF_EXECINSTR
    sec2 = struct.pack("<IIQQQQIIQQ", 11, 1, sec2_flags, 0x401000, off_text, len(text_payload), 0, 0, 16, 0)
    # Section 3: .data (offset 17 into shstrtab)
    sec3_flags = 3 # SHF_WRITE | SHF_ALLOC
    sec3 = struct.pack("<IIQQQQIIQQ", 17, 1, sec3_flags, 0x402000, off_data, len(data_payload), 0, 0, 16, 0)
    
    sh_data = sec0 + sec1 + sec2 + sec3
    
    raw = bytearray()
    raw.extend(e_ident)
    raw.extend(elf_hdr)
    raw.extend(ph_data)
    raw.extend(shstrtab)
    raw.extend(text_payload)
    raw.extend(data_payload)
    
    # Pad to off_sh
    if len(raw) < off_sh:
        raw.extend(b"\x00" * (off_sh - len(raw)))
    
    raw.extend(sh_data)
    return bytes(raw)

def test_elf_magic_identification():
    """Confirms file_identifier recognizes \x7fELF independently of filename."""
    elf_bytes = _build_synthetic_elf64()
    with tempfile.NamedTemporaryFile(delete=False, suffix=".bin") as tmp:
        tmp.write(elf_bytes)
        tmp_p = Path(tmp.name)
    try:
        triage = identify_file_format(tmp_p, "linux_payload.dat")
        assert triage["detected_format"] == "elf"
        assert triage["mime_type"] == "application/x-executable"
        assert "64-bit" in triage["details"]
    finally:
        tmp_p.unlink(missing_ok=True)

def test_elf_standard_parsing():
    """Confirms header, bitness, machine, and section parsing for 64-bit ELF."""
    elf_bytes = _build_synthetic_elf64()
    with tempfile.NamedTemporaryFile(delete=False, suffix=".elf") as tmp:
        tmp.write(elf_bytes)
        tmp_p = Path(tmp.name)
    try:
        meta, arts, fnds = analyze_elf_evidence(tmp_p, "EVD-001", "INV-TEST-ELF-001")
        assert meta["format"] == "elf"
        assert meta["bitness"] == "64-bit"
        assert meta["machine"] == "x86-64 / AMD64"
        assert meta["type"] == "ET_EXEC (Executable binary)"
        assert meta["entry_point"] == "0x401000"
        assert len(meta["segments"]) == 2
        assert len(meta["sections"]) == 4
        sec_names = [s["name"] for s in meta["sections"]]
        assert ".text" in sec_names
        assert ".data" in sec_names
        assert len(arts) == 1
        assert arts[0].artifact_type == "elf_metadata"
    finally:
        tmp_p.unlink(missing_ok=True)

def test_elf_wx_segment_and_exec_stack_detection():
    """Confirms detection of W+X segment and executable stack security hazards."""
    elf_bytes = _build_synthetic_elf64(is_wx_segment=True, is_exec_stack=True)
    with tempfile.NamedTemporaryFile(delete=False, suffix=".elf") as tmp:
        tmp.write(elf_bytes)
        tmp_p = Path(tmp.name)
    try:
        meta, arts, fnds = analyze_elf_evidence(tmp_p, "EVD-002", "INV-TEST-ELF-002")
        assert meta["security_flags"]["has_wx_segment"] is True
        assert meta["security_flags"]["executable_stack"] is True
        
        titles = [f.title for f in fnds]
        assert any("W+X" in t for t in titles)
        assert any("Executable Stack" in t for t in titles)
    finally:
        tmp_p.unlink(missing_ok=True)

def test_elf_high_entropy_and_ioc_extraction():
    """Confirms Shannon entropy threshold alerting and embedded IOC string extraction."""
    elf_bytes = _build_synthetic_elf64(has_high_entropy_section=True, embed_ioc=True)
    with tempfile.NamedTemporaryFile(delete=False, suffix=".elf") as tmp:
        tmp.write(elf_bytes)
        tmp_p = Path(tmp.name)
    try:
        meta, arts, fnds = analyze_elf_evidence(tmp_p, "EVD-003", "INV-TEST-ELF-003")
        assert ".text" in meta["security_flags"]["high_entropy_sections"]
        
        iocs = meta["iocs"]
        ioc_values = [i["value"] for i in iocs]
        assert any("evil-c2-server.com" in v for v in ioc_values)
        assert any("198.51.100.45" in v for v in ioc_values)
        assert any("/bin/sh" in v for v in ioc_values)
    finally:
        tmp_p.unlink(missing_ok=True)
