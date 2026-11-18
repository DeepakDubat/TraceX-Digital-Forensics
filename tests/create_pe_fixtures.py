import struct
from pathlib import Path

def create_minimal_pe32(
    file_path: Path,
    machine: int = 0x014c, # x86
    custom_strings: bytes = b"",
    make_wx_section: bool = False,
    section_name_override: str = ".data"
) -> Path:
    """
    Constructs a completely harmless, structurally valid minimal PE32 executable.
    Does not contain any active malware code (contains NOPs and RET instructions).
    Used safely for automated testing of PE headers, sections, hashes, and parsers.
    """
    # 1. DOS Header (64 bytes)
    # Magic 'MZ', e_lfanew at offset 0x3C = 0x80 (128)
    dos_header = bytearray(64)
    dos_header[0:2] = b"MZ"
    struct.pack_into("<I", dos_header, 0x3C, 0x80)

    # 2. DOS Stub (64 bytes from 0x40 to 0x80)
    dos_stub = b"This program cannot be run in DOS mode.\r\r\n$\x00\x00\x00\x00\x00\x00\x00"
    dos_stub = dos_stub.ljust(64, b"\x00")

    # 3. PE Signature (4 bytes)
    pe_sig = b"PE\x00\x00"

    # 4. COFF File Header (20 bytes)
    num_sections = 2
    time_date = 1609459200 # 2021-01-01 00:00:00 UTC
    size_opt_hdr = 224 # PE32 optional header size
    chars = 0x0102 # IMAGE_FILE_32BIT_MACHINE | IMAGE_FILE_EXECUTABLE_IMAGE
    coff_header = struct.pack("<HHIIIHH", machine, num_sections, time_date, 0, 0, size_opt_hdr, chars)

    # 5. Optional Header Standard Fields (28 bytes)
    magic = 0x010B # PE32
    opt_std = struct.pack(
        "<HBBIIIIII",
        magic, 14, 0, # Magic, MajorLinker, MinorLinker
        512, 512, 0,  # SizeOfCode, SizeOfInitializedData, SizeOfUninitializedData
        0x1000, 0x1000, 0x2000 # EntryPoint, BaseOfCode, BaseOfData
    )

    # 6. Windows-Specific Fields (68 bytes)
    image_base = 0x00400000
    sec_align = 0x1000
    file_align = 0x0200
    size_of_image = 0x3000
    size_of_headers = 0x0200
    checksum = 0
    subsystem = 2 # IMAGE_SUBSYSTEM_WINDOWS_GUI
    dll_chars = 0x8140 # DYNAMIC_BASE | NX_COMPAT | TERMINAL_SERVER_AWARE
    rva_sizes = 16

    opt_win = struct.pack(
        "<IIIHHHHHHIIIIHHIIIIII",
        image_base, sec_align, file_align,
        6, 0, 0, 0, 6, 0, 0, # OS, Image, Subsystem versions, Win32VersionValue
        size_of_image, size_of_headers, checksum,
        subsystem, dll_chars,
        0x100000, 0x1000, 0x100000, 0x1000, # Stack/Heap Reserve/Commit
        0, rva_sizes
    )

    # 7. Data Directories (16 * 8 = 128 bytes, all zero)
    data_dirs = b"\x00" * 128

    # 8. Section Headers (2 * 40 = 80 bytes)
    # Section 1: .text (Code, Executable, Readable)
    text_name = b".text\x00\x00\x00"
    text_chars = 0x60000020 # IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ
    sec_text = struct.pack(
        "<8sIIIIIIHHI",
        text_name,
        512, 0x1000, # VirtualSize, VirtualAddress
        512, 0x0200, # SizeOfRawData, PointerToRawData
        0, 0, 0, 0,  # Relocations, LineNumbers
        text_chars
    )

    # Section 2: .data (Initialized data)
    data_name = section_name_override.encode('ascii').ljust(8, b'\x00')[:8]
    data_chars = 0xC0000040 # IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE
    if make_wx_section:
        # Enable IMAGE_SCN_MEM_EXECUTE (0x20000000) for testing W+X anomaly detection
        data_chars |= 0x20000000

    sec_data = struct.pack(
        "<8sIIIIIIHHI",
        data_name,
        512, 0x2000, # VirtualSize, VirtualAddress
        512, 0x0400, # SizeOfRawData, PointerToRawData
        0, 0, 0, 0,
        data_chars
    )

    headers = dos_header + dos_stub + pe_sig + coff_header + opt_std + opt_win + data_dirs + sec_text + sec_data
    # Pad headers up to file_align (0x0200 = 512 bytes)
    headers = headers.ljust(512, b"\x00")

    # Raw Data for Section 1 (.text): NOPs + RET (0x90...0xC3)
    text_raw = (b"\x90" * 511 + b"\xc3").ljust(512, b"\x00")

    # Raw Data for Section 2 (.data): default strings or custom forensic test indicators
    data_payload = custom_strings if custom_strings else (
        b"Windows Forensic Test Binary Payload\x00"
        b"http://trojan-c2.duckdns.org:8443/beacon.php\x00"
        b"198.51.100.25\x00"
        b"Software\\Microsoft\\Windows\\CurrentVersion\\Run\x00"
        b"AIzaSyD-TestKeyGoogleForensics1234567\x00"
    )
    data_raw = data_payload.ljust(512, b"\x00")

    complete_pe = headers + text_raw + data_raw
    file_path.parent.mkdir(parents=True, exist_ok=True)
    file_path.write_bytes(complete_pe)
    return file_path

def create_minimal_pe64(file_path: Path) -> Path:
    """Constructs a harmless minimal 64-bit PE32+ (x64) executable."""
    dos_header = bytearray(64)
    dos_header[0:2] = b"MZ"
    struct.pack_into("<I", dos_header, 0x3C, 0x80)

    dos_stub = b"This program cannot be run in DOS mode.\r\r\n$\x00".ljust(64, b"\x00")
    pe_sig = b"PE\x00\x00"

    # COFF Header (20 bytes) for AMD64
    machine = 0x8664 # IMAGE_FILE_MACHINE_AMD64
    num_sections = 1
    time_date = 1609459200
    size_opt_hdr = 240 # PE32+ optional header size
    chars = 0x0022 # IMAGE_FILE_EXECUTABLE_IMAGE | IMAGE_FILE_LARGE_ADDRESS_AWARE
    coff_header = struct.pack("<HHIIIHH", machine, num_sections, time_date, 0, 0, size_opt_hdr, chars)

    # Optional Header Standard Fields (24 bytes for PE32+)
    magic = 0x020B # PE32+
    opt_std = struct.pack(
        "<HBBIIIII",
        magic, 14, 0,
        512, 0, 0,
        0x1000, 0x1000
    )

    # Windows-Specific Fields (88 bytes for PE32+, 64-bit addresses)
    image_base = 0x0000000140000000
    sec_align = 0x1000
    file_align = 0x0200
    size_of_image = 0x2000
    size_of_headers = 0x0200
    checksum = 0
    subsystem = 3 # IMAGE_SUBSYSTEM_WINDOWS_CUI (Console)
    dll_chars = 0x8160 # HIGH_ENTROPY_VA | DYNAMIC_BASE | NX_COMPAT | TERMINAL_SERVER_AWARE
    rva_sizes = 16

    opt_win = struct.pack(
        "<QIIHHHHHHIIIIHHQQQQII",
        image_base, sec_align, file_align,
        6, 0, 0, 0, 6, 0, 0, # OS, Image, Subsystem versions, Win32VersionValue
        size_of_image, size_of_headers, checksum,
        subsystem, dll_chars,
        0x100000, 0x1000, 0x100000, 0x1000,
        0, rva_sizes
    )

    data_dirs = b"\x00" * 128

    # Section 1: .text
    text_name = b".text\x00\x00\x00"
    text_chars = 0x60000020
    sec_text = struct.pack(
        "<8sIIIIIIHHI",
        text_name,
        512, 0x1000,
        512, 0x0200,
        0, 0, 0, 0,
        text_chars
    )

    headers = (dos_header + dos_stub + pe_sig + coff_header + opt_std + opt_win + data_dirs + sec_text).ljust(512, b"\x00")
    text_raw = (b"\x90" * 511 + b"\xc3").ljust(512, b"\x00")

    file_path.parent.mkdir(parents=True, exist_ok=True)
    file_path.write_bytes(headers + text_raw)
    return file_path
