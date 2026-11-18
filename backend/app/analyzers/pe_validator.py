import os
import struct
from pathlib import Path
from typing import Tuple, Dict, Any, Optional
import pefile
from backend.app.config import settings

DOS_MAGIC = b"MZ"
PE_SIGNATURE = b"PE\x00\x00"

SUPPORTED_MACHINES = {
    0x014c: "IMAGE_FILE_MACHINE_I386 (x86 32-bit)",
    0x8664: "IMAGE_FILE_MACHINE_AMD64 (x64 64-bit)",
    0x01c0: "IMAGE_FILE_MACHINE_ARM (ARM little endian)",
    0x01c4: "IMAGE_FILE_MACHINE_ARMNT (ARM Thumb-2)",
    0xaa64: "IMAGE_FILE_MACHINE_ARM64 (ARM64 64-bit)",
    0x0200: "IMAGE_FILE_MACHINE_IA64 (Intel Itanium)"
}

OPTIONAL_HEADER_MAGICS = {
    0x10b: "PE32 (32-bit executable)",
    0x20b: "PE32+ (64-bit executable)",
    0x107: "ROM image"
}

def validate_pe_file(file_path: Path, max_size_mb: Optional[int] = None) -> Tuple[bool, str, Dict[str, Any]]:
    """
    Validate a Windows PE (Portable Executable) binary strictly and safely.
    Checks MZ DOS header, e_lfanew offset, PE signature, COFF header,
    machine architecture, optional header, section table boundaries, and structural integrity.
    Never executes or launches the binary.
    
    Returns:
        (is_valid: bool, reason: str, details: dict)
    """
    if max_size_mb is None:
        max_size_mb = getattr(settings, "MAX_UPLOAD_SIZE_MB", 200)
    details: Dict[str, Any] = {
        "file_size": 0,
        "machine": "Unknown",
        "format": "Unknown",
        "sections_count": 0,
        "is_pe32_plus": False,
        "anomalies": []
    }

    if not file_path.exists():
        return False, "File does not exist.", details

    file_size = file_path.stat().st_size
    details["file_size"] = file_size

    if file_size == 0:
        return False, "File is empty (0 bytes).", details

    if file_size < 64:
        return False, "File is too small to contain a valid DOS header (minimum 64 bytes required).", details

    if file_size > (max_size_mb * 1024 * 1024):
        return False, f"File exceeds maximum permissible size of {max_size_mb} MB.", details

    # Safe low-level header parsing
    try:
        with open(file_path, "rb") as f:
            # 1. DOS Header
            dos_header = f.read(64)
            if not dos_header.startswith(DOS_MAGIC):
                return False, "Invalid file format: Missing DOS header magic ('MZ').", details

            # e_lfanew is at offset 0x3C (4 bytes, unsigned int, little-endian)
            e_lfanew = struct.unpack("<I", dos_header[0x3C:0x40])[0]
            details["e_lfanew"] = e_lfanew

            if e_lfanew < 64 or e_lfanew > (file_size - 4):
                return False, f"Corrupted PE structure: Invalid e_lfanew offset (0x{e_lfanew:X}) pointing outside file.", details

            # 2. PE Signature
            f.seek(e_lfanew)
            pe_sig = f.read(4)
            if pe_sig != PE_SIGNATURE:
                return False, "Invalid PE file: Missing standard 'PE\\x00\\x00' signature at e_lfanew.", details

            # 3. COFF File Header (20 bytes)
            coff_header_data = f.read(20)
            if len(coff_header_data) < 20:
                return False, "Truncated PE file: Incomplete COFF file header.", details

            machine, num_sections, timedate, sym_ptr, num_syms, opt_hdr_size, characteristics = struct.unpack(
                "<HHIIIHH", coff_header_data
            )
            details["machine_id"] = machine
            details["machine"] = SUPPORTED_MACHINES.get(machine, f"Unsupported/Unknown Machine (0x{machine:04X})")
            details["sections_count"] = num_sections
            details["size_of_optional_header"] = opt_hdr_size
            details["characteristics"] = characteristics

            if num_sections == 0:
                return False, "Malformed PE file: Number of sections declared is 0.", details
            if num_sections > 96:
                details["anomalies"].append(f"Abnormally high section count: {num_sections}")

            # 4. Optional Header (if present)
            if opt_hdr_size >= 2:
                opt_magic_data = f.read(2)
                if len(opt_magic_data) == 2:
                    opt_magic = struct.unpack("<H", opt_magic_data)[0]
                    details["opt_magic"] = opt_magic
                    details["format"] = OPTIONAL_HEADER_MAGICS.get(opt_magic, f"Unknown (0x{opt_magic:04X})")
                    details["is_pe32_plus"] = (opt_magic == 0x20b)
    except Exception as e:
        return False, f"Low-level structural parsing error: {str(e)}", details

    # 5. pefile structural validation
    try:
        pe = pefile.PE(str(file_path), fast_load=True)
        try:
            # Check for section boundaries
            for section in pe.sections:
                sec_name = section.Name.decode('utf-8', errors='ignore').strip('\x00')
                raw_offset = section.PointerToRawData
                raw_size = section.SizeOfRawData
                if (raw_offset + raw_size) > file_size:
                    details["anomalies"].append(
                        f"Section '{sec_name}' raw data ({raw_offset} + {raw_size}) exceeds physical file size ({file_size})."
                    )
        finally:
            pe.close()
    except pefile.PEFormatError as e:
        return False, f"Invalid PE structure detected by parser: {str(e)}", details
    except Exception as e:
        return False, f"PE validation exception: {str(e)}", details

    return True, "Valid Windows Portable Executable (PE) binary.", details
