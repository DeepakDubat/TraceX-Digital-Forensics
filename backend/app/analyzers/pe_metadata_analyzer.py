import pefile
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Any, List, Tuple
from backend.app.core.models import PeMetadata

SUBSYSTEM_NAMES = {
    1: "IMAGE_SUBSYSTEM_NATIVE (Device Driver / Native)",
    2: "IMAGE_SUBSYSTEM_WINDOWS_GUI (Windows GUI)",
    3: "IMAGE_SUBSYSTEM_WINDOWS_CUI (Windows Command Line / Console)",
    5: "IMAGE_SUBSYSTEM_OS2_CUI (OS/2 Console)",
    7: "IMAGE_SUBSYSTEM_POSIX_CUI (POSIX Console)",
    9: "IMAGE_SUBSYSTEM_WINDOWS_CE_GUI (Windows CE GUI)",
    10: "IMAGE_SUBSYSTEM_EFI_APPLICATION (EFI Application)",
    11: "IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER (EFI Boot Service Driver)",
    12: "IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER (EFI Runtime Driver)",
    13: "IMAGE_SUBSYSTEM_EFI_ROM (EFI ROM)",
    14: "IMAGE_SUBSYSTEM_XBOX (Xbox)",
    16: "IMAGE_SUBSYSTEM_WINDOWS_BOOT_APPLICATION (Windows Boot Application)"
}

DLL_CHARACTERISTICS_MAP = {
    0x0020: "IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA (64-bit ASLR capable)",
    0x0040: "IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE (ASLR enabled)",
    0x0080: "IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY (Code Integrity check enforced)",
    0x0100: "IMAGE_DLLCHARACTERISTICS_NX_COMPAT (DEP/NX compatible)",
    0x0200: "IMAGE_DLLCHARACTERISTICS_NO_ISOLATION (No isolation)",
    0x0400: "IMAGE_DLLCHARACTERISTICS_NO_SEH (No SEH handler)",
    0x0800: "IMAGE_DLLCHARACTERISTICS_NO_BIND (Do not bind)",
    0x1000: "IMAGE_DLLCHARACTERISTICS_APPCONTAINER (AppContainer)",
    0x2000: "IMAGE_DLLCHARACTERISTICS_WDM_DRIVER (WDM Driver)",
    0x4000: "IMAGE_DLLCHARACTERISTICS_GUARD_CF (Control Flow Guard enabled)",
    0x8000: "IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE (Terminal Server aware)"
}

FILE_CHARACTERISTICS_MAP = {
    0x0001: "IMAGE_FILE_RELOCS_STRIPPED (Relocation info stripped)",
    0x0002: "IMAGE_FILE_EXECUTABLE_IMAGE (File is executable)",
    0x0004: "IMAGE_FILE_LINE_NUMS_STRIPPED (Line numbers stripped)",
    0x0008: "IMAGE_FILE_LOCAL_SYMS_STRIPPED (Local symbols stripped)",
    0x0010: "IMAGE_FILE_AGGRESIVE_WS_TRIM (Aggressive working set trim)",
    0x0020: "IMAGE_FILE_LARGE_ADDRESS_AWARE (Large address aware > 2GB)",
    0x0080: "IMAGE_FILE_BYTES_REVERSED_LO (Bytes reversed low)",
    0x0100: "IMAGE_FILE_32BIT_MACHINE (32-bit word architecture)",
    0x0200: "IMAGE_FILE_DEBUG_STRIPPED (Debugging info stripped)",
    0x0400: "IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP (Run from swap if removable)",
    0x0800: "IMAGE_FILE_NET_RUN_FROM_SWAP (Run from swap if network)",
    0x1000: "IMAGE_FILE_SYSTEM (System file)",
    0x2000: "IMAGE_FILE_DLL (File is dynamic-link library)",
    0x4000: "IMAGE_FILE_UP_SYSTEM_ONLY (Uni-processor only)",
    0x8000: "IMAGE_FILE_BYTES_REVERSED_HI (Bytes reversed high)"
}

def analyze_pe_metadata(pe: pefile.PE, file_path: Path) -> PeMetadata:
    """
    Extract comprehensive PE file metadata:
    - Architecture & format
    - Compilation timestamp and anomaly assessment
    - Headers, RVAs, image base, and sizes
    - Subsystem, file & DLL characteristics
    - Embedded Version Information resources
    - Authenticode digital signature presence
    """
    # 1. Machine & Format
    machine_val = pe.FILE_HEADER.Machine
    machine_desc = pefile.MACHINE_TYPE.get(machine_val, f"IMAGE_FILE_MACHINE_UNKNOWN (0x{machine_val:04X})")
    
    magic_val = getattr(pe.OPTIONAL_HEADER, 'Magic', 0)
    magic_desc = "PE32+" if magic_val == 0x20b else ("PE32" if magic_val == 0x10b else f"Unknown (0x{magic_val:04X})")

    # 2. Timestamp analysis
    timestamp_raw = pe.FILE_HEADER.TimeDateStamp
    compilation_ts_str = None
    timestamp_assessment = "Normal"

    if timestamp_raw == 0:
        compilation_ts_str = "0 (Stripped / Zero)"
        timestamp_assessment = "Missing or stripped compilation timestamp."
    else:
        try:
            dt = datetime.fromtimestamp(timestamp_raw, tz=timezone.utc)
            compilation_ts_str = dt.strftime("%Y-%m-%d %H:%M:%S UTC")
            now_dt = datetime.now(tz=timezone.utc)
            if dt > now_dt:
                timestamp_assessment = f"Future timestamp detected ({compilation_ts_str}). Common in deliberate timestamp tampering."
            elif dt.year < 1995:
                timestamp_assessment = f"Unusually early timestamp ({compilation_ts_str}). May indicate epoch reset, deliberate tampering, or Delphi 0x2A425E19 default."
            else:
                timestamp_assessment = "Plausible historical compilation timestamp."
        except Exception:
            compilation_ts_str = f"Invalid ({timestamp_raw})"
            timestamp_assessment = "Invalid or unparseable timestamp value."

    # 3. Optional Header fields
    entry_point_rva = f"0x{getattr(pe.OPTIONAL_HEADER, 'AddressOfEntryPoint', 0):08X}"
    image_base = f"0x{getattr(pe.OPTIONAL_HEADER, 'ImageBase', 0):016X}" if magic_val == 0x20b else f"0x{getattr(pe.OPTIONAL_HEADER, 'ImageBase', 0):08X}"
    size_of_image = getattr(pe.OPTIONAL_HEADER, 'SizeOfImage', 0)
    size_of_headers = getattr(pe.OPTIONAL_HEADER, 'SizeOfHeaders', 0)
    checksum = f"0x{getattr(pe.OPTIONAL_HEADER, 'CheckSum', 0):08X}"

    # 4. Subsystem
    subsystem_val = getattr(pe.OPTIONAL_HEADER, 'Subsystem', 0)
    subsystem = SUBSYSTEM_NAMES.get(subsystem_val, f"Unknown Subsystem ({subsystem_val})")

    # 5. Characteristics flags
    dll_char_val = getattr(pe.OPTIONAL_HEADER, 'DllCharacteristics', 0)
    dll_chars = [desc for flag, desc in DLL_CHARACTERISTICS_MAP.items() if (dll_char_val & flag)]

    file_char_val = pe.FILE_HEADER.Characteristics
    file_chars = [desc for flag, desc in FILE_CHARACTERISTICS_MAP.items() if (file_char_val & flag)]

    num_sections = pe.FILE_HEADER.NumberOfSections
    num_data_dirs = getattr(pe.OPTIONAL_HEADER, 'NumberOfRvaAndSizes', 0)

    # 6. Version Information Resources
    version_info: Dict[str, str] = {}
    if hasattr(pe, 'FileInfo'):
        try:
            for file_info_entry in pe.FileInfo:
                for sub_entry in file_info_entry:
                    if hasattr(sub_entry, 'StringTable'):
                        for st in sub_entry.StringTable:
                            for key, val in st.entries.items():
                                k = key.decode('utf-8', errors='ignore') if isinstance(key, bytes) else str(key)
                                v = val.decode('utf-8', errors='ignore') if isinstance(val, bytes) else str(val)
                                version_info[k] = v
        except Exception:
            pass

    # 7. Authenticode Digital Signature Detection
    is_signed = False
    signature_info: Dict[str, Any] = {
        "present": False,
        "security_directory_rva": "0x0",
        "security_directory_size": 0,
        "assessment": "No digital certificate found (Unsigned executable)."
    }
    try:
        security_dir = None
        if hasattr(pe, 'OPTIONAL_HEADER') and hasattr(pe.OPTIONAL_HEADER, 'DATA_DIRECTORY'):
            if len(pe.OPTIONAL_HEADER.DATA_DIRECTORY) > pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_SECURITY']:
                security_dir = pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_SECURITY']]
        
        if security_dir and security_dir.VirtualAddress > 0 and security_dir.Size > 0:
            is_signed = True
            signature_info["present"] = True
            signature_info["security_directory_rva"] = f"0x{security_dir.VirtualAddress:08X}"
            signature_info["security_directory_size"] = security_dir.Size
            signature_info["assessment"] = (
                f"Digital certificate structure found ({security_dir.Size} bytes at file offset 0x{security_dir.VirtualAddress:08X}). "
                "Note: A digital signature does not prove safety; malware authors frequently use stolen or forged certificates."
            )
    except Exception as e:
        signature_info["assessment"] = f"Error evaluating digital signature directory: {str(e)}"

    # 8. Export Table (if present)
    exports: List[str] = []
    if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
        try:
            for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                if exp.name:
                    exports.append(exp.name.decode('utf-8', errors='ignore'))
                elif exp.ordinal:
                    exports.append(f"Ordinal_{exp.ordinal}")
        except Exception:
            pass

    return PeMetadata(
        file_type="exe",
        machine=machine_desc,
        magic=magic_desc,
        compilation_timestamp=compilation_ts_str,
        compilation_timestamp_raw=timestamp_raw,
        timestamp_assessment=timestamp_assessment,
        entry_point_rva=entry_point_rva,
        image_base=image_base,
        size_of_image=size_of_image,
        size_of_headers=size_of_headers,
        checksum=checksum,
        subsystem=subsystem,
        dll_characteristics=dll_chars,
        file_characteristics=file_chars,
        number_of_sections=num_sections,
        number_of_data_directories=num_data_dirs,
        version_info=version_info,
        sections=[],
        imports=[],
        exports=exports,
        is_signed=is_signed,
        signature_info=signature_info,
        packer_detected=False,
        packer_indicators=[]
    )
