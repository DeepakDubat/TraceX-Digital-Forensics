import math
import os
import hashlib
from pathlib import Path
from typing import Dict, Any, Tuple, Optional, List

# Standard MIME type mappings
MIME_MAP = {
    "apk": "application/vnd.android.package-archive",
    "exe": "application/x-dosexec",
    "dll": "application/x-dosexec",
    "pe": "application/x-dosexec",
    "elf": "application/x-executable",
    "so": "application/x-sharedlib",
    "pdf": "application/pdf",
    "png": "image/png",
    "jpeg": "image/jpeg",
    "jpg": "image/jpeg",
    "webp": "image/webp",
    "gif": "image/gif",
    "bmp": "image/bmp",
    "tiff": "image/tiff",
    "docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    "xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    "pptx": "application/vnd.openxmlformats-officedocument.presentationml.presentation",
    "zip": "application/zip",
    "tar": "application/x-tar",
    "gzip": "application/gzip",
    "7z": "application/x-7z-compressed",
    "rar": "application/x-rar-compressed",
    "eml": "message/rfc822",
    "pcap": "application/vnd.tcpdump.pcap",
    "pcapng": "application/x-pcapng",
    "evtx": "application/x-ms-eventlog",
    "lnk": "application/x-ms-shortcut",
    "txt": "text/plain",
    "json": "application/json",
    "xml": "application/xml",
    "csv": "text/csv",
    "log": "text/plain"
}

def calculate_streaming_hashes(file_path: Path) -> Dict[str, str]:
    """
    Computes SHA-256, SHA-512, MD5, and SHA-1 hashes using streaming reads.
    Protects memory usage on large evidence artifacts.
    """
    h_sha256 = hashlib.sha256()
    h_sha512 = hashlib.sha512()
    h_md5 = hashlib.md5()
    h_sha1 = hashlib.sha1()

    with open(file_path, "rb") as f:
        while chunk := f.read(65536):
            h_sha256.update(chunk)
            h_sha512.update(chunk)
            h_md5.update(chunk)
            h_sha1.update(chunk)

    return {
        "sha256": h_sha256.hexdigest(),
        "sha512": h_sha512.hexdigest(),
        "md5": h_md5.hexdigest(),
        "sha1": h_sha1.hexdigest()
    }

def calculate_shannon_entropy(file_path: Path, max_sample_bytes: int = 5_000_000) -> Tuple[float, str]:
    """
    Calculates Shannon entropy (0.0 to 8.0) of file contents.
    Returns (entropy_value, assessment_label).
    """
    if not file_path.exists() or file_path.stat().st_size == 0:
        return 0.0, "Zero / Empty"

    byte_counts = [0] * 256
    total_bytes = 0

    with open(file_path, "rb") as f:
        while chunk := f.read(65536):
            for b in chunk:
                byte_counts[b] += 1
            total_bytes += len(chunk)
            if total_bytes >= max_sample_bytes:
                break

    if total_bytes == 0:
        return 0.0, "Empty"

    entropy = 0.0
    for count in byte_counts:
        if count > 0:
            p = count / total_bytes
            entropy -= p * math.log2(p)

    entropy = round(entropy, 4)

    if entropy >= 7.3:
        assessment = "Very High (Packed, Encrypted, or Compressed)"
    elif entropy >= 6.4:
        assessment = "High (Code, Compiled Binary, or Structured Archive)"
    elif entropy >= 4.0:
        assessment = "Moderate (Typical Text, Code, or Document Data)"
    elif entropy >= 1.0:
        assessment = "Low (Highly Repetitive or Sparse Data)"
    else:
        assessment = "Very Low (Padding or Null Bytes)"

    return entropy, assessment

def identify_file_format(file_path: Path, declared_filename: Optional[str] = None) -> Dict[str, Any]:
    """
    Identifies actual file format using magic bytes and structural validation,
    independent of filename extension. Compares against declared extension.
    """
    filename = declared_filename or file_path.name
    declared_ext = Path(filename).suffix.lower().lstrip(".")
    size = file_path.stat().st_size if file_path.exists() else 0

    if size == 0:
        return {
            "detected_format": "empty",
            "mime_type": "application/x-empty",
            "extension": declared_ext,
            "format_mismatch": False,
            "confidence": "Confirmed",
            "details": "File is completely empty (0 bytes).",
            "is_truncated": False,
            "processing_state": "GENERIC_TRIAGE_ONLY"
        }

    # Read header and trailer
    with open(file_path, "rb") as f:
        header = f.read(1024)
        if size > 1024:
            f.seek(max(0, size - 512))
            trailer = f.read(512)
        else:
            trailer = b""

    detected_format = "unknown"
    mime_type = "application/octet-stream"
    details = "Unrecognized binary or proprietary structure."
    is_truncated = False
    processing_state = "GENERIC_TRIAGE_ONLY"

    # 1. Windows PE Executable / DLL (MZ + PE signature check)
    if header.startswith(b"MZ"):
        detected_format = "exe"
        mime_type = "application/x-dosexec"
        processing_state = "FULL"
        if len(header) >= 0x40:
            pe_offset = int.from_bytes(header[0x3C:0x40], byteorder="little")
            if pe_offset < size - 4:
                with open(file_path, "rb") as pf:
                    pf.seek(pe_offset)
                    sig = pf.read(4)
                    if sig == b"PE\x00\x00":
                        detected_format = "exe"
                        details = f"Valid Windows PE binary. PE signature located at offset 0x{pe_offset:X}."
                    else:
                        details = f"DOS MZ executable header found, but missing standard PE\\0\\0 at offset 0x{pe_offset:X}."
            else:
                is_truncated = True
                details = "DOS MZ header found, but e_lfanew PE header offset points outside file boundaries."

    # 2. Linux ELF Executable / Shared Object (\x7fELF)
    elif header.startswith(b"\x7fELF"):
        detected_format = "elf"
        mime_type = "application/x-executable"
        processing_state = "FULL"
        bitness = "64-bit" if len(header) > 4 and header[4] == 2 else "32-bit"
        endianness = "Little-endian" if len(header) > 5 and header[5] == 1 else "Big-endian"
        details = f"Valid Linux Executable and Linkable Format (ELF) binary ({bitness}, {endianness})."

    # 3. PDF Document (%PDF-)
    elif header.startswith(b"%PDF-"):
        detected_format = "pdf"
        mime_type = "application/pdf"
        processing_state = "FULL"
        version_str = header[5:8].decode("ascii", errors="ignore")
        details = f"Valid Adobe PDF document (Version 1.{version_str[-1] if version_str else '?'})."
        if b"%%EOF" not in trailer and b"%%EOF" not in header:
            is_truncated = True
            details += " Warning: Standard %%EOF trailer marker missing (potential truncated or linear stream)."

    # 3. PK Zip / OpenXML / Android APK
    elif header.startswith(b"PK\x03\x04"):
        # Distinguish between APK, DOCX, XLSX, PPTX, and standard ZIP
        detected_format = "zip"
        mime_type = "application/zip"
        processing_state = "FULL"
        details = "Standard ZIP compressed archive."

        # Scan central directory / local headers for APK or Office OpenXML indicators
        with open(file_path, "rb") as zf:
            sample_content = zf.read(min(size, 65536))
            if b"AndroidManifest.xml" in sample_content or b"classes.dex" in sample_content:
                detected_format = "apk"
                mime_type = MIME_MAP["apk"]
                details = "Android Application Package (APK) with AndroidManifest.xml and DEX bytecode."
            elif b"word/" in sample_content or b"[Content_Types].xml" in sample_content and declared_ext == "docx":
                detected_format = "docx"
                mime_type = MIME_MAP["docx"]
                details = "Microsoft Word Document (Office OpenXML DOCX)."
            elif b"xl/" in sample_content or (b"[Content_Types].xml" in sample_content and declared_ext in ("xlsx", "xlsm")):
                detected_format = "xlsx"
                mime_type = MIME_MAP["xlsx"]
                details = "Microsoft Excel Spreadsheet (Office OpenXML XLSX)."
            elif b"ppt/" in sample_content or (b"[Content_Types].xml" in sample_content and declared_ext == "pptx"):
                detected_format = "pptx"
                mime_type = MIME_MAP["pptx"]
                details = "Microsoft PowerPoint Presentation (Office OpenXML PPTX)."

    # 4. Images
    elif header.startswith(b"\x89PNG\r\n\x1a\n"):
        detected_format = "png"
        mime_type = "image/png"
        processing_state = "FULL"
        details = "Portable Network Graphics (PNG) image."
    elif header.startswith(b"\xff\xd8\xff"):
        detected_format = "jpeg"
        mime_type = "image/jpeg"
        processing_state = "FULL"
        details = "JPEG photographic image."
    elif header.startswith(b"RIFF") and b"WEBP" in header[8:16]:
        detected_format = "webp"
        mime_type = "image/webp"
        processing_state = "FULL"
        details = "Google WebP raster image."
    elif header.startswith(b"GIF87a") or header.startswith(b"GIF89a"):
        detected_format = "gif"
        mime_type = "image/gif"
        processing_state = "FULL"
        details = "Graphics Interchange Format (GIF) image."
    elif header.startswith(b"BM"):
        detected_format = "bmp"
        mime_type = "image/bmp"
        processing_state = "FULL"
        details = "Windows Bitmap (BMP) uncompressed image."
    elif header.startswith(b"II*\x00") or header.startswith(b"MM\x00*"):
        detected_format = "tiff"
        mime_type = "image/tiff"
        processing_state = "FULL"
        details = "Tagged Image File Format (TIFF)."

    # 5. Network Captures
    elif header.startswith(b"\xd4\xc3\xb2\xa1") or header.startswith(b"\xa1\xb2\xc3\xd4") or header.startswith(b"\x4d\x3c\xb2\xa1"):
        detected_format = "pcap"
        mime_type = "application/vnd.tcpdump.pcap"
        processing_state = "FULL"
        details = "Libpcap network packet capture (PCAP)."
    elif header.startswith(b"\n\r\r\n"): # Section Header Block 0x0A0D0D0A
        detected_format = "pcapng"
        mime_type = "application/x-pcapng"
        processing_state = "FULL"
        details = "PCAP Next Generation (PCAPNG) network capture."

    # 6. GZIP, TAR, 7Z, RAR
    elif header.startswith(b"\x1f\x8b"):
        detected_format = "gzip"
        mime_type = "application/gzip"
        processing_state = "FULL"
        details = "GZIP compressed container."
    elif header.startswith(b"7z\xbc\xaf\x27\x1c"):
        detected_format = "7z"
        mime_type = "application/x-7z-compressed"
        processing_state = "FULL"
        details = "7-Zip compressed archive."
    elif header.startswith(b"Rar!\x1a\x07"):
        detected_format = "rar"
        mime_type = "application/x-rar-compressed"
        processing_state = "FULL"
        details = "RAR compressed archive."
    elif len(header) >= 262 and header[257:262] == b"ustar":
        detected_format = "tar"
        mime_type = "application/x-tar"
        processing_state = "FULL"
        details = "Unix Standard Tape Archive (POSIX TAR)."

    # 7. Windows Forensics (EVTX, LNK, Prefetch)
    elif header.startswith(b"ElfFile\x00"):
        detected_format = "evtx"
        mime_type = "application/x-ms-eventlog"
        processing_state = "METADATA_ONLY"
        details = "Windows XML Event Log (EVTX) binary format."
    elif header.startswith(b"\x4c\x00\x00\x00\x01\x14\x02\x00"):
        detected_format = "lnk"
        mime_type = "application/x-ms-shortcut"
        processing_state = "METADATA_ONLY"
        details = "Windows Shell Link / Shortcut (LNK) file."

    # 8. Email (EML / MBOX)
    elif header.startswith(b"From ") or any(h in header[:200] for h in (b"From:", b"To:", b"Subject:", b"Received:", b"Return-Path:")):
        detected_format = "eml"
        mime_type = "message/rfc822"
        processing_state = "FULL"
        details = "RFC 822/2822/5322 electronic mail message (EML/MBOX)."

    # 9. Plain text / CSV / JSON / Logs / Configs
    else:
        try:
            sample_text = header.decode("utf-8")
            if sample_text.strip().startswith("{") or sample_text.strip().startswith("["):
                detected_format = "json"
                mime_type = "application/json"
                details = "JSON structured text data."
            elif sample_text.strip().startswith("<?xml") or sample_text.strip().startswith("<"):
                detected_format = "xml"
                mime_type = "application/xml"
                details = "XML structured markup document."
            elif declared_ext == "csv" or ("," in sample_text and "\n" in sample_text):
                detected_format = "csv"
                mime_type = "text/csv"
                details = "Comma-Separated Values (CSV) table."
            elif declared_ext in ("log", "txt", "ini", "conf", "yaml", "yml", "toml"):
                detected_format = declared_ext
                mime_type = "text/plain"
                details = f"Plain text / configuration file ({declared_ext.upper()})."
            else:
                detected_format = "txt"
                mime_type = "text/plain"
                details = "UTF-8 / ASCII readable text file."
            processing_state = "FULL"
        except UnicodeDecodeError:
            detected_format = declared_ext if declared_ext in MIME_MAP else "unknown"
            mime_type = MIME_MAP.get(detected_format, "application/octet-stream")
            details = "Binary file with proprietary or unrecognized signature."
            processing_state = "GENERIC_TRIAGE_ONLY"

    # Compare detected format against declared extension
    normalized_declared = declared_ext
    if declared_ext in ("jpg", "jpeg"):
        normalized_declared = "jpeg"
    elif declared_ext in ("dll", "sys"):
        normalized_declared = "exe"

    format_mismatch = (
        bool(declared_ext) and
        detected_format not in ("unknown", "empty", "txt", "zip") and
        normalized_declared != detected_format and
        not (normalized_declared == "apk" and detected_format == "zip") # APK is structurally a ZIP
    )

    return {
        "detected_format": detected_format,
        "mime_type": mime_type,
        "extension": declared_ext,
        "format_mismatch": format_mismatch,
        "confidence": "Confirmed" if detected_format != "unknown" else "Low",
        "details": details,
        "is_truncated": is_truncated,
        "processing_state": processing_state
    }
