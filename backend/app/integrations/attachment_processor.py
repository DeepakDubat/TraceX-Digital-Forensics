import os
import io
import re
import csv
import json
import base64
import hashlib
import zipfile
import logging
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple

from backend.app.config import settings
from backend.app.core.security import sanitize_filename, redact_secret
from backend.app.core.redaction import redact_sensitive_text

logger = logging.getLogger("attachment_processor")

MAX_ATTACHMENT_SIZE_BYTES = 50 * 1024 * 1024 # 50 MB
MAX_EXTRACTED_CHARS = 80_000 # Truncation limit for AI prompt safety

# Supported Extensions mapped to categories
CATEGORIES: Dict[str, List[str]] = {
    "text": [
        ".txt", ".md", ".log", ".csv", ".json", ".xml", ".yaml", ".yml",
        ".ini", ".conf", ".toml"
    ],
    "code": [
        ".py", ".js", ".ts", ".tsx", ".jsx", ".html", ".css", ".sql",
        ".java", ".kt", ".c", ".cpp", ".h", ".go", ".rs", ".php",
        ".ps1", ".bat", ".sh"
    ],
    "document": [".pdf", ".docx", ".xlsx"],
    "image": [".png", ".jpg", ".jpeg", ".webp"],
    "forensic": [
        ".apk", ".exe", ".dll", ".dex", ".smali", ".yara", ".pcap", ".pcapng"
    ]
}

def get_allowed_extensions() -> List[str]:
    exts = []
    for cat_exts in CATEGORIES.values():
        exts.extend(cat_exts)
    return exts

def classify_extension(filename: str) -> Tuple[str, str]:
    """Returns (category, clean_ext_without_dot)"""
    ext = Path(filename).suffix.lower()
    for cat, ext_list in CATEGORIES.items():
        if ext in ext_list:
            return cat, ext.lstrip(".")
    return "unknown", ext.lstrip(".")

def validate_magic_bytes(file_path: Path, category: str, ext: str) -> Tuple[bool, str]:
    """
    Checks magic bytes to prevent masquerading attacks.
    """
    if not file_path.exists():
        return False, "File does not exist on disk."

    size = file_path.stat().st_size
    if size == 0:
        return False, "Uploaded file is empty (0 bytes)."
    if size > MAX_ATTACHMENT_SIZE_BYTES:
        return False, f"File exceeds maximum size limit of {MAX_ATTACHMENT_SIZE_BYTES // (1024 * 1024)}MB."

    with open(file_path, "rb") as f:
        header = f.read(32)

    if ext == "pdf":
        if not header.startswith(b"%PDF-"):
            return False, "Invalid PDF file: Missing %PDF- magic signature."
    elif ext == "png":
        if not header.startswith(b"\x89PNG\r\n\x1a\n"):
            return False, "Invalid PNG file: Missing PNG magic signature."
    elif ext in ("jpg", "jpeg"):
        if not header.startswith(b"\xff\xd8\xff"):
            return False, "Invalid JPEG file: Missing JPEG magic signature."
    elif ext == "webp":
        if not (header.startswith(b"RIFF") and b"WEBP" in header[:16]):
            return False, "Invalid WebP file: Missing RIFF/WEBP magic signature."
    elif ext in ("apk", "docx", "xlsx"):
        if not header.startswith(b"PK\x03\x04"):
            return False, f"Invalid {ext.upper()} archive: Missing ZIP/PK header signature."
    elif ext in ("exe", "dll"):
        if not header.startswith(b"MZ"):
            return False, f"Invalid PE binary: Missing DOS/MZ magic signature."
    elif ext == "dex":
        if not header.startswith(b"dex\n"):
            return False, "Invalid DEX file: Missing DEX magic signature."
    elif ext == "pcap":
        # Magic bytes 0xa1b2c3d4 or 0xd4c3b2a1
        if not (header.startswith(b"\xd4\xc3\xb2\xa1") or header.startswith(b"\xa1\xb2\xc3\xd4")):
            return False, "Invalid PCAP file: Missing PCAP magic signature."
    elif ext == "pcapng":
        # Block type 0x0a0d0d0a
        if not header.startswith(b"\n\r\r\n"):
            return False, "Invalid PCAPNG file: Missing PCAPNG section header signature."

    return True, "Valid"

def calculate_hashes(file_path: Path) -> Dict[str, str]:
    md5 = hashlib.md5()
    sha256 = hashlib.sha256()
    with open(file_path, "rb") as f:
        while chunk := f.read(65536):
            md5.update(chunk)
            sha256.update(chunk)
    return {"md5": md5.hexdigest(), "sha256": sha256.hexdigest()}

def extract_text_safely(file_path: Path) -> str:
    """Reads text with multiple encoding fallbacks."""
    raw = file_path.read_bytes()
    for enc in ("utf-8", "utf-8-sig", "latin-1", "cp1252"):
        try:
            return raw.decode(enc)
        except UnicodeDecodeError:
            continue
    return raw.decode("utf-8", errors="replace")

def generate_image_thumbnail(file_path: Path) -> Tuple[Optional[str], Dict[str, Any]]:
    """Generates base64 data URL thumbnail and metadata using PIL."""
    try:
        from PIL import Image
        with Image.open(file_path) as img:
            w, h = img.size
            fmt = img.format or "PNG"
            mode = img.mode

            # Generate max 240x240 thumbnail
            thumb = img.copy()
            thumb.thumbnail((240, 240))
            buf = io.BytesIO()
            thumb.save(buf, format="PNG")
            b64 = base64.b64encode(buf.getvalue()).decode("ascii")
            data_url = f"data:image/png;base64,{b64}"

            return data_url, {"width": w, "height": h, "format": fmt, "mode": mode}
    except Exception as e:
        logger.warning(f"Failed to generate thumbnail for {file_path}: {e}")
        return None, {"error": str(e)}

def parse_pdf_document(file_path: Path) -> str:
    """Extracts text page by page from PDF using pypdf."""
    from pypdf import PdfReader
    reader = PdfReader(file_path)
    pages_text = []
    total_pages = len(reader.pages)

    for idx, page in enumerate(reader.pages):
        txt = page.extract_text() or ""
        if txt.strip():
            pages_text.append(f"--- [PDF Page {idx + 1} of {total_pages}] ---\n{txt.strip()}")

    if not pages_text:
        return f"[PDF: {file_path.name}] Document contains {total_pages} page(s), but no selectable text was found (document may be scanned or image-based; OCR required for visual text extraction)."

    return "\n\n".join(pages_text)

def parse_docx_document(file_path: Path) -> str:
    """Extracts paragraphs and tables from DOCX using python-docx."""
    import docx
    doc = docx.Document(file_path)
    lines = []

    for p in doc.paragraphs:
        if p.text.strip():
            lines.append(p.text.strip())

    for t_idx, table in enumerate(doc.tables):
        lines.append(f"\n[Table {t_idx + 1}]")
        for row in table.rows:
            cells = [cell.text.strip() for cell in row.cells]
            lines.append(" | ".join(cells))

    return "\n".join(lines) if lines else f"[DOCX: {file_path.name}] Empty document."

def parse_xlsx_document(file_path: Path) -> str:
    """Extracts sheet names and rows from XLSX using openpyxl."""
    import openpyxl
    wb = openpyxl.load_workbook(file_path, data_only=True, read_only=True)
    try:
        output = []
        for sheet_name in wb.sheetnames:
            sheet = wb[sheet_name]
            output.append(f"=== Sheet: {sheet_name} ===")
            row_count = 0
            for row in sheet.iter_rows(values_only=True):
                if any(cell is not None for cell in row):
                    row_str = " | ".join(str(cell) if cell is not None else "" for cell in row)
                    output.append(row_str)
                    row_count += 1
                    if row_count >= 150: # Limit rows per sheet for prompt length
                        output.append(f"... [Truncated at 150 rows in sheet '{sheet_name}']")
                        break
            output.append("")
        return "\n".join(output) if output else f"[XLSX: {file_path.name}] Empty spreadsheet."
    finally:
        wb.close()

def parse_csv_document(file_path: Path) -> str:
    """Formats CSV content cleanly."""
    text = extract_text_safely(file_path)
    lines = text.splitlines()
    if len(lines) > 200:
        return "\n".join(lines[:200]) + f"\n... [Truncated at 200 rows of {len(lines)} total]"
    return text

def parse_pe_forensic(file_path: Path) -> str:
    """Extracts structural PE metadata, sections, and imports using pefile."""
    import pefile
    try:
        pe = pefile.PE(str(file_path), fast_load=True)
        try:
            pe.parse_data_directories()

            lines = [
                f"=== WINDOWS PE BINARY ANALYSIS: {file_path.name} ===",
                f"- Machine: 0x{pe.FILE_HEADER.Machine:04x}",
                f"- Subsystem: 0x{pe.OPTIONAL_HEADER.Subsystem:04x}",
                f"- Number of Sections: {pe.FILE_HEADER.NumberOfSections}",
                f"- Entry Point RVA: 0x{pe.OPTIONAL_HEADER.AddressOfEntryPoint:08x}",
                f"- Image Base: 0x{pe.OPTIONAL_HEADER.ImageBase:08x}",
                ""
            ]

            lines.append("[SECTIONS]")
            for sec in pe.sections:
                name = sec.Name.decode("utf-8", errors="replace").strip("\x00")
                entropy = sec.get_entropy()
                vsize = sec.Misc_VirtualSize
                rsize = sec.SizeOfRawData
                lines.append(f"  * {name:<8} VirtualSize: {vsize:<8} RawSize: {rsize:<8} Entropy: {entropy:.2f}")

            if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
                lines.append("\n[IMPORTED MODULES & APIs (Sample)]")
                for entry in pe.DIRECTORY_ENTRY_IMPORT[:8]:
                    dll_name = entry.dll.decode("utf-8", errors="replace")
                    func_names = [imp.name.decode("utf-8", errors="replace") for imp in entry.imports if imp.name]
                    lines.append(f"  * {dll_name}: {', '.join(func_names[:8])}{' ...' if len(func_names) > 8 else ''}")

            lines.append("\nNOTICE: Binary parsed structurally without execution.")
            lines.append("To run full automated static analysis, YARA scanning, and threat intelligence, use the Workbench's 'New Investigation' page.")
            return "\n".join(lines)
        finally:
            pe.close()
    except Exception as e:
        return f"[PE Error] Could not parse PE structure: {e}"

def parse_apk_forensic(file_path: Path) -> str:
    """Extracts APK package metadata and manifest without execution."""
    try:
        with zipfile.ZipFile(file_path, "r") as z:
            names = z.namelist()
            dex_files = [n for n in names if n.endswith(".dex")]
            has_manifest = "AndroidManifest.xml" in names
            has_certs = any(n.startswith("META-INF/") for n in names)
            
            lines = [
                f"=== ANDROID APK PACKAGE ANALYSIS: {file_path.name} ===",
                f"- Total Packaged Entries: {len(names)}",
                f"- DEX Bytecode Files: {', '.join(dex_files) if dex_files else 'None'}",
                f"- Has AndroidManifest.xml: {has_manifest}",
                f"- Has Signature Certificates: {has_certs}",
                ""
            ]

            # Try to read manifest if readable or check permissions with Androguard
            try:
                from androguard.core.bytecodes.apk import APK
                a = APK(str(file_path))
                lines.append(f"- Package Name: {a.get_package()}")
                lines.append(f"- App Name: {a.get_app_name()}")
                lines.append(f"- Min SDK: {a.get_min_sdk_version()} | Target SDK: {a.get_target_sdk_version()}")
                perms = a.get_permissions()
                if perms:
                    lines.append(f"\n[DECLARED PERMISSIONS ({len(perms)} total)]")
                    for p in perms[:15]:
                        lines.append(f"  * {p}")
            except Exception as e:
                lines.append(f"(Androguard manifest inspection: {e})")

            lines.append("\nNOTICE: APK examined without execution.")
            lines.append("To run full static decompilation, YARA scanning, and C2 intelligence, use the Workbench's 'New Investigation' page.")
            return "\n".join(lines)
    except Exception as e:
        return f"[APK Error] Could not inspect APK package: {e}"

def sanitize_attachment_filename(filename: str) -> str:
    """Sanitizes filename while strictly preserving its original valid extension."""
    base = os.path.basename(filename)
    sanitized = re.sub(r'[^a-zA-Z0-9._-]', '_', base)
    if not sanitized or sanitized.startswith('.'):
        sanitized = f"attachment_{sanitized.lstrip('.')}"
    return sanitized

class AttachmentManager:
    """Manages chat attachment storage, content extraction, and lifecycle."""

    def __init__(self):
        self.base_dir = settings.CHAT_ATTACHMENTS_DIR
        self.base_dir.mkdir(parents=True, exist_ok=True)
        self._memory_cache: Dict[str, Dict[str, Any]] = {}
        # SHA-256 content-hash cache to eliminate redundant parsing of identical files
        self._content_cache: Dict[str, Dict[str, Any]] = {}

    def get_session_dir(self, session_id: str) -> Path:
        # Sanitize session_id to prevent path traversal
        clean_sid = re.sub(r"[^a-zA-Z0-9_-]", "_", session_id)
        s_dir = self.base_dir / clean_sid
        s_dir.mkdir(parents=True, exist_ok=True)
        return s_dir

    def process_and_store_attachment(
        self,
        session_id: str,
        filename: str,
        file_bytes: bytes,
        redact_secrets: bool = True
    ) -> Dict[str, Any]:
        """
        Stores file safely, validates magic bytes, extracts context, and returns metadata.
        """
        clean_name = sanitize_attachment_filename(filename)
        category, ext = classify_extension(clean_name)
        if category == "unknown":
            raise ValueError(f"Unsupported file type '.{ext}'. Supported types include Text, Code, PDF, DOCX, XLSX, Images, and Forensics.")

        # Generate unique attachment ID
        att_id = f"att_{hashlib.md5(file_bytes[:1024] + clean_name.encode()).hexdigest()[:12]}"
        session_dir = self.get_session_dir(session_id)
        target_path = session_dir / f"{att_id}_{clean_name}"

        # Write file to disk
        target_path.write_bytes(file_bytes)

        # Validate magic signature
        valid, reason = validate_magic_bytes(target_path, category, ext)
        if not valid:
            target_path.unlink(missing_ok=True)
            raise ValueError(f"File validation failed for '{clean_name}': {reason}")

        hashes = calculate_hashes(target_path)
        cache_key = f"{hashes['sha256']}_{redact_secrets}"
        thumbnail_url = None
        img_meta = {}
        extracted_text = ""

        # Check content-hash cache first to avoid re-parsing identical files
        if cache_key in self._content_cache:
            logger.info(f"Reusing cached extraction for hash {hashes['sha256'][:12]}")
            cached = self._content_cache[cache_key]
            extracted_text = cached.get("extracted_text", "")
            thumbnail_url = cached.get("thumbnail_url")
            img_meta = cached.get("img_meta", {})
        else:
            # Content extraction based on category
            try:
                if category == "image":
                    thumbnail_url, img_meta = generate_image_thumbnail(target_path)
                    extracted_text = (
                        f"[IMAGE ATTACHMENT: {clean_name}]\n"
                        f"Format: {img_meta.get('format', ext.upper())} | "
                        f"Dimensions: {img_meta.get('width', 'N/A')}x{img_meta.get('height', 'N/A')} px | "
                        f"Size: {len(file_bytes)} bytes | SHA256: {hashes['sha256']}"
                    )
                elif category in ("text", "code"):
                    raw_text = extract_text_safely(target_path)
                    if redact_secrets:
                        # Redact recognized tokens/keys in code/text
                        raw_text = redact_sensitive_text(raw_text)
                    if len(raw_text) > MAX_EXTRACTED_CHARS:
                        extracted_text = raw_text[:MAX_EXTRACTED_CHARS] + f"\n\n... [Content truncated at {MAX_EXTRACTED_CHARS} characters for prompt length safety]"
                    else:
                        extracted_text = raw_text
                elif ext == "pdf":
                    extracted_text = parse_pdf_document(target_path)
                elif ext == "docx":
                    extracted_text = parse_docx_document(target_path)
                elif ext == "xlsx":
                    extracted_text = parse_xlsx_document(target_path)
                elif ext in ("exe", "dll"):
                    extracted_text = parse_pe_forensic(target_path)
                elif ext == "apk":
                    extracted_text = parse_apk_forensic(target_path)
                elif ext == "yara":
                    extracted_text = f"=== YARA RULE SPECIFICATION ===\n{extract_text_safely(target_path)}"
                elif ext in ("pcap", "pcapng"):
                    extracted_text = (
                        f"=== PACKET CAPTURE METADATA: {clean_name} ===\n"
                        f"Format: {ext.upper()} Capture\n"
                        f"Size: {len(file_bytes)} bytes\n"
                        f"SHA-256: {hashes['sha256']}\n"
                        f"MD5: {hashes['md5']}\n"
                        f"Note: Packet capture payload stored. Examine network conversations and protocol layers."
                    )
                elif ext in ("dex", "smali"):
                    if ext == "dex":
                        extracted_text = (
                            f"=== DALVIK EXECUTABLE (DEX): {clean_name} ===\n"
                            f"Size: {len(file_bytes)} bytes\n"
                            f"SHA-256: {hashes['sha256']}\n"
                            f"Header Magic: dex\\n035\n"
                            f"Notice: Compiled Dalvik bytecode binary."
                        )
                    else:
                        extracted_text = f"=== SMALI DISASSEMBLY ===\n{extract_text_safely(target_path)}"
                else:
                    extracted_text = f"[{clean_name}] Forensic artifact reference (SHA-256: {hashes['sha256']})."

                # Cache successful extraction
                self._content_cache[cache_key] = {
                    "extracted_text": extracted_text,
                    "thumbnail_url": thumbnail_url,
                    "img_meta": img_meta
                }
            except Exception as e:
                logger.error(f"Error parsing {clean_name}: {e}")
                extracted_text = f"[{clean_name}] File could not be fully parsed: {str(e)}"

        if redact_secrets and extracted_text:
            extracted_text = redact_sensitive_text(extracted_text)

        preview = extracted_text[:300] if extracted_text else ""
        est_tokens = max(1, len(extracted_text) // 4)
        is_truncated = len(extracted_text) >= MAX_EXTRACTED_CHARS

        record = {
            "id": att_id,
            "session_id": session_id,
            "filename": clean_name,
            "file_size": len(file_bytes),
            "category": category,
            "format": ext,
            "sha256": hashes["sha256"],
            "md5": hashes["md5"],
            "status": "ready",
            "file_path": str(target_path),
            "file_uri": "file:///" + str(target_path).replace("\\", "/"),
            "extracted_text": extracted_text,
            "preview": preview,
            "thumbnail_data_url": thumbnail_url,
            "image_meta": img_meta,
            "is_forensic_binary": category == "forensic" and ext in ("apk", "exe", "dll"),
            "estimated_tokens": est_tokens,
            "truncated": is_truncated
        }

        self._memory_cache[att_id] = record
        self._save_session_metadata(session_id)
        return record

    def estimate_context_size(self, attachment_ids: List[str]) -> Dict[str, Any]:
        """Calculates combined token and size estimates for selected attachments."""
        total_bytes = 0
        total_tokens = 0
        total_chars = 0
        items = []
        for att_id in attachment_ids:
            att = self._memory_cache.get(att_id)
            if att:
                txt_len = len(att.get("extracted_text", ""))
                tokens = att.get("estimated_tokens", max(1, txt_len // 4))
                total_bytes += att.get("file_size", 0)
                total_tokens += tokens
                total_chars += txt_len
                items.append({
                    "id": att["id"],
                    "filename": att["filename"],
                    "file_size": att["file_size"],
                    "estimated_tokens": tokens,
                    "truncated": att.get("truncated", False)
                })
        return {
            "total_bytes": total_bytes,
            "total_tokens": total_tokens,
            "total_chars": total_chars,
            "is_large_context": total_tokens > 15_000,
            "items": items
        }

    def get_attachment(self, attachment_id: str) -> Optional[Dict[str, Any]]:
        return self._memory_cache.get(attachment_id)

    def delete_attachment(self, attachment_id: str) -> bool:
        record = self._memory_cache.pop(attachment_id, None)
        if record:
            path = Path(record["file_path"])
            if path.exists():
                try:
                    path.unlink(missing_ok=True)
                except Exception as e:
                    logger.warning(f"Could not immediately unlink {path}: {e}")
            self._save_session_metadata(record["session_id"])
            return True
        return False

    def get_session_attachments(self, session_id: str) -> List[Dict[str, Any]]:
        return [r for r in self._memory_cache.values() if r.get("session_id") == session_id]

    def cleanup_session(self, session_id: str):
        """Cleans up all temporary attachments for a deleted session."""
        session_dir = self.get_session_dir(session_id)
        for att_id in list(self._memory_cache.keys()):
            if self._memory_cache[att_id].get("session_id") == session_id:
                del self._memory_cache[att_id]
        if session_dir.exists():
            import shutil
            try:
                shutil.rmtree(session_dir, ignore_errors=True)
            except Exception as e:
                logger.warning(f"Could not clean up session dir: {e}")

    def _save_session_metadata(self, session_id: str):
        """Persists metadata to session directory."""
        try:
            s_dir = self.get_session_dir(session_id)
            meta_path = s_dir / "attachments_meta.json"
            items = [r for r in self._memory_cache.values() if r.get("session_id") == session_id]
            meta_path.write_text(json.dumps(items, indent=2), encoding="utf-8")
        except Exception as e:
            logger.warning(f"Could not save session metadata: {e}")

# Global singleton
attachment_mgr = AttachmentManager()
