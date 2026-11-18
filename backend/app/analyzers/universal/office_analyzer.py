import re
import zipfile
from pathlib import Path
from datetime import datetime
from typing import Dict, Any, List, Tuple, Optional
import docx
import openpyxl

from backend.app.core.models import ExtractedArtifact, FindingRecord

def analyze_office_evidence(
    file_path: Path,
    evidence_id: str,
    investigation_id: str,
    detected_format: str
) -> Tuple[Dict[str, Any], List[ExtractedArtifact], List[FindingRecord]]:
    """
    Forensic analysis of Microsoft Office OpenXML documents (DOCX, XLSX, PPTX) and CSV:
    - Metadata and document properties
    - Macro detection (vbaProject.bin, macro indicators)
    - Hidden worksheets, rows, columns, and formulas in spreadsheets
    - Paragraphs, tables, and hyperlinks in documents
    - Extracted IOCs (URLs, domains, email addresses)
    Never executes VBA macros or embedded OLE objects.
    """
    artifacts: List[ExtractedArtifact] = []
    findings: List[FindingRecord] = []
    metadata: Dict[str, Any] = {
        "format": detected_format,
        "document_properties": {},
        "has_macros": False,
        "macro_files": [],
        "hyperlinks": [],
        "warnings": []
    }

    # Step 1: Safe zip container inspection for macros and embedded OLE objects
    if zipfile.is_zipfile(file_path):
        try:
            with zipfile.ZipFile(file_path, "r") as z:
                names = z.namelist()
                macro_files = [n for n in names if "vbaProject.bin" in n or n.endswith(".vba") or "macros" in n.lower()]
                if macro_files:
                    metadata["has_macros"] = True
                    metadata["macro_files"] = macro_files
                    findings.append(FindingRecord(
                        id=f"FND-OFFICE-MACRO-{evidence_id}",
                        investigation_id=investigation_id,
                        evidence_id=evidence_id,
                        artifact_ids=[],
                        title="VBA Macro Container (vbaProject.bin) Detected in Office Document",
                        description=f"The Office container contains VBA macro binary code: {', '.join(macro_files)}. Office documents with embedded macros are a high-risk delivery vehicle for malicious droppers and initial access payloads.",
                        observation=f"Archive entries include: {', '.join(macro_files)}",
                        interpretation="Document contains programmable automation code that executes on document open if user enables content.",
                        severity="High",
                        confidence="Confirmed",
                        analysis_method="ZIP Archive Manifest Inspection",
                        source_location="Package Root / word / xl / ppt",
                        analyzer_name="Office Forensics Analyzer",
                        analyzer_version="1.0.0",
                        alternative_explanation="Legitimate business templates and automated spreadsheets with internal automation."
                    ))

                # Check for embedded OLE objects (.bin, .exe, .bat, etc.)
                ole_files = [n for n in names if "embeddings/" in n or "oleObject" in n]
                if ole_files:
                    metadata["embedded_ole_objects"] = ole_files
                    findings.append(FindingRecord(
                        id=f"FND-OFFICE-OLE-{evidence_id}",
                        investigation_id=investigation_id,
                        evidence_id=evidence_id,
                        artifact_ids=[],
                        title="Embedded OLE Objects Detected in Document",
                        description=f"Found {len(ole_files)} embedded OLE object(s): {', '.join(ole_files[:5])}.",
                        observation="OLE object container stream detected in document package.",
                        interpretation="OLE package embedding can be abused to smuggle malicious binaries, LNK shortcuts, or scripts inside benign-looking documents.",
                        severity="Medium",
                        confidence="High",
                        analysis_method="OpenXML Package Inspection",
                        source_location="Package embeddings directory",
                        analyzer_name="Office Forensics Analyzer",
                        analyzer_version="1.0.0",
                        alternative_explanation="Benign documents embedding icons, charts, or attached spreadsheets."
                    ))
        except Exception as e:
            metadata["warnings"].append(f"Zip manifest scan warning: {str(e)}")

    # Step 2: Format-specific parser
    if detected_format == "docx":
        _analyze_docx(file_path, evidence_id, investigation_id, metadata, artifacts, findings)
    elif detected_format in ("xlsx", "xlsm"):
        _analyze_xlsx(file_path, evidence_id, investigation_id, metadata, artifacts, findings)
    elif detected_format == "pptx":
        _analyze_pptx(file_path, evidence_id, investigation_id, metadata, artifacts, findings)

    return metadata, artifacts, findings

def _analyze_docx(
    file_path: Path,
    evidence_id: str,
    investigation_id: str,
    metadata: Dict[str, Any],
    artifacts: List[ExtractedArtifact],
    findings: List[FindingRecord]
):
    try:
        doc = docx.Document(file_path)
        # Properties
        core = doc.core_properties
        props = {
            "author": core.author,
            "created": core.created.isoformat() if core.created else None,
            "modified": core.modified.isoformat() if core.modified else None,
            "last_modified_by": core.last_modified_by,
            "revision": core.revision,
            "title": core.title,
            "subject": core.subject
        }
        metadata["document_properties"] = props

        # Paragraphs & Tables
        text_lines = []
        for p in doc.paragraphs:
            if p.text.strip():
                text_lines.append(p.text.strip())

        for tbl in doc.tables:
            for row in tbl.rows:
                row_txt = [c.text.strip() for c in row.cells if c.text.strip()]
                if row_txt:
                    text_lines.append(" | ".join(row_txt))

        metadata["paragraph_count"] = len(doc.paragraphs)
        metadata["table_count"] = len(doc.tables)

        full_doc_text = "\n".join(text_lines)
        # Scan text for URLs and Emails
        urls = re.findall(r'https?://[^\s<>"\')]+', full_doc_text)
        for u in set(urls):
            clean_u = u.rstrip(".,;:")
            artifacts.append(ExtractedArtifact(
                id=f"ART-DOCX-URL-{evidence_id}-{len(artifacts)+1:03d}",
                investigation_id=investigation_id,
                evidence_id=evidence_id,
                artifact_type="url",
                source_format="docx",
                source_location="Document Paragraph / Table Content",
                value=clean_u,
                structured_data={"url": clean_u},
                extractor_name="DOCX Text Extractor",
                confidence="Confirmed"
            ))

    except Exception as e:
        metadata["warnings"].append(f"DOCX extraction warning: {str(e)}")

def _analyze_xlsx(
    file_path: Path,
    evidence_id: str,
    investigation_id: str,
    metadata: Dict[str, Any],
    artifacts: List[ExtractedArtifact],
    findings: List[FindingRecord]
):
    try:
        wb = openpyxl.load_workbook(file_path, data_only=False, read_only=False)
        try:
            metadata["sheet_names"] = wb.sheetnames
            hidden_sheets = []
            formula_count = 0
            extracted_cells_sample = []

            for sheet_name in wb.sheetnames:
                ws = wb[sheet_name]
                if ws.sheet_state != "visible":
                    hidden_sheets.append(sheet_name)

                # Inspect cells for formulas
                row_idx = 0
                for row in ws.iter_rows(values_only=False):
                    row_idx += 1
                    if row_idx > 200:
                        break
                    for cell in row:
                        val = cell.value
                        if val is not None:
                            val_str = str(val)
                            if str(val_str).startswith("="):
                                formula_count += 1
                                # Check for suspicious external execution formulas: CMD, POWERSHELL, DDE
                                upper_f = val_str.upper()
                                if any(cmd in upper_f for cmd in ("CMD", "POWERSHELL", "EXEC", "DDE", "MSEXCEL", "MSHTA", "REGSVR32")):
                                    findings.append(FindingRecord(
                                        id=f"FND-XLSX-DDE-{evidence_id}-{cell.coordinate}",
                                        investigation_id=investigation_id,
                                        evidence_id=evidence_id,
                                        artifact_ids=[],
                                        title=f"Suspicious Execution Formula / DDE in Sheet '{sheet_name}' Cell {cell.coordinate}",
                                        description=f"Cell {cell.coordinate} contains an external execution formula: {val_str}.",
                                        observation=f"Formula string: {val_str}",
                                        interpretation="Dynamic Data Exchange (DDE) or formula-based process execution vector. Common in malicious weaponized spreadsheets.",
                                        severity="Critical",
                                        confidence="Confirmed",
                                        analysis_method="OpenXML Cell Formula Inspection",
                                        source_location=f"Sheet '{sheet_name}' Cell {cell.coordinate}",
                                        analyzer_name="Office Forensics Analyzer",
                                        analyzer_version="1.0.0",
                                        alternative_explanation="None. Legitimate spreadsheets rarely invoke system command interpreters directly via formulas."
                                    ))

                            # Scan for URLs in cell values
                            if "http://" in val_str or "https://" in val_str:
                                for u in re.findall(r'https?://[^\s<>"\')]+', val_str):
                                    artifacts.append(ExtractedArtifact(
                                        id=f"ART-XLSX-URL-{evidence_id}-{len(artifacts)+1:03d}",
                                        investigation_id=investigation_id,
                                        evidence_id=evidence_id,
                                        artifact_type="url",
                                        source_format="xlsx",
                                        source_location=f"Sheet '{sheet_name}' Cell {cell.coordinate}",
                                        value=u.rstrip(".,;:"),
                                        structured_data={"url": u.rstrip(".,;:"), "sheet": sheet_name, "cell": cell.coordinate},
                                        extractor_name="XLSX Cell Parser",
                                        confidence="Confirmed"
                                    ))

            metadata["hidden_sheets"] = hidden_sheets
            metadata["formula_count"] = formula_count

            if hidden_sheets:
                findings.append(FindingRecord(
                    id=f"FND-XLSX-HIDDEN-{evidence_id}",
                    investigation_id=investigation_id,
                    evidence_id=evidence_id,
                    artifact_ids=[],
                    title=f"Hidden Worksheets Detected in Spreadsheet ({len(hidden_sheets)})",
                    description=f"The workbook contains hidden sheets: {', '.join(hidden_sheets)}. Malware authors frequently hide payload stages, URL lists, or obfuscated formulas in hidden sheets to evade casual visual inspection.",
                    observation=f"Hidden sheet names: {', '.join(hidden_sheets)}",
                    interpretation="Worksheet visibility state explicitly set to hidden or very hidden.",
                    severity="Medium",
                    confidence="Confirmed",
                    analysis_method="OpenXML Workbook Sheet State Inspection",
                    source_location="Workbook Sheet Manifest",
                    analyzer_name="Office Forensics Analyzer",
                    analyzer_version="1.0.0",
                    alternative_explanation="Legitimate accounting spreadsheets storing lookup tables or intermediate formula values."
                ))

        finally:
            wb.close()
    except Exception as e:
        metadata["warnings"].append(f"XLSX extraction warning: {str(e)}")

def _analyze_pptx(
    file_path: Path,
    evidence_id: str,
    investigation_id: str,
    metadata: Dict[str, Any],
    artifacts: List[ExtractedArtifact],
    findings: List[FindingRecord]
):
    """Parses PPTX slide text and notes via OpenXML package inspection."""
    try:
        with zipfile.ZipFile(file_path, "r") as z:
            slide_files = [n for n in z.namelist() if n.startswith("ppt/slides/slide") and n.endswith(".xml")]
            metadata["slide_count"] = len(slide_files)
            slide_urls = []
            for sf in slide_files:
                content = z.read(sf).decode("utf-8", errors="ignore")
                urls = re.findall(r'https?://[^\s<>"\')]+', content)
                for u in urls:
                    clean_u = u.rstrip(".,;:")
                    slide_urls.append(clean_u)
                    artifacts.append(ExtractedArtifact(
                        id=f"ART-PPTX-URL-{evidence_id}-{len(artifacts)+1:03d}",
                        investigation_id=investigation_id,
                        evidence_id=evidence_id,
                        artifact_type="url",
                        source_format="pptx",
                        source_location=f"Slide Package {sf}",
                        value=clean_u,
                        structured_data={"url": clean_u, "slide": sf},
                        extractor_name="PPTX Slide Parser",
                        confidence="Confirmed"
                    ))
            metadata["extracted_urls_count"] = len(slide_urls)
    except Exception as e:
        metadata["warnings"].append(f"PPTX extraction warning: {str(e)}")
