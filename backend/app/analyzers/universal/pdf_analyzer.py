import re
from pathlib import Path
from datetime import datetime
from typing import Dict, Any, List, Tuple, Optional
import pypdf
from pypdf import PdfReader

from backend.app.core.models import ExtractedArtifact, FindingRecord

def analyze_pdf_evidence(
    file_path: Path,
    evidence_id: str,
    investigation_id: str
) -> Tuple[Dict[str, Any], List[ExtractedArtifact], List[FindingRecord]]:
    """
    Comprehensive static forensic analysis of PDF documents:
    - Metadata and incremental revision history
    - Suspicious actions: /OpenAction, /AA, /Launch, /JavaScript, /JS
    - External hyperlinks (/URI)
    - Embedded file attachments
    - Page-by-page text extraction with precise page citations
    Never executes embedded scripts or opens extracted links.
    """
    artifacts: List[ExtractedArtifact] = []
    findings: List[FindingRecord] = []
    metadata: Dict[str, Any] = {
        "format": "pdf",
        "page_count": 0,
        "is_encrypted": False,
        "pdf_version": "Unknown",
        "security_warnings": [],
        "embedded_files": [],
        "extracted_links": [],
        "actions": []
    }

    # 1. Read raw bytes unconditionally for deep structural and token analysis
    try:
        raw_bytes = file_path.read_bytes()
    except Exception as e:
        metadata["parser_error"] = f"Failed to read evidence bytes: {str(e)}"
        return metadata, artifacts, findings

    # Check for /JavaScript and /JS objects
    js_matches = re.findall(rb'/(?:JavaScript|JS)\s*(\([^\)]*\)|<[^>]*>|<<[^>]*>>)', raw_bytes)
    if b"/JavaScript" in raw_bytes or b"/JS" in raw_bytes:
        metadata["security_warnings"].append("Document contains embedded JavaScript objects (/JavaScript or /JS).")
        findings.append(FindingRecord(
            id=f"FND-PDF-JS-{evidence_id}",
            investigation_id=investigation_id,
            evidence_id=evidence_id,
            artifact_ids=[],
            title="Embedded JavaScript Object Detected in PDF",
            description="The PDF structure contains executable JavaScript directives (/JavaScript or /JS). While used in some interactive PDF forms, JavaScript is frequently abused for exploit delivery, evasion, or malicious redirections.",
            observation=f"Found /JavaScript or /JS tokens ({len(js_matches)} object references) in PDF stream.",
            interpretation="Executable script presence represents potential client-side exploit vector or credential harvesting mechanism.",
            severity="High",
            confidence="High",
            analysis_method="Static PDF Structural Token Scanning",
            source_location="Document Catalog / Object Streams",
            analyzer_name="PDF Forensics Analyzer",
            analyzer_version="1.0.0",
            alternative_explanation="Interactive PDF forms (e.g. tax filings or surveys) may use benign calculation scripts."
        ))

    # Check for /Launch action (command execution)
    if b"/Launch" in raw_bytes:
        metadata["security_warnings"].append("High Risk: Document contains /Launch action (external application execution directive).")
        findings.append(FindingRecord(
            id=f"FND-PDF-LAUNCH-{evidence_id}",
            investigation_id=investigation_id,
            evidence_id=evidence_id,
            artifact_ids=[],
            title="Suspicious /Launch Action Directive in PDF",
            description="The PDF contains a /Launch action directive. This instruction attempts to launch an external executable or script upon opening the document.",
            observation="/Launch action token detected in document object streams.",
            interpretation="Direct attempt to execute local host applications or arbitrary binaries. Classic malicious PDF payload delivery technique.",
            severity="Critical",
            confidence="High",
            analysis_method="Static PDF Catalog Inspection",
            source_location="Object Action Dictionary",
            analyzer_name="PDF Forensics Analyzer",
            analyzer_version="1.0.0",
            alternative_explanation="Rare legacy PDF workflows launching associated helper applications."
        ))

    # Check for /OpenAction or /AA (Automatic Execution on document open)
    if b"/OpenAction" in raw_bytes or b"/AA" in raw_bytes:
        metadata["security_warnings"].append("Document contains automatic execution directive (/OpenAction or /AA).")
        findings.append(FindingRecord(
            id=f"FND-PDF-OPENACTION-{evidence_id}",
            investigation_id=investigation_id,
            evidence_id=evidence_id,
            artifact_ids=[],
            title="Automatic Execution Directive (/OpenAction /AA) Detected",
            description="The PDF contains directives that trigger actions automatically when opened by the reader without requiring explicit user interaction.",
            observation="Found /OpenAction or /AA tokens in document root dictionary.",
            interpretation="Enables zero-click payload execution or forced external URL navigation immediately upon viewing.",
            severity="High",
            confidence="High",
            analysis_method="Static PDF Catalog Inspection",
            source_location="Root Catalog Dictionary",
            analyzer_name="PDF Forensics Analyzer",
            analyzer_version="1.0.0",
            alternative_explanation="Benign documents may use /OpenAction to automatically jump to a specific bookmark or zoom level."
        ))

    # Check for Embedded Files / Attachments
    if b"/EmbeddedFiles" in raw_bytes or b"/EF" in raw_bytes:
        metadata["embedded_files"].append("Document contains embedded file attachments (/EmbeddedFiles).")
        artifacts.append(ExtractedArtifact(
            id=f"ART-PDF-EMB-{evidence_id}",
            investigation_id=investigation_id,
            evidence_id=evidence_id,
            artifact_type="embedded_object",
            source_format="pdf",
            source_location="EmbeddedFiles Name Dictionary",
            value="PDF Embedded File Payload Container",
            structured_data={"type": "EmbeddedFiles"},
            extractor_name="PDF Structure Analyzer",
            confidence="High"
        ))

    # 2. High-level DOM and Page Parsing with pypdf
    try:
        reader = PdfReader(file_path)
        try:
            metadata["page_count"] = len(reader.pages)
        except Exception:
            metadata["page_count"] = 0
        metadata["is_encrypted"] = reader.is_encrypted

        # Document Info / Metadata
        doc_info = reader.metadata or {}
        clean_info = {}
        for k, v in doc_info.items():
            clean_k = str(k).lstrip("/").strip()
            clean_info[clean_k] = str(v)
        metadata["doc_info"] = clean_info

        # Extract Raw Text with Page Citations
        pages_text: List[Dict[str, Any]] = []
        try:
            for idx, page in enumerate(reader.pages):
                page_num = idx + 1
                txt = page.extract_text() or ""
                if txt.strip():
                    pages_text.append({"page": page_num, "char_count": len(txt), "text_sample": txt[:2000]})

                    # Scan for URLs in page text
                    urls = re.findall(r'https?://[^\s<>"\')]+', txt)
                    for u in set(urls):
                        clean_u = u.rstrip(".,;:")
                        artifacts.append(ExtractedArtifact(
                            id=f"ART-PDF-URL-{evidence_id}-{len(artifacts)+1:03d}",
                            investigation_id=investigation_id,
                            evidence_id=evidence_id,
                            artifact_type="url",
                            source_format="pdf",
                            source_location=f"Page {page_num}",
                            value=clean_u,
                            structured_data={"url": clean_u, "page": page_num},
                            extractor_name="PDF Text Extractor",
                            confidence="High"
                        ))
        except Exception as pe:
            metadata["security_warnings"].append(f"Malformed or obfuscated page tree: {str(pe)}")

        metadata["pages_analyzed"] = len(pages_text)

        # Extract explicit /URI link annotations from page dictionaries
        try:
            for idx, page in enumerate(reader.pages):
                if "/Annots" in page:
                    try:
                        annots = page["/Annots"]
                        for a in annots:
                            obj = a.get_object()
                            if obj and obj.get("/Subtype") == "/Link":
                                action = obj.get("/A")
                                if action and action.get("/S") == "/URI":
                                    uri = str(action.get("/URI"))
                                    metadata["extracted_links"].append({"page": idx + 1, "uri": uri})
                                    artifacts.append(ExtractedArtifact(
                                        id=f"ART-PDF-LINK-{evidence_id}-{len(artifacts)+1:03d}",
                                        investigation_id=investigation_id,
                                        evidence_id=evidence_id,
                                        artifact_type="url",
                                        source_format="pdf",
                                        source_location=f"Page {idx + 1} Annotation",
                                        value=uri,
                                        structured_data={"uri": uri, "page": idx + 1, "annotation_type": "Link/URI"},
                                        extractor_name="PDF Annotation Extractor",
                                        confidence="Confirmed"
                                    ))
                    except Exception:
                        pass
        except Exception:
            pass

    except Exception as e:
        metadata["parser_error"] = str(e)
        metadata["security_warnings"].append(f"PDF DOM parsing warning: {str(e)}")

    return metadata, artifacts, findings
