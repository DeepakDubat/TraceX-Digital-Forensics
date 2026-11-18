import re
import email
from email import policy
from email.parser import BytesParser
import hashlib
from pathlib import Path
from datetime import datetime
from typing import Dict, Any, List, Tuple, Optional

from backend.app.core.models import ExtractedArtifact, FindingRecord

def analyze_email_evidence(
    file_path: Path,
    evidence_id: str,
    investigation_id: str,
    output_dir: Path
) -> Tuple[Dict[str, Any], List[ExtractedArtifact], List[FindingRecord], List[Dict[str, Any]]]:
    """
    Forensic analysis of electronic mail messages (EML / MBOX):
    - Envelope & Transport Headers: From, To, CC, Subject, Date, Message-ID
    - Hop analysis via Received: headers
    - Authentication status: SPF, DKIM, DMARC
    - Text and HTML body URL/Domain extraction
    - Attachment extraction with SHA-256 computation
    Never contacts external servers or opens links.
    """
    artifacts: List[ExtractedArtifact] = []
    findings: List[FindingRecord] = []
    child_evidence_items: List[Dict[str, Any]] = []
    metadata: Dict[str, Any] = {
        "format": "email",
        "headers": {},
        "received_hops": [],
        "authentication_results": [],
        "attachments": [],
        "warnings": []
    }

    output_dir.mkdir(parents=True, exist_ok=True)

    try:
        raw_bytes = file_path.read_bytes()
        msg = BytesParser(policy=policy.default).parsebytes(raw_bytes)

        metadata["headers"] = {
            "from": msg.get("from", ""),
            "to": msg.get("to", ""),
            "cc": msg.get("cc", ""),
            "subject": msg.get("subject", ""),
            "date": msg.get("date", ""),
            "message_id": msg.get("message-id", ""),
            "return_path": msg.get("return-path", ""),
            "reply_to": msg.get("reply-to", "")
        }

        # Track Received hops
        received_headers = msg.get_all("received", [])
        for r in received_headers:
            metadata["received_hops"].append(str(r).strip())

        # Authentication headers
        auth_res = msg.get_all("authentication-results", [])
        dkim = msg.get_all("dkim-signature", [])
        for ar in auth_res:
            metadata["authentication_results"].append(str(ar).strip())

        # Extract Email Addresses and Add as Artifacts
        for addr_type in ("from", "to", "cc", "reply_to"):
            addr_val = metadata["headers"].get(addr_type)
            if addr_val:
                emails_found = re.findall(r'[\w\.-]+@[\w\.-]+\.\w+', addr_val)
                for em in emails_found:
                    artifacts.append(ExtractedArtifact(
                        id=f"ART-EML-ADDR-{evidence_id}-{len(artifacts)+1:03d}",
                        investigation_id=investigation_id,
                        evidence_id=evidence_id,
                        artifact_type="email_address",
                        source_format="email",
                        source_location=f"Header: {addr_type.upper()}",
                        value=em.lower(),
                        structured_data={"address": em.lower(), "header": addr_type},
                        extractor_name="Email Header Parser",
                        confidence="Confirmed"
                    ))

        # Extract Body text and URLs
        body_text = ""
        for part in msg.walk():
            ctype = part.get_content_type()
            cdisp = str(part.get("content-disposition", ""))

            # Handle body
            if ctype in ("text/plain", "text/html") and "attachment" not in cdisp:
                try:
                    payload = part.get_content()
                    if isinstance(payload, str):
                        body_text += "\n" + payload
                except Exception:
                    pass

            # Handle attachments
            filename = part.get_filename()
            if filename:
                safe_name = Path(filename).name
                payload_bytes = part.get_payload(decode=True)
                if payload_bytes:
                    att_path = output_dir / safe_name
                    # Prevent overwriting
                    counter = 1
                    while att_path.exists():
                        att_path = output_dir / f"{att_path.stem}_{counter}{att_path.suffix}"
                        counter += 1

                    att_path.write_bytes(payload_bytes)
                    att_sha256 = hashlib.sha256(payload_bytes).hexdigest()

                    metadata["attachments"].append({
                        "filename": safe_name,
                        "size": len(payload_bytes),
                        "content_type": ctype,
                        "sha256": att_sha256
                    })

                    child_evidence_items.append({
                        "filename": safe_name,
                        "relative_path": f"attachments/{safe_name}",
                        "file_path": str(att_path),
                        "file_size": len(payload_bytes),
                        "sha256": att_sha256,
                        "parent_evidence_id": evidence_id
                    })

                    artifacts.append(ExtractedArtifact(
                        id=f"ART-EML-ATT-{evidence_id}-{len(artifacts)+1:03d}",
                        investigation_id=investigation_id,
                        evidence_id=evidence_id,
                        artifact_type="email_attachment",
                        source_format="email",
                        source_location=f"MIME Part (Content-Type: {ctype})",
                        value=safe_name,
                        structured_data={"filename": safe_name, "size": len(payload_bytes), "sha256": att_sha256, "mime": ctype},
                        sha256=att_sha256,
                        extractor_name="MIME Attachment Extractor",
                        confidence="Confirmed"
                    ))

        # Scan Body for URLs
        urls = re.findall(r'https?://[^\s<>"\')]+', body_text)
        for u in set(urls):
            clean_u = u.rstrip(".,;:")
            artifacts.append(ExtractedArtifact(
                id=f"ART-EML-URL-{evidence_id}-{len(artifacts)+1:03d}",
                investigation_id=investigation_id,
                evidence_id=evidence_id,
                artifact_type="url",
                source_format="email",
                source_location="Message Body",
                value=clean_u,
                structured_data={"url": clean_u},
                extractor_name="Email Body URL Extractor",
                confidence="Confirmed"
            ))

        # Security check: Check for suspicious attachments (EXE, SCR, ISO, VBS, JS, HTA)
        for att in metadata["attachments"]:
            lower_att = att["filename"].lower()
            if lower_att.endswith((".exe", ".scr", ".iso", ".vbs", ".js", ".hta", ".bat", ".cmd", ".ps1", ".lnk")):
                findings.append(FindingRecord(
                    id=f"FND-EML-EXEC-ATT-{evidence_id}-{abs(hash(lower_att)) % 10000}",
                    investigation_id=investigation_id,
                    evidence_id=evidence_id,
                    artifact_ids=[],
                    title=f"High-Risk Executable Email Attachment: {att['filename']}",
                    description=f"Email contains a direct executable or script attachment: '{att['filename']}'. Common phishing and malware distribution technique.",
                    observation=f"Attached file: {att['filename']}, SHA-256: {att['sha256']}.",
                    interpretation="Direct malicious payload delivery vector.",
                    severity="Critical",
                    confidence="Confirmed",
                    analysis_method="Email Attachment Extension & MIME Triage",
                    source_location=f"Email Attachment: {att['filename']}",
                    analyzer_name="Email Forensics Analyzer",
                    analyzer_version="1.0.0"
                ))

    except Exception as e:
        metadata["warnings"].append(f"Email analysis error: {str(e)}")

    return metadata, artifacts, findings, child_evidence_items
