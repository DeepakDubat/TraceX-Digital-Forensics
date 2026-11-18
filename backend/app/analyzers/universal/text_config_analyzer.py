import re
from pathlib import Path
from datetime import datetime
from typing import Dict, Any, List, Tuple, Optional

from backend.app.core.models import ExtractedArtifact, FindingRecord
from backend.app.core.security import redact_secret
from backend.app.analyzers.secret_analyzer import SECRET_RULES

def analyze_text_evidence(
    file_path: Path,
    evidence_id: str,
    investigation_id: str,
    detected_format: str
) -> Tuple[Dict[str, Any], List[ExtractedArtifact], List[FindingRecord]]:
    """
    Forensic analysis of text, logs, configuration files, and source code:
    - Normalizes line encodings
    - Extracts URLs, IP addresses, domains, and email addresses
    - Identifies embedded API keys, authentication tokens, and secrets
    - Redacts sensitive secrets for safe dashboard and AI reporting
    """
    artifacts: List[ExtractedArtifact] = []
    findings: List[FindingRecord] = []
    metadata: Dict[str, Any] = {
        "format": detected_format,
        "line_count": 0,
        "char_count": 0,
        "extracted_iocs_count": 0,
        "secrets_detected": 0,
        "warnings": []
    }

    try:
        raw = file_path.read_bytes()
        text = ""
        for enc in ("utf-8", "utf-8-sig", "latin-1", "cp1252"):
            try:
                text = raw.decode(enc)
                break
            except UnicodeDecodeError:
                continue
        if not text:
            text = raw.decode("utf-8", errors="replace")

        lines = text.splitlines()
        metadata["line_count"] = len(lines)
        metadata["char_count"] = len(text)

        # 1. Extract URLs
        urls = re.findall(r'https?://[^\s<>"\')]+', text)
        for u in set(urls):
            clean_u = u.rstrip(".,;:")
            artifacts.append(ExtractedArtifact(
                id=f"ART-TXT-URL-{evidence_id}-{len(artifacts)+1:03d}",
                investigation_id=investigation_id,
                evidence_id=evidence_id,
                artifact_type="url",
                source_format=detected_format,
                source_location="Text Stream",
                value=clean_u,
                structured_data={"url": clean_u},
                extractor_name="Text Pattern Extractor",
                confidence="Confirmed"
            ))

        # 2. Extract IPv4
        ips = re.findall(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', text)
        for ip in set(ips):
            parts = ip.split(".")
            if all(0 <= int(p) <= 255 for p in parts):
                is_priv = ip.startswith(("10.", "192.168.", "127.", "172.16."))
                artifacts.append(ExtractedArtifact(
                    id=f"ART-TXT-IP-{evidence_id}-{len(artifacts)+1:03d}",
                    investigation_id=investigation_id,
                    evidence_id=evidence_id,
                    artifact_type="ip_endpoint",
                    source_format=detected_format,
                    source_location="Text Stream",
                    value=ip,
                    structured_data={"ip": ip, "is_private": is_priv},
                    extractor_name="Text Pattern Extractor",
                    confidence="Confirmed"
                ))

        # 3. Extract Emails
        emails = re.findall(r'[\w\.-]+@[\w\.-]+\.\w+', text)
        for em in set(emails):
            artifacts.append(ExtractedArtifact(
                id=f"ART-TXT-EMAIL-{evidence_id}-{len(artifacts)+1:03d}",
                investigation_id=investigation_id,
                evidence_id=evidence_id,
                artifact_type="email_address",
                source_format=detected_format,
                source_location="Text Stream",
                value=em.lower(),
                structured_data={"email": em.lower()},
                extractor_name="Text Pattern Extractor",
                confidence="Confirmed"
            ))

        # 4. Secret / Token / API Key Scanning with Redaction
        for rule in SECRET_RULES:
            category = rule["category"]
            pattern = rule["pattern"]
            confidence = rule["confidence"]
            matches = pattern.finditer(text)
            for m in matches:
                raw_val = m.group(0)
                # Avoid trivial matches
                if len(raw_val) < 8 or raw_val.lower().startswith("http"):
                    continue
                redacted = redact_secret(raw_val)

                artifacts.append(ExtractedArtifact(
                    id=f"ART-TXT-SECRET-{evidence_id}-{len(artifacts)+1:03d}",
                    investigation_id=investigation_id,
                    evidence_id=evidence_id,
                    artifact_type="redacted_secret",
                    source_format=detected_format,
                    source_location=f"Character Offset {m.start()}",
                    value=redacted,
                    structured_data={"category": category, "redacted": redacted},
                    extractor_name="Secret Pattern Scanner",
                    confidence=confidence
                ))

                findings.append(FindingRecord(
                    id=f"FND-TXT-SECRET-{evidence_id}-{abs(hash(redacted)) % 10000}",
                    investigation_id=investigation_id,
                    evidence_id=evidence_id,
                    artifact_ids=[],
                    title=f"Embedded Credential / {category.replace('_', ' ').title()}",
                    description=f"Detected pattern matching {category.replace('_', ' ')}: {redacted}.",
                    observation=f"Matched regex pattern for {category}.",
                    interpretation="Sensitive API credential or key embedded in configuration/text. Potential unauthorized access or data exfiltration token.",
                    severity="High",
                    confidence=confidence,
                    analysis_method="Heuristic Secret Pattern Matching",
                    source_location=f"Offset {m.start()}",
                    analyzer_name="Text Forensics Analyzer",
                    analyzer_version="1.0.0",
                    alternative_explanation="Placeholder, documentation example, or test key."
                ))

        metadata["extracted_iocs_count"] = len(artifacts)
        metadata["secrets_detected"] = len([a for a in artifacts if a.artifact_type == "redacted_secret"])

    except Exception as e:
        metadata["warnings"].append(f"Text analysis warning: {str(e)}")

    return metadata, artifacts, findings
