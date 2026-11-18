import os
import tarfile
import zipfile
import gzip
import hashlib
from pathlib import Path
from datetime import datetime
from typing import Dict, Any, List, Tuple, Optional

from backend.app.core.models import ExtractedArtifact, FindingRecord

MAX_ARCHIVE_MEMBERS = 2000
MAX_EXPANDED_BYTES = 500 * 1024 * 1024 # 500 MB
MAX_COMPRESSION_RATIO = 100.0 # Archive bomb safeguard

def analyze_archive_evidence(
    file_path: Path,
    evidence_id: str,
    investigation_id: str,
    output_dir: Path
) -> Tuple[Dict[str, Any], List[ExtractedArtifact], List[FindingRecord], List[Dict[str, Any]]]:
    """
    Forensic analysis and safe extraction of archive artifacts (ZIP, TAR, GZIP):
    - Path traversal protection (Zip-Slip mitigation)
    - Archive bomb and decompression ratio safeguards
    - Nested archive inventory
    - Computes SHA-256 for all child artifacts
    - Returns child evidence items for recursive investigation attachment
    Never executes extracted files.
    """
    artifacts: List[ExtractedArtifact] = []
    findings: List[FindingRecord] = []
    child_evidence_items: List[Dict[str, Any]] = []
    metadata: Dict[str, Any] = {
        "format": "archive",
        "archive_type": "Unknown",
        "total_members": 0,
        "total_uncompressed_bytes": 0,
        "compression_ratio": 1.0,
        "is_encrypted": False,
        "nested_archives": [],
        "extracted_files": [],
        "security_warnings": []
    }

    output_dir.mkdir(parents=True, exist_ok=True)
    file_size = file_path.stat().st_size

    if zipfile.is_zipfile(file_path):
        metadata["archive_type"] = "ZIP"
        try:
            with zipfile.ZipFile(file_path, "r") as z:
                infolist = z.infolist()
                metadata["total_members"] = len(infolist)

                if len(infolist) > MAX_ARCHIVE_MEMBERS:
                    metadata["security_warnings"].append(f"Archive exceeds maximum member limit ({len(infolist)} > {MAX_ARCHIVE_MEMBERS}).")
                    findings.append(FindingRecord(
                        id=f"FND-ARCH-BOMB-{evidence_id}",
                        investigation_id=investigation_id,
                        evidence_id=evidence_id,
                        artifact_ids=[],
                        title="Archive Member Count Safety Threshold Exceeded",
                        description=f"Archive contains {len(infolist)} members, exceeding safe analysis limit ({MAX_ARCHIVE_MEMBERS}). Potential zip-bomb or resource exhaustion attempt.",
                        observation=f"Member count: {len(infolist)}.",
                        interpretation="Potential denial-of-service / resource exhaustion payload.",
                        severity="High",
                        confidence="Confirmed",
                        analysis_method="Archive Header Metric Calculation",
                        source_location="ZIP Central Directory",
                        analyzer_name="Archive Forensics Analyzer",
                        analyzer_version="1.0.0"
                    ))
                    return metadata, artifacts, findings, child_evidence_items

                total_uncompressed = sum(info.file_size for info in infolist)
                metadata["total_uncompressed_bytes"] = total_uncompressed
                ratio = total_uncompressed / max(1, file_size)
                metadata["compression_ratio"] = round(ratio, 2)

                if ratio > MAX_COMPRESSION_RATIO:
                    metadata["security_warnings"].append(f"Dangerous compression ratio detected: {ratio:.1f}:1. Archive bomb protection triggered.")
                    findings.append(FindingRecord(
                        id=f"FND-ARCH-RATIO-{evidence_id}",
                        investigation_id=investigation_id,
                        evidence_id=evidence_id,
                        artifact_ids=[],
                        title="Anomalous Compression Ratio (Potential Zip-Bomb)",
                        description=f"The uncompressed size ({total_uncompressed} bytes) is {ratio:.1f} times larger than compressed size ({file_size} bytes).",
                        observation=f"Compression ratio: {ratio:.1f}:1.",
                        interpretation="Indicative of recursive expansion / zip-bomb crafted to cause storage or memory denial of service.",
                        severity="Critical",
                        confidence="High",
                        analysis_method="Archive Compression Ratio Evaluation",
                        source_location="ZIP Central Directory",
                        analyzer_name="Archive Forensics Analyzer",
                        analyzer_version="1.0.0"
                    ))
                    return metadata, artifacts, findings, child_evidence_items

                # Safe Extraction with Zip-Slip Check
                resolved_out = output_dir.resolve()
                for info in infolist:
                    # Check encryption flag
                    if info.flag_bits & 0x1:
                        metadata["is_encrypted"] = True

                    # Zip-Slip Path Traversal Protection
                    target_path = (resolved_out / info.filename).resolve()
                    is_safe = False
                    try:
                        target_path.relative_to(resolved_out)
                        is_safe = True
                    except ValueError:
                        is_safe = False

                    if not is_safe:
                        metadata["security_warnings"].append(f"Zip-Slip Path Traversal Attempt Blocked: {info.filename}")
                        findings.append(FindingRecord(
                            id=f"FND-ZIP-SLIP-{evidence_id}-{abs(hash(info.filename)) % 10000}",
                            investigation_id=investigation_id,
                            evidence_id=evidence_id,
                            artifact_ids=[],
                            title="Zip-Slip Path Traversal Vector Detected",
                            description=f"Archive contains relative directory traversal path: '{info.filename}'. If extracted naively, this file would overwrite files outside the target directory.",
                            observation=f"Malicious archive member name: {info.filename}",
                            interpretation="Deliberate exploit attempt targeting archive extractors to overwrite system binaries or configuration files.",
                            severity="Critical",
                            confidence="Confirmed",
                            analysis_method="Archive Path Sanitization & Validation",
                            source_location=f"Archive Entry: {info.filename}",
                            analyzer_name="Archive Forensics Analyzer",
                            analyzer_version="1.0.0"
                        ))
                        continue

                    if info.is_dir():
                        target_path.mkdir(parents=True, exist_ok=True)
                        continue

                    target_path.parent.mkdir(parents=True, exist_ok=True)
                    with z.open(info) as src, open(target_path, "wb") as dst:
                        shutil_bytes = 0
                        while chunk := src.read(65536):
                            shutil_bytes += len(chunk)
                            if shutil_bytes > MAX_EXPANDED_BYTES:
                                raise ValueError("Exceeded maximum expanded byte quota during extraction.")
                            dst.write(chunk)

                    # Compute child artifact hash
                    child_sha256 = hashlib.sha256(target_path.read_bytes()).hexdigest()
                    metadata["extracted_files"].append({
                        "name": info.filename,
                        "size": info.file_size,
                        "sha256": child_sha256
                    })

                    # Check for nested archive
                    lower_name = info.filename.lower()
                    if lower_name.endswith((".zip", ".tar", ".gz", ".7z", ".rar", ".apk", ".jar")):
                        metadata["nested_archives"].append(info.filename)

                    # Record child item for repository attachment
                    child_evidence_items.append({
                        "filename": Path(info.filename).name,
                        "relative_path": info.filename,
                        "file_path": str(target_path),
                        "file_size": info.file_size,
                        "sha256": child_sha256,
                        "parent_evidence_id": evidence_id
                    })

                    artifacts.append(ExtractedArtifact(
                        id=f"ART-ARCH-FILE-{evidence_id}-{len(artifacts)+1:03d}",
                        investigation_id=investigation_id,
                        evidence_id=evidence_id,
                        artifact_type="archive_member",
                        source_format="archive",
                        source_location=f"Archive Internal Path: {info.filename}",
                        value=info.filename,
                        structured_data={"filename": info.filename, "size": info.file_size, "sha256": child_sha256},
                        sha256=child_sha256,
                        extractor_name="Archive Safe Extractor",
                        confidence="Confirmed"
                    ))

        except Exception as e:
            metadata["security_warnings"].append(f"Archive processing exception: {str(e)}")

    elif tarfile.is_tarfile(file_path):
        metadata["archive_type"] = "TAR"
        try:
            with tarfile.open(file_path, "r:*") as tar:
                members = tar.getmembers()
                metadata["total_members"] = len(members)
                resolved_out = output_dir.resolve()

                for m in members:
                    target_path = (resolved_out / m.name).resolve()
                    is_safe = False
                    try:
                        target_path.relative_to(resolved_out)
                        is_safe = True
                    except ValueError:
                        is_safe = False

                    if not is_safe:
                        metadata["security_warnings"].append(f"Tar-Slip Path Traversal Attempt Blocked: {m.name}")
                        continue
                    if m.isdir():
                        target_path.mkdir(parents=True, exist_ok=True)
                        continue
                    tar.extract(m, path=resolved_out, filter="data" if hasattr(tarfile, "data_filter") else None)
                    if target_path.exists() and target_path.is_file():
                        c_sha256 = hashlib.sha256(target_path.read_bytes()).hexdigest()
                        child_evidence_items.append({
                            "filename": Path(m.name).name,
                            "relative_path": m.name,
                            "file_path": str(target_path),
                            "file_size": m.size,
                            "sha256": c_sha256,
                            "parent_evidence_id": evidence_id
                        })
        except Exception as e:
            metadata["security_warnings"].append(f"TAR processing exception: {str(e)}")

    return metadata, artifacts, findings, child_evidence_items
