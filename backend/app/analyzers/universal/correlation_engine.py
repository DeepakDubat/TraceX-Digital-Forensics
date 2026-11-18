from typing import List, Dict, Any, Tuple
from backend.app.core.models import (
    EvidenceItem, ExtractedArtifact, EvidenceRelationship
)

def _hamming_distance(hex1: str, hex2: str) -> int:
    """Computes bitwise Hamming distance between two hexadecimal perceptual hashes."""
    try:
        val1 = int(hex1, 16)
        val2 = int(hex2, 16)
        xor_val = val1 ^ val2
        return bin(xor_val).count("1")
    except Exception:
        return 999

def correlate_investigation_evidence(
    investigation_id: str,
    evidence_items: List[EvidenceItem],
    artifacts: List[ExtractedArtifact]
) -> List[EvidenceRelationship]:
    """
    Unified Cross-File Evidence Correlation Engine:
    1. Exact cryptographic matches (Identical SHA-256)
    2. Parent-child relationships (Archive extraction, Email attachments)
    3. Shared network indicators (Shared C2 domains, IPs, URLs)
    4. Shared identity/communication metadata (Shared email addresses)
    5. Shared cryptographic tokens / secrets
    6. Perceptual image similarity (dHash Hamming distance <= 6)
    """
    relationships: List[EvidenceRelationship] = []
    rel_counter = 1

    evd_by_id: Dict[str, EvidenceItem] = {e.id: e for e in evidence_items}
    arts_by_evd: Dict[str, List[ExtractedArtifact]] = {}
    for a in artifacts:
        arts_by_evd.setdefault(a.evidence_id, []).append(a)

    # 1. Exact Cryptographic Hash Matches across different Evidence Items
    hash_map: Dict[str, List[EvidenceItem]] = {}
    for e in evidence_items:
        hash_map.setdefault(e.sha256, []).append(e)

    for sha256_val, items in hash_map.items():
        if len(items) > 1:
            for i in range(len(items)):
                for j in range(i + 1, len(items)):
                    relationships.append(EvidenceRelationship(
                        id=f"REL-{investigation_id[-6:]}-{rel_counter:04d}",
                        investigation_id=investigation_id,
                        source_evidence_id=items[i].id,
                        target_evidence_id=items[j].id,
                        relationship_type="EXACT_HASH_MATCH",
                        supporting_artifact_ids=[],
                        matching_method=f"Cryptographic SHA-256 Match ({sha256_val[:16]}...)",
                        strength="Exact",
                        limitations="Identical content hash confirms duplicate bytes; does not guarantee identical temporal provenance or acquisition path."
                    ))
                    rel_counter += 1

    # 2. Parent-Child Hierarchical Relationships (Archives and Email Attachments)
    for e in evidence_items:
        if e.parent_evidence_id and e.parent_evidence_id in evd_by_id:
            parent = evd_by_id[e.parent_evidence_id]
            rel_type = "EMAIL_ATTACHMENT" if parent.detected_format == "email" else "PARENT_CHILD_ARCHIVE"
            relationships.append(EvidenceRelationship(
                id=f"REL-{investigation_id[-6:]}-{rel_counter:04d}",
                investigation_id=investigation_id,
                source_evidence_id=parent.id,
                target_evidence_id=e.id,
                relationship_type=rel_type,
                supporting_artifact_ids=[],
                matching_method="Archive Member or MIME Extraction Trace",
                strength="Exact",
                limitations="Direct child artifact extracted securely during forensic container ingestion."
            ))
            rel_counter += 1

    # 3. Correlate Artifacts Across Different Evidence Files
    # Group artifacts by type and value
    ioc_map: Dict[Tuple[str, str], List[ExtractedArtifact]] = {}
    for a in artifacts:
        if a.artifact_type in ("url", "dns_query", "http_host", "tls_sni", "ip_endpoint", "email_address", "redacted_secret"):
            norm_val = a.value.strip().lower()
            ioc_map.setdefault((a.artifact_type, norm_val), []).append(a)

    seen_pairs: set = set()
    for (atype, val), matches in ioc_map.items():
        # Only correlate across DIFFERENT evidence files
        matching_evds = list({m.evidence_id for m in matches})
        if len(matching_evds) > 1:
            for i in range(len(matching_evds)):
                for j in range(i + 1, len(matching_evds)):
                    pair_key = (min(matching_evds[i], matching_evds[j]), max(matching_evds[i], matching_evds[j]), atype, val)
                    if pair_key in seen_pairs:
                        continue
                    seen_pairs.add(pair_key)

                    rel_type = "SHARED_C2_DOMAIN"
                    if atype == "ip_endpoint":
                        rel_type = "SHARED_IP"
                    elif atype == "url":
                        rel_type = "SHARED_URL"
                    elif atype == "email_address":
                        rel_type = "SHARED_EMAIL"
                    elif atype == "redacted_secret":
                        rel_type = "SHARED_SECRET"

                    supp_ids = [m.id for m in matches if m.evidence_id in (matching_evds[i], matching_evds[j])]

                    relationships.append(EvidenceRelationship(
                        id=f"REL-{investigation_id[-6:]}-{rel_counter:04d}",
                        investigation_id=investigation_id,
                        source_evidence_id=matching_evds[i],
                        target_evidence_id=matching_evds[j],
                        relationship_type=rel_type,
                        supporting_artifact_ids=supp_ids,
                        matching_method=f"Normalized {atype.replace('_', ' ').title()} Indicator Overlap ('{val}')",
                        strength="High",
                        limitations="Common infrastructure or public service endpoints (e.g. cloud CDNs, Google DNS) should be evaluated in context of analyst triage."
                    ))
                    rel_counter += 1

    # 4. Perceptual Image Similarity (dHash)
    image_items = [e for e in evidence_items if e.detected_format in ("png", "jpeg", "jpg", "webp", "tiff", "bmp", "gif")]
    for i in range(len(image_items)):
        for j in range(i + 1, len(image_items)):
            e1 = image_items[i]
            e2 = image_items[j]
            dh1 = e1.triage_summary.get("dhash") or e1.metadata.get("dhash")
            dh2 = e2.triage_summary.get("dhash") or e2.metadata.get("dhash")
            if dh1 and dh2 and len(dh1) == len(dh2):
                dist = _hamming_distance(dh1, dh2)
                if dist <= 6: # Standard perceptual threshold for near-duplicate images
                    strength = "Exact" if dist == 0 else "Heuristic"
                    relationships.append(EvidenceRelationship(
                        id=f"REL-{investigation_id[-6:]}-{rel_counter:04d}",
                        investigation_id=investigation_id,
                        source_evidence_id=e1.id,
                        target_evidence_id=e2.id,
                        relationship_type="PERCEPTUAL_IMAGE_SIMILARITY",
                        supporting_artifact_ids=[],
                        matching_method=f"Visual Perceptual dHash Distance: {dist} bits (Threshold <= 6)",
                        strength=strength,
                        limitations="Visual similarity indicates near-identical composition, cropping, or minor format transcoding; does not guarantee identical binary source."
                    ))
                    rel_counter += 1

    return relationships
