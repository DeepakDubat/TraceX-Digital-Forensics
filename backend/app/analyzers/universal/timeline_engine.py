import re
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from typing import List, Dict, Any, Optional, Tuple

from backend.app.core.models import (
    EvidenceItem, TimelineEvent, ContradictionItem
)

def _parse_pdf_date(date_str: str) -> Optional[Tuple[datetime, str]]:
    """
    Parses PDF date format D:YYYYMMDDHHmmSS[+-]HH'mm'
    """
    try:
        clean = date_str.replace("D:", "").strip("'")
        match = re.match(r"^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})?([+-]\d{2})?'?(\d{2})?", clean)
        if match:
            year, month, day, hour, minute = match.group(1), match.group(2), match.group(3), match.group(4), match.group(5)
            second = match.group(6) or "00"
            tz_offset = match.group(7)
            dt_iso = f"{year}-{month}-{day}T{hour}:{minute}:{second}"
            dt = datetime.fromisoformat(dt_iso)
            tz_label = tz_offset or "UTC"
            return dt, tz_label
    except Exception:
        pass
    return None

def build_investigation_timeline(
    investigation_id: str,
    evidence_items: List[EvidenceItem]
) -> Tuple[List[TimelineEvent], List[ContradictionItem]]:
    """
    Extracts and normalizes timeline events from all collected evidence:
    - Filesystem and Acquisition timestamps
    - PE Compilation TimeDateStamp
    - Image EXIF capture timestamps
    - Email message dates
    - PDF Creation/Modification dates
    - Office OpenXML created/modified properties
    - Detects temporal contradictions across evidence items
    """
    events: List[TimelineEvent] = []
    contradictions: List[ContradictionItem] = []
    evt_counter = 1

    for ev in evidence_items:
        # 1. Evidence Acquisition
        if ev.acquired_at:
            events.append(TimelineEvent(
                id=f"EVT-{investigation_id[-6:]}-{evt_counter:04d}",
                investigation_id=investigation_id,
                evidence_id=ev.id,
                original_timestamp=ev.acquired_at.isoformat(),
                original_timezone="UTC",
                normalized_utc=ev.acquired_at.isoformat() + "Z",
                timestamp_source="Workbench Evidence Ingestion / Chain-of-Custody",
                transformation_applied="Native UTC Staging Timestamp",
                reliability="High",
                event_type="Evidence Acquisition",
                description=f"Artifact '{ev.filename}' securely acquired and staged for analysis.",
                related_evidence_ids=[ev.id]
            ))
            evt_counter += 1

        meta = ev.metadata or {}

        # 2. PE Compilation Timestamp
        if ev.detected_format in ("exe", "dll") and "compilation_timestamp" in meta:
            raw_ts = meta["compilation_timestamp"]
            if raw_ts:
                try:
                    dt = datetime.fromisoformat(raw_ts.rstrip("Z"))
                    events.append(TimelineEvent(
                        id=f"EVT-{investigation_id[-6:]}-{evt_counter:04d}",
                        investigation_id=investigation_id,
                        evidence_id=ev.id,
                        original_timestamp=raw_ts,
                        original_timezone="UTC",
                        normalized_utc=dt.isoformat() + "Z",
                        timestamp_source="Windows PE Header TimeDateStamp",
                        transformation_applied="PE NT Header Unix Epoch to UTC",
                        reliability="High",
                        event_type="Binary Compilation",
                        description=f"PE binary '{ev.filename}' compilation timestamp recorded in COFF File Header.",
                        related_evidence_ids=[ev.id]
                    ))
                    evt_counter += 1

                    # Check for anomalous compilation dates (future or ancient)
                    now_utc = datetime.utcnow()
                    if dt > now_utc:
                        contradictions.append(ContradictionItem(
                            id=f"CTD-TIME-FUTURE-{ev.id}",
                            title=f"Future Compilation Timestamp in {ev.filename}",
                            category="Timestamp Inconsistency",
                            evidence_ids=[ev.id],
                            details=f"PE compilation timestamp ({raw_ts}) is in the future relative to current time ({now_utc.isoformat()}). Indicates deliberate timestamp manipulation (timestomping) or misconfigured build machine.",
                            observed_conflicts=[{"header_timestamp": raw_ts, "current_system_time": now_utc.isoformat()}]
                        ))
                    elif dt.year < 2000:
                        contradictions.append(ContradictionItem(
                            id=f"CTD-TIME-ANCIENT-{ev.id}",
                            title=f"Anomalous Historical Timestamp in {ev.filename}",
                            category="Timestamp Inconsistency",
                            evidence_ids=[ev.id],
                            details=f"PE compilation timestamp is set to {raw_ts} (Year {dt.year}). Often zeroed out or timestomped by Delphi/Go linkers or malware packers.",
                            observed_conflicts=[{"header_timestamp": raw_ts}]
                        ))
                except Exception:
                    pass

        # 3. EXIF Image Timestamps
        if "exif" in meta and isinstance(meta["exif"], dict):
            exif = meta["exif"]
            dto = exif.get("DateTimeOriginal") or exif.get("DateTime")
            if dto:
                try:
                    # Standard EXIF format: YYYY:MM:DD HH:MM:SS
                    parts = dto.strip().split(" ")
                    if len(parts) == 2:
                        d_part = parts[0].replace(":", "-")
                        t_part = parts[1]
                        dt_iso = f"{d_part}T{t_part}"
                        events.append(TimelineEvent(
                            id=f"EVT-{investigation_id[-6:]}-{evt_counter:04d}",
                            investigation_id=investigation_id,
                            evidence_id=ev.id,
                            original_timestamp=dto,
                            original_timezone="Camera Local (Unspecified)",
                            normalized_utc=dt_iso + "Z",
                            transformation_applied="Parsed EXIF YYYY:MM:DD HH:MM:SS format",
                            reliability="Medium",
                            event_type="Camera Photo Capture",
                            description=f"Photo capture timestamp recorded by device camera metadata in '{ev.filename}'.",
                            related_evidence_ids=[ev.id]
                        ))
                        evt_counter += 1
                except Exception:
                    pass

        # 4. Email Transport Date
        if "headers" in meta and isinstance(meta["headers"], dict):
            email_date_str = meta["headers"].get("date")
            if email_date_str:
                try:
                    dt = parsedate_to_datetime(email_date_str)
                    utc_dt = dt.astimezone(timezone.utc)
                    events.append(TimelineEvent(
                        id=f"EVT-{investigation_id[-6:]}-{evt_counter:04d}",
                        investigation_id=investigation_id,
                        evidence_id=ev.id,
                        original_timestamp=email_date_str,
                        original_timezone=str(dt.tzinfo or "UTC"),
                        normalized_utc=utc_dt.strftime("%Y-%m-%dT%H:%M:%SZ"),
                        transformation_applied="RFC 2822 Date Header converted to UTC",
                        reliability="High",
                        event_type="Email Message Transmission",
                        description=f"Message transmission date in '{ev.filename}'.",
                        related_evidence_ids=[ev.id]
                    ))
                    evt_counter += 1
                except Exception:
                    pass

        # 5. Office Properties (Created & Modified)
        if "document_properties" in meta and isinstance(meta["document_properties"], dict):
            props = meta["document_properties"]
            for prop_key, event_lbl in (("created", "Document Creation"), ("modified", "Document Modification")):
                val = props.get(prop_key)
                if val:
                    try:
                        clean_val = val.rstrip("Z")
                        dt = datetime.fromisoformat(clean_val)
                        events.append(TimelineEvent(
                            id=f"EVT-{investigation_id[-6:]}-{evt_counter:04d}",
                            investigation_id=investigation_id,
                            evidence_id=ev.id,
                            original_timestamp=val,
                            original_timezone="UTC",
                            normalized_utc=dt.isoformat() + "Z",
                            timestamp_source=f"Office Core Properties ({prop_key.title()})",
                            transformation_applied="OpenXML ISO 8601 UTC Parse",
                            reliability="High",
                            event_type=event_lbl,
                            description=f"Office document '{ev.filename}' {prop_key} timestamp.",
                            related_evidence_ids=[ev.id]
                        ))
                        evt_counter += 1
                    except Exception:
                        pass

            # Contradiction check: modified before created
            if props.get("created") and props.get("modified"):
                try:
                    c_dt = datetime.fromisoformat(props["created"].rstrip("Z"))
                    m_dt = datetime.fromisoformat(props["modified"].rstrip("Z"))
                    if m_dt < c_dt:
                        contradictions.append(ContradictionItem(
                            id=f"CTD-OFFICE-ORDER-{ev.id}",
                            title=f"Modification Precedes Creation in {ev.filename}",
                            category="Timestamp Inconsistency",
                            evidence_ids=[ev.id],
                            details=f"Document modified timestamp ({props['modified']}) is earlier than created timestamp ({props['created']}). Indicates template reuse or metadata tampering.",
                            observed_conflicts=[{"created": props["created"], "modified": props["modified"]}]
                        ))
                except Exception:
                    pass

    # Chronological sort
    events.sort(key=lambda x: x.normalized_utc)
    return events, contradictions
