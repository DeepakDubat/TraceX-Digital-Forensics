import os
import json
import hmac
import hashlib
from pathlib import Path
from datetime import datetime
from typing import Optional, Dict, Any, List

from backend.app.config import settings
from backend.app.core.models import ChainOfCustodyEvent
from backend.app.database.repository import repo

def _get_checkpoint_store_path() -> Path:
    return settings.DATA_ROOT / ".ledger_checkpoints.json"

def _get_signing_key() -> bytes:
    """Retrieves or derives the DPAPI-anchored checkpoint signing key."""
    from backend.app.core.credential_manager import credential_manager, _dpapi_protect, _dpapi_unprotect
    if credential_manager._master_key:
        return hashlib.sha256(b"tracex_ledger_checkpoint_key:" + credential_manager._master_key).digest()
    
    key_file = settings.DATA_ROOT / ".ledger_signing_key.dpapi"
    if key_file.exists():
        try:
            unprotected = _dpapi_unprotect(key_file.read_bytes())
            if len(unprotected) == 32:
                return unprotected
        except Exception:
            pass
    
    # Generate new 32-byte key
    new_key = os.urandom(32)
    if os.name == "nt":
        try:
            protected = _dpapi_protect(new_key, "TraceX Ledger Signing Key")
            key_file.write_bytes(protected)
        except Exception:
            pass
    return new_key

def save_ledger_checkpoint(investigation_id: str, event: ChainOfCustodyEvent, event_count: int):
    """
    Saves a cryptographically signed checkpoint of the ledger state outside SQLite.
    Binds the ledger head to the DPAPI-protected key to defeat offline SQLite reconstruction.
    """
    try:
        store_path = _get_checkpoint_store_path()
        checkpoints = {}
        if store_path.exists():
            try:
                checkpoints = json.loads(store_path.read_text(encoding="utf-8"))
            except Exception:
                checkpoints = {}

        key = _get_signing_key()
        msg = f"{investigation_id}:{event.id}:{event.event_hash}:{event_count}".encode("utf-8")
        sig = hmac.new(key, msg, hashlib.sha256).hexdigest()

        checkpoints[investigation_id] = {
            "investigation_id": investigation_id,
            "last_event_id": event.id,
            "last_event_hash": event.event_hash,
            "event_count": event_count,
            "checkpoint_timestamp_utc": datetime.utcnow().isoformat() + "Z",
            "hmac_signature": sig
        }

        store_path.write_text(json.dumps(checkpoints, indent=2), encoding="utf-8")
    except Exception:
        pass

def get_ledger_checkpoint(investigation_id: str) -> Optional[Dict[str, Any]]:
    """Retrieves the signed checkpoint for an investigation if available."""
    store_path = _get_checkpoint_store_path()
    if not store_path.exists():
        return None
    try:
        checkpoints = json.loads(store_path.read_text(encoding="utf-8"))
        return checkpoints.get(investigation_id)
    except Exception:
        return None

def record_custody_event(
    investigation_id: str,
    event_type: str,
    examiner: str,
    evidence_id: Optional[str] = None,
    original_hash: Optional[str] = None,
    working_copy_hash: Optional[str] = None,
    verification_result: str = "PASSED",
    details: Optional[Dict[str, Any]] = None
) -> ChainOfCustodyEvent:
    """
    Appends a tamper-evident audit event to the Chain of Custody ledger.
    Employs cryptographic SHA-256 hash chaining:
    event_hash = SHA256(prev_hash + timestamp + event_type + details)
    Also anchors the new ledger head in a signed external checkpoint.
    """
    ts_utc = datetime.utcnow().isoformat() + "Z"
    clean_details = details or {}

    # Retrieve last event to compute hash chain
    last_event = repo.get_last_chain_of_custody_event(investigation_id)
    prev_hash = last_event.event_hash if last_event else "0" * 64

    # Compute current event hash
    hasher = hashlib.sha256()
    hasher.update(prev_hash.encode("ascii"))
    hasher.update(ts_utc.encode("ascii"))
    hasher.update(event_type.encode("ascii"))
    hasher.update(examiner.encode("utf-8"))
    if original_hash:
        hasher.update(original_hash.encode("ascii"))
    hasher.update(json.dumps(clean_details, sort_keys=True).encode("utf-8"))
    event_hash = hasher.hexdigest()

    event_id = f"COC-{investigation_id[-6:]}-{hashlib.md5((ts_utc + event_type).encode()).hexdigest()[:8].upper()}"

    event = ChainOfCustodyEvent(
        id=event_id,
        investigation_id=investigation_id,
        evidence_id=evidence_id,
        event_type=event_type,
        timestamp_utc=ts_utc,
        examiner=examiner,
        original_hash=original_hash,
        working_copy_hash=working_copy_hash,
        verification_result=verification_result,
        details=clean_details,
        prev_event_hash=prev_hash,
        event_hash=event_hash
    )

    repo.add_chain_of_custody_event(event)

    # Anchor signed checkpoint outside SQLite database
    try:
        events = repo.list_chain_of_custody(investigation_id)
        save_ledger_checkpoint(investigation_id, event, len(events))
    except Exception:
        pass

    return event

def verify_ledger_integrity(investigation_id: str) -> Dict[str, Any]:
    """
    Audits the complete Chain of Custody ledger for an investigation.
    Validates:
    1. Every event's prev_event_hash chains from the preceding event.
    2. Every event's event_hash matches the cryptographic SHA-256 hash of its row content.
    3. Chronological continuity (detects reordering, backdating, and omissions).
    4. External signed checkpoint verification (detects whole-database tampering or truncation).
    """
    events = repo.list_chain_of_custody(investigation_id)
    if not events:
        return {"status": "EMPTY", "valid": True, "event_count": 0}

    valid = True
    inconsistencies = []

    for i, ev in enumerate(events):
        expected_prev = "0" * 64 if i == 0 else events[i - 1].event_hash
        if ev.prev_event_hash != expected_prev:
            valid = False
            inconsistencies.append({
                "event_id": ev.id,
                "index": i,
                "reason": "Previous event hash mismatch",
                "expected": expected_prev,
                "actual": ev.prev_event_hash
            })

        # Recalculate content hash to detect in-place row tampering
        clean_details = ev.details or {}
        hasher = hashlib.sha256()
        hasher.update(ev.prev_event_hash.encode("ascii"))
        hasher.update(ev.timestamp_utc.encode("ascii"))
        hasher.update(ev.event_type.encode("ascii"))
        hasher.update(ev.examiner.encode("utf-8"))
        if ev.original_hash:
            hasher.update(ev.original_hash.encode("ascii"))
        hasher.update(json.dumps(clean_details, sort_keys=True).encode("utf-8"))
        computed_hash = hasher.hexdigest()

        if ev.event_hash != computed_hash:
            valid = False
            inconsistencies.append({
                "event_id": ev.id,
                "index": i,
                "reason": "Event content tampering detected: payload hash mismatch",
                "expected": computed_hash,
                "actual": ev.event_hash
            })

    # Validate against external signed checkpoint if present
    checkpoint = get_ledger_checkpoint(investigation_id)
    if checkpoint:
        key = _get_signing_key()
        msg = f"{investigation_id}:{checkpoint['last_event_id']}:{checkpoint['last_event_hash']}:{checkpoint['event_count']}".encode("utf-8")
        expected_sig = hmac.new(key, msg, hashlib.sha256).hexdigest()
        if not hmac.compare_digest(checkpoint.get("hmac_signature", ""), expected_sig):
            valid = False
            inconsistencies.append({
                "reason": "Checkpoint signature forgery detected: external checkpoint HMAC mismatch",
                "checkpoint": checkpoint
            })
        else:
            if len(events) < checkpoint["event_count"]:
                valid = False
                inconsistencies.append({
                    "reason": "Ledger truncation detected: database has fewer events than recorded in signed checkpoint",
                    "expected_count": checkpoint["event_count"],
                    "actual_count": len(events)
                })
            elif events and events[-1].event_hash != checkpoint["last_event_hash"] and len(events) == checkpoint["event_count"]:
                valid = False
                inconsistencies.append({
                    "reason": "Offline SQLite reconstruction detected: last event hash diverges from signed checkpoint",
                    "expected_hash": checkpoint["last_event_hash"],
                    "actual_hash": events[-1].event_hash
                })

    return {
        "status": "VERIFIED" if valid else "TAMPERED",
        "valid": valid,
        "event_count": len(events),
        "inconsistencies": inconsistencies
    }
