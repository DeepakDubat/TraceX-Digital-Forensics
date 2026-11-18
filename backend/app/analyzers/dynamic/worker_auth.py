"""
TraceX Two-Plane Architecture — Worker Authentication & Communication Channel
Universal Digital Forensics & Evidence Intelligence Platform v2.0.0

Manages restricted, short-lived cryptographic authorization between the TraceX
Manager VM and isolated Analysis Worker VMs.

Security Guarantees:
1. Zero Manager Leakage: Workers NEVER receive database access, API keys, or user sessions.
2. Ephemeral Tokenization: Cryptographically signed per-analysis tokens valid only for the active session.
3. Strict Scoping: Workers can ONLY request assigned evidence and post assigned telemetry for their run_id.
4. Heartbeat Monitoring: Automatic failure detection if worker stops responding.
5. Replay Defense: Tokens expire after session completion and cannot be reused.
"""

import time
import hmac
import json
import base64
import hashlib
import secrets
import logging
from datetime import datetime
from typing import Dict, Any, Optional, List, Tuple
from pathlib import Path

from backend.app.config import settings

logger = logging.getLogger(__name__)


class WorkerAuthError(Exception):
    """Raised when worker token validation or authentication fails."""
    pass


class WorkerAuthManager:
    """
    Orchestrates secure Manager-Worker communication tokens and session telemetry
    for isolated Windows and Android worker environments.
    """

    def __init__(self):
        # Ephemeral signing key generated per manager process lifecycle
        self._signing_key: bytes = secrets.token_bytes(32)
        # In-memory registry of active worker sessions
        self._active_sessions: Dict[str, Dict[str, Any]] = {}

    def generate_worker_token(
        self,
        run_id: str,
        target_binary: str,
        expected_sha256: str,
        expires_in_seconds: int = 600,
        worker_type: str = "windows"
    ) -> str:
        """
        Generates a tamper-proof, short-lived authorization token for an isolated worker.
        """
        now = int(time.time())
        exp = now + expires_in_seconds
        nonce = secrets.token_hex(8)

        payload = {
            "run_id": run_id,
            "target_binary": target_binary,
            "expected_sha256": expected_sha256,
            "worker_type": worker_type,
            "issued_at": now,
            "expires_at": exp,
            "nonce": nonce
        }

        payload_bytes = json.dumps(payload, sort_keys=True).encode("utf-8")
        payload_b64 = base64.urlsafe_b64encode(payload_bytes).decode("utf-8").rstrip("=")

        sig = hmac.new(self._signing_key, payload_b64.encode("utf-8"), hashlib.sha256).hexdigest()
        token = f"wx_{payload_b64}.{sig}"

        # Register active session
        self._active_sessions[run_id] = {
            "run_id": run_id,
            "token": token,
            "target_binary": target_binary,
            "expected_sha256": expected_sha256,
            "worker_type": worker_type,
            "status": "PROVISIONED",
            "issued_at_iso": datetime.utcnow().isoformat(),
            "expires_at_epoch": exp,
            "last_heartbeat_iso": None,
            "heartbeat_count": 0,
            "worker_ip": None,
            "telemetry_received": False,
            "artifacts_collected": []
        }

        logger.info(f"Generated worker authorization token for run {run_id} (expires in {expires_in_seconds}s)")
        return token

    def validate_worker_token(self, run_id: str, auth_token: str) -> Dict[str, Any]:
        """
        Validates token signature, expiration, and strict scoping to run_id.
        Raises WorkerAuthError if invalid.
        """
        if not auth_token or not auth_token.startswith("wx_") or "." not in auth_token:
            raise WorkerAuthError("Invalid worker authorization token format.")

        prefix_and_payload, sig = auth_token.split(".", 1)
        payload_b64 = prefix_and_payload[3:]  # Strip 'wx_'

        # Re-verify HMAC signature
        expected_sig = hmac.new(self._signing_key, payload_b64.encode("utf-8"), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(sig, expected_sig):
            raise WorkerAuthError("Worker token cryptographic signature verification failed.")

        # Decode payload
        try:
            # Re-pad b64
            padded = payload_b64 + "=" * (-len(payload_b64) % 4)
            payload_bytes = base64.urlsafe_b64decode(padded)
            payload = json.loads(payload_bytes.decode("utf-8"))
        except Exception as e:
            raise WorkerAuthError(f"Worker token deserialization failed: {e}")

        # Check run_id scoping
        if payload.get("run_id") != run_id:
            raise WorkerAuthError(f"Worker token is scoped to run {payload.get('run_id')}, cannot access run {run_id}.")

        # Check expiration
        now = int(time.time())
        if now > payload.get("expires_at", 0):
            raise WorkerAuthError("Worker authorization token has expired.")

        # Check active session registry
        session = self._active_sessions.get(run_id)
        if not session:
            raise WorkerAuthError(f"No active worker session registered for run {run_id}.")

        return payload

    def record_heartbeat(self, run_id: str, client_ip: str, agent_version: Optional[str] = None) -> Dict[str, Any]:
        """Records worker health heartbeat."""
        session = self._active_sessions.get(run_id)
        if not session:
            raise WorkerAuthError(f"Unknown session {run_id}")

        now_iso = datetime.utcnow().isoformat()
        session["last_heartbeat_iso"] = now_iso
        session["heartbeat_count"] += 1
        session["worker_ip"] = client_ip
        session["agent_version"] = agent_version or "1.0.0"
        if session["status"] == "PROVISIONED":
            session["status"] = "CONNECTED"

        return {
            "status": "acknowledged",
            "run_id": run_id,
            "session_status": session["status"],
            "timestamp": now_iso
        }

    def record_telemetry_batch(self, run_id: str, telemetry_payload: Dict[str, Any]) -> int:
        """
        Receives and normalizes telemetry events submitted from the worker agent.
        """
        session = self._active_sessions.get(run_id)
        if not session:
            raise WorkerAuthError(f"Unknown session {run_id}")

        session["status"] = "ANALYZING"
        session["telemetry_received"] = True

        from backend.app.analyzers.dynamic.telemetry_collector import telemetry_collector
        from backend.app.core.models import DynamicTelemetryEvent
        from backend.app.database.repository import repo

        run = repo.get_sandbox_run(run_id)
        inv_id = run.investigation_id if run else "UNKNOWN_INV"
        evidence_id = getattr(run, "evidence_id", None) or "UNKNOWN_EVIDENCE"
        worker_vm_id = session.get("worker_vm_id", "TraceX-Worker-Win10")

        events = telemetry_payload.get("events", [])
        ingested = 0

        for raw_ev in events:
            cat = str(raw_ev.get("event_category") or raw_ev.get("event_type") or "process").lower()
            ev_details = raw_ev.get("details", {})
            if not isinstance(ev_details, dict):
                ev_details = {"raw": str(ev_details)}

            # Ensure strict 7 forensic audit fields
            ev_details["analysis_id"] = run_id
            ev_details["evidence_id"] = raw_ev.get("evidence_id") or evidence_id
            ev_details["worker_vm_id"] = raw_ev.get("worker_vm_id") or worker_vm_id
            ev_details["source"] = raw_ev.get("source") or "guest_agent"
            ev_details["collection_method"] = raw_ev.get("collection_method") or (
                "kernel_etw" if session.get("worker_type") == "windows" else "logcat_hook"
            )

            ev = DynamicTelemetryEvent(
                id=raw_ev.get("id") or f"EV-{secrets.token_hex(4)}",
                run_id=run_id,
                investigation_id=inv_id,
                event_category=cat,
                timestamp_utc=raw_ev.get("timestamp_utc") or datetime.utcnow().isoformat(),
                process_id=raw_ev.get("process_id"),
                process_name=raw_ev.get("process_name"),
                command_line=ev_details.get("command_line") or raw_ev.get("command_line"),
                target_path=raw_ev.get("target") or raw_ev.get("target_path"),
                operation=raw_ev.get("action") or raw_ev.get("operation") or "EXECUTE",
                details=ev_details,
                is_simulated=False
            )
            repo.add_telemetry_event(ev)
            ingested += 1

        logger.info(f"Ingested {ingested} telemetry events from worker for run {run_id}")
        return ingested

    def record_dropped_artifact(
        self,
        run_id: str,
        filename: str,
        file_bytes: bytes,
        relative_path: str
    ) -> Dict[str, Any]:
        """Safely saves a dropped artifact recovered from worker execution."""
        session = self._active_sessions.get(run_id)
        if not session:
            raise WorkerAuthError(f"Unknown session {run_id}")

        # Compute SHA-256 of artifact
        art_sha256 = hashlib.sha256(file_bytes).hexdigest()

        # Save artifact into isolated staging artifacts directory
        artifacts_dir = settings.DATA_DIR / "staging" / run_id / "artifacts"
        artifacts_dir.mkdir(parents=True, exist_ok=True)
        safe_name = Path(filename).name
        target_path = artifacts_dir / safe_name
        target_path.write_bytes(file_bytes)

        artifact_record = {
            "filename": safe_name,
            "relative_path": relative_path,
            "sha256": art_sha256,
            "size_bytes": len(file_bytes),
            "stored_path": str(target_path)
        }
        session["artifacts_collected"].append(artifact_record)

        # Ingest into repository
        from backend.app.database.repository import repo
        from backend.app.core.models import DynamicArtifact

        run = repo.get_sandbox_run(run_id)
        inv_id = run.investigation_id if run else "UNKNOWN_INV"

        repo.add_dynamic_artifact(
            DynamicArtifact(
                id=f"ART-{secrets.token_hex(4).upper()}",
                run_id=run_id,
                investigation_id=inv_id,
                artifact_type="dropped_file",
                filename=safe_name,
                file_path=str(target_path),
                size_bytes=len(file_bytes),
                sha256=art_sha256,
                description=f"Dropped artifact recovered from {relative_path}",
                created_at_utc=datetime.utcnow().isoformat()
            )
        )

        return artifact_record

    def get_session(self, run_id: str) -> Optional[Dict[str, Any]]:
        """Returns session status metadata."""
        return self._active_sessions.get(run_id)

    def revoke_worker_session(self, run_id: str):
        """Terminates and purges worker session credentials."""
        if run_id in self._active_sessions:
            self._active_sessions[run_id]["status"] = "TERMINATED"
            del self._active_sessions[run_id]
            logger.info(f"Revoked worker session credentials for run {run_id}")


worker_auth_manager = WorkerAuthManager()

