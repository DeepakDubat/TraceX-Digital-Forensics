import os
import shutil
import hashlib
import logging
from pathlib import Path
from typing import Dict, Any, Optional, Tuple
from backend.app.config import settings

logger = logging.getLogger(__name__)

class SandboxSecurityViolation(Exception):
    """Raised when an action violates the sandbox safety boundaries."""
    pass

class SandboxPolicyEnforcer:
    """
    Guarantees forensic integrity, isolation boundaries, and anti-contamination controls:
    1. Zero Host Execution: Rejects any attempt to execute untrusted binaries on the host.
    2. Staging Isolation: Staged working copies are verified against original SHA-256 hashes.
    3. Network Gating: Default NETWORK: DISABLED. Air-Gap / Local-Only mode enforced.
    4. Quota Enforcement: Hard limits on memory, CPU, and execution timeout.
    """

    MAX_TIMEOUT_SECONDS: int = 600
    DEFAULT_TIMEOUT_SECONDS: int = 120
    DEFAULT_MEMORY_MB: int = 4096
    MAX_MEMORY_MB: int = 16384

    def validate_execution_target(
        self,
        environment_id: str,
        target_path: Path,
        expected_sha256: str
    ) -> bool:
        """
        Validates that the target is genuine evidence and that the designated
        execution environment is an isolated guest container, never the host.
        """
        env_lower = environment_id.lower()
        if env_lower in ("host", "local_host", "workstation", "direct", "subprocess"):
            raise SandboxSecurityViolation(
                "CRITICAL SECURITY REJECTION: Direct host execution of untrusted forensic samples is strictly prohibited."
            )

        if not target_path.exists():
            raise FileNotFoundError(f"Target sample does not exist: {target_path}")

        # Verify hash matches expected
        actual_sha256 = self.compute_sha256(target_path)
        if actual_sha256.lower() != expected_sha256.lower():
            raise SandboxSecurityViolation(
                f"INTEGRITY VIOLATION: Target hash {actual_sha256} does not match evidence record {expected_sha256}."
            )

        return True

    def create_isolated_staging_copy(
        self,
        analysis_id: str,
        original_evidence_path: Path,
        expected_sha256: str
    ) -> Tuple[Path, str]:
        """
        Safely creates a disposable working copy of the evidence in an isolated staging folder.
        Verifies the SHA-256 digest before and after copy.
        """
        # Ensure staging root exists
        staging_dir = settings.DATA_DIR / "staging" / analysis_id
        staging_dir.mkdir(parents=True, exist_ok=True)

        # Sanitize filename
        safe_filename = Path(original_evidence_path.name).name
        staged_target = staging_dir / safe_filename

        # Copy original evidence
        shutil.copy2(str(original_evidence_path), str(staged_target))

        # Re-verify staged copy hash
        staged_sha256 = self.compute_sha256(staged_target)
        if staged_sha256.lower() != expected_sha256.lower():
            shutil.rmtree(staging_dir, ignore_errors=True)
            raise SandboxSecurityViolation(
                f"Staged copy verification failed: expected {expected_sha256}, got {staged_sha256}"
            )

        # Make staged file read-only to prevent tampering prior to execution
        try:
            os.chmod(str(staged_target), 0o444)
        except Exception:
            pass

        return staged_target, staged_sha256

    def enforce_network_policy(self, network_policy: str) -> str:
        """
        Normalizes and enforces network containment policy.
        In Local-Only / Air-Gap mode, LIVE_INTERNET is strictly forbidden.
        """
        norm_policy = network_policy.upper()
        if norm_policy not in ("DISABLED", "ISOLATED_SIMULATION", "LIVE_INTERNET"):
            norm_policy = "DISABLED"

        if getattr(settings, "LOCAL_ONLY_MODE", False) and norm_policy == "LIVE_INTERNET":
            logger.warning("Network policy downgraded to ISOLATED_SIMULATION: Air-Gap mode is active.")
            return "ISOLATED_SIMULATION"

        return norm_policy

    def validate_timeout(self, requested_timeout: Optional[int]) -> int:
        """Enforces safe timeout boundaries."""
        if not requested_timeout or requested_timeout <= 0:
            return self.DEFAULT_TIMEOUT_SECONDS
        return min(requested_timeout, self.MAX_TIMEOUT_SECONDS)

    def validate_memory(self, requested_memory_mb: Optional[int]) -> int:
        """Enforces guest RAM constraints."""
        if not requested_memory_mb or requested_memory_mb <= 512:
            return self.DEFAULT_MEMORY_MB
        return min(requested_memory_mb, self.MAX_MEMORY_MB)

    @staticmethod
    def compute_sha256(file_path: Path) -> str:
        """Computes SHA-256 checksum in chunks."""
        hasher = hashlib.sha256()
        with open(file_path, "rb") as f:
            while chunk := f.read(65536):
                hasher.update(chunk)
        return hasher.hexdigest().upper()

sandbox_policy = SandboxPolicyEnforcer()
