"""
TraceX Network Privacy & Connection Mode Engine
================================================
Authoritative controller for TraceX global network connectivity:
- LOCAL_ONLY: Strictly air-gapped forensic processing. Zero outbound external queries.
- HYBRID: Local processing combined with explicitly configured external threat intel & OSINT.

Guarantees:
- Backend is the single authoritative source of truth.
- Mode is persisted securely across application restarts.
- Fresh installations default to LOCAL_ONLY.
- Evidence files (APK, PE, ELF, etc.) are NEVER automatically uploaded to cloud services.
"""

from enum import Enum
from typing import Dict, Any, List
import logging
from backend.app.config import settings
from backend.app.database.repository import repo

logger = logging.getLogger("tracex.network_mode")


class NetworkMode(str, Enum):
    LOCAL_ONLY = "LOCAL_ONLY"
    HYBRID = "HYBRID"


def get_network_mode() -> NetworkMode:
    """Returns authoritative current NetworkMode enum, consulting DB ledger if available."""
    try:
        saved_mode = repo.get_setting("network_mode")
        if saved_mode and saved_mode.upper() in (NetworkMode.LOCAL_ONLY.value, NetworkMode.HYBRID.value):
            is_local = (saved_mode.upper() == NetworkMode.LOCAL_ONLY.value)
            settings.LOCAL_ONLY_MODE = is_local
            return NetworkMode.LOCAL_ONLY if is_local else NetworkMode.HYBRID
    except Exception:
        pass
    is_local_only = getattr(settings, "LOCAL_ONLY_MODE", True)
    return NetworkMode.LOCAL_ONLY if is_local_only else NetworkMode.HYBRID


LOCAL_ONLY_DESCRIPTION = "All forensic processing stays on the local computer."
LOCAL_ONLY_FEATURES: List[str] = [
    "Offline static analysis.",
    "Local forensic tools.",
    "Local YARA scanning.",
    "Offline reports.",
    "External API requests blocked.",
    "No automatic cloud communication."
]

HYBRID_DESCRIPTION = "Use local forensic processing together with explicitly configured online integrations."
HYBRID_FEATURES: List[str] = [
    "Local static analysis remains enabled.",
    "VirusTotal.",
    "AlienVault OTX.",
    "AbuseIPDB.",
    "Shodan.",
    "URLhaus.",
    "Other configured OSINT and threat intelligence services."
]


def get_current_network_mode() -> Dict[str, Any]:
    """Retrieves authoritative current network mode and capabilities, consulting DB ledger."""
    mode_enum = get_network_mode()
    is_local_only = (mode_enum == NetworkMode.LOCAL_ONLY)
    mode = mode_enum.value

    return {
        "success": True,
        "mode": mode,
        "local_only_mode": is_local_only,
        "description": LOCAL_ONLY_DESCRIPTION if is_local_only else HYBRID_DESCRIPTION,
        "features": LOCAL_ONLY_FEATURES if is_local_only else HYBRID_FEATURES,
        "available_modes": [NetworkMode.LOCAL_ONLY.value, NetworkMode.HYBRID.value],
        "privacy_guarantees": [
            "zero_evidence_upload",
            "evidence_stays_local",
            "dpapi_encrypted_keys",
        ],
        "evidence_upload_policy": "STRICTLY_LOCAL_NEVER_AUTO_UPLOAD",
    }


def set_network_mode(mode_input: str) -> Dict[str, Any]:
    """
    Sets and persists the authoritative global network mode.
    Updates in-memory settings and SQLite configuration ledger.
    """
    normalized = mode_input.upper().strip()
    if normalized not in (NetworkMode.LOCAL_ONLY.value, NetworkMode.HYBRID.value):
        raise ValueError(f"Invalid network mode '{mode_input}'. Must be 'LOCAL_ONLY' or 'HYBRID'.")

    is_local_only = (normalized == NetworkMode.LOCAL_ONLY.value)
    
    # 1. Update in-memory runtime setting
    settings.LOCAL_ONLY_MODE = is_local_only

    # 2. Persist to database settings table
    try:
        repo.save_setting("network_mode", normalized)
        repo.save_setting("local_only_mode", "true" if is_local_only else "false")
    except Exception as e:
        logger.error(f"Failed to persist network mode to database: {e}")

    logger.info(f"TraceX Network Privacy Mode updated to: {normalized} (LOCAL_ONLY_MODE={is_local_only})")

    return {
        "success": True,
        "mode": normalized,
        "local_only_mode": is_local_only,
        "message": f"Network privacy mode successfully updated to {normalized}.",
        "description": LOCAL_ONLY_DESCRIPTION if is_local_only else HYBRID_DESCRIPTION,
        "features": LOCAL_ONLY_FEATURES if is_local_only else HYBRID_FEATURES,
        "evidence_upload_policy": "STRICTLY_LOCAL_NEVER_AUTO_UPLOAD",
    }


def init_network_mode() -> str:
    """
    Called on backend startup / lifespan.
    Restores previously saved network mode from database or defaults to LOCAL_ONLY on fresh install.
    Returns the active mode string ("LOCAL_ONLY" or "HYBRID").
    """
    try:
        saved_mode = repo.get_setting("network_mode")
        if saved_mode and saved_mode.upper() in (NetworkMode.LOCAL_ONLY.value, NetworkMode.HYBRID.value):
            mode = saved_mode.upper()
            settings.LOCAL_ONLY_MODE = (mode == NetworkMode.LOCAL_ONLY.value)
            logger.info(f"Restored persisted network mode: {mode}")
            return mode

        saved_local_only = repo.get_setting("local_only_mode")
        if saved_local_only is not None:
            is_local = saved_local_only.lower() in ("true", "1", "yes")
            settings.LOCAL_ONLY_MODE = is_local
            mode = NetworkMode.LOCAL_ONLY.value if is_local else NetworkMode.HYBRID.value
            repo.save_setting("network_mode", mode)
            logger.info(f"Migrated and restored local_only setting: {mode}")
            return mode

        # Fresh installation: Default to LOCAL_ONLY (Strict Privacy by Default)
        settings.LOCAL_ONLY_MODE = True
        repo.save_setting("network_mode", NetworkMode.LOCAL_ONLY.value)
        repo.save_setting("local_only_mode", "true")
        logger.info("Initialized fresh installation default: LOCAL_ONLY mode.")
        return NetworkMode.LOCAL_ONLY.value
    except Exception as e:
        logger.warning(f"Could not read network mode from database during initialization: {e}")
        settings.LOCAL_ONLY_MODE = True
        return NetworkMode.LOCAL_ONLY.value
