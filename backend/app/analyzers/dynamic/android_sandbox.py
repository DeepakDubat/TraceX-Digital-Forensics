import logging
from pathlib import Path
from typing import Dict, Any, Optional

from backend.app.core.models import DynamicSandboxRun
from backend.app.analyzers.dynamic.sandbox_registry import sandbox_registry
from backend.app.analyzers.dynamic.android_emulator_provider import android_emulator_provider
from backend.app.analyzers.dynamic.mobfs_dynamic_adapter import mobsf_dynamic_adapter
from backend.app.analyzers.dynamic.sandbox_policy import sandbox_policy

logger = logging.getLogger(__name__)

class AndroidSandboxCoordinator:
    """
    Coordinates dynamic analysis workflows for Android APK applications.
    Manages provider selection, preflight readiness checks, controlled APK installation,
    and telemetry ingestion.
    """

    def __init__(self):
        # Register Android providers with registry
        sandbox_registry.register(android_emulator_provider)
        sandbox_registry.register(mobsf_dynamic_adapter)

    def select_provider(self, requested_provider: Optional[str] = None):
        """Resolves the designated or best available Android provider."""
        if requested_provider:
            p = sandbox_registry.get_provider(requested_provider)
            if p and p.os_family == "android":
                return p

        # Fallback to best available
        return sandbox_registry.resolve_best_provider(target_type="apk") or android_emulator_provider

android_sandbox_coordinator = AndroidSandboxCoordinator()
