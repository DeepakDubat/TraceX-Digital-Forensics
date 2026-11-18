import logging
from abc import ABC, abstractmethod
from typing import Dict, Any, List, Optional, Type
from pathlib import Path

from backend.app.core.models import (
    DynamicSandboxRun,
    SandboxEnvironmentInfo
)

logger = logging.getLogger(__name__)

class ISandboxProvider(ABC):
    """
    Standard interface for all TraceX isolated dynamic execution providers.
    Every provider must manage isolated provisioning, execution, telemetry collection,
    termination, and clean snapshot restoration.
    """

    @property
    @abstractmethod
    def provider_id(self) -> str:
        """Unique provider identifier (e.g. 'windows_sandbox', 'hyperv', 'android_emulator')."""
        pass

    @property
    @abstractmethod
    def name(self) -> str:
        """Human-readable provider name."""
        pass

    @property
    @abstractmethod
    def os_family(self) -> str:
        """Target operating system family: 'windows' or 'android'."""
        pass

    @abstractmethod
    def preflight(self) -> Dict[str, Any]:
        """
        Conducts genuine environment readiness inspection.
        Returns: {'ready': bool, 'status': str, 'details': dict}
        """
        pass

    @abstractmethod
    def provision(self, run: DynamicSandboxRun, staged_file: Path) -> Dict[str, Any]:
        """
        Prepares the disposable VM, container, or emulator snapshot.
        Configures network isolation, memory limits, and guest instrumentation.
        """
        pass

    @abstractmethod
    def execute(self, run: DynamicSandboxRun, timeout_seconds: int) -> Dict[str, Any]:
        """
        Starts the isolated execution inside the guest.
        Returns initial execution confirmation.
        """
        pass

    @abstractmethod
    def collect_telemetry(self, run: DynamicSandboxRun) -> Dict[str, Any]:
        """
        Extracts guest telemetry (processes, files, registry, network flows, logs).
        Returns structured telemetry dictionary.
        """
        pass

    @abstractmethod
    def terminate(self, run: DynamicSandboxRun) -> None:
        """Immediately halts the guest execution process."""
        pass

    @abstractmethod
    def restore_and_cleanup(self, run: DynamicSandboxRun) -> None:
        """
        Restores clean baseline snapshot and cleans up temporary staging files.
        Guarantees zero persistent malware remnants.
        """
        pass

class SandboxRegistry:
    """
    Central repository of registered dynamic analysis providers.
    Supports pluggable hypervisors, container engines, and Android emulators.
    """

    def __init__(self):
        self._providers: Dict[str, ISandboxProvider] = {}

    def register(self, provider: ISandboxProvider):
        """Registers a dynamic analysis execution provider."""
        self._providers[provider.provider_id] = provider
        logger.info(f"Registered dynamic sandbox provider: {provider.name} ({provider.provider_id})")

    def get_provider(self, provider_id: str) -> Optional[ISandboxProvider]:
        """Retrieves a provider by ID."""
        return self._providers.get(provider_id)

    def list_providers(self, os_family: Optional[str] = None) -> List[ISandboxProvider]:
        """Returns all registered providers, optionally filtered by OS family."""
        if os_family:
            return [p for p in self._providers.values() if p.os_family.lower() == os_family.lower()]
        return list(self._providers.values())

    def resolve_best_provider(self, target_type: str) -> Optional[ISandboxProvider]:
        """
        Resolves the best available execution provider based on target format.
        Prefers genuinely ready providers.
        """
        os_target = "android" if target_type.lower() == "apk" else "windows"
        candidates = self.list_providers(os_family=os_target)

        # First pass: find provider reporting ready
        for p in candidates:
            try:
                chk = p.preflight()
                if chk.get("ready"):
                    return p
            except Exception:
                continue

        # Second pass: return default configured candidate if none actively ready
        return candidates[0] if candidates else None

sandbox_registry = SandboxRegistry()
