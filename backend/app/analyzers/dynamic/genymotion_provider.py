import shutil
import logging
from pathlib import Path
from typing import Dict, Any, Optional

from backend.app.core.models import DynamicSandboxRun
from backend.app.analyzers.dynamic.sandbox_registry import ISandboxProvider

logger = logging.getLogger(__name__)

class GenymotionProvider(ISandboxProvider):
    """
    Orchestrates Genymotion Desktop / Player Android virtual devices via gmtool and adb.
    """

    @property
    def provider_id(self) -> str:
        return "genymotion"

    @property
    def name(self) -> str:
        return "Genymotion Desktop Android Player"

    @property
    def os_family(self) -> str:
        return "android"

    def preflight(self) -> Dict[str, Any]:
        """Detects if gmtool is installed and accessible."""
        gmtool_exe = shutil.which("gmtool")
        if gmtool_exe:
            return {
                "ready": True,
                "status": "INSTALLED_AND_READY",
                "details": {"path": gmtool_exe}
            }
        return {
            "ready": False,
            "status": "NOT_CONFIGURED",
            "details": {
                "message": "Genymotion command-line utility (gmtool) is not found in system PATH.",
                "hint": "Install Genymotion Desktop and add its directory to system PATH."
            }
        }

    def provision(self, run: DynamicSandboxRun, staged_file: Path) -> Dict[str, Any]:
        pre = self.preflight()
        if not pre.get("ready"):
            raise RuntimeError("Genymotion is not configured on this host.")
        return {"staged_file": str(staged_file)}

    def execute(self, run: DynamicSandboxRun, timeout_seconds: int) -> Dict[str, Any]:
        raise NotImplementedError("Genymotion execution requires configured gmtool.")

    def collect_telemetry(self, run: DynamicSandboxRun) -> Dict[str, Any]:
        return {"processes": [], "network_flows": [], "logs": []}

    def terminate(self, run: DynamicSandboxRun) -> None:
        pass

    def restore_and_cleanup(self, run: DynamicSandboxRun) -> None:
        pass

genymotion_provider = GenymotionProvider()
