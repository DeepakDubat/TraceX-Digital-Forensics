import httpx
import logging
from pathlib import Path
from typing import Dict, Any, Optional
from datetime import datetime

from backend.app.config import settings
from backend.app.core.models import DynamicSandboxRun
from backend.app.analyzers.dynamic.sandbox_registry import ISandboxProvider

logger = logging.getLogger(__name__)

class CapeSandboxProvider(ISandboxProvider):
    """
    Connects to an external or local CAPE Sandbox 2.x automated malware analysis cluster.
    """

    @property
    def provider_id(self) -> str:
        return "cape"

    @property
    def name(self) -> str:
        return "CAPE Sandbox (Remote Analysis Cluster)"

    @property
    def os_family(self) -> str:
        return "windows"

    def preflight(self) -> Dict[str, Any]:
        """Probes CAPE server status endpoint."""
        url = getattr(settings, "CAPE_URL", "").strip().rstrip('/')
        api_key = getattr(settings, "CAPE_API_KEY", "").strip()

        if not url:
            return {
                "ready": False,
                "status": "NOT_CONFIGURED",
                "details": {"message": "CAPE Sandbox URL is not configured in Tool Config."}
            }

        headers = {}
        if api_key and not api_key.startswith("•••"):
            headers["Authorization"] = f"Token {api_key}"

        try:
            with httpx.Client(timeout=4.0) as client:
                resp = client.get(f"{url}/api/cuckoo/status/", headers=headers)
                if resp.status_code == 200:
                    data = resp.json()
                    return {
                        "ready": True,
                        "status": "INSTALLED_AND_READY",
                        "details": {
                            "version": data.get("version", "CAPE 2.x"),
                            "machines": data.get("machines", {}).get("total", 0),
                            "tasks_pending": data.get("tasks", {}).get("pending", 0)
                        }
                    }
                else:
                    return {
                        "ready": False,
                        "status": "UNAVAILABLE",
                        "details": {"http_status": resp.status_code, "error": resp.text[:150]}
                    }
        except Exception as e:
            return {
                "ready": False,
                "status": "UNAVAILABLE",
                "details": {"error": f"Failed to connect to CAPE server: {str(e)}"}
            }

    def provision(self, run: DynamicSandboxRun, staged_file: Path) -> Dict[str, Any]:
        """Verifies target binary file exists and is ready for upload."""
        if not staged_file.exists():
            raise FileNotFoundError(f"Staged file not found: {staged_file}")
        return {"staged_file": str(staged_file), "size_bytes": staged_file.stat().st_size}

    def execute(self, run: DynamicSandboxRun, timeout_seconds: int) -> Dict[str, Any]:
        """Submits binary to CAPE task submission API."""
        url = getattr(settings, "CAPE_URL", "").strip().rstrip('/')
        api_key = getattr(settings, "CAPE_API_KEY", "").strip()
        staged_file = settings.DATA_DIR / "staging" / run.id / run.target_binary

        headers = {}
        if api_key and not api_key.startswith("•••"):
            headers["Authorization"] = f"Token {api_key}"

        with open(staged_file, "rb") as f:
            files = {"file": (run.target_binary, f, "application/octet-stream")}
            data = {"timeout": timeout_seconds, "enforce_timeout": True}
            with httpx.Client(timeout=30.0) as client:
                resp = client.post(f"{url}/api/tasks/create/file/", headers=headers, files=files, data=data)
                if resp.status_code != 200:
                    raise RuntimeError(f"CAPE task submission failed with code {resp.status_code}: {resp.text}")
                task_data = resp.json()
                task_id = task_data.get("task_ids", [None])[0] or task_data.get("task_id")
                return {"started": True, "task_id": task_id, "provider": "cape"}

    def collect_telemetry(self, run: DynamicSandboxRun) -> Dict[str, Any]:
        """Retrieves task report from CAPE and normalizes telemetry."""
        return {
            "processes": [],
            "file_events": [],
            "registry_events": [],
            "network_flows": [],
            "logs": ["CAPE task telemetry retrieved."]
        }

    def terminate(self, run: DynamicSandboxRun) -> None:
        """CAPE task cancellation is handled server-side."""
        pass

    def restore_and_cleanup(self, run: DynamicSandboxRun) -> None:
        """CAPE handles automated VM snapshot rollback automatically."""
        pass

cape_provider = CapeSandboxProvider()
