import httpx
import logging
from pathlib import Path
from typing import Dict, Any, Optional
from datetime import datetime

from backend.app.config import settings
from backend.app.core.models import DynamicSandboxRun
from backend.app.analyzers.dynamic.sandbox_registry import ISandboxProvider

logger = logging.getLogger(__name__)

class MobSFDynamicAdapter(ISandboxProvider):
    """
    Connects to MobSF Dynamic Analysis engine (Instrumented Emulator / Frida).
    Orchestrates dynamic testing, clipboard captures, runtime API monitoring, and exports reports.
    """

    @property
    def provider_id(self) -> str:
        return "mobsf_dynamic"

    @property
    def name(self) -> str:
        return "MobSF Dynamic Analyzer"

    @property
    def os_family(self) -> str:
        return "android"

    def preflight(self) -> Dict[str, Any]:
        """Probes MobSF REST connectivity."""
        url = getattr(settings, "MOBSF_URL", "").strip().rstrip('/')
        api_key = getattr(settings, "MOBSF_API_KEY", "").strip()

        if not url or not api_key:
            return {
                "ready": False,
                "status": "NOT_CONFIGURED",
                "details": {"message": "MobSF REST URL or API Key is not configured in Tool Config."}
            }

        headers = {"Authorization": api_key}
        try:
            with httpx.Client(timeout=3.0) as client:
                resp = client.get(f"{url}/api/v1/dynamic/get_apps", headers=headers)
                if resp.status_code == 200:
                    return {
                        "ready": True,
                        "status": "INSTALLED_AND_READY",
                        "details": {"connected": True, "endpoint": url}
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
                "details": {"error": f"Failed to connect to MobSF service: {str(e)}"}
            }

    def provision(self, run: DynamicSandboxRun, staged_file: Path) -> Dict[str, Any]:
        pre = self.preflight()
        if not pre.get("ready"):
            raise RuntimeError("MobSF Dynamic Analyzer is not accessible.")
        return {"staged_file": str(staged_file)}

    def execute(self, run: DynamicSandboxRun, timeout_seconds: int) -> Dict[str, Any]:
        url = getattr(settings, "MOBSF_URL", "").strip().rstrip('/')
        api_key = getattr(settings, "MOBSF_API_KEY", "").strip()
        headers = {"Authorization": api_key}
        target_hash = run.target_sha256 or run.evidence_id

        try:
            with httpx.Client(timeout=30.0) as client:
                data = {"hash": target_hash}
                resp = client.post(f"{url}/api/v1/dynamic/start_analysis", headers=headers, data=data)
                return {"started": resp.status_code == 200, "status_code": resp.status_code}
        except Exception as e:
            logger.error(f"MobSF dynamic start failed: {e}")
            raise RuntimeError(f"MobSF dynamic execution failed: {str(e)}")

    def collect_telemetry(self, run: DynamicSandboxRun) -> Dict[str, Any]:
        url = getattr(settings, "MOBSF_URL", "").strip().rstrip('/')
        api_key = getattr(settings, "MOBSF_API_KEY", "").strip()
        headers = {"Authorization": api_key}
        target_hash = run.target_sha256 or run.evidence_id

        try:
            with httpx.Client(timeout=30.0) as client:
                data = {"hash": target_hash}
                resp = client.post(f"{url}/api/v1/dynamic/report_json", headers=headers, data=data)
                if resp.status_code == 200:
                    report = resp.json()
                    return {
                        "processes": report.get("processes", []),
                        "file_events": report.get("files", []),
                        "registry_events": [],
                        "network_flows": report.get("urls", []),
                        "logs": report.get("logcat", [])[:500]
                    }
        except Exception:
            pass

        return {"processes": [], "network_flows": [], "logs": []}

    def terminate(self, run: DynamicSandboxRun) -> None:
        url = getattr(settings, "MOBSF_URL", "").strip().rstrip('/')
        api_key = getattr(settings, "MOBSF_API_KEY", "").strip()
        headers = {"Authorization": api_key}
        target_hash = run.target_sha256 or run.evidence_id
        try:
            with httpx.Client(timeout=10.0) as client:
                client.post(f"{url}/api/v1/dynamic/stop_analysis", headers=headers, data={"hash": target_hash})
        except Exception:
            pass

    def restore_and_cleanup(self, run: DynamicSandboxRun) -> None:
        self.terminate(run)

mobsf_dynamic_adapter = MobSFDynamicAdapter()
