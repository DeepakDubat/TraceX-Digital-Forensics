import shutil
import subprocess
from pathlib import Path
from typing import Dict, Any, List
import httpx

from backend.app.config import settings
from backend.app.core.models import SandboxToolStatus

class SandboxDetector:
    """
    Detects the availability and operational readiness of local and remote
    dynamic analysis sandboxes, network simulation tools, and packet inspection engines.
    Does not assume any tool is present; accurately reports real environment state.
    """

    def detect_all_tools(self) -> List[SandboxToolStatus]:
        return [
            self.detect_cape_sandbox(),
            self.detect_fakenet(),
            self.detect_inetsim(),
            self.detect_tshark(),
            self.detect_zeek(),
            self.detect_suricata()
        ]

    def detect_cape_sandbox(self) -> SandboxToolStatus:
        """Inspects CAPE Sandbox remote API connectivity."""
        url = settings.CAPE_URL.strip()
        api_key = settings.CAPE_API_KEY.strip()

        if not url:
            return SandboxToolStatus(
                tool_name="CAPE Sandbox",
                status="NOT_CONFIGURED",
                details={"message": "CAPE Sandbox URL is not configured in settings."}
            )

        headers = {}
        if api_key and not api_key.startswith("•••"):
            headers["Authorization"] = f"Token {api_key}"

        try:
            with httpx.Client(timeout=4.0) as client:
                resp = client.get(f"{url.rstrip('/')}/api/cuckoo/status/", headers=headers)
                if resp.status_code == 200:
                    data = resp.json()
                    version = data.get("version", "CAPE 2.x")
                    return SandboxToolStatus(
                        tool_name="CAPE Sandbox",
                        status="INSTALLED",
                        version=version,
                        details={
                            "connected": True,
                            "machines": data.get("machines", {}).get("total", 0),
                            "tasks_pending": data.get("tasks", {}).get("pending", 0)
                        }
                    )
                else:
                    return SandboxToolStatus(
                        tool_name="CAPE Sandbox",
                        status="UNAVAILABLE",
                        details={"http_status": resp.status_code, "error": resp.text[:200]}
                    )
        except Exception as e:
            return SandboxToolStatus(
                tool_name="CAPE Sandbox",
                status="UNAVAILABLE",
                details={"error": f"Failed to connect to CAPE server: {str(e)}"}
            )

    def detect_fakenet(self) -> SandboxToolStatus:
        """Checks for FakeNet-NG network simulation tool."""
        configured_path = settings.FAKENET_PATH.strip()
        fakenet_exe = configured_path if configured_path and Path(configured_path).exists() else shutil.which("fakenet")

        if fakenet_exe and Path(fakenet_exe).exists():
            return SandboxToolStatus(
                tool_name="FakeNet-NG",
                status="INSTALLED",
                details={"path": str(fakenet_exe), "type": "Network Simulation Engine"}
            )
        elif configured_path:
            return SandboxToolStatus(
                tool_name="FakeNet-NG",
                status="UNAVAILABLE",
                details={"configured_path": configured_path, "error": "Configured path does not exist on disk."}
            )
        else:
            return SandboxToolStatus(
                tool_name="FakeNet-NG",
                status="NOT_CONFIGURED",
                details={"message": "FakeNet-NG executable not found in PATH or config."}
            )

    def detect_inetsim(self) -> SandboxToolStatus:
        """Checks for INetSim Internet simulation suite."""
        configured_path = settings.INETSIM_PATH.strip()
        inetsim_exe = configured_path if configured_path and Path(configured_path).exists() else shutil.which("inetsim")

        if inetsim_exe and Path(inetsim_exe).exists():
            return SandboxToolStatus(
                tool_name="INetSim",
                status="INSTALLED",
                details={"path": str(inetsim_exe), "type": "Simulated Internet Services"}
            )
        else:
            return SandboxToolStatus(
                tool_name="INetSim",
                status="NOT_CONFIGURED",
                details={"message": "INetSim not detected on host."}
            )

    def detect_tshark(self) -> SandboxToolStatus:
        """Checks for Wireshark / tshark command-line packet dissector."""
        configured_path = settings.TSHARK_PATH.strip()
        tshark_exe = configured_path if configured_path and Path(configured_path).exists() else shutil.which("tshark")

        if tshark_exe and Path(tshark_exe).exists():
            try:
                res = subprocess.run([tshark_exe, "-v"], capture_output=True, text=True, timeout=3.0)
                version_line = res.stdout.splitlines()[0] if res.stdout else "Wireshark/tshark"
                return SandboxToolStatus(
                    tool_name="Wireshark/tshark",
                    status="INSTALLED",
                    version=version_line,
                    details={"path": str(tshark_exe)}
                )
            except Exception:
                return SandboxToolStatus(
                    tool_name="Wireshark/tshark",
                    status="INSTALLED",
                    details={"path": str(tshark_exe)}
                )
        else:
            return SandboxToolStatus(
                tool_name="Wireshark/tshark",
                status="NOT_CONFIGURED",
                details={"message": "tshark binary not detected. Built-in Pure-Python PCAP engine is used."}
            )

    def detect_zeek(self) -> SandboxToolStatus:
        """Checks for Zeek Network Security Monitor."""
        configured_path = settings.ZEEK_PATH.strip()
        zeek_exe = configured_path if configured_path and Path(configured_path).exists() else shutil.which("zeek")

        if zeek_exe and Path(zeek_exe).exists():
            return SandboxToolStatus(
                tool_name="Zeek",
                status="INSTALLED",
                details={"path": str(zeek_exe)}
            )
        else:
            return SandboxToolStatus(
                tool_name="Zeek",
                status="NOT_CONFIGURED",
                details={"message": "Zeek network monitor is not installed."}
            )

    def detect_suricata(self) -> SandboxToolStatus:
        """Checks for Suricata IDS/IPS engine."""
        configured_path = settings.SURICATA_PATH.strip()
        suricata_exe = configured_path if configured_path and Path(configured_path).exists() else shutil.which("suricata")

        if suricata_exe and Path(suricata_exe).exists():
            return SandboxToolStatus(
                tool_name="Suricata",
                status="INSTALLED",
                details={"path": str(suricata_exe)}
            )
        else:
            return SandboxToolStatus(
                tool_name="Suricata",
                status="NOT_CONFIGURED",
                details={"message": "Suricata IDS is not installed."}
            )

sandbox_detector = SandboxDetector()
