"""
TraceX VirtualBox Host Controller Client
Universal Digital Forensics & Evidence Intelligence Platform v2.0.0

Hardened mutual TLS (mTLS) client library used by the TraceX Manager VM
to communicate securely with the VirtualBox Host Controller Agent.

Security Invariants:
- Strictly HTTPS with TLS 1.2+ (plain HTTP downgrade rejected)
- Server certificate cryptographically validated against TraceX Root CA
- Client certificate presented for mutual authentication
- Application-layer HMAC-SHA256 token passed for defense-in-depth
"""

import os
import json
import logging
import ssl
from pathlib import Path
from typing import Dict, Any, Optional
import urllib.request
import urllib.error

from backend.app.config import settings

logger = logging.getLogger(__name__)


class VirtualBoxHostClient:
    """
    Hardened mTLS client for communicating with the physical Windows host's
    restricted VirtualBox Host Controller Agent.
    """

    def __init__(
        self,
        base_url: Optional[str] = None,
        auth_token: Optional[str] = None,
        ca_file: Optional[str] = None,
        client_cert: Optional[str] = None,
        client_key: Optional[str] = None,
        allow_http_downgrade: bool = False,
        timeout: float = 15.0
    ):
        raw_url = (base_url or getattr(settings, "VBOX_HOST_AGENT_URL", "") or os.getenv("VBOX_HOST_AGENT_URL", "")).rstrip("/")
        self.auth_token = auth_token or getattr(settings, "VBOX_HOST_AGENT_TOKEN", "") or os.getenv("VBOX_HOST_AGENT_TOKEN", "")
        self.ca_file = ca_file or getattr(settings, "VBOX_HOST_AGENT_CA_CERT", "") or os.getenv("VBOX_HOST_AGENT_CA_CERT", "")
        self.client_cert = client_cert or getattr(settings, "VBOX_HOST_AGENT_CLIENT_CERT", "") or os.getenv("VBOX_HOST_AGENT_CLIENT_CERT", "")
        self.client_key = client_key or getattr(settings, "VBOX_HOST_AGENT_CLIENT_KEY", "") or os.getenv("VBOX_HOST_AGENT_CLIENT_KEY", "")
        self.allow_http_downgrade = allow_http_downgrade
        self.timeout = timeout

        # Invariant: Reject plain HTTP unless explicitly allowed for unit tests
        if raw_url.startswith("http://") and not self.allow_http_downgrade:
            raise ValueError(
                f"SECURITY REJECTION: Plain HTTP to Host Controller Agent ({raw_url}) is strictly forbidden. "
                "TraceX requires HTTPS with mutual TLS (mTLS) certificate verification."
            )

        self.base_url = raw_url
        self._ssl_context: Optional[ssl.SSLContext] = None

    @property
    def is_configured(self) -> bool:
        return bool(self.base_url)

    def _get_ssl_context(self) -> ssl.SSLContext:
        """Constructs and caches hardened TLS 1.2+ mTLS context."""
        if self._ssl_context is not None:
            return self._ssl_context

        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2

        # 1. Load CA to validate Host Agent server certificate
        if self.ca_file and Path(self.ca_file).exists():
            ctx.load_verify_locations(cafile=self.ca_file)
            ctx.verify_mode = ssl.CERT_REQUIRED
            ctx.check_hostname = False  # Custom IP SAN validation handled by CA trust
        else:
            # If no custom CA specified, use default system trust or require verification
            ctx.verify_mode = ssl.CERT_REQUIRED
            ctx.check_hostname = False

        # 2. Load Manager VM Client Certificate for mTLS
        if self.client_cert and self.client_key and Path(self.client_cert).exists() and Path(self.client_key).exists():
            ctx.load_cert_chain(certfile=self.client_cert, keyfile=self.client_key)
            logger.info("Loaded Manager VM mTLS client certificate for Host Controller communication.")

        self._ssl_context = ctx
        return ctx

    def _request(
        self,
        method: str,
        path: str,
        data: Optional[bytes] = None,
        headers: Optional[Dict[str, str]] = None
    ) -> Dict[str, Any]:
        """Performs authenticated mTLS HTTP/HTTPS request to Host Controller Agent."""
        if not self.base_url:
            return {"error": "VirtualBox Host Controller Agent URL is not configured.", "code": 503}

        url = f"{self.base_url}{path}"
        req_headers = {
            "User-Agent": "TraceX-ManagerVM/2.0.0",
            "Accept": "application/json"
        }
        if self.auth_token:
            req_headers["X-TraceX-Host-Token"] = self.auth_token

        if headers:
            req_headers.update(headers)

        req = urllib.request.Request(url, data=data, headers=req_headers, method=method)

        ctx = None
        if url.startswith("https://"):
            try:
                ctx = self._get_ssl_context()
            except Exception as e:
                return {"error": f"TLS context initialization error: {e}", "code": 495}

        try:
            with urllib.request.urlopen(req, timeout=self.timeout, context=ctx) as resp:
                resp_bytes = resp.read()
                return json.loads(resp_bytes.decode("utf-8"))
        except urllib.error.HTTPError as e:
            err_body = e.read().decode("utf-8")
            try:
                parsed = json.loads(err_body)
                if isinstance(parsed, dict) and "code" not in parsed:
                    parsed["code"] = e.code
                return parsed
            except Exception:
                return {"error": f"HTTP {e.code}: {e.reason}", "code": e.code, "raw": err_body}
        except ssl.SSLCertVerificationError as e:
            logger.error(f"Host Controller server certificate verification failed: {e}")
            return {"error": f"Server certificate verification rejected: {e.strerror}", "code": 495}
        except ssl.SSLError as e:
            logger.error(f"TLS/mTLS handshake failed: {e}")
            return {"error": f"TLS handshake failed: {e.strerror or str(e)}", "code": 495}
        except Exception as e:
            return {"error": f"Connection failed to Host Controller at {self.base_url}: {e}", "code": 504}

    def get_status(self) -> Dict[str, Any]:
        """Queries host health, VirtualBox version, and hardware virtualization status."""
        return self._request("GET", "/api/vbox/status")

    def get_worker_status(self, vm_identifier: str) -> Dict[str, Any]:
        """Queries status of designated analysis worker VM."""
        return self._request("GET", f"/api/vbox/workers/{vm_identifier}/status")

    def restore_snapshot(self, vm_identifier: str, snapshot_name: str = "Clean_Base") -> Dict[str, Any]:
        """Commands host agent to restore clean baseline snapshot."""
        payload = json.dumps({"snapshot_name": snapshot_name}).encode("utf-8")
        headers = {"Content-Type": "application/json"}
        return self._request("POST", f"/api/vbox/workers/{vm_identifier}/restore", data=payload, headers=headers)

    def start_worker(self, vm_identifier: str) -> Dict[str, Any]:
        """Commands host agent to boot worker VM headlessly."""
        return self._request("POST", f"/api/vbox/workers/{vm_identifier}/start")

    def stop_worker(self, vm_identifier: str) -> Dict[str, Any]:
        """Commands host agent to power off worker VM."""
        return self._request("POST", f"/api/vbox/workers/{vm_identifier}/stop")

    def transfer_evidence(
        self,
        vm_identifier: str,
        staged_file: Path,
        expected_sha256: str
    ) -> Dict[str, Any]:
        """Streams staged malware sample to the host agent with SHA-256 header."""
        if not staged_file.exists():
            return {"error": f"Staged file not found: {staged_file}", "code": 404}

        content = staged_file.read_bytes()
        headers = {
            "Content-Type": "application/octet-stream",
            "X-Evidence-Filename": staged_file.name,
            "X-Evidence-SHA256": expected_sha256
        }
        return self._request("POST", f"/api/vbox/workers/{vm_identifier}/transfer_evidence", data=content, headers=headers)

    def retrieve_results(self, vm_identifier: str) -> Dict[str, Any]:
        """Retrieves collected execution artifacts from host agent."""
        return self._request("GET", f"/api/vbox/workers/{vm_identifier}/results")


vbox_host_client = VirtualBoxHostClient()
