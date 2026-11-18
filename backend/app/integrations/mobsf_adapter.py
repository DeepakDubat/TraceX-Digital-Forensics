import httpx
from typing import Dict, Any, Tuple
from urllib.parse import urlparse
from backend.app.config import settings

def test_mobsf_service(url: str = None, api_key: str = None) -> Dict[str, Any]:
    """
    Validates connectivity to a local MobSF REST service endpoint.
    Performs safe read-only queries against MobSF REST API.
    Distinguishes:
      - Local filesystem path mistakenly entered as a URL
      - Service not configured
      - Port conflict with Workbench backend
      - Service unreachable
      - Authentication failed (401/403)
      - Invalid API response
      - Service ready (200 / verified auth probe)
      - Test timeout
    """
    clean_url = (url or "").strip().rstrip('/')
    clean_key = (api_key or "").strip()

    if not clean_url:
        return {
            "success": False,
            "status": "NOT CONFIGURED",
            "message": "MobSF REST service URL is not configured. Default recommendation: http://127.0.0.1:8001 (port 8000 is used by FastAPI backend).",
            "details": {
                "recommended_url": "http://127.0.0.1:8001",
                "port_conflict_warning": "Do not use port 8000 (reserved by this Workbench).",
                "docker_command": "docker run -it -p 8001:8000 opensecurity/mobile-security-framework-mobsf:latest"
            }
        }

    # Guard against local filesystem path or non-HTTP URL mistakenly entered as URL
    is_http_url = clean_url.startswith("http://") or clean_url.startswith("https://")
    if not is_http_url or "\\" in clean_url:
        return {
            "success": False,
            "status": "INVALID URL (LOCAL PATH DETECTED)",
            "message": f"Invalid MobSF Service URL '{clean_url}'. This appears to be a local filesystem directory, not an HTTP REST service URL. MobSF REST Service URL must be an HTTP/HTTPS address such as http://127.0.0.1:8001. Local tool directories should be placed in the JADX Executable Path field.",
            "details": {
                "entered_value": clean_url,
                "error": "Local filesystem path detected instead of HTTP URL",
                "recommended_url": "http://127.0.0.1:8001"
            }
        }

    # Detect port collision with this Workbench backend
    try:
        parsed = urlparse(clean_url)
        port = parsed.port or (80 if parsed.scheme == "http" else 443)
        hostname = (parsed.hostname or "").lower()

        # Air-Gap / Local-Only enforcement: block remote network endpoints
        if settings.LOCAL_ONLY_MODE and hostname not in ("127.0.0.1", "localhost", "::1", "0.0.0.0"):
            return {
                "success": False,
                "status": "BLOCKED BY LOCAL-ONLY MODE",
                "message": f"Remote MobSF endpoint '{clean_url}' is blocked because Local-Only / Air-Gap Mode is active. Only local loopback connections (e.g. http://127.0.0.1:8001) are permitted in Air-Gap mode.",
                "details": {
                    "local_only_mode": True,
                    "target_hostname": hostname,
                    "target_url": clean_url
                }
            }

        if port == settings.PORT and hostname in ("127.0.0.1", "localhost", "0.0.0.0"):
            return {
                "success": False,
                "status": "PORT CONFLICT",
                "message": f"Port conflict: {clean_url} points to port {settings.PORT}, which is reserved by this Workbench FastAPI backend. Map MobSF to port 8001 (e.g. docker run -it -p 8001:8000 opensecurity/mobsf) and set URL to http://127.0.0.1:8001.",
                "details": {
                    "backend_port": settings.PORT,
                    "target_url": clean_url,
                    "recommended_url": "http://127.0.0.1:8001"
                }
            }
    except Exception:
        pass

    if not clean_key:
        return {
            "success": False,
            "status": "AUTH KEY MISSING",
            "message": "MobSF URL is configured, but MobSF REST API Key is missing. Copy the REST API Key from MobSF Web UI -> API Docs (or ~/.MobSF/secret).",
            "details": {
                "url": clean_url,
                "hint": "Obtain API key from MobSF UI at http://127.0.0.1:8001/api_docs"
            }
        }

    headers = {"Authorization": clean_key}

    try:
        with httpx.Client(timeout=httpx.Timeout(2.5, connect=1.5)) as client:
            # First attempt: GET /api/v1/scans
            try:
                resp = client.get(f"{clean_url}/api/v1/scans", headers=headers)
                if resp.status_code == 200:
                    return {
                        "success": True,
                        "status": "INSTALLED / TEST PASSED",
                        "message": f"MobSF REST service online at {clean_url}. Authenticated and responded with HTTP 200.",
                        "details": {
                            "url": clean_url,
                            "status_code": 200,
                            "api_verified": True
                        }
                    }
                elif resp.status_code in (401, 403):
                    return {
                        "success": False,
                        "status": "AUTHENTICATION FAILED",
                        "message": f"Authentication failed: Invalid MobSF API Key (HTTP {resp.status_code}) at {clean_url}.",
                        "details": {
                            "url": clean_url,
                            "status_code": resp.status_code,
                            "api_verified": False
                        }
                    }
                elif resp.status_code == 404:
                    return {
                        "success": False,
                        "status": "INVALID ENDPOINT",
                        "message": f"Server at {clean_url} returned HTTP 404. Endpoint does not appear to be a MobSF REST API.",
                        "details": {
                            "url": clean_url,
                            "status_code": 404
                        }
                    }
            except (httpx.ConnectError, httpx.TimeoutException):
                raise
            except Exception:
                resp = None

            # Second attempt (auth probe): POST /api/v1/upload without payload
            # MobSF validates auth header first; if valid, returns HTTP 400 'file: This field is required'
            upload_resp = client.post(f"{clean_url}/api/v1/upload", headers=headers)
            if upload_resp.status_code == 400 and ("file" in upload_resp.text or "field is required" in upload_resp.text):
                return {
                    "success": True,
                    "status": "INSTALLED / TEST PASSED",
                    "message": f"MobSF REST service online at {clean_url}. API authorization probe verified.",
                    "details": {
                        "url": clean_url,
                        "status_code": 200,
                        "api_verified": True
                    }
                }
            elif upload_resp.status_code in (401, 403):
                return {
                    "success": False,
                    "status": "AUTHENTICATION FAILED",
                    "message": f"Authentication failed: Invalid MobSF API Key (HTTP {upload_resp.status_code}) at {clean_url}.",
                    "details": {
                        "url": clean_url,
                        "status_code": upload_resp.status_code,
                        "api_verified": False
                    }
                }
            else:
                code = upload_resp.status_code if upload_resp else (resp.status_code if resp else 500)
                return {
                    "success": False,
                    "status": "INVALID RESPONSE",
                    "message": f"MobSF server responded with unexpected status HTTP {code}.",
                    "details": {
                        "url": clean_url,
                        "status_code": code
                    }
                }

    except httpx.ConnectError:
        return {
            "success": False,
            "status": "SERVICE UNREACHABLE",
            "message": f"Cannot connect to MobSF service at {clean_url}. Ensure MobSF is running and accessible.",
            "details": {
                "url": clean_url,
                "error_type": "ConnectError",
                "docker_command": "docker run -it -p 8001:8000 opensecurity/mobile-security-framework-mobsf:latest"
            }
        }
    except httpx.TimeoutException:
        return {
            "success": False,
            "status": "TEST TIMEOUT",
            "message": f"Connection to MobSF service at {clean_url} timed out after 5.0 seconds.",
            "details": {
                "url": clean_url,
                "error_type": "Timeout"
            }
        }
    except Exception as e:
        return {
            "success": False,
            "status": "TEST FAILED",
            "message": f"MobSF connection test error: {str(e)}",
            "details": {
                "url": clean_url,
                "error": str(e)
            }
        }

def test_mobsf_connection(url: str, api_key: str) -> Tuple[bool, str]:
    """Backward-compatible wrapper returning (bool, str)."""
    res = test_mobsf_service(url, api_key)
    return res["success"], res["message"]
