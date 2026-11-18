"""
Granular External API Error Classifier
Universal Digital Forensics & Evidence Intelligence Platform v2.0.0

Provides accurate HTTP status code and response body diagnosis for external APIs,
preventing misclassification of quota limits, permissions, or billing issues
as 'Invalid API Key'. Ensures zero credential exposure in error messages.
"""

import re
import json
from typing import Dict, Any, Optional

def sanitize_error_text(text: str) -> str:
    """Removes potential secrets, keys, and tokens from error strings."""
    if not text:
        return ""
    # Mask potential API keys (alphanumeric strings >= 20 chars)
    sanitized = re.sub(r'(?i)(key|token|secret|auth|bearer)[\s:=]+([a-zA-Z0-9_\-\.]{16,})', r'\1=***REDACTED***', text)
    sanitized = re.sub(r'AIzaSy[a-zA-Z0-9_\-]{33}', '***REDACTED_GEMINI_KEY***', sanitized)
    sanitized = re.sub(r'sk-[a-zA-Z0-9_\-]{32,}', '***REDACTED_OPENAI_KEY***', sanitized)
    sanitized = re.sub(r'sk-ant-[a-zA-Z0-9_\-]{32,}', '***REDACTED_ANTHROPIC_KEY***', sanitized)
    sanitized = re.sub(r'gsk_[a-zA-Z0-9_\-]{32,}', '***REDACTED_GROQ_KEY***', sanitized)
    return sanitized.strip()[:300]


def classify_api_error(
    provider_id: str,
    status_code: Optional[int],
    response_text: Optional[str] = None,
    exception: Optional[Exception] = None
) -> Dict[str, Any]:
    """
    Classifies external API errors into standard categories with actionable recommendations:
    - AUTHENTICATION_FAILED (401)
    - PERMISSION_DENIED (403)
    - RATE_LIMITED (429)
    - INVALID_REQUEST (400)
    - NOT_FOUND (404)
    - SERVER_ERROR (5xx)
    - NETWORK_ERROR (Timeout / Connection error)
    """
    # 1. Network or Client Exception
    if exception is not None or status_code is None:
        err_str = str(exception) if exception else "Connection failed"
        err_lower = err_str.lower()
        exc_type = type(exception).__name__.lower() if exception else ""
        if "timeout" in err_lower or "timed out" in err_lower or "timeout" in exc_type:
            msg = f"Connection to {provider_id.title()} timed out. The provider or network is slow to respond."
            return {
                "success": False,
                "connected": False,
                "error_code": "NETWORK_TIMEOUT",
                "status": "Connection Timeout",
                "message": msg,
                "error": msg,
                "actionable_hint": "Check network connectivity, proxy settings, or firewall outbound rules."
            }
        msg = f"Unable to reach {provider_id.title()} API: {sanitize_error_text(err_str)}"
        return {
            "success": False,
            "connected": False,
            "error_code": "NETWORK_ERROR",
            "status": "Network Error",
            "message": msg,
            "error": msg,
            "actionable_hint": "Verify network connection and ensure outbound HTTPS is permitted."
        }

    raw_text = response_text or ""
    parsed_json: Optional[Dict[str, Any]] = None
    try:
        if raw_text.strip().startswith("{"):
            parsed_json = json.loads(raw_text)
    except Exception:
        pass

    # Provider-specific error extraction
    extracted_detail = ""
    error_reason = ""

    if parsed_json:
        # Google RPC Error format: {"error": {"code": 400, "message": "...", "status": "...", "details": [...]}}
        if "error" in parsed_json and isinstance(parsed_json["error"], dict):
            err_obj = parsed_json["error"]
            extracted_detail = err_obj.get("message", "")
            error_reason = err_obj.get("status", "")
            for d in err_obj.get("details", []):
                if isinstance(d, dict) and "reason" in d:
                    error_reason = d["reason"]

        # OpenAI / Anthropic format: {"error": {"message": "...", "type": "..."}}
        elif "error" in parsed_json and isinstance(parsed_json["error"], dict):
            extracted_detail = parsed_json["error"].get("message", "")
            error_reason = parsed_json["error"].get("type", "")

        # VirusTotal format: {"error": {"message": "...", "code": "..."}}
        elif "error" in parsed_json:
            if isinstance(parsed_json["error"], dict):
                extracted_detail = parsed_json["error"].get("message", "")
                error_reason = parsed_json["error"].get("code", "")
            else:
                extracted_detail = str(parsed_json["error"])

        # AbuseIPDB format: {"errors": [{"detail": "...", "status": 401}]}
        elif "errors" in parsed_json and isinstance(parsed_json["errors"], list) and parsed_json["errors"]:
            extracted_detail = parsed_json["errors"][0].get("detail", "")

        # General detail field
        elif "detail" in parsed_json:
            extracted_detail = str(parsed_json["detail"])

    cleaned_detail = sanitize_error_text(extracted_detail or raw_text)

    # 2. HTTP 401: Authentication Failed
    if status_code == 401:
        hint = "Verify that the API key was copied correctly and has not expired or been revoked."
        if provider_id == "abuseipdb" and "api" in cleaned_detail.lower():
            hint = "Ensure you are using an AbuseIPDB APIv2 key (not legacy v1 key)."
        elif provider_id == "gemini" and "oauth" in cleaned_detail.lower():
            hint = "OAuth token expired or invalid. Re-authenticate via Connect Account."

        return {
            "success": False,
            "connected": False,
            "error_code": "AUTHENTICATION_FAILED",
            "status": "Authentication Failed (401)",
            "message": cleaned_detail or f"Authentication failed for {provider_id.title()}. Invalid or revoked credentials.",
            "actionable_hint": hint
        }

    # 3. HTTP 403: Permission Denied or Account Restriction
    if status_code == 403:
        hint = "Check provider account permissions, project associations, or IP allowlists."
        if provider_id == "gemini":
            if "generativelanguage.googleapis.com" in cleaned_detail.lower() or "disabled" in cleaned_detail.lower():
                hint = "The Generative Language API is disabled in your Google Cloud Project. Enable it in Google Cloud Console."
            elif "billing" in cleaned_detail.lower():
                hint = "Google Cloud billing account is inactive or not linked to this project."
            else:
                hint = "Check API key restrictions (HTTP referrers, IP restrictions, or API scope restrictions) in Google Cloud Console."
        elif provider_id == "openai":
            if "country" in cleaned_detail.lower() or "region" in cleaned_detail.lower():
                hint = "OpenAI API is restricted in your geographic region or organization policy."
            else:
                hint = "Your OpenAI API key may lack permissions for this model or project."
        elif provider_id == "anthropic":
            hint = "Anthropic account has insufficient permissions, organization restriction, or credit balance is zero."

        return {
            "success": False,
            "connected": False,
            "error_code": "PERMISSION_DENIED",
            "status": "Permission Denied (403)",
            "message": cleaned_detail or f"Access restricted by {provider_id.title()}: permission or project policy violation.",
            "actionable_hint": hint
        }

    # 4. HTTP 429: Rate Limit or Quota Exceeded
    if status_code == 429:
        hint = "Your account has reached its rate limit or free tier quota. Wait before retrying or upgrade plan."
        return {
            "success": False,
            "connected": False,
            "error_code": "RATE_LIMITED",
            "status": "Rate Limited / Quota Exceeded (429)",
            "message": cleaned_detail or f"{provider_id.title()} rate limit or usage quota exceeded.",
            "actionable_hint": hint
        }

    # 5. HTTP 400: Bad Request / Invalid Configuration
    if status_code == 400:
        hint = "Verify configuration fields, model identifiers, or parameter formats."
        if provider_id == "gemini":
            if "API_KEY_INVALID" in error_reason or "api key not valid" in cleaned_detail.lower():
                return {
                    "success": False,
                    "connected": False,
                    "error_code": "AUTHENTICATION_FAILED",
                    "status": "Invalid API Key (400)",
                    "message": "Google Gemini reported this API key is invalid or malformed.",
                    "actionable_hint": "Generate a new API key in Google AI Studio (https://aistudio.google.com/app/apikey)."
                }
        elif provider_id == "anthropic" and "credit" in cleaned_detail.lower():
            return {
                "success": False,
                "connected": False,
                "error_code": "CREDIT_BALANCE_ZERO",
                "status": "Credit Balance Depleted",
                "message": "Anthropic account balance is zero or depleted.",
                "actionable_hint": "Add pre-paid API credits in Anthropic Console (https://console.anthropic.com/settings/billing)."
            }

        return {
            "success": False,
            "connected": False,
            "error_code": "INVALID_REQUEST",
            "status": "Invalid Request (400)",
            "message": cleaned_detail or f"Bad request sent to {provider_id.title()}.",
            "actionable_hint": hint
        }

    # 6. HTTP 404: Not Found
    if status_code == 404:
        return {
            "success": False,
            "connected": False,
            "error_code": "NOT_FOUND",
            "status": "Resource / Model Not Found (404)",
            "message": cleaned_detail or f"{provider_id.title()} endpoint or requested model not found.",
            "actionable_hint": "Check model identifier or custom base URL in configuration."
        }

    # 7. HTTP 5xx: External Provider Server Error
    if status_code >= 500:
        return {
            "success": False,
            "connected": False,
            "error_code": "PROVIDER_ERROR",
            "status": f"Provider Service Error ({status_code})",
            "message": cleaned_detail or f"{provider_id.title()} service is currently experiencing upstream errors.",
            "actionable_hint": "Check the official provider status page. The error is on the provider side."
        }

    # Generic fallback
    return {
        "success": False,
        "connected": False,
        "error_code": f"HTTP_{status_code}",
        "status": f"HTTP {status_code}",
        "message": cleaned_detail or f"Provider responded with HTTP {status_code}",
        "actionable_hint": "Review provider documentation and settings."
    }
