"""
External API Error Classifier Tests
Universal Digital Forensics & Evidence Intelligence Platform v2.0.0
"""

import json
from backend.app.core.api_error_classifier import classify_api_error, sanitize_error_text


def test_gemini_permission_denied_classification():
    """Verify Gemini 403 API disabled error is not classified as invalid API key."""
    google_err = json.dumps({
        "error": {
            "code": 403,
            "message": "Generative Language API has not been used in project 123456 before or it is disabled. Enable it at https://console.developers.google.com/apis/api/generativelanguage.googleapis.com/overview",
            "status": "PERMISSION_DENIED",
            "details": [
                {
                    "@type": "type.googleapis.com/google.rpc.ErrorInfo",
                    "reason": "SERVICE_DISABLED",
                    "domain": "googleapis.com"
                }
            ]
        }
    })

    result = classify_api_error("gemini", 403, google_err)
    assert result["connected"] is False
    assert result["error_code"] == "PERMISSION_DENIED"
    assert "disabled" in result["message"].lower() or "permission denied" in result["status"].lower()
    assert "console" in result["actionable_hint"].lower()


def test_gemini_400_bad_request_classification():
    """Verify Gemini 400 parameter errors are classified as Invalid Request, not Invalid Key."""
    google_400 = json.dumps({
        "error": {
            "code": 400,
            "message": "API key not valid. Please pass a valid API key.",
            "status": "INVALID_ARGUMENT"
        }
    })

    result = classify_api_error("gemini", 400, google_400)
    assert result["connected"] is False
    assert result["error_code"] in ("INVALID_REQUEST", "AUTHENTICATION_FAILED")


def test_anthropic_credit_balance_too_low():
    """Verify Anthropic 400 credit balance error provides billing advice."""
    anthropic_err = json.dumps({
        "type": "error",
        "error": {
            "type": "invalid_request_error",
            "message": "Your credit balance is too low to access the Anthropic API. Please go to Plans & Billing to upgrade or purchase credits."
        }
    })

    result = classify_api_error("anthropic", 400, anthropic_err)
    assert result["connected"] is False
    assert "credit balance is too low" in result["message"].lower() or "billing" in result["actionable_hint"].lower()


def test_rate_limit_429_classification():
    """Verify 429 status is classified as RATE_LIMITED with quota advice."""
    result = classify_api_error("openai", 429, '{"error": {"message": "You exceeded your current quota, please check your plan and billing details."}}')
    assert result["connected"] is False
    assert result["error_code"] == "RATE_LIMITED"
    assert "quota" in result["message"].lower() or "rate limit" in result["message"].lower()


def test_timeout_and_network_classification():
    """Verify timeouts provide network connectivity advice."""
    result = classify_api_error("virustotal", None, None, TimeoutError("Request timed out after 6000ms"))
    assert result["connected"] is False
    assert result["error_code"] == "NETWORK_TIMEOUT"
    assert "connectivity" in result["actionable_hint"].lower() or "proxy" in result["actionable_hint"].lower()


def test_secret_redaction_in_errors():
    """Verify raw API keys are never leaked in error messages."""
    leaked_text = "Failed to connect using key=AIzaSyA1B2C3D4E5F6G7H8I9J0K1L2M3N4O5P6 and sk-ant-api03-abcdef1234567890abcdef1234567890"
    sanitized = sanitize_error_text(leaked_text)
    assert "AIzaSy" not in sanitized
    assert "sk-ant" not in sanitized
    assert "***REDACTED" in sanitized
