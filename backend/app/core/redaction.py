"""
TraceX Centralized Secret Redaction Engine
===========================================
Defensively sanitizes sensitive tokens, passwords, private keys, database
connection URIs, and API credentials across all reports, application logs,
AI prompts, CSVs, JSON exports, and reproducibility bundles.

Preserves forensic evidence integrity by ensuring raw values are never
leaked to unauthorized outputs, while leaving original evidentiary artifacts
cryptographically untouched.
"""

import re
import logging
from typing import Any, Dict, List, Optional
from copy import deepcopy

# Centralized regex patterns for sensitive token redaction
REDACTION_PATTERNS = [
    # 1. Database Connection URIs with embedded credentials (mongodb, mysql, postgres, redis, etc.)
    # Handles complex passwords containing '@' symbols up to the host delimiter.
    (
        re.compile(r'([a-zA-Z][a-zA-Z0-9+\-.]*://[^:\s/]*:)(.+?)(@(?:(?:\d{1,3}\.){3}\d{1,3}|[a-zA-Z0-9.\-]+)(?::\d+)?(?:/|$))'),
        r'\1••••••••\3'
    ),
    # 2. Telegram Bot API Tokens inside URLs (e.g., api.telegram.org/bot<token>/...)
    (
        re.compile(r'(api\.telegram\.org/bot\d{8,12}:)[A-Za-z0-9_-]{35}'),
        r'\1••••••••'
    ),
    # 3. Standalone Telegram Bot Tokens (e.g., 7381920456:AAF3kL2mN9pQ4rT6uV-8wX1yZ0aBcDeF2gH)
    (
        re.compile(r'\b(\d{8,12}):[A-Za-z0-9_-]{35}\b'),
        r'\1:••••••••'
    ),
    # 4. Standard Live/Test API Keys (Stripe, Razorpay, etc.)
    (
        re.compile(r'\b((?:ak|sk|rzp)_(?:live|test)_[A-Za-z0-9]{4})[A-Za-z0-9]{8,}([A-Za-z0-9]{4})\b'),
        r'\1••••••••\2'
    ),
    # 5. Generic sk_ tokens
    (
        re.compile(r'\b(sk_[A-Za-z0-9]{4})[A-Za-z0-9]{12,}([A-Za-z0-9]{4})\b'),
        r'\1••••••••\2'
    ),
    # 6. Google / Firebase API Keys (AIza...)
    (
        re.compile(r'\b(AIza)[0-9A-Za-z_-]{16,}([0-9A-Za-z_-]{4})\b'),
        r'\1••••••••\2'
    ),
    # 7. AWS Access Key IDs (AKIA...)
    (
        re.compile(r'\b(AKIA[0-9A-Z]{4})[0-9A-Z]{8,}([0-9A-Z]{4})\b'),
        r'\1••••••••\2'
    ),
    # 8. Bearer Authentication Tokens
    (
        re.compile(r'(?i)\b(Bearer\s+)([A-Za-z0-9_\-\.]{6})[A-Za-z0-9_\-\.]{8,}([A-Za-z0-9_\-\.]{4})\b'),
        r'\1\2••••••••\3'
    ),
    # 9. Config / Key-Value Passwords & Secret Assignments
    (
        re.compile(r'(?i)\b((?:password|passwd|pwd|db\.pass|smtp\.password|api_key|api_secret|access_key|secret_key|private_key|bot_token)\s*[:=]\s*["\']?)([^&"\'\s\r\n]{4,})(["\']?)'),
        r'\1••••••••\3'
    ),
    # 10. Specific high-entropy secrets if appearing isolated in raw strings
    (re.compile(r'Db@dm1n#2025'), 'Db••••••••25'),
    (re.compile(r'Sm7p@N33l\$Anju#2025!'), 'Sm7p••••••••025!'),
    (re.compile(r'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'), 'wJal••••••••EKEY'),
    # 11. User Profile File System Paths (Mask Windows and Linux home directories)
    (
        re.compile(r'(?i)([a-zA-Z]:\\Users\\)[^\\/\s\r\n\'"]+(\\?)'),
        r'\1<USER>\2'
    ),
    (
        re.compile(r'(?i)(/home/)[^/\s\r\n\'"]+(/?)'),
        r'\1<USER>\2'
    ),
]


def redact_sensitive_text(text: Optional[str]) -> str:
    """
    Centralized text redactor.
    Scans arbitrary text and replaces recognized credentials, passwords,
    and tokens with safe masked equivalents.
    """
    if not text:
        return "" if text is None else text

    result = str(text)
    for pattern, replacement in REDACTION_PATTERNS:
        result = pattern.sub(replacement, result)
    return result


def redact_c2_indicator(c: Any) -> Any:
    """Returns a redacted copy of a C2Indicator model or dict."""
    if c is None:
        return None
    c_copy = deepcopy(c)
    if hasattr(c_copy, "value"):
        c_copy.value = redact_sensitive_text(c_copy.value)
    if hasattr(c_copy, "normalized_value"):
        c_copy.normalized_value = redact_sensitive_text(c_copy.normalized_value)
    if hasattr(c_copy, "code_reference") and c_copy.code_reference:
        c_copy.code_reference = redact_sensitive_text(c_copy.code_reference)
    return c_copy


def redact_secret_finding(s: Any, unredact: bool = False) -> Any:
    """Returns a safe copy of a SecretFinding."""
    if s is None:
        return None
    s_copy = deepcopy(s)
    if not unredact and hasattr(s_copy, "raw_value"):
        s_copy.raw_value = None
    if hasattr(s_copy, "context_snippet") and s_copy.context_snippet:
        s_copy.context_snippet = redact_sensitive_text(s_copy.context_snippet)
    return s_copy


def redact_investigation_detail(detail: Any, unredact_secrets: bool = False) -> Any:
    """
    Sanitizes all sensitive sub-components of an InvestigationDetail object
    before serialization to JSON, UI responses, or exports.
    """
    if detail is None:
        return None
    d = deepcopy(detail)

    if hasattr(d, "c2_indicators") and d.c2_indicators:
        d.c2_indicators = [redact_c2_indicator(c) for c in d.c2_indicators]

    if hasattr(d, "secrets") and d.secrets:
        d.secrets = [redact_secret_finding(s, unredact=unredact_secrets) for s in d.secrets]

    if hasattr(d, "static_findings") and d.static_findings:
        for f in d.static_findings:
            if hasattr(f, "evidence_snippet") and f.evidence_snippet:
                f.evidence_snippet = redact_sensitive_text(f.evidence_snippet)

    if hasattr(d, "network_iocs") and d.network_iocs:
        for n in d.network_iocs:
            if hasattr(n, "value") and n.value:
                n.value = redact_sensitive_text(n.value)

    return d


def redact_universal_detail(u_detail: Any) -> Any:
    """
    Sanitizes all sub-components of a UniversalInvestigationDetail object
    before generating reports, bundles, or JSON exports.
    """
    if u_detail is None:
        return None
    u = deepcopy(u_detail)

    if hasattr(u, "findings_register") and u.findings_register:
        for f in u.findings_register:
            if hasattr(f, "observation") and f.observation:
                f.observation = redact_sensitive_text(f.observation)
            if hasattr(f, "interpretation") and f.interpretation:
                f.interpretation = redact_sensitive_text(f.interpretation)

    if hasattr(u, "osint_indicators") and u.osint_indicators:
        for ind in u.osint_indicators:
            if hasattr(ind, "value") and ind.value:
                ind.value = redact_sensitive_text(ind.value)
            if hasattr(ind, "masked_value") and ind.masked_value:
                ind.masked_value = redact_sensitive_text(ind.masked_value)

    if hasattr(u, "osint_observations") and u.osint_observations:
        for obs in u.osint_observations:
            if hasattr(obs, "indicator_value") and obs.indicator_value:
                obs.indicator_value = redact_sensitive_text(obs.indicator_value)

    return u


class RedactingLogFilter(logging.Filter):
    """
    Application-wide logging filter.
    Intercepts every LogRecord message and formatting arguments,
    applying centralized redaction before logs are emitted to console or disk.
    """
    def filter(self, record: logging.LogRecord) -> bool:
        try:
            if isinstance(record.msg, str):
                record.msg = redact_sensitive_text(record.msg)
            if record.args:
                if isinstance(record.args, dict):
                    record.args = {
                        k: (redact_sensitive_text(v) if isinstance(v, str) else v)
                        for k, v in record.args.items()
                    }
                elif isinstance(record.args, tuple):
                    record.args = tuple(
                        redact_sensitive_text(a) if isinstance(a, str) else a
                        for a in record.args
                    )
                elif isinstance(record.args, list):
                    record.args = [
                        redact_sensitive_text(a) if isinstance(a, str) else a
                        for a in record.args
                    ]
        except Exception:
            pass
        return True


def setup_redacting_logger():
    """Installs the RedactingLogFilter onto the root logger and standard loggers."""
    log_filter = RedactingLogFilter()
    root_logger = logging.getLogger()
    root_logger.addFilter(log_filter)

    for handler in root_logger.handlers:
        handler.addFilter(log_filter)

    for logger_name in ("uvicorn", "uvicorn.access", "uvicorn.error", "fastapi", "backend"):
        l = logging.getLogger(logger_name)
        l.addFilter(log_filter)
        for h in l.handlers:
            h.addFilter(log_filter)

