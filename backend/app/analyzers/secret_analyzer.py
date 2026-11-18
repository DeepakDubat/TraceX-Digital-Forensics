import re
from typing import List, Dict, Any, Tuple
from backend.app.core.models import SecretFinding
from backend.app.core.security import redact_secret

# Curated regex rules for known token structures
SECRET_RULES = [
    {
        "category": "api_key",
        "name": "Google API Key",
        "pattern": re.compile(r'\bAIza[0-9A-Za-z_\-]{32,40}\b'),
        "confidence": "High",
        "verification": "Pattern Matched: Valid Google API Key structure"
    },
    {
        "category": "cloud_credential",
        "name": "AWS Access Key ID",
        "pattern": re.compile(r'\b(?:AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16,28}\b'),
        "confidence": "High",
        "verification": "Pattern Matched: Valid AWS Access Key format"
    },
    {
        "category": "cloud_credential",
        "name": "AWS Secret Access Key",
        "pattern": re.compile(r'(?:aws\.secret_key|aws_secret_key|aws_secret_access_key)\s*=\s*([A-Za-z0-9/+=]{30,60})', re.IGNORECASE),
        "confidence": "High",
        "verification": "Pattern Matched: Hardcoded AWS Secret Access Key assignment"
    },
    {
        "category": "telegram_bot",
        "name": "Telegram Bot API Token",
        "pattern": re.compile(r'\b[0-9]{8,10}:[a-zA-Z0-9_\-]{35}\b'),
        "confidence": "High",
        "verification": "Pattern Matched: Standard Telegram Bot Token structure"
    },
    {
        "category": "database_uri",
        "name": "Database Connection URI with Credentials",
        "pattern": re.compile(r'\b(?:mongodb(?:\+srv)?|mysql|postgres|postgresql|redis)://[a-zA-Z0-9_.-]+:[^\s@"\'<>]+@[^\s"\'<>]+', re.IGNORECASE),
        "confidence": "High",
        "verification": "Pattern Matched: Full Database Connection URI with embedded username and password"
    },
    {
        "category": "api_key",
        "name": "Production Server API Key",
        "pattern": re.compile(r'\bak_live_[0-9a-zA-Z_\-]{20,64}\b'),
        "confidence": "High",
        "verification": "Pattern Matched: Live Application Server API Key (ak_live_ prefix)"
    },
    {
        "category": "api_key",
        "name": "Production Server Secret Key",
        "pattern": re.compile(r'\bsk_[0-9a-zA-Z_\-]{20,64}\b'),
        "confidence": "High",
        "verification": "Pattern Matched: Application Server Secret Key (sk_ prefix)"
    },
    {
        "category": "password",
        "name": "Hardcoded Service Password Assignment",
        "pattern": re.compile(r'(?:smtp\.password|db\.pass|db\.password|admin_password)\s*=\s*([^\s\r\n"\']{6,64})', re.IGNORECASE),
        "confidence": "High",
        "verification": "Context Matched: Configuration property password assignment"
    },
    {
        "category": "jwt",
        "name": "JSON Web Token (JWT)",
        "pattern": re.compile(r'\beyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b'),
        "confidence": "High",
        "verification": "Pattern Matched: Base64URL-encoded JWT header and payload"
    },
    {
        "category": "private_key",
        "name": "RSA/EC Private Key Header",
        "pattern": re.compile(r'-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----'),
        "confidence": "High",
        "verification": "Pattern Matched: Standard PEM Private Key Header"
    },
    {
        "category": "bearer",
        "name": "Bearer Authentication Header",
        "pattern": re.compile(r'\bBearer\s+[A-Za-z0-9\-._~+/]+=*\b', re.IGNORECASE),
        "confidence": "Medium",
        "verification": "Context Matched: HTTP Authorization Bearer pattern"
    },
    {
        "category": "auth_token",
        "name": "Hardcoded Secret/Token Assignment",
        "pattern": re.compile(r'(?:api_key|apikey|secret_key|auth_token|client_secret|access_token)\s*[:=]\s*["\']([A-Za-z0-9_\-]{16,64})["\']', re.IGNORECASE),
        "confidence": "Medium",
        "verification": "Context Matched: Variable assignment to secret identifier"
    }
]

COMMON_FALSE_POSITIVES = {
    "your_api_key_here", "dummy_key", "sample_token", "placeholder",
    "abcdefghijklmnopqrstuvwxyz", "1234567890123456", "xxxxxxxxxxxxxxxx"
}

def analyze_secrets(strings_pool: List[Tuple[str, str]], dex_methods: List[str]) -> List[SecretFinding]:
    """
    Scans extracted strings for hardcoded credentials, tokens, and API keys.
    Employs context analysis and false-positive filtering.
    """
    secrets: List[SecretFinding] = []
    seen_raw = set()
    counter = 1

    all_methods_text = " ".join(dex_methods)

    for source_file, text in strings_pool:
        if not text or len(text) < 12:
            continue

        for rule in SECRET_RULES:
            matches = rule["pattern"].findall(text)
            for match in matches:
                # If regex had a capturing group, match might be tuple or string
                val = match if isinstance(match, str) else match[0]
                val = val.strip().strip('"\'')

                if len(val) < 12 or val.lower() in COMMON_FALSE_POSITIVES:
                    continue
                if val in seen_raw:
                    continue
                seen_raw.add(val)

                # Context check: Does it appear in a network-related code path?
                in_network_path = any(kw in all_methods_text for kw in ["HttpURLConnection", "OkHttpClient", "Authorization", "setHeader"])
                
                # Check for nearby related indicator (e.g. domain or URL)
                related_ind = None
                if "telegram" in rule["category"]:
                    related_ind = "api.telegram.org"
                elif "api" in rule["category"]:
                    related_ind = "HTTP API Service"

                redacted = redact_secret(val)
                snippet = f"...{text[max(0, text.find(val)-20):min(len(text), text.find(val)+len(val)+20)]}..."

                secrets.append(SecretFinding(
                    id=f"SEC-FIND-{counter:03d}",
                    token_category=rule["category"],
                    redacted_value=redacted,
                    raw_value=val,
                    source_location=source_file,
                    code_reference=f"Found in {source_file}",
                    rule_matched=rule["name"],
                    in_network_path=in_network_path,
                    related_indicator=related_ind,
                    confidence=rule["confidence"],
                    verification_status=rule["verification"],
                    context_snippet=snippet
                ))
                counter += 1

    return secrets
