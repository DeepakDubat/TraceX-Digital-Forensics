import re
from typing import List, Dict, Any, Tuple
from backend.app.core.models import SecretFinding
from backend.app.core.security import redact_secret

PE_SECRET_RULES = [
    {
        "category": "api_key",
        "name": "Google API Key",
        "pattern": re.compile(r'\bAIza[0-9A-Za-z_\-]{32,40}\b'),
        "confidence": "High",
        "verification": "Pattern Matched: Valid Google API Key structure"
    },
    {
        "category": "telegram_bot",
        "name": "Telegram Bot Token",
        "pattern": re.compile(r'\b[0-9]{8,10}:[a-zA-Z0-9_\-]{35}\b'),
        "confidence": "High",
        "verification": "Pattern Matched: Standard Telegram Bot HTTP API token format"
    },
    {
        "category": "cloud_credential",
        "name": "AWS Access Key ID",
        "pattern": re.compile(r'\b(AKIA[0-9A-Z]{16})\b'),
        "confidence": "High",
        "verification": "Pattern Matched: AWS IAM Access Key ID prefix (AKIA)"
    },
    {
        "category": "jwt",
        "name": "JSON Web Token (JWT)",
        "pattern": re.compile(r'\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b'),
        "confidence": "High",
        "verification": "Pattern Matched: Base64URL three-part JWT signature"
    },
    {
        "category": "private_key",
        "name": "RSA / OpenSSH Private Key Header",
        "pattern": re.compile(r'-----BEGIN\s+(?:RSA|OPENSSH|DSA|EC)?\s*PRIVATE KEY-----'),
        "confidence": "High",
        "verification": "Pattern Matched: Cryptographic PEM Private Key container"
    },
    {
        "category": "database_connection",
        "name": "Database Connection String",
        "pattern": re.compile(r'\b(?:Server|Data Source)=.+;Database=.+;User Id=.+;Password=.+', re.IGNORECASE),
        "confidence": "High",
        "verification": "Pattern Matched: Embedded OLEDB / SQL Server credential string"
    },
    {
        "category": "bearer",
        "name": "Bearer Authorization Header",
        "pattern": re.compile(r'Bearer\s+([A-Za-z0-9_\-\.]{20,})', re.IGNORECASE),
        "confidence": "Medium",
        "verification": "Pattern Matched: HTTP Bearer authorization token"
    }
]

FALSE_POSITIVE_SUBSTRINGS = [
    "example", "your_api_key", "placeholder", "insert_key_here",
    "00000000", "xxxxxxxx"
]

def analyze_pe_secrets(raw_strings: List[Dict[str, Any]]) -> List[SecretFinding]:
    """
    Scan extracted PE strings for embedded credentials, API tokens, and secret material.
    Ensures safe redaction by default according to digital forensic standards.
    """
    findings: List[SecretFinding] = []
    seen_secrets = set()
    counter = 1

    for item in raw_strings:
        val = item["value"].strip()
        offset = item.get("offset", 0)
        section = item.get("section", "Unknown")

        # Skip obvious placeholder values
        val_lower = val.lower()
        if any(fp in val_lower for fp in FALSE_POSITIVE_SUBSTRINGS):
            continue

        for rule in PE_SECRET_RULES:
            matches = rule["pattern"].findall(val)
            for m in matches:
                secret_str = m if isinstance(m, str) else m[0]
                if secret_str in seen_secrets or len(secret_str) < 8:
                    continue
                seen_secrets.add(secret_str)

                findings.append(SecretFinding(
                    id=f"PE-SEC-{counter:03d}",
                    token_category=rule["category"],
                    redacted_value=redact_secret(secret_str),
                    raw_value=secret_str,
                    source_location=f"PE Section: {section}",
                    code_reference=f"File Offset: 0x{offset:08X}",
                    rule_matched=rule["name"],
                    in_network_path=("http" in val_lower or "api" in val_lower),
                    confidence=rule["confidence"],
                    verification_status=rule["verification"],
                    context_snippet=f"Offset 0x{offset:08X} in section '{section}'"
                ))
                counter += 1

    return findings
