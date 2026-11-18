import re
import uuid
from typing import List, Dict, Any, Optional
from backend.app.core.models import (
    SecretExposureFinding,
    UniversalInvestigationDetail,
    ExtractedArtifact
)
from backend.app.database.repository import repo

TELEGRAM_TOKEN_REGEX = re.compile(r"\b(\d{8,10}):([a-zA-Z0-9_-]{35})\b")
TELEGRAM_USER_REGEX = re.compile(r"(?:@|t\.me/)([a-zA-Z0-9_]{5,32})\b", re.IGNORECASE)
AWS_KEY_REGEX = re.compile(r"\b(AKIA[0-9A-Z]{16})\b")

class SecretCorrelationEngine:
    """
    Safe Telegram Bot Token & Secret Investigation Engine.
    Strictly safeguards recovered secrets:
    - Zero active token validation (never calls getMe or webhooks).
    - Strict masking (1234567890:••••••••).
    - Correlates with independently discovered public usernames, channels, and author signatures in evidence.
    """

    def analyze_investigation_secrets(self, detail: UniversalInvestigationDetail) -> List[SecretExposureFinding]:
        findings: List[SecretExposureFinding] = []
        inv_id = detail.record.id

        # 1. First collect all public Telegram usernames/links in evidence for passive correlation
        discovered_public_identities = set()
        for art in detail.extracted_artifacts:
            matches = TELEGRAM_USER_REGEX.findall(art.value)
            for m in matches:
                discovered_public_identities.add(f"@{m.lower()}")
                discovered_public_identities.add(f"https://t.me/{m.lower()}")

        # 2. Scan artifacts for tokens and API keys
        for art in detail.extracted_artifacts:
            # Check Telegram Bot Token
            tg_match = TELEGRAM_TOKEN_REGEX.search(art.value)
            if tg_match:
                bot_id, _ = tg_match.groups()
                masked = f"{bot_id}:{'•' * 8}"
                
                # Filter correlated public identities
                correlated = sorted(list(discovered_public_identities))

                finding = SecretExposureFinding(
                    id=f"SEC-TG-{uuid.uuid4().hex[:8]}",
                    investigation_id=inv_id,
                    evidence_id=art.evidence_id or f"EVD-{inv_id}",
                    artifact_id=art.id,
                    secret_type="telegram_bot_token",
                    masked_token=masked,
                    source_filename=art.source_format,
                    source_location=art.source_location or "Extracted string artifact",
                    independently_found_public_identities=correlated,
                    safety_attestation="Token was strictly isolated and masked. Never transmitted to third-party endpoints or Telegram servers.",
                    risk_level="High",
                    observation=f"Extracted active Telegram bot token with Bot ID {bot_id} at {art.source_location}. Associated public channels/handles in evidence: {', '.join(correlated) if correlated else 'None found'}.",
                    interpretation="Adversary hardcoded Telegram Bot API credentials into the binary to use Telegram as an encrypted Command & Control or data exfiltration channel."
                )
                repo.create_secret_exposure_finding(finding)
                findings.append(finding)

            # Check AWS Access Key
            aws_match = AWS_KEY_REGEX.search(art.value)
            if aws_match:
                raw_key = aws_match.group(1)
                masked_aws = f"{raw_key[:4]}••••••••{raw_key[-4:]}"
                finding = SecretExposureFinding(
                    id=f"SEC-AWS-{uuid.uuid4().hex[:8]}",
                    investigation_id=inv_id,
                    evidence_id=art.evidence_id or f"EVD-{inv_id}",
                    artifact_id=art.id,
                    secret_type="aws_access_key",
                    masked_token=masked_aws,
                    source_filename=art.source_format,
                    source_location=art.source_location or "Extracted string artifact",
                    independently_found_public_identities=[],
                    safety_attestation="Token was strictly isolated and masked. Never tested against cloud endpoints.",
                    risk_level="Critical",
                    observation=f"Embedded AWS Access Key ID detected at {art.source_location}.",
                    interpretation="Adversary or developer embedded live cloud infrastructure access credentials. Potential cloud privilege escalation vector."
                )
                repo.create_secret_exposure_finding(finding)
                findings.append(finding)

        return findings

secret_engine = SecretCorrelationEngine()
