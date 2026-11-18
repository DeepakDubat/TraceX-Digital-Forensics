import re
import ipaddress
import uuid
from datetime import datetime
from typing import List, Dict, Any, Optional, Set
from urllib.parse import urlparse
from backend.app.core.models import (
    OSINTIndicator,
    UniversalInvestigationDetail,
    ExtractedArtifact,
    EvidenceItem
)
from backend.app.database.repository import repo

TELEGRAM_TOKEN_REGEX = re.compile(r"\b(\d{8,10}):([a-zA-Z0-9_-]{35})\b")
TELEGRAM_USER_REGEX = re.compile(r"(?:@|t\.me/)([a-zA-Z0-9_]{5,32})\b", re.IGNORECASE)

class OSINTCollector:
    """
    Automatic indicator extractor and provenance linker.
    Extracts all network, cryptographic, and infrastructure indicators across
    all analyzed evidence files, linking exact byte offsets or source locations.
    """

    def collect_from_investigation(self, detail: UniversalInvestigationDetail) -> List[OSINTIndicator]:
        inv_id = detail.record.id
        indicators: List[OSINTIndicator] = []
        seen_keys: Set[str] = set()

        # Build evidence lookup
        evidence_map: Dict[str, EvidenceItem] = {e.id: e for e in detail.evidence_items}

        # 1. Collect hashes from Evidence Items
        for ev in detail.evidence_items:
            if ev.sha256:
                key = f"hash:{ev.sha256.lower()}"
                if key not in seen_keys:
                    seen_keys.add(key)
                    ind = OSINTIndicator(
                        id=f"IND-HASH-{uuid.uuid4().hex[:8]}",
                        investigation_id=inv_id,
                        evidence_id=ev.id,
                        source_filename=ev.filename,
                        source_location="File Header / Primary Binary SHA-256",
                        indicator_type="hash",
                        value=ev.sha256,
                        normalized_value=ev.sha256.lower(),
                        provenance_type="DIRECT_EVIDENCE",
                        extractor_or_provider="FileIdentifier",
                        confidence="Confirmed",
                        pivot_depth=0
                    )
                    repo.create_osint_indicator(ind)
                    indicators.append(ind)

        # 2. Collect from Extracted Artifacts
        for art in detail.extracted_artifacts:
            source_file = None
            if art.evidence_id and art.evidence_id in evidence_map:
                source_file = evidence_map[art.evidence_id].filename

            extracted = self._extract_indicators_from_artifact(art, inv_id, source_file)
            for ind in extracted:
                key = f"{ind.indicator_type}:{ind.normalized_value}"
                if key not in seen_keys:
                    seen_keys.add(key)
                    repo.create_osint_indicator(ind)
                    indicators.append(ind)

        # 3. Collect from Legacy C2 / Network IOCs if present
        for c2 in getattr(detail, "c2_indicators", []):
            if c2.ip_address:
                norm_ip = self._normalize_ip(c2.ip_address)
                if norm_ip:
                    key = f"ip:{norm_ip}"
                    if key not in seen_keys:
                        seen_keys.add(key)
                        ind = OSINTIndicator(
                            id=f"IND-IP-{uuid.uuid4().hex[:8]}",
                            investigation_id=inv_id,
                            source_filename=detail.record.filename,
                            source_location="C2 Indicator Extraction",
                            indicator_type="ip",
                            value=c2.ip_address,
                            normalized_value=norm_ip,
                            provenance_type="DIRECT_EVIDENCE",
                            extractor_or_provider="C2Analyzer",
                            confidence="High",
                            pivot_depth=0
                        )
                        repo.create_osint_indicator(ind)
                        indicators.append(ind)

            if c2.domain:
                norm_dom = self._normalize_domain(c2.domain)
                if norm_dom:
                    key = f"domain:{norm_dom}"
                    if key not in seen_keys:
                        seen_keys.add(key)
                        ind = OSINTIndicator(
                            id=f"IND-DOM-{uuid.uuid4().hex[:8]}",
                            investigation_id=inv_id,
                            source_filename=detail.record.filename,
                            source_location="C2 Domain Extraction",
                            indicator_type="domain",
                            value=c2.domain,
                            normalized_value=norm_dom,
                            provenance_type="DIRECT_EVIDENCE",
                            extractor_or_provider="C2Analyzer",
                            confidence="High",
                            pivot_depth=0
                        )
                        repo.create_osint_indicator(ind)
                        indicators.append(ind)

        return indicators

    def _extract_indicators_from_artifact(self, art: ExtractedArtifact, inv_id: str, source_filename: Optional[str]) -> List[OSINTIndicator]:
        results: List[OSINTIndicator] = []
        raw_val = art.value.strip()
        art_type = art.artifact_type.lower()

        # A. Telegram Bot Token Detection
        tg_match = TELEGRAM_TOKEN_REGEX.search(raw_val)
        if tg_match:
            bot_id, secret = tg_match.groups()
            masked = f"{bot_id}:{'•' * 8}"
            results.append(OSINTIndicator(
                id=f"IND-SEC-{uuid.uuid4().hex[:8]}",
                investigation_id=inv_id,
                evidence_id=art.evidence_id,
                artifact_id=art.id,
                source_filename=source_filename,
                source_location=art.source_location or "Extracted String Artifact",
                indicator_type="telegram_bot_token",
                value=raw_val,
                normalized_value=f"{bot_id}:{secret}",
                provenance_type="DIRECT_EVIDENCE",
                extractor_or_provider=art.extractor_name,
                confidence="Confirmed",
                pivot_depth=0,
                is_sensitive_secret=True,
                masked_value=masked,
                limitations="Secret token detected. Protected by strict local containment."
            ))
            return results

        # B. Telegram Public Username Detection
        tg_user_match = TELEGRAM_USER_REGEX.search(raw_val)
        if tg_user_match:
            u_name = tg_user_match.group(1)
            results.append(OSINTIndicator(
                id=f"IND-TGU-{uuid.uuid4().hex[:8]}",
                investigation_id=inv_id,
                evidence_id=art.evidence_id,
                artifact_id=art.id,
                source_filename=source_filename,
                source_location=art.source_location or "Extracted String / Channel Link",
                indicator_type="telegram_username",
                value=raw_val,
                normalized_value=f"@{u_name.lower()}",
                provenance_type="DIRECT_EVIDENCE",
                extractor_or_provider=art.extractor_name,
                confidence="High",
                pivot_depth=0
            ))

        # C. IP Address
        if art_type in ("ip", "ipv4", "ipv6") or self._is_valid_ip(raw_val):
            norm_ip = self._normalize_ip(raw_val)
            if norm_ip:
                results.append(OSINTIndicator(
                    id=f"IND-IP-{uuid.uuid4().hex[:8]}",
                    investigation_id=inv_id,
                    evidence_id=art.evidence_id,
                    artifact_id=art.id,
                    source_filename=source_filename,
                    source_location=art.source_location,
                    indicator_type="ip",
                    value=raw_val,
                    normalized_value=norm_ip,
                    provenance_type="DIRECT_EVIDENCE",
                    extractor_or_provider=art.extractor_name,
                    confidence=art.confidence or "High",
                    pivot_depth=0
                ))
                return results

        # D. Domain / Hostname
        if art_type in ("domain", "hostname") or self._is_valid_domain(raw_val):
            norm_dom = self._normalize_domain(raw_val)
            if norm_dom:
                results.append(OSINTIndicator(
                    id=f"IND-DOM-{uuid.uuid4().hex[:8]}",
                    investigation_id=inv_id,
                    evidence_id=art.evidence_id,
                    artifact_id=art.id,
                    source_filename=source_filename,
                    source_location=art.source_location,
                    indicator_type="domain",
                    value=raw_val,
                    normalized_value=norm_dom,
                    provenance_type="DIRECT_EVIDENCE",
                    extractor_or_provider=art.extractor_name,
                    confidence=art.confidence or "High",
                    pivot_depth=0
                ))
                return results

        # E. URL
        if art_type in ("url", "c2_url") or (raw_val.startswith("http://") or raw_val.startswith("https://")):
            norm_url = raw_val.strip()
            results.append(OSINTIndicator(
                id=f"IND-URL-{uuid.uuid4().hex[:8]}",
                investigation_id=inv_id,
                evidence_id=art.evidence_id,
                artifact_id=art.id,
                source_filename=source_filename,
                source_location=art.source_location,
                indicator_type="url",
                value=raw_val,
                normalized_value=norm_url,
                provenance_type="DIRECT_EVIDENCE",
                extractor_or_provider=art.extractor_name,
                confidence=art.confidence or "High",
                pivot_depth=0
            ))

            # Also extract the embedded domain from the URL for correlated pivot
            try:
                parsed = urlparse(norm_url)
                if parsed.netloc:
                    host = parsed.netloc.split(":")[0]
                    norm_h = self._normalize_domain(host)
                    if norm_h and norm_h != norm_url:
                        results.append(OSINTIndicator(
                            id=f"IND-DOM-{uuid.uuid4().hex[:8]}",
                            investigation_id=inv_id,
                            evidence_id=art.evidence_id,
                            artifact_id=art.id,
                            source_filename=source_filename,
                            source_location=f"Host component of {norm_url}",
                            indicator_type="domain",
                            value=host,
                            normalized_value=norm_h,
                            provenance_type="DIRECT_EVIDENCE",
                            extractor_or_provider=art.extractor_name,
                            confidence=art.confidence or "High",
                            pivot_depth=0
                        ))
            except Exception:
                pass

            return results

        # F. Hash
        if art_type in ("hash", "sha256", "md5", "sha1") or (len(raw_val) in (32, 40, 64) and re.match(r"^[a-fA-F0-9]+$", raw_val)):
            results.append(OSINTIndicator(
                id=f"IND-HASH-{uuid.uuid4().hex[:8]}",
                investigation_id=inv_id,
                evidence_id=art.evidence_id,
                artifact_id=art.id,
                source_filename=source_filename,
                source_location=art.source_location,
                indicator_type="hash",
                value=raw_val,
                normalized_value=raw_val.lower(),
                provenance_type="DIRECT_EVIDENCE",
                extractor_or_provider=art.extractor_name,
                confidence=art.confidence or "High",
                pivot_depth=0
            ))
            return results

        # G. Email Address
        if art_type in ("email", "author") and "@" in raw_val:
            email_match = re.search(r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+", raw_val)
            if email_match:
                em = email_match.group(0).lower()
                results.append(OSINTIndicator(
                    id=f"IND-EML-{uuid.uuid4().hex[:8]}",
                    investigation_id=inv_id,
                    evidence_id=art.evidence_id,
                    artifact_id=art.id,
                    source_filename=source_filename,
                    source_location=art.source_location,
                    indicator_type="email",
                    value=em,
                    normalized_value=em,
                    provenance_type="DIRECT_EVIDENCE",
                    extractor_or_provider=art.extractor_name,
                    confidence=art.confidence or "High",
                    pivot_depth=0
                ))

        return results

    def _is_valid_ip(self, val: str) -> bool:
        try:
            ipaddress.ip_address(val.strip())
            return True
        except ValueError:
            return False

    def _normalize_ip(self, val: str) -> Optional[str]:
        try:
            return str(ipaddress.ip_address(val.strip()))
        except ValueError:
            return None

    def _is_valid_domain(self, val: str) -> bool:
        clean = val.strip().lower()
        if len(clean) < 4 or "." not in clean or " " in clean or "/" in clean:
            return False
        # Avoid common code artifacts
        if clean.endswith(".py") or clean.endswith(".dll") or clean.endswith(".exe") or clean.endswith(".png"):
            return False
        return bool(re.match(r"^[a-zA-Z0-9][-a-zA-Z0-9]*\.[a-zA-Z]{2,}$", clean))

    def _normalize_domain(self, val: str) -> Optional[str]:
        clean = val.strip().lower().rstrip(".")
        if ":" in clean:
            clean = clean.split(":")[0]
        return clean if self._is_valid_domain(clean) else None

osint_collector = OSINTCollector()
