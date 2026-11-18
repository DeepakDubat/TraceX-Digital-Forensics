"""
Normalization of local-tool output into TraceX's evidence-backed FindingRecord model.

Only observations present in real tool output are converted. Every finding retains
its source evidence, source artifact, frame/packet reference where available,
timestamp, engine, rule identifier, severity, confidence, and the original hash.
Deterministic deduplication prevents repeated indicators from being registered
multiple times when several engines observe the same value.
"""

import hashlib
import json
import re
from typing import Any, Dict, Iterable, List, Optional, Tuple

from backend.app.core.models import FindingRecord

_URL_RE = re.compile(r"https?://[^\s\"'<>]+", re.IGNORECASE)
_IP_RE = re.compile(r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b")
_DOMAIN_RE = re.compile(r"\b(?:[a-zA-Z0-9-]+\.)+(?:com|org|net|io|info|biz|ru|cn|xyz|top|club|online|site|tech)\b", re.IGNORECASE)
_HASH_RE = re.compile(r"\b[a-f0-9]{32,64}\b", re.IGNORECASE)
_PERMISSION_RE = re.compile(r"android\.permission\.[A-Z_]+", re.IGNORECASE)

_SEVERITY_RANK = {"Informational": 0, "Low": 1, "Medium": 2, "High": 3, "Critical": 4}
_CONFIDENCE_RANK = {"Low": 0, "Medium": 1, "High": 2, "Confirmed": 3}

MOBSEF_SEVERITY_MAP = {
    "info": "Informational",
    "good": "Informational",
    "low": "Low",
    "warning": "Medium",
    "medium": "Medium",
    "high": "High",
    "critical": "Critical",
}
SURICATA_SEVERITY_MAP = {1: "Critical", 2: "High", 3: "Medium", 4: "Low"}


def _clipped(value: Any, limit: int = 1200) -> str:
    text = value if isinstance(value, str) else json.dumps(value, ensure_ascii=False, default=str)
    return text[:limit]


def _severity(value: Any, default: str = "Medium") -> str:
    if isinstance(value, int):
        return SURICATA_SEVERITY_MAP.get(value, default)
    return MOBSEF_SEVERITY_MAP.get(str(value or "").strip().lower(), str(value or default).capitalize())


def _make_finding(
    investigation_id: str,
    evidence_id: str,
    title: str,
    description: str,
    observation: str,
    interpretation: str,
    engine: str,
    source_file: str,
    original_hash: Optional[str],
    source_evidence: Any,
    *,
    severity: str = "Medium",
    confidence: str = "High",
    rule_id: Optional[str] = None,
    frame_number: Optional[int] = None,
    packet_number: Optional[int] = None,
    timestamp: Optional[str] = None,
    analyzer_version: Optional[str] = None,
) -> FindingRecord:
    dedupe_source = "|".join([
        engine.lower(),
        str(rule_id or "").lower(),
        str(source_file or "").lower(),
        str(frame_number or packet_number or ""),
        _clipped(source_evidence, 6000).lower(),
    ])
    finding_id = "FND-TOOL-" + hashlib.sha256(dedupe_source.encode("utf-8", errors="replace")).hexdigest()[:16]
    return FindingRecord(
        id=finding_id,
        investigation_id=investigation_id,
        evidence_id=evidence_id,
        title=title[:300],
        description=description[:2000],
        observation=_clipped(observation),
        interpretation=interpretation[:1000],
        severity=severity,
        confidence=confidence,
        analysis_method=f"{engine} Offline Static Analysis",
        source_location=source_file,
        analyzer_name=engine,
        analyzer_version=analyzer_version,
        rule_version=None,
        source_evidence=_clipped(source_evidence),
        source_file=source_file,
        frame_number=frame_number,
        packet_number=packet_number,
        timestamp=timestamp,
        engine=engine,
        rule_id=str(rule_id) if rule_id is not None else None,
        original_hash=original_hash,
        limitations="Offline static analysis only; no code execution, live capture, or active scanning was performed.",
    )


def _dedupe_tokens(finding: FindingRecord) -> Tuple[str, ...]:
    text = " ".join([
        finding.title or "",
        finding.source_evidence or "",
        finding.observation or "",
    ])
    tokens = set()
    for pattern in (_URL_RE, _IP_RE, _DOMAIN_RE, _HASH_RE, _PERMISSION_RE):
        tokens.update(match.group(0).lower().rstrip(".,;") for match in pattern.finditer(text))
    if finding.rule_id:
        tokens.add("rule:" + str(finding.rule_id).lower())
    if not tokens:
        tokens.add(re.sub(r"\W+", "", finding.title.lower())[:120] or finding.id)
    return tuple(sorted(tokens))


def dedupe_findings(findings: Iterable[FindingRecord]) -> List[FindingRecord]:
    """Deterministically removes repeated indicators, preferring the strongest finding."""
    best: Dict[Tuple[Tuple[str, ...], str, str], FindingRecord] = {}
    for finding in findings or []:
        key = (
            _dedupe_tokens(finding),
            (finding.source_file or "").lower(),
            (finding.original_hash or "").lower(),
        )
        current = best.get(key)
        if current is None:
            best[key] = finding
            continue
        current_score = (
            _SEVERITY_RANK.get(current.severity, 2),
            _CONFIDENCE_RANK.get(current.confidence, 1),
        )
        candidate_score = (
            _SEVERITY_RANK.get(finding.severity, 2),
            _CONFIDENCE_RANK.get(finding.confidence, 1),
        )
        if candidate_score > current_score:
            best[key] = finding
    return sorted(best.values(), key=lambda item: item.id)


def _tshark_findings(result: Dict[str, Any], inv: str, ev: str, source: str, original_hash: Optional[str]) -> List[FindingRecord]:
    findings: List[FindingRecord] = []
    details = result.get("details") or {}
    for frame in (details.get("frames") or [])[:100]:
        number = frame.get("frame.number", "")
        frame_no = int(number) if str(number).isdigit() else None
        dns_name = frame.get("dns.qry.name") or ""
        dns_answer = frame.get("dns.a") or ""
        http_host = frame.get("http.host") or ""
        http_uri = frame.get("http.request.full_uri") or ""
        protocol = frame.get("_ws.col.Protocol") or ""
        evidence_bits = [f"{key}={value}" for key, value in frame.items() if value]
        if not (dns_name or dns_answer or http_host or http_uri or protocol in ("TLS", "TCP")):
            continue
        if dns_name or dns_answer:
            title = f"DNS observation: {dns_name or dns_answer}"
            severity = "Informational"
        elif http_uri or http_host:
            title = f"HTTP request observed: {http_host or http_uri}"
            severity = "Low"
        else:
            title = f"{protocol} connection observed in synthetic capture"
            severity = "Informational"
        findings.append(_make_finding(
            inv, ev, title,
            "TShark dissected this frame from the submitted packet capture.",
            "; ".join(evidence_bits),
            "Network metadata was parsed offline from the evidentiary PCAP.",
            "TShark", source, original_hash, frame,
            severity=severity, confidence="High",
            frame_number=frame_no, packet_number=frame_no,
            timestamp=frame.get("frame.time_epoch"),
            analyzer_version=details.get("version"),
        ))
    return findings


def _zeek_findings(result: Dict[str, Any], inv: str, ev: str, source: str, original_hash: Optional[str]) -> List[FindingRecord]:
    findings: List[FindingRecord] = []
    details = result.get("details") or {}
    for row in (details.get("dns_log") or [])[:50]:
        query = row.get("query") or ""
        if not query:
            continue
        findings.append(_make_finding(
            inv, ev, f"Zeek DNS query: {query}",
            "Zeek generated a DNS log entry from the submitted packet capture.",
            row, "DNS activity was reconstructed from packet metadata offline.",
            "Zeek", source, original_hash, row,
            severity="Informational", confidence="High",
            timestamp=row.get("ts"),
        ))
    for row in (details.get("conn_log") or [])[:50]:
        responder = row.get("id.resp_h") or ""
        if not responder:
            continue
        findings.append(_make_finding(
            inv, ev, f"Zeek connection to {responder}",
            "Zeek generated a connection log entry from the submitted packet capture.",
            row, "Connection metadata was reconstructed from packet data offline.",
            "Zeek", source, original_hash, row,
            severity="Informational", confidence="High",
            timestamp=row.get("ts"),
        ))
    return findings


def _suricata_findings(result: Dict[str, Any], inv: str, ev: str, source: str, original_hash: Optional[str]) -> List[FindingRecord]:
    findings: List[FindingRecord] = []
    details = result.get("details") or {}
    for alert in (details.get("alerts") or [])[:100]:
        rule_id = alert.get("rule_id") or None
        findings.append(_make_finding(
            inv, ev, f"Suricata signature: {alert.get('rule_msg') or rule_id or 'alert'}",
            "Suricata matched a rule while reading the submitted packet capture offline.",
            alert, "Rule evaluation is based solely on observed packet bytes.",
            "Suricata", source, original_hash, alert,
            severity=_severity(alert.get("severity"), default="Medium"),
            confidence="High", rule_id=rule_id,
            timestamp=alert.get("timestamp"),
            analyzer_version=details.get("version"),
        ))
    return findings


def _exiftool_findings(result: Dict[str, Any], inv: str, ev: str, source: str, original_hash: Optional[str]) -> List[FindingRecord]:
    details = result.get("details") or {}
    metadata = details.get("metadata") or {}
    if not metadata:
        return []
    return [_make_finding(
        inv, ev, f"Metadata extracted from {source.rsplit('/', 1)[-1].rsplit(chr(92), 1)[-1]}",
        "ExifTool parsed embedded metadata tags from the submitted artifact.",
        metadata, "Metadata values are direct observations from the file structure.",
        "ExifTool", source, original_hash, metadata,
        severity="Informational", confidence="High",
        analyzer_version=details.get("version"),
    )]


def _strings_findings(result: Dict[str, Any], inv: str, ev: str, source: str, original_hash: Optional[str]) -> List[FindingRecord]:
    findings: List[FindingRecord] = []
    details = result.get("details") or {}
    classification = details.get("classification") or {}
    category_severity = {
        "urls": "Low", "ips": "Low", "domains": "Informational",
        "shell_commands": "High", "decoded_items": "Medium",
        "doh_indicators": "Low", "dynamic_dns_items": "Low",
    }
    for category, items in classification.items():
        for item in (items or [])[:50]:
            evidence = item.get("value") or item.get("url") or item.get("ip") or item.get("domain") or item.get("command") or item
            findings.append(_make_finding(
                inv, ev, f"String-derived indicator ({category}): {_clipped(evidence, 100)}",
                "The built-in multi-encoding Strings Utility extracted this indicator from the artifact.",
                item, "The indicator was observed directly in decoded binary content.",
                "Strings Utility", source, original_hash, item,
                severity=category_severity.get(category, "Low"), confidence="High",
            ))
    return findings


def _iter_mobsf_security_items(report: Dict[str, Any]) -> Iterable[Tuple[str, Any]]:
    manifest = (report.get("manifest_analysis") or {}).get("manifest_findings") or []
    for item in manifest:
        if isinstance(item, dict):
            yield "MobSF Manifest", item

    code_findings = (report.get("code_analysis") or {}).get("findings") or {}
    for rule_id, item in code_findings.items():
        if isinstance(item, dict):
            yield rule_id, item

    for item in (report.get("certificate_analysis") or {}).get("certificate_findings") or []:
        if isinstance(item, (list, tuple)) and len(item) >= 3:
            yield "MobSF Certificate", {"severity": item[0], "description": item[1], "title": item[2]}

    for item in (report.get("network_security") or {}).get("network_findings") or []:
        if isinstance(item, dict):
            yield "MobSF Network", item

    for section in ("binary_analysis", "file_analysis", "secrets"):
        for item in report.get(section) or []:
            if isinstance(item, dict):
                yield f"MobSF {section}", item

    malware = report.get("malware_permissions") or {}
    permissions = (malware.get("top_malware_permissions") or [])[:10]
    if permissions:
        yield "MobSF Permissions", {
            "title": "High-risk Android permissions requested",
            "severity": "warning",
            "description": ", ".join(permissions),
        }


def _mobsf_findings(result: Dict[str, Any], inv: str, ev: str, source: str, original_hash: Optional[str]) -> List[FindingRecord]:
    findings: List[FindingRecord] = []
    details = result.get("details") or {}
    report = details.get("report") or {}
    for engine, item in _iter_mobsf_security_items(report):
        metadata = item.get("metadata") or {}
        description = item.get("description") or metadata.get("description") or ""
        severity_value = item.get("severity") or metadata.get("severity") or "warning"
        rule_id = item.get("rule") or (engine if engine.startswith("MobSF") else None)
        title = item.get("title") or item.get("name") or rule_id or "MobSF static finding"
        evidence = {
            "title": title,
            "description": description,
            "rule": rule_id,
            "component": item.get("component"),
            "files": item.get("files"),
            "cwe": metadata.get("cwe"),
            "owasp_mobile": metadata.get("owasp-mobile"),
            "masvs": metadata.get("masvs"),
            "cvss": metadata.get("cvss"),
        }
        findings.append(_make_finding(
            inv, ev, f"MobSF: {title}",
            description or "MobSF static analyzer reported this observation.",
            evidence, "Finding was produced by the official MobSF static-analysis workflow.",
            engine if engine.startswith("MobSF") else "MobSF", source, original_hash, evidence,
            severity=_severity(severity_value), confidence="High",
            rule_id=rule_id, timestamp=report.get("timestamp"),
            analyzer_version=str(report.get("version") or ""),
        ))
    return findings[:200]


NORMALIZERS = {
    "tshark": _tshark_findings,
    "zeek": _zeek_findings,
    "suricata": _suricata_findings,
    "exiftool": _exiftool_findings,
    "strings": _strings_findings,
    "mobsf": _mobsf_findings,
}


def normalize_tool_results(
    tool_results: Dict[str, Dict[str, Any]],
    investigation_id: str,
    evidence_id: str,
    source_file: str,
    original_hash: Optional[str] = None,
) -> List[FindingRecord]:
    """Normalizes successful adapter results and deduplicates repeated indicators."""
    findings: List[FindingRecord] = []
    for tool, result in (tool_results or {}).items():
        if not result or not result.get("success"):
            continue
        normalizer = NORMALIZERS.get(tool.lower())
        if not normalizer:
            continue
        try:
            findings.extend(normalizer(result, investigation_id, evidence_id, source_file, original_hash))
        except Exception:
            # A normalizer failure must never invalidate the other engines' evidence.
            continue
    return dedupe_findings(findings)
