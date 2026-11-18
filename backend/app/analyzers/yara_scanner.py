from pathlib import Path
from typing import List, Dict, Any, Tuple
from backend.app.config import settings
from backend.app.core.models import StaticFinding

try:
    import yara
    YARA_AVAILABLE = True
except ImportError:
    yara = None
    YARA_AVAILABLE = False

def run_yara_scan(target_file: Path) -> Tuple[List[StaticFinding], str]:
    """
    Executes compiled YARA rules against an APK file or extracted DEX.
    Returns list of StaticFinding and scanner status message.
    """
    findings: List[StaticFinding] = []
    
    if not YARA_AVAILABLE:
        return findings, "yara-python library is not installed."
        
    rules_file = settings.RULES_DIR / "yara_rules.yar"
    if not rules_file.exists():
        return findings, f"YARA rules file not found at {rules_file}."
        
    try:
        rules = yara.compile(filepath=str(rules_file))
        matches = rules.match(str(target_file))
        
        for match in matches:
            meta = match.meta or {}
            severity = meta.get("severity", "High")
            confidence = meta.get("confidence", "High")
            desc = meta.get("description", f"Matched YARA rule: {match.rule}")
            
            # Extract string match excerpts
            string_snippets = []
            for s in match.strings[:3]:
                # match.strings is a list of tuples: (offset, identifier, data)
                if len(s) >= 3:
                    try:
                        str_val = s[2].decode('utf-8', errors='ignore')
                        string_snippets.append(f"{s[1]} = {str_val[:60]}")
                    except Exception:
                        pass
                        
            findings.append(StaticFinding(
                id=f"YARA-{match.rule}",
                category="yara_signature",
                severity=severity,
                confidence=confidence,
                title=f"YARA Rule Matched: {match.rule}",
                description=desc,
                source_file=target_file.name,
                code_reference=", ".join(string_snippets) if string_snippets else None,
                evidence_snippet=", ".join(string_snippets[:2]) if string_snippets else None,
                explanation=f"Signatures identified specific bytecode sequences defined in rule '{match.rule}'.",
                remediation_advice="Review matching classes and methods in static decompiler."
            ))
            
        return findings, f"YARA scan completed: {len(matches)} rules matched."
    except Exception as e:
        return findings, f"YARA scan error: {str(e)}"
