import os
import re
import json
from pathlib import Path

ROOT = Path(r"Z:\Antigravity\Cyber projects\APK Tool Analysis")

EXCLUDE_DIRS = {
    ".git", "node_modules", ".pytest_cache", "__pycache__", 
    "dist", "build", "archive_legacy_snapshots", "_pre_rollback_backup",
    ".system_generated", "scratch"
}

EXTENSIONS = {
    ".py", ".ts", ".tsx", ".js", ".json", ".bat", ".ps1", ".sh",
    ".env", ".example", ".iss", ".md", ".txt", ".yaml", ".yml", ".ini", ".cfg"
}

KNOWN_SECRETS = [
    "eba35f09740925df08f673c831ad9a652de3643e17673ecd32aa89203a27e895",
    "1a5366747b6579f5918fd0b6a4f6e7cfab23b0e0191b6f72",
]

PERSONAL_TERMS = [
    r"Deepak",
    r"deepak",
    r"C:\\Users\\Deepak",
    r"c:/users/deepak"
]

PROVIDER_KEYWORDS = [
    "virustotal", "abuseipdb", "alienvault", "otx", "urlhaus", "malwarebazaar",
    "shodan", "censys", "greynoise", "ipinfo", "misp", "urlscan", "passivedns",
    "mobsf", "cape", "fakenet", "tshark", "zeek", "suricata", "opencode",
    "openai", "anthropic", "gemini", "groq", "huggingface", "jadx", "apktool", "androguard", "yara"
]

SECRET_PATTERNS = [
    (r"(?i)(api[_-]?key|secret|token|password|auth|bearer)\s*[:=]\s*['\"]([^'\"]{8,})['\"]", "Assigned secret string"),
    (r"(?i)(api[_-]?key|secret|token|password|auth|bearer)\s*=\s*([a-zA-Z0-9_-]{16,})", "Bare secret token"),
    (r"(?i)bearer\s+[a-zA-Z0-9_\-\.]{16,}", "Bearer token"),
    (r"AKIA[0-9A-Z]{16}", "AWS Access Key"),
    (r"AIza[0-9A-Za-z-_]{35}", "Google API Key"),
    (r"ghp_[0-9a-zA-Z]{36}", "GitHub Personal Access Token"),
]

def scan_repository():
    findings = {
        "personal_data": [],
        "known_secrets": [],
        "regex_secrets": [],
        "provider_occurrences": {p: [] for p in PROVIDER_KEYWORDS},
        "all_scanned_files": 0
    }

    for root, dirs, files in os.walk(ROOT):
        # Exclude directories in-place
        dirs[:] = [d for d in dirs if d not in EXCLUDE_DIRS and not d.startswith(".")]

        for file in files:
            file_path = Path(root) / file
            rel_path = file_path.relative_to(ROOT).as_posix()

            if file_path.suffix.lower() not in EXTENSIONS and not file.startswith(".env"):
                continue

            findings["all_scanned_files"] += 1

            try:
                content = file_path.read_text(encoding="utf-8", errors="ignore")
            except Exception as e:
                continue

            lines = content.splitlines()

            # Check personal terms
            for p_term in PERSONAL_TERMS:
                pattern = re.compile(p_term, re.IGNORECASE)
                for line_no, line in enumerate(lines, 1):
                    if pattern.search(line):
                        findings["personal_data"].append({
                            "file": rel_path,
                            "line": line_no,
                            "term": p_term,
                            "content": line.strip()[:200]
                        })

            # Check known secrets
            for secret in KNOWN_SECRETS:
                if secret in content:
                    for line_no, line in enumerate(lines, 1):
                        if secret in line:
                            findings["known_secrets"].append({
                                "file": rel_path,
                                "line": line_no,
                                "secret": secret[:8] + "..." + secret[-4:],
                                "content": line.strip()[:200]
                            })

            # Check regex secret patterns
            for pat, pat_name in SECRET_PATTERNS:
                regex = re.compile(pat)
                for line_no, line in enumerate(lines, 1):
                    # Filter out comments, docstrings, and tests if false positives
                    matches = regex.findall(line)
                    if matches:
                        # Ignore typical mock / test keys or placeholder names
                        text_lower = line.lower()
                        if any(x in text_lower for x in ["placeholder", "example", "mock", "dummy", "test_key", "your_api_key", "none", "true", "false", "<", ">", "process.env"]):
                            continue
                        findings["regex_secrets"].append({
                            "file": rel_path,
                            "line": line_no,
                            "pattern": pat_name,
                            "content": line.strip()[:200]
                        })

            # Check provider references
            for prov in PROVIDER_KEYWORDS:
                prov_re = re.compile(rf"\b{prov}\b", re.IGNORECASE)
                for line_no, line in enumerate(lines, 1):
                    if prov_re.search(line):
                        findings["provider_occurrences"][prov].append({
                            "file": rel_path,
                            "line": line_no
                        })
                        break # Only record file presence once per provider

    return findings

if __name__ == "__main__":
    results = scan_repository()
    out_dir = ROOT / "PROJECT_CREDENTIAL_AUDIT"
    out_dir.mkdir(parents=True, exist_ok=True)
    
    with open(out_dir / "raw_findings.json", "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)
    
    print(f"Scanned {results['all_scanned_files']} files.")
    print(f"Personal data findings: {len(results['personal_data'])}")
    print(f"Known secrets findings: {len(results['known_secrets'])}")
    print(f"Regex potential secrets: {len(results['regex_secrets'])}")
    print(f"Providers referenced: {sum(1 for k, v in results['provider_occurrences'].items() if len(v) > 0)}")

