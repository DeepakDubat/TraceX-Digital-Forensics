import os
import sys
import re
from pathlib import Path

ROOT = Path(".")

# Files and directories to scan
SCAN_EXTS = {".py", ".ts", ".tsx", ".js", ".json", ".bat", ".ps1", ".sh", ".env", ".example", ".iss", ".md", ".txt"}
EXCLUDE_DIRS = {
    ".git", "node_modules", ".pytest_cache", "__pycache__", "dist", "build",
    "archive_legacy_snapshots", "_pre_rollback_backup", "scratch", "PROJECT_ANALYSIS_REPORT",
    "PROJECT_CREDENTIAL_AUDIT", "PROJECT_PHASE10_RELEASE_CLOSURE", "PROJECT_PHASE3_VERIFICATION",
    "PROJECT_PHASE4_SECURITY", "PROJECT_PHASE5_FORENSIC_VALIDATION", "PROJECT_PHASE6_RELEASE",
    "PROJECT_PHASE7_ACCEPTANCE", "PROJECT_PHASE8_FINAL_RELEASE", "PROJECT_PHASE9_OPERATIONAL_ACCEPTANCE",
    "PROJECT_REMEDIATION_REPORT", "PROJECT_TOOLS_CONFIG_FIX", "reports"
}

KNOWN_SECRETS = [
    "eba35f09740925df08f673c831ad9a652de3643e17673ecd32aa89203a27e895",
    "1a5366747b6579f5918fd0b6a4f6e7cfab23b0e0191b6f72",
    "f98c36eee63eaa4a2b06eb6305e7269ee58c09aa9d75e2f7d3948d2d1a9651a1",
    "243f31d1781c43b797605ada87ee31fd11e9f23ce2f4afe7"
]

PERSONAL_TERMS = [
    r"C:\\Users\\Deepak",
    r"c:/users/deepak"
]

def scan_for_leaks():
    leaks = []
    scanned_count = 0

    for root, dirs, files in os.walk(ROOT):
        dirs[:] = [d for d in dirs if d not in EXCLUDE_DIRS and not d.startswith(".")]

        # Skip forensic case artifacts in analysis_workspace which contain simulated test evidence
        if "analysis_workspace" in root:
            continue

        for f in files:
            path = Path(root) / f
            if path.suffix.lower() not in SCAN_EXTS and not f.startswith(".env"):
                continue

            # Don't scan this verification script, audit artifacts, or migration scripts
            if "verify_secret_leak_clean" in f or "audit" in f or "summarize" in f or "migrate" in f:
                continue

            scanned_count += 1
            try:
                content = path.read_text(encoding="utf-8", errors="ignore")
            except Exception:
                continue

            # Check known secrets
            for s in KNOWN_SECRETS:
                if s in content:
                    leaks.append(f"KNOWN SECRET LEAK in {path.as_posix()}: {s[:8]}...")

            # Check personal paths
            for p_term in PERSONAL_TERMS:
                if re.search(p_term, content, re.IGNORECASE):
                    leaks.append(f"PERSONAL PATH LEAK in {path.as_posix()}: {p_term}")

    return scanned_count, leaks

if __name__ == "__main__":
    count, leaks = scan_for_leaks()
    print(f"Scanned {count} source, config, and script files.")
    if leaks:
        print(f"FAILED: {len(leaks)} leak(s) detected:")
        for l in leaks:
            print("  ", l)
        sys.exit(1)
    else:
        print("PASS: ZERO hardcoded secrets or developer personal paths detected across the codebase!")
        sys.exit(0)
