"""
TraceX – Software Bill of Materials (SBOM) Generator
Generates CycloneDX JSON SBOM (dist/SBOM.json) and Markdown SBOM (SBOM.md)
"""
import subprocess
import json
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent

# Query pip packages
pip_out = subprocess.check_output(['py', '-3.11', '-m', 'pip', 'list', '--format=json'])
py_pkgs = json.loads(pip_out)

# Query frontend npm packages
frontend_pkg_json = json.loads((ROOT_DIR / 'frontend' / 'package.json').read_text(encoding='utf-8'))
npm_deps = frontend_pkg_json.get('dependencies', {})
npm_dev_deps = frontend_pkg_json.get('devDependencies', {})

# Bundled tools
bundled_tools = [
    {"name": "OpenJDK Runtime", "version": "21.0.10 LTS", "purl": "pkg:generic/openjdk@21.0.10", "description": "Minimal custom Java runtime image for JADX and Apktool execution"},
    {"name": "JADX Decompiler (CLI & GUI)", "version": "1.5.6", "purl": "pkg:generic/jadx@1.5.6", "description": "DEX to Java decompiler and interactive GUI code viewer"},
    {"name": "Apktool", "version": "3.0.3", "purl": "pkg:generic/apktool@3.0.3", "description": "Android APK resource and Smali bytecode disassembler"},
    {"name": "Tesseract OCR", "version": "5.4.0", "purl": "pkg:generic/tesseract@5.4.0", "description": "Optical character recognition engine with English trained model"},
    {"name": "ExifTool", "version": "13.64", "purl": "pkg:generic/exiftool@13.64", "description": "Comprehensive image, document, and media metadata extraction engine"},
    {"name": "TShark Standalone Dissector", "version": "4.6.9", "purl": "pkg:generic/tshark@4.6.9", "description": "Offline command-line packet capture and network protocol dissection"},
    {"name": "Suricata Offline Engine", "version": "8.0.8", "purl": "pkg:generic/suricata@8.0.8", "description": "Offline network intrusion detection, threat signatures, and protocol inspection"},
    {"name": "YARA Engine & Rules", "version": "4.5.4", "purl": "pkg:generic/yara@4.5.4", "description": "Pattern matching swiss knife for malware researchers"},
    {"name": "Androguard", "version": "4.1.4", "purl": "pkg:pypi/androguard@4.1.4", "description": "Android APK reverse engineering and Dalvik decompilation framework"},
    {"name": "pefile", "version": "2024.8.26", "purl": "pkg:pypi/pefile@2024.8.26", "description": "Portable Executable (PE) analysis and parsing library"},
    {"name": "Microsoft Edge WebView2 Evergreen", "version": "System Evergreen", "purl": "pkg:generic/webview2@evergreen", "description": "Native Windows Chromium web runtime host"},
    {"name": "pywebview", "version": "6.2.1", "purl": "pkg:pypi/pywebview@6.2.1", "description": "Lightweight cross-platform desktop wrapper around WebView2"},
    {"name": "Argon2id (argon2-cffi)", "version": "23.1.0", "purl": "pkg:pypi/argon2-cffi@23.1.0", "description": "Memory-hard cryptographic password hashing algorithm"},
    {"name": "cryptography", "version": "43.0.1", "purl": "pkg:pypi/cryptography@43.0.1", "description": "Cryptographic recipes and primitives including AES-256-GCM"},
    {"name": "FastAPI", "version": "0.115.0", "purl": "pkg:pypi/fastapi@0.115.0", "description": "High-performance Python web framework"},
    {"name": "Uvicorn", "version": "0.31.0", "purl": "pkg:pypi/uvicorn@0.31.0", "description": "ASGI web server implementation"}
]

sbom_components = []

for t in bundled_tools:
    sbom_components.append({
        "name": t["name"],
        "version": t["version"],
        "purl": t["purl"],
        "type": "application" if "Engine" in t["name"] or "WebView2" in t["name"] else "library",
        "scope": "required",
        "description": t["description"]
    })

for p in py_pkgs:
    sbom_components.append({
        "name": p["name"],
        "version": p["version"],
        "purl": f"pkg:pypi/{p['name']}@{p['version']}",
        "type": "library",
        "scope": "required"
    })

for k, v in npm_deps.items():
    clean_v = v.lstrip("^~")
    sbom_components.append({
        "name": k,
        "version": clean_v,
        "purl": f"pkg:npm/{k}@{clean_v}",
        "type": "library",
        "scope": "required"
    })

cyclonedx_sbom = {
    "$schema": "http://cyclonedx.org/schema/bom-1.5.json",
    "bomFormat": "CycloneDX",
    "specVersion": "1.5",
    "serialNumber": "urn:uuid:tracex-forensics-v2.0.0-sbom",
    "version": 1,
    "metadata": {
        "timestamp": "2026-11-08T09:00:00Z",
        "tools": [
            {
                "vendor": "TraceX Project Team",
                "name": "TraceX SBOM Generator",
                "version": "2.0.0"
            }
        ],
        "component": {
            "name": "TraceX – Digital Forensics & Cyber Investigation Suite",
            "version": "2.0.0",
            "type": "application",
            "description": "Desktop digital forensics and cyber investigation application for Windows x64",
            "licenses": [{"license": {"id": "Apache-2.0"}}]
        }
    },
    "components": sbom_components
}

dist_dir = ROOT_DIR / "dist"
dist_dir.mkdir(parents=True, exist_ok=True)
json_path = dist_dir / "SBOM.json"
json_path.write_text(json.dumps(cyclonedx_sbom, indent=2), encoding="utf-8")

# Generate Markdown SBOM
md_lines = [
    "# Software Bill of Materials (SBOM)",
    "## TraceX – Digital Forensics & Cyber Investigation Suite v2.0.0",
    "",
    "**Standard:** CycloneDX 1.5 JSON & Human-Readable Markdown  ",
    "**Target Architecture:** Windows 10/11 x64  ",
    f"**Total Components Cataloged:** {len(sbom_components)}  ",
    "**JSON Artifact:** [`dist/SBOM.json`](dist/SBOM.json)  ",
    "",
    "---",
    "",
    "### 1. Core Forensic Engines & Bundled Runtimes",
    "",
    "| Component | Version | Package URL (purl) | Description |",
    "| :--- | :--- | :--- | :--- |",
]

for t in bundled_tools:
    md_lines.append(f"| **{t['name']}** | `{t['version']}` | `{t['purl']}` | {t['description']} |")

md_lines.extend([
    "",
    "---",
    "",
    "### 2. Frontend Dependencies (React 19 / TypeScript / Vite)",
    "",
    "| Package | Version | purl |",
    "| :--- | :--- | :--- |",
])

for k, v in sorted(npm_deps.items()):
    clean_v = v.lstrip("^~")
    md_lines.append(f"| `{k}` | `{clean_v}` | `pkg:npm/{k}@{clean_v}` |")

md_lines.extend([
    "",
    "---",
    "",
    "### 3. Backend Python Libraries (Python 3.11 x64)",
    "",
    "| Package | Version | purl |",
    "| :--- | :--- | :--- |",
])

for p in sorted(py_pkgs, key=lambda x: x["name"].lower()):
    md_lines.append(f"| `{p['name']}` | `{p['version']}` | `pkg:pypi/{p['name']}@{p['version']}` |")

md_path = ROOT_DIR / "SBOM.md"
md_path.write_text("\n".join(md_lines), encoding="utf-8")

print(f"[+] Successfully wrote {json_path} and {md_path}")

