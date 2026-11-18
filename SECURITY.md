# Security Policy

## Reporting Security Vulnerabilities

We take the security and integrity of TraceX seriously. If you identify a potential security vulnerability, weakness in cryptographic verification, unintended data exposure, or bypass of local network isolation boundaries, please report it responsibly.

### Responsible Disclosure Process

1. **Do not create a public GitHub Issue** for suspected vulnerabilities or zero-day issues.
2. Report the vulnerability privately via **GitHub Security Advisories**:
   - Navigate to the repository's **Security** tab: [Security Advisories](https://github.com/DeepakDubat/TraceX-Digital-Forensics/security/advisories)
   - Click **Report a vulnerability** to open a private advisory draft.
3. Include the following details to assist triage and validation:
   - Type of vulnerability (e.g., path traversal, memory unsafety, cryptographic validation flaw, unauthorized egress).
   - Component affected (Backend FastAPI, Frontend React, WebView2 Host, Analyzers).
   - Step-by-step reproduction steps or minimal test fixture.
   - Potential impact on evidence integrity, confidentiality, or workstation security.

### Response & Remediation Timeline

* **Acknowledgment:** Within 48 hours of initial report receipt.
* **Triage & Reproduction:** Within 5 business days.
* **Remediation & Patch Release:** Coordinated security patch released before public disclosure.

---

## Secret Handling & BYOK Security Architecture

TraceX operates on a strict **Bring Your Own Key (BYOK)** model with zero hardcoded API keys:

* **Local DPAPI Encryption:** When running on Windows, external API tokens (VirusTotal, AbuseIPDB, AlienVault OTX, Shodan) are encrypted at rest using the Windows Data Protection API (`CryptProtectData`) tied to the active Windows user account.
* **In-Memory Scrubbing:** Credential values are kept in memory only when active and scrubbed upon session termination.
* **Centralized Redaction:** All diagnostic logging, terminal output, and plain-text exports automatically pass through a centralized token redactor that masks high-entropy API keys (`••••••••`).
* **Zero Cloud Synchronization:** Stored credentials never leave the host workstation and are never transmitted to third-party tracking services or telemetry relays.

---

## Evidence Privacy & Network Isolation Boundaries

TraceX is built for forensic examiners, security researchers, and incident responders handling sensitive malware samples and evidentiary artifacts:

1. **LOCAL ONLY vs. HYBRID Mode:**
   * **LOCAL ONLY (Default):** Strictly prohibits all outbound network requests. All static decompilation, YARA pattern matching, PE parsing, and string extraction execute entirely offline on local CPU. External OSINT/AI queries are blocked at the application core.
   * **HYBRID Mode:** Allows opt-in passive threat intelligence queries (e.g., file hash lookup against VirusTotal or IP reputation via AbuseIPDB). **Raw binary evidence is never uploaded to external clouds.**
2. **Read-Only Evidence Protection:**
   * Upon ingestion, evidentiary artifacts are staged in an isolated read-only store (`0o444` permissions) and immediately fingerprinted with MD5, SHA-1, SHA-256, and SHA-512 hashes.
   * All static analyzers operate exclusively on an identical working copy to guarantee Chain of Custody preservation.
3. **No Execution Guarantee:**
   * The static analysis pipeline parses binary headers (ELF, PE, DEX, Zip) and decompiles bytecodes strictly through safe parsing libraries and dedicated tools. Binaries are never spawned or executed natively on the host workstation.
