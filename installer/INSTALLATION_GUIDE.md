# Universal Forensics Workbench — Windows Installation & User Guide

## System Requirements

- **Operating System:** Windows 10 (64-bit, build 19041+) or Windows 11 (64-bit)
- **Architecture:** x64
- **Processor:** 4 cores minimum recommended for multi-evidence timeline and bytecode parsing
- **Memory:** 8 GB RAM minimum (16 GB recommended for large APK decompilation & PCAP telemetry)
- **Disk Space:** 500 MB for basic application runtime; 5 GB+ for case evidence and reports
- **Browser:** Google Chrome, Microsoft Edge, or Mozilla Firefox (modern Chromium or Gecko)

---

## Installation Options

### Option 1: Standard Windows Installer (`ForensicsWorkbench-Setup.exe`)

The Windows installer provides a guided, one-click setup experience:

1. Download `ForensicsWorkbench-Setup.exe`.
2. Double-click the installer. If Windows Defender SmartScreen displays an alert (*"Unknown Publisher"*), click **More Info** -> **Run Anyway** (this occurs because the package is open-source and unsigned).
3. Choose your desired install mode:
   - **Standard (Recommended):** Installs the application, bundled Python 3.11 runtime, and core detection rulesets.
   - **Minimal:** Installs only the core application runtime without default rule samples.
4. Select whether to create a Desktop shortcut and Start Menu folder.
5. Click **Install**.
6. When finished, check **Launch Universal Forensics Workbench** and click **Finish**.

#### Application Data Location
The installer isolates application binaries from user evidence:
- **Application Binaries:** `C:\Program Files\ForensicsWorkbench\` (or `%LOCALAPPDATA%\Programs\ForensicsWorkbench\` for non-admin installs)
- **User Data & Investigations:** `%LOCALAPPDATA%\ForensicsWorkbench\`
  - Database: `%LOCALAPPDATA%\ForensicsWorkbench\workbench.db`
  - Evidence: `%LOCALAPPDATA%\ForensicsWorkbench\evidence\`
  - Reports: `%LOCALAPPDATA%\ForensicsWorkbench\reports\`
  - Custom Rules: `%LOCALAPPDATA%\ForensicsWorkbench\rules\`

#### Uninstallation
- Run the uninstaller via Windows Settings -> Apps -> Installed Apps -> **Universal Forensics Workbench** -> Uninstall.
- The uninstaller removes application binaries while **explicitly preserving** your case history, investigation database, and forensic evidence in `%LOCALAPPDATA%\ForensicsWorkbench\`.

---

### Option 2: Standalone Portable Package (`ForensicsWorkbench-Portable.zip`)

The portable package requires zero installation, registry modifications, or administrator privileges:

1. Download and extract `ForensicsWorkbench-Portable.zip` into any folder or USB drive (e.g. `D:\ForensicsWorkbench\`).
2. Double-click **`Launch_Workbench.bat`** (or `ForensicsWorkbench.exe`).
3. The local backend server will start and your web browser will automatically open to `http://127.0.0.1:8000`.
4. **Data Isolation:** All evidence, reports, and database records are stored entirely inside `.\data\` within the extracted folder.
5. To completely remove the application, simply delete the extracted folder.

---

## First-Run Configuration

### 1. Initial Administrator Setup
On the first launch of a fresh installation, the platform displays the **Initial Administrator Setup Wizard**:
- **Create Custom Credentials:** Set your investigator username (default `admin`) and a unique password (minimum 8 characters).
- **Argon2id Password Security:** Passwords are mathematically derived using memory-hard Argon2id key derivation with a 16-byte cryptographically random salt.
- **Zero Default Passwords:** The application distributes no universal or default password.
- **Permanent Setup Lockdown:** Once the primary administrator account is initialized, the setup endpoint permanently locks down (`HTTP 403 Forbidden`) to prevent administrative takeover.

### 2. Loopback Security Policy
By default, the workbench strictly binds to **IPv4 Loopback (`127.0.0.1`)** and never listens on `0.0.0.0`. In single-user workstation mode, all inbound connections from non-loopback network addresses are blocked (`HTTP 403 Forbidden`), preventing remote LAN exposure.

### 3. Threat Intelligence & AI Provider Integrations
The installer contains **no hardcoded API keys**. To enable external intelligence enrichment or AI assistance:
1. Open the workbench and navigate to **Integration Manager & Tools** (gear icon in sidebar).
2. Sign in with your administrator credentials.
3. Configure your API credentials for:
   - AI Providers: Google Gemini (OAuth 2.0 PKCE or API Key), OpenAI, Anthropic, Groq
   - Threat Intel & OSINT: VirusTotal, AlienVault OTX, AbuseIPDB, URLhaus, MalwareBazaar, IPinfo
4. Test connectivity using the built-in **Test Connection** buttons. Keys are encrypted at rest with the platform master key (AES-128/Fernet) and are never displayed in raw plaintext or leaked into exported reports.

### 4. Local-Only Mode (Air-Gapped Operation)
If you are analyzing sensitive malware or proprietary binaries, toggle **Local-Only Mode** to `ON` in Settings or during new case creation. This automatically activates a hardware-level network kill-switch, blocking all outbound DNS, HTTP, and threat intelligence queries.

---

## Integrating Optional External Tools

The workbench includes native Python engines for APK bytecode, Windows PE executables, PDF documents, and Office files. For advanced decompilation and dynamic emulation:

| Tool | Purpose | Setup Method |
|---|---|---|
| **JADX** | Java decompilation | Run `powershell -File installer/install_tools.ps1 -Tool jadx` (requires Java 11+) |
| **Apktool** | Resource decoding | Run `powershell -File installer/install_tools.ps1 -Tool apktool` (requires Java 8+) |
| **MobSF** | Mobile Security Docker | Install Docker Desktop, then run: `docker run -it --rm -p 8001:8000 opensecurity/mobsf:latest` |
| **Wireshark** | PCAP analysis | Download and install from `https://www.wireshark.org/download.html` (standard tshark path is auto-detected) |
| **OpenCode** | AI assistance | Run `npm install -g opencode` in terminal |

---

## Troubleshooting

- **Port Conflict:** If port 8000 is occupied by another service on your machine, the launcher automatically selects an alternative port (e.g. `8001` or `8002`) and informs you in the startup console.
- **Diagnostics Export:** If you encounter unexpected behavior, navigate to **Settings** -> click **Export Diagnostics** to download a sanitized JSON report containing your runtime environment and tool status (secrets are automatically omitted).
