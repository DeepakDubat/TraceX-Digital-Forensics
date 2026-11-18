# Universal Forensics Workbench — Known Limitations & Architectural Notes

## Version 2.0.0 (Windows Release)

### 1. Code Signing & SmartScreen Prompts
- **Status:** Unsigned Open-Source Release
- **Detail:** The installer (`ForensicsWorkbench-Setup.exe`) and portable executables are not digitally signed with an Authenticode Extended Validation (EV) certificate. Windows Defender SmartScreen will display an *"Unknown Publisher"* prompt on first launch. Click **More Info** -> **Run Anyway**.
- **Remediation:** Users or enterprise organizations can sign the binary using their internal enterprise code-signing certificate via `signtool.exe sign /fd SHA256 /tr ...`.

### 2. External Tools Requiring Dedicated Environments
- **MobSF Docker Container:** MobSF relies on a Linux container environment with dynamic Android emulators. It cannot be bundled as a native Windows `.exe`. MobSF must be run via Docker Desktop (`opensecurity/mobsf:latest`) on port 8001 (to avoid port 8000 collision).
- **Wireshark / TShark Packet Capture:** Packet analysis requires the Npcap Windows kernel driver, which requires administrator privileges to install. TShark executable is detected from `%ProgramFiles%\Wireshark\tshark.exe` once installed.
- **Zeek & Suricata:** Both engines are fundamentally designed for Linux environments. On Windows, they can be accessed via WSL2 (Windows Subsystem for Linux) or dedicated network sensor feeds.
- **Dynamic Analysis Sandbox (CAPE):** Full execution of malicious APK/EXE files must never occur directly on the analyst workstation. CAPE Sandbox integration requires a dedicated, isolated virtualization server.

### 3. Java Runtime for JADX & Apktool
- **Requirement:** JADX requires Java JRE/JDK 11 or newer. Apktool requires Java JRE 8 or newer.
- **Behavior:** If Java is not installed, the native Androguard bytecode analyzer and YARA scanner remain fully operational for static APK analysis, but Java source-level decompilation through JADX will report "Java runtime required".

### 4. Memory Usage on Massive Datasets
- For multi-evidence cases containing several thousand files or PCAPs exceeding 500 MB, timeline extraction and graph rendering may require significant memory (8–16 GB recommended).

### 5. Multi-Evidence Hub
- In compliance with design directives, the legacy Multi-Evidence Hub is retired; all multi-evidence investigations and recursive pivots are processed through the unified Universal Forensics & Timeline Pipeline.
