# Integrated Forensic Engines & Tool Specifications

TraceX coordinates multiple industry-standard static analysis tools, decompilers, and protocol parsers through unified Python orchestration engines.

---

## Tool Integration Matrix

| Tool Name | Version / Spec | Primary Purpose | Distribution Classification | Fallback Mechanism |
| :--- | :--- | :--- | :--- | :--- |
| **JADX** | v1.5.6 | Dalvik bytecode decompiler (DEX to Java). Recovers source classes, activities, and logic. | **Bundled in Windows Installer** (`tools/jadx`) / System PATH in development | Falls back to Smali disassembler via Apktool |
| **Apktool** | v3.0.3 | Android binary resource extraction, decoding `AndroidManifest.xml` and resource tables (`resources.arsc`). | **Bundled in Windows Installer** (`tools/apktool`) / System PATH in development | Internal Python pure-ZIP and XML parser |
| **YARA** | v4.5.1 | High-performance pattern matching against compiled rulesets (cryptography, packer signatures, malware indicators). | **Bundled in Windows Installer** (`tools/yara`) via `yara-python` bindings | Regex keyword scanning pool |
| **TShark** | v4.6.9 | Standalone command-line network protocol analyzer for offline PCAP/PCAPNG dissection. | **Bundled in Windows Installer** (`tools/tshark`) / System PATH | Python `scapy` / `dpkt` parsing |
| **Suricata** | v8.0.8 | Standalone offline signature-based network intrusion detection engine (PCAP replay). | **Bundled in Windows Installer** (`tools/suricata`) / Optional external | TShark protocol dissection |
| **ExifTool** | v13.64 | Metadata extraction from media, Office documents, PDFs, and executable container headers. | **Bundled in Windows Installer** (`tools/exiftool`) / System PATH | Native Python format metadata extractors |
| **OpenJDK** | 21.0.4 LTS | Stripped minimal Java Runtime Environment generated via `jlink` to run JADX and Apktool. | **Bundled in Windows Installer** (`tools/java`) / System `JAVA_HOME` | System default Java runtime |
| **pefile** | v2024.8.26 | Multi-platform Windows Portable Executable (PE/DLL) structural parser (COFF headers, sections, imports/exports). | **Integrated Python Library** (`pefile`) | Native DOS/PE header fallback validator |
| **Androguard** | v3.4.0a1 | Mobile APK structural parsing, manifest permission analysis, certificate digest verification (V1/V2/V3). | **Integrated Python Library** | Internal zip/manifest parser |
| **OpenCode CLI** | Optional | Forensic observation assistant for synthesized natural language analysis. | **External Developer Tool** (BYOK / User-managed) | Fully disabled when not configured |

---

## Configuration & Environment Variables

When running in developer or standalone server mode, paths to local tool binaries can be declared in `.env` or system environment variables:

```bash
# Path to JADX executable (leave blank to search system PATH)
JADX_PATH=C:\Tools\jadx\bin\jadx.bat

# Path to Apktool jar or wrapper
APKTOOL_PATH=C:\Tools\apktool\apktool.bat

# Path to TShark CLI
TSHARK_PATH=C:\Program Files\Wireshark\tshark.exe

# Path to Suricata engine
SURICATA_PATH=C:\Program Files\Suricata\suricata.exe

# Path to ExifTool
EXIFTOOL_PATH=C:\Tools\exiftool.exe

# Path to OpenCode CLI
OPENCODE_PATH=opencode.cmd
```

In the packaged Windows distribution (`TraceX-Setup.exe` and `TraceX-Portable.zip`), all redistributable tools are staged inside the isolated `tools\` directory, and paths are resolved automatically relative to the executable bundle without requiring external environment configuration.
