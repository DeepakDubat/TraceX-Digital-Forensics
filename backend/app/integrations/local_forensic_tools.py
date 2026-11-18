"""
Offline, evidence-backed adapters for TraceX utility and network-analysis tools.

All local tools are executed with argument lists through ``safe_run_command``:
no shell, no visible console window, bounded timeout, captured stdout/stderr,
process-tree cleanup on timeout, and redacted rotating diagnostics.

The network tools are only ever pointed at locally generated, harmless PCAP
fixtures. No live capture, public upload, inline blocking, or active scanning
is performed by this module.
"""

import csv
import hashlib
import io
import json
import os
import re
import shutil
import struct
import time
import zlib
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

import httpx

from backend.app.analyzers.string_analyzer import (
    extract_and_classify_strings,
    extract_strings_from_path,
)
from backend.app.config import settings
from backend.app.core.security import safe_run_command, write_tool_diagnostic
from backend.app.database.repository import repo

INSTALLED = "INSTALLED"
NOT_INSTALLED = "NOT INSTALLED"
BUILT_IN = "BUILT-IN"
AVAILABLE = "AVAILABLE"
CONNECTED = "CONNECTED"
CONFIGURATION_ERROR = "CONFIGURATION ERROR"
DEPENDENCY_MISSING = "DEPENDENCY MISSING"
NOT_SUPPORTED = "NOT SUPPORTED ON THIS PLATFORM"

VALIDATION_DIR = settings.CACHE_DIR / "offline_tool_validation"


# ---------------------------------------------------------------------------
# Result and path helpers
# ---------------------------------------------------------------------------

def _result(
    tool: str,
    success: bool,
    status: str,
    message: str,
    **details: Any,
) -> Dict[str, Any]:
    payload = {
        "tool": tool,
        "success": bool(success),
        "status": status,
        "message": message,
        "details": details,
    }
    return payload


def resolve_local_tool_path(tool_id: str, custom_path: Optional[str] = None) -> Optional[str]:
    """Resolves a tool path from an explicit value, persisted setting, config, then PATH."""
    raw = (
        custom_path
        or repo.get_setting(f"{tool_id}_path")
        or getattr(settings, f"{tool_id.upper()}_PATH", "")
        or ""
    )
    raw = str(raw).strip()
    if not raw:
        return None
    candidate = Path(raw)
    if candidate.is_file():
        return str(candidate.resolve())
    for ext in (".exe", ".bat", ".cmd"):
        extended = Path(raw + ext if candidate.suffix == "" else raw)
        if extended.is_file():
            return str(extended.resolve())
    on_path = shutil.which(raw)
    return on_path if on_path and Path(on_path).is_file() else raw


def _validation_subdir(name: str) -> Path:
    path = VALIDATION_DIR / name
    path.mkdir(parents=True, exist_ok=True)
    return path


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


# ---------------------------------------------------------------------------
# Harmless offline fixtures (generated locally, never downloaded)
# ---------------------------------------------------------------------------

def _ipv4_checksum(header: bytes) -> int:
    if len(header) % 2:
        header += b"\x00"
    total = sum(struct.unpack(f"!{len(header) // 2}H", header))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def _ipv4_packet(payload: bytes, protocol: int, src: str, dst: str, identification: int) -> bytes:
    total_length = 20 + len(payload)
    header = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        total_length,
        identification,
        0x4000,
        64,
        protocol,
        0,
        bytes(int(part) for part in src.split(".")),
        bytes(int(part) for part in dst.split(".")),
    )
    header = header[:10] + struct.pack("!H", _ipv4_checksum(header)) + header[12:]
    return header + payload


def _udp_packet(payload: bytes, src_port: int, dst_port: int) -> bytes:
    return struct.pack("!HHHH", src_port, dst_port, 8 + len(payload), 0) + payload


def _tcp_packet(payload: bytes, src_port: int, dst_port: int, seq: int, ack: int, flags: int) -> bytes:
    header = struct.pack(
        "!HHIIBBHHH",
        src_port,
        dst_port,
        seq,
        ack,
        (5 << 4),
        flags,
        65535,
        0,
        0,
    )
    return header + payload


def _dns_labels(name: str) -> bytes:
    return b"".join(struct.pack("!B", len(label)) + label.encode("ascii") for label in name.split(".")) + b"\x00"


def _dns_query(name: str) -> bytes:
    return (
        struct.pack("!HHHHHH", 0x5A5A, 0x0100, 1, 0, 0, 0)
        + _dns_labels(name)
        + struct.pack("!HH", 1, 1)
    )


def _dns_response(name: str, answer_ip: str) -> bytes:
    question = _dns_labels(name) + struct.pack("!HH", 1, 1)
    answer = (
        struct.pack("!HHHIH", 0xC00C, 1, 1, 60, 4)
        + bytes(int(part) for part in answer_ip.split("."))
    )
    return struct.pack("!HHHHHH", 0x5A5A, 0x8180, 1, 1, 0, 0) + question + answer


def ensure_synthetic_pcap(destination: Optional[Path] = None) -> Path:
    """Creates a tiny deterministic PCAP containing harmless DNS/TCP traffic."""
    out_dir = Path(destination) if destination else _validation_subdir("pcap")
    out_dir.mkdir(parents=True, exist_ok=True)
    pcap_path = out_dir / "tracex_synthetic_traffic.pcap"
    if pcap_path.is_file() and pcap_path.stat().st_size > 0:
        return pcap_path

    domain = "tracex-test.example.com"
    answer_ip = "93.184.216.34"
    client_ip, dns_ip, web_ip = "192.168.56.10", "8.8.8.8", answer_ip

    packets = [
        _ipv4_packet(
            _udp_packet(_dns_query(domain), 53000, 53),
            17,
            client_ip,
            dns_ip,
            1,
        ),
        _ipv4_packet(
            _udp_packet(_dns_response(domain, answer_ip), 53, 53000),
            17,
            dns_ip,
            client_ip,
            2,
        ),
        _ipv4_packet(
            _tcp_packet(b"", 49152, 80, 1000, 0, 0x02),
            6,
            client_ip,
            web_ip,
            3,
        ),
        _ipv4_packet(
            _tcp_packet(
                f"GET /tracex-validation HTTP/1.1\r\nHost: {domain}\r\nUser-Agent: TraceX-Validation\r\n\r\n".encode(),
                49152,
                80,
                1001,
                1,
                0x18,
            ),
            6,
            client_ip,
            web_ip,
            4,
        ),
    ]

    buffer = io.BytesIO()
    buffer.write(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
    for index, frame in enumerate(packets):
        ethernet = b"\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\x08\x00" + frame
        buffer.write(struct.pack("<IIII", 1700000000, index * 1000, len(ethernet), len(ethernet)))
        buffer.write(ethernet)
    pcap_path.write_bytes(buffer.getvalue())
    return pcap_path


def _png_chunk(kind: bytes, data: bytes) -> bytes:
    return (
        struct.pack("!I", len(data))
        + kind
        + data
        + struct.pack("!I", zlib.crc32(kind + data) & 0xFFFFFFFF)
    )


def ensure_synthetic_png(destination: Optional[Path] = None) -> Path:
    """Creates a tiny PNG with an ExifTool-readable Comment tag."""
    out_dir = Path(destination) if destination else _validation_subdir("media")
    out_dir.mkdir(parents=True, exist_ok=True)
    png_path = out_dir / "tracex_validation.png"
    if png_path.is_file() and png_path.stat().st_size > 0:
        return png_path

    ihdr = struct.pack("!IIBBBBB", 1, 1, 8, 2, 0, 0, 0)
    raw_scanline = b"\x00\xff\xff\xff"
    png = (
        b"\x89PNG\r\n\x1a\n"
        + _png_chunk(b"IHDR", ihdr)
        + _png_chunk(b"tEXt", b"Comment\x00tracex-validation")
        + _png_chunk(b"IDAT", zlib.compress(raw_scanline))
        + _png_chunk(b"IEND", b"")
    )
    png_path.write_bytes(png)
    return png_path


# ---------------------------------------------------------------------------
# ExifTool
# ---------------------------------------------------------------------------

def analyze_with_exiftool(file_path: Optional[Path] = None, custom_path: Optional[str] = None) -> Dict[str, Any]:
    binary = resolve_local_tool_path("exiftool", custom_path)
    if not binary or not Path(binary).is_file():
        return _result("ExifTool", False, NOT_INSTALLED, "ExifTool executable was not found.")

    target = Path(file_path) if file_path else ensure_synthetic_png()
    if not target.is_file():
        return _result("ExifTool", False, CONFIGURATION_ERROR, f"Metadata target does not exist: {target}")

    command = [binary, "-j", "-G1", "-n", str(target)]
    code, stdout, stderr = safe_run_command(command, timeout=int(settings.TOOL_TIMEOUT_SECONDS))
    write_tool_diagnostic("ExifTool", "metadata_extraction", command=command, exit_code=code, stdout=stdout, stderr=stderr)
    if code != 0:
        return _result(
            "ExifTool", False, CONFIGURATION_ERROR,
            f"ExifTool failed with exit code {code}: {(stderr or stdout).strip()[:300]}",
            executable_path=binary, exit_code=code, source_file=str(target),
        )
    try:
        parsed = json.loads(stdout)
        metadata = parsed[0] if isinstance(parsed, list) and parsed else (parsed if isinstance(parsed, dict) else {})
    except Exception as exc:
        return _result(
            "ExifTool", False, CONFIGURATION_ERROR,
            f"ExifTool returned unparseable metadata: {exc}",
            executable_path=binary, source_file=str(target),
        )

    expected = "tracex-validation" if target.name.startswith("tracex_validation") else None
    if expected and expected not in json.dumps(metadata, ensure_ascii=False):
        return _result(
            "ExifTool", False, CONFIGURATION_ERROR,
            "ExifTool smoke test could not read the generated validation marker.",
            executable_path=binary, source_file=str(target), metadata=metadata,
        )

    version_code, version_out, _ = safe_run_command([binary, "-ver"], timeout=15)
    version = version_out.strip() if version_code == 0 else None
    return _result(
        "ExifTool", True, CONNECTED,
        f"ExifTool {version or ''} parsed metadata from '{target.name}' offline.",
        executable_path=binary, version=version, source_file=str(target),
        metadata=metadata, sha256=sha256_file(target),
    )


# ---------------------------------------------------------------------------
# TShark
# ---------------------------------------------------------------------------

def analyze_with_tshark(file_path: Optional[Path] = None, custom_path: Optional[str] = None) -> Dict[str, Any]:
    binary = resolve_local_tool_path("tshark", custom_path)
    if not binary or not Path(binary).is_file():
        return _result("TShark", False, NOT_INSTALLED, "TShark executable was not found.")

    pcap = Path(file_path) if file_path else ensure_synthetic_pcap()
    if not pcap.is_file():
        return _result("TShark", False, CONFIGURATION_ERROR, f"PCAP file does not exist: {pcap}")

    fields = [
        "frame.number", "frame.time_epoch", "ip.src", "ip.dst", "_ws.col.Protocol",
        "dns.qry.name", "dns.a", "http.host", "http.request.full_uri", "tls.handshake.type",
    ]
    command = [binary, "-r", str(pcap), "-T", "fields", "-E", "separator=\t", "-E", "quote=n"]
    for field in fields:
        command.extend(["-e", field])

    code, stdout, stderr = safe_run_command(command, timeout=int(settings.TOOL_TIMEOUT_SECONDS))
    write_tool_diagnostic("TShark", "offline_pcap_dissection", command=command, exit_code=code, stdout=stdout, stderr=stderr)
    if code != 0:
        return _result(
            "TShark", False, CONFIGURATION_ERROR,
            f"TShark could not dissect the PCAP (exit {code}): {(stderr or stdout).strip()[:300]}",
            executable_path=binary, source_file=str(pcap), exit_code=code,
        )

    frames: List[Dict[str, Any]] = []
    for line in stdout.splitlines():
        if not line.strip():
            continue
        values = line.split("\t")
        record = {field: values[index] if index < len(values) else "" for index, field in enumerate(fields)}
        if record.get("frame.number", "").isdigit():
            frames.append(record)

    combined = stdout.lower()
    expected_dns = "tracex-test.example.com" in combined
    if len(frames) < 3 or not expected_dns:
        return _result(
            "TShark", False, CONFIGURATION_ERROR,
            "TShark ran but the synthetic DNS/HTTP evidence was not observed in its dissection output.",
            executable_path=binary, source_file=str(pcap), frames=frames[:20],
        )

    version_code, version_out, _ = safe_run_command([binary, "-v"], timeout=15)
    version_line = next((line for line in version_out.splitlines() if line.strip()), "")
    version_match = re.search(r"(\d+\.\d+\.\d+)", version_line)
    return _result(
        "TShark", True, CONNECTED,
        f"TShark dissected {len(frames)} synthetic frames offline and resolved the validation DNS name.",
        executable_path=binary, version=version_match.group(1) if version_match else None,
        source_file=str(pcap), sha256=sha256_file(pcap), frames=frames,
        protocols=sorted({f.get("_ws.col.Protocol", "") for f in frames if f.get("_ws.col.Protocol")}),
    )


# ---------------------------------------------------------------------------
# Zeek (offline Docker or native binary)
# ---------------------------------------------------------------------------

def _parse_zeek_log(path: Path) -> List[Dict[str, str]]:
    if not path.is_file():
        return []
    fields: List[str] = []
    rows: List[Dict[str, str]] = []
    with path.open("r", encoding="utf-8", errors="replace") as handle:
        for line in handle:
            line = line.rstrip("\r\n")
            if line.startswith("#fields"):
                fields = line.split("\t")[1:]
                continue
            if line.startswith("#") or not fields or not line:
                continue
            values = line.split("\t")
            rows.append({field: values[index] if index < len(values) else "" for index, field in enumerate(fields)})
    return rows


def analyze_with_zeek(file_path: Optional[Path] = None, custom_path: Optional[str] = None) -> Dict[str, Any]:
    pcap = Path(file_path) if file_path else ensure_synthetic_pcap()
    if not pcap.is_file():
        return _result("Zeek", False, CONFIGURATION_ERROR, f"PCAP file does not exist: {pcap}")
    output_dir = _validation_subdir("zeek_output")

    native = resolve_local_tool_path("zeek", custom_path)
    if native and Path(native).is_file():
        command = [native, "-C", "-r", str(pcap)]
        code, stdout, stderr = safe_run_command(command, cwd=output_dir, timeout=int(settings.TOOL_TIMEOUT_SECONDS))
        write_tool_diagnostic("Zeek", "offline_native_pcap_analysis", command=command, exit_code=code, stdout=stdout, stderr=stderr)
        if code != 0:
            return _result(
                "Zeek", False, CONFIGURATION_ERROR,
                f"Native Zeek failed with exit code {code}: {(stderr or stdout).strip()[:300]}",
                executable_path=native, source_file=str(pcap), exit_code=code,
            )
        executable = native
    else:
        docker = shutil.which("docker")
        if not docker:
            return _result("Zeek", False, DEPENDENCY_MISSING, "Docker is required for Zeek on Windows and was not found.")
        image = settings.ZEEK_DOCKER_IMAGE
        inspect_cmd = [docker, "image", "inspect", image]
        inspect_code, _, inspect_err = safe_run_command(inspect_cmd, timeout=30)
        write_tool_diagnostic("Zeek", "docker_image_check", command=inspect_cmd, exit_code=inspect_code, stderr=inspect_err)
        if inspect_code != 0:
            return _result("Zeek", False, DEPENDENCY_MISSING, f"Official Zeek Docker image '{image}' is not available locally.", docker_image=image)

        command = [
            docker, "run", "--rm", "--network", settings.ZEEK_DOCKER_NETWORK,
            "-v", f"{pcap.parent}:/pcap:ro", "-v", f"{output_dir}:/output",
            "-w", "/output", image, "zeek", "-C", "-r", f"/pcap/{pcap.name}",
        ]
        code, stdout, stderr = safe_run_command(command, timeout=int(settings.TOOL_TIMEOUT_SECONDS))
        write_tool_diagnostic("Zeek", "offline_docker_pcap_analysis", command=command, exit_code=code, stdout=stdout, stderr=stderr)
        if code != 0:
            return _result(
                "Zeek", False, CONFIGURATION_ERROR,
                f"Zeek Docker analysis failed with exit code {code}: {(stderr or stdout).strip()[:300]}",
                docker_image=image, source_file=str(pcap), exit_code=code,
            )
        executable = docker

    dns_rows = _parse_zeek_log(output_dir / "dns.log")
    conn_rows = _parse_zeek_log(output_dir / "conn.log")
    dns_text = json.dumps(dns_rows, ensure_ascii=False)
    conn_text = json.dumps(conn_rows, ensure_ascii=False)
    expected = "tracex-test.example.com" in dns_text or "93.184.216.34" in (dns_text + conn_text)
    if not expected:
        return _result(
            "Zeek", False, CONFIGURATION_ERROR,
            "Zeek produced logs but the synthetic DNS evidence was not observed.",
            executable_path=executable, source_file=str(pcap),
            log_files=sorted(p.name for p in output_dir.glob("*.log")),
        )
    return _result(
        "Zeek", True, CONNECTED,
        f"Zeek processed the synthetic PCAP offline and produced {len(dns_rows)} DNS log entries.",
        executable_path=executable, source_file=str(pcap), sha256=sha256_file(pcap),
        docker_image=None if native else settings.ZEEK_DOCKER_IMAGE,
        dns_log=dns_rows[:50], conn_log=conn_rows[:50],
        log_files=sorted(p.name for p in output_dir.glob("*.log")),
    )


# ---------------------------------------------------------------------------
# Suricata
# ---------------------------------------------------------------------------

def _parse_suricata_alerts(output_dir: Path) -> List[Dict[str, Any]]:
    alerts: List[Dict[str, Any]] = []
    eve_path = output_dir / "eve.json"
    if eve_path.is_file():
        with eve_path.open("r", encoding="utf-8", errors="replace") as handle:
            for line in handle:
                try:
                    event = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if event.get("event_type") != "alert":
                    continue
                alert = event.get("alert") or {}
                alerts.append({
                    "timestamp": event.get("timestamp"),
                    "engine": event.get("engine_name") or "Suricata",
                    "rule_id": str(alert.get("signature_id") or ""),
                    "rule_msg": alert.get("signature") or alert.get("msg") or "",
                    "severity": alert.get("severity"),
                    "src_ip": event.get("src_ip"),
                    "dest_ip": event.get("dest_ip"),
                    "src_port": event.get("src_port"),
                    "dest_port": event.get("dest_port"),
                    "proto": event.get("proto"),
                })
    return alerts


def analyze_with_suricata(file_path: Optional[Path] = None, custom_path: Optional[str] = None) -> Dict[str, Any]:
    binary = resolve_local_tool_path("suricata", custom_path)
    if not binary or not Path(binary).is_file():
        return _result("Suricata", False, NOT_INSTALLED, "Suricata executable was not found.")

    pcap = Path(file_path) if file_path else ensure_synthetic_pcap()
    if not pcap.is_file():
        return _result("Suricata", False, CONFIGURATION_ERROR, f"PCAP file does not exist: {pcap}")

    config = Path(settings.SURICATA_CONFIG_PATH)
    if not config.is_file():
        return _result("Suricata", False, CONFIGURATION_ERROR, f"Suricata configuration was not found: {config}")

    binary_dir = Path(binary).parent
    missing_dlls = [name for name in ("wpcap.dll", "Packet.dll") if not (binary_dir / name).is_file()]
    if missing_dlls:
        return _result(
            "Suricata", False, DEPENDENCY_MISSING,
            "Suricata runtime packet libraries are missing: " + ", ".join(missing_dlls),
            executable_path=binary, missing_dependencies=missing_dlls,
        )

    rules = Path(settings.SURICATA_RULES_PATH)
    if not rules.is_file():
        rules = settings.BUNDLE_RULES_DIR / "tracex_synthetic_validation.rules"
    if not rules.is_file():
        return _result("Suricata", False, CONFIGURATION_ERROR, "No offline Suricata validation rule file is available.")

    output_dir = _validation_subdir("suricata_output")
    threshold = output_dir / "threshold.config"
    threshold.touch(exist_ok=True)

    command = [
        binary,
        "-c", str(config),
        "--set", "rule-files=[]",
        "-S", str(rules),
        "--set", f"threshold-file={threshold}",
    ]
    if settings.SURICATA_IGNORE_CHECKSUMS:
        command.extend(["--set", "pcap-file.checksum-checks=no"])
    command.extend(["-r", str(pcap), "-l", str(output_dir)])

    code, stdout, stderr = safe_run_command(command, timeout=int(settings.TOOL_TIMEOUT_SECONDS))
    write_tool_diagnostic("Suricata", "offline_pcap_rule_evaluation", command=command, exit_code=code, stdout=stdout, stderr=stderr)
    alerts = _parse_suricata_alerts(output_dir)
    fast_log = output_dir / "fast.log"
    fast_text = fast_log.read_text(encoding="utf-8", errors="replace") if fast_log.is_file() else ""
    expected_alert = any("900011" in item.get("rule_id", "") for item in alerts) or "[**] [1:900011" in fast_text

    if code != 0 or not expected_alert:
        return _result(
            "Suricata", False, CONFIGURATION_ERROR,
            f"Suricata offline rule evaluation did not produce the expected validation alert (exit {code}).",
            executable_path=binary, source_file=str(pcap), exit_code=code,
            alerts=alerts, fast_log=fast_text[:2000], stderr=stderr.strip()[:500],
        )

    version_code, version_out, _ = safe_run_command([binary, "-V"], timeout=15)
    version_match = re.search(r"(\d+\.\d+\.\d+)", version_out)
    return _result(
        "Suricata", True, CONNECTED,
        f"Suricata evaluated {pcap.name} offline and emitted validation signature 900011.",
        executable_path=binary, version=version_match.group(1) if version_match else None,
        source_file=str(pcap), sha256=sha256_file(pcap), rules_file=str(rules),
        alerts=alerts, log_files=sorted(p.name for p in output_dir.glob("*.log")),
    )


# ---------------------------------------------------------------------------
# Built-in Strings Utility
# ---------------------------------------------------------------------------

def analyze_with_strings(file_path: Optional[Path] = None, custom_path: Optional[str] = None) -> Dict[str, Any]:
    target = Path(file_path) if file_path else ensure_synthetic_pcap()
    if not target.is_file():
        return _result("Strings Utility", False, CONFIGURATION_ERROR, f"Strings target does not exist: {target}")

    raw = extract_strings_from_path(
        target,
        min_length=int(settings.STRINGS_MIN_LENGTH),
        max_results=int(settings.STRINGS_MAX_RESULTS),
        max_bytes=int(settings.STRINGS_MAX_SCAN_BYTES),
        regex_pattern=None,
    )
    if raw.get("error"):
        return _result("Strings Utility", False, CONFIGURATION_ERROR, raw["error"], source_file=str(target))

    pairs = [(str(target), item["value"]) for item in raw.get("strings", [])]
    classified = extract_and_classify_strings(pairs)
    indicator_count = sum(len(classified.get(key, [])) for key in (
        "urls", "ips", "domains", "shell_commands", "decoded_items", "doh_indicators", "dynamic_dns_items"
    ))
    if raw.get("string_count", 0) == 0:
        return _result(
            "Strings Utility", False, CONFIGURATION_ERROR,
            "Built-in string extraction completed but produced no printable strings.",
            source_file=str(target),
        )
    return _result(
        "Strings Utility", True, CONNECTED,
        f"Built-in multi-encoding string engine extracted {raw['string_count']} strings and {indicator_count} IOCs offline.",
        source_file=str(target), sha256=sha256_file(target),
        extraction=raw, classification=classified, indicator_count=indicator_count,
    )


# ---------------------------------------------------------------------------
# MobSF local static-analysis service
# ---------------------------------------------------------------------------

def normalize_mobsf_url(raw_url: Optional[str]) -> str:
    """Accepts only loopback HTTP(S) endpoints; prevents public/sensitive exposure."""
    url = (raw_url or settings.MOBSF_URL or "http://127.0.0.1:8001").strip().rstrip("/")
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        raise ValueError("MobSF URL must be an http:// or https:// endpoint.")
    hostname = parsed.hostname.lower()
    if hostname not in ("127.0.0.1", "localhost", "::1"):
        raise ValueError("MobSF is restricted to loopback-only URLs in TraceX.")
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    if port == int(settings.PORT):
        raise ValueError(f"MobSF cannot use TraceX backend port {settings.PORT}; use 8001 instead.")
    return f"{parsed.scheme}://{hostname}:{port}"


def analyze_with_mobsf(
    apk_path: Path,
    url: Optional[str] = None,
    api_key: Optional[str] = None,
) -> Dict[str, Any]:
    """Runs the real MobSF upload -> scan -> report_json static-analysis workflow."""
    target = Path(apk_path)
    if not target.is_file():
        return _result("MobSF", False, CONFIGURATION_ERROR, f"APK file does not exist: {target}")

    try:
        base_url = normalize_mobsf_url(url)
    except ValueError as exc:
        return _result("MobSF", False, CONFIGURATION_ERROR, str(exc))

    key = (api_key or settings.MOBSF_API_KEY or "").strip()
    if not key:
        return _result("MobSF", False, CONFIGURATION_ERROR, "MobSF REST API key is not configured.")

    headers = {"Authorization": key}
    timeout = httpx.Timeout(float(settings.MOBSF_SCAN_TIMEOUT_SECONDS), connect=10.0)
    workflow: Dict[str, Any] = {"url": base_url, "upload_status": None, "scan_status": None, "report_status": None}

    try:
        with httpx.Client(timeout=timeout, trust_env=False) as client:
            with target.open("rb") as handle:
                upload = client.post(
                    f"{base_url}/api/v1/upload",
                    headers=headers,
                    files={"file": (target.name, handle, "application/vnd.android.package-archive")},
                )
            workflow["upload_status"] = upload.status_code
            if upload.status_code != 200:
                return _result(
                    "MobSF", False, CONFIGURATION_ERROR,
                    f"MobSF upload failed with HTTP {upload.status_code}: {upload.text[:200]}",
                    workflow=workflow, source_file=str(target),
                )
            scan_hash = str((upload.json() or {}).get("hash") or "").strip()
            if not scan_hash:
                return _result(
                    "MobSF", False, CONFIGURATION_ERROR,
                    "MobSF upload response did not contain a scan hash.",
                    workflow=workflow, source_file=str(target),
                )

            scan = client.post(
                f"{base_url}/api/v1/scan",
                headers=headers,
                data={"hash": scan_hash, "re_scan": "0"},
            )
            workflow["scan_status"] = scan.status_code
            if scan.status_code != 200:
                return _result(
                    "MobSF", False, CONFIGURATION_ERROR,
                    f"MobSF static scan failed with HTTP {scan.status_code}: {scan.text[:200]}",
                    workflow=workflow, scan_hash=scan_hash, source_file=str(target),
                )

            report = None
            report_resp = None
            workflow["report_attempts"] = 0
            for attempt in range(12):
                report_resp = client.post(
                    f"{base_url}/api/v1/report_json",
                    headers=headers,
                    data={"hash": scan_hash},
                )
                workflow["report_attempts"] = attempt + 1
                if report_resp.status_code == 200:
                    candidate = report_resp.json()
                    if isinstance(candidate, dict) and candidate:
                        report = candidate
                        break
                if report_resp.status_code not in (404, 409, 425):
                    break
                time.sleep(2)
            workflow["report_status"] = report_resp.status_code if report_resp else None
            if report is None:
                body = report_resp.text[:200] if report_resp else ""
                return _result(
                    "MobSF", False, CONFIGURATION_ERROR,
                    f"MobSF JSON report request failed with HTTP {workflow['report_status']}: {body}",
                    workflow=workflow, scan_hash=scan_hash, source_file=str(target),
                )
    except httpx.ConnectError:
        return _result("MobSF", False, DEPENDENCY_MISSING, f"Cannot connect to loopback MobSF service at {base_url}.", workflow=workflow)
    except httpx.TimeoutException:
        return _result("MobSF", False, CONFIGURATION_ERROR, "MobSF static analysis timed out.", workflow=workflow)
    except Exception as exc:
        return _result("MobSF", False, CONFIGURATION_ERROR, f"MobSF static analysis error: {exc}", workflow=workflow)

    write_tool_diagnostic(
        "MobSF", "static_apk_workflow",
        command=[base_url + "/api/v1/upload", base_url + "/api/v1/scan", base_url + "/api/v1/report_json"],
        details={"workflow": workflow, "scan_hash": scan_hash, "source_file": str(target)},
    )
    return _result(
        "MobSF", True, CONNECTED,
        "MobSF completed real upload, static scan, and JSON report retrieval.",
        workflow=workflow, scan_hash=scan_hash, source_file=str(target),
        sha256=sha256_file(target), report=report,
    )
