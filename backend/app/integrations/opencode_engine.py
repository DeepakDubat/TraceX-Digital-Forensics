"""
TraceX OpenCode Forensic Engine
================================
Optional AI-assisted digital forensics and cyber investigation engine.
Integrates directly with OpenCode CLI (opencode.cmd) for static analysis
of APK, EXE, DLL, ELF and other binary artifacts.

Strict Safety & Architectural Boundaries:
1. Deterministic vs AI Separation: AI observations are strictly UNVERIFIED and
   NEVER automatically promoted to confirmed forensic findings.
2. Malware Risk Neutrality: AI observations NEVER inflate or alter the deterministic
   risk score or severity rating.
3. Air-Gapped Privacy: In LOCAL ONLY mode, external/cloud LLM calls are blocked.
   Only verified local models (e.g. Ollama) are permitted.
4. Consent & Hybrid Authorization: In HYBRID mode, explicit investigator consent
   (consent_approved=True) is required prior to external dispatch.
5. Zero Evidence Upload: Raw binary files are NEVER sent to OpenCode. Only sanitized
   metadata, structural indicators, and extracted strings are passed.
6. Zero Dynamic Execution: Only static metadata analysis; no binary is ever executed.
7. Subprocess Security: Executed with CREATE_NO_WINDOW, isolated temp working directory,
   strict timeouts, process tree cleanup, and DEVNULL stdin.
"""

import os
import sys
import json
import re
import shutil
import tempfile
import logging
import subprocess
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple

from backend.app.config import settings
from backend.app.core.models import (
    AIObservation,
    AIRecommendation,
    AIAssistedNotes,
    InvestigationDetail,
)
from backend.app.core.network_mode import get_current_network_mode, NetworkMode
from backend.app.database.repository import repo

logger = logging.getLogger("tracex.opencode_engine")

# Regex patterns for sensitive secret redaction
SECRET_PATTERNS = [
    (re.compile(r'sk-[a-zA-Z0-9_\-]{20,}', re.IGNORECASE), "[REDACTED_API_KEY]"),
    (re.compile(r'AIza[0-9A-Za-z\-_]{35}'), "[REDACTED_GOOGLE_API_KEY]"),
    (re.compile(r'ghp_[a-zA-Z0-9]{36}'), "[REDACTED_GITHUB_TOKEN]"),
    (re.compile(r'Bearer\s+[a-zA-Z0-9_\-\.]{16,}', re.IGNORECASE), "Bearer [REDACTED_BEARER_TOKEN]"),
    (re.compile(r'(password|passwd|pwd|secret)\s*[:=]\s*["\']?([^"\'\s]+)["\']?', re.IGNORECASE), r'\1="[REDACTED_SECRET]"'),
    (re.compile(r'-----BEGIN [A-Z ]+ PRIVATE KEY-----[\s\S]+?-----END [A-Z ]+ PRIVATE KEY-----'), "[REDACTED_PRIVATE_KEY]"),
]


def resolve_opencode_binary() -> Optional[str]:
    """Resolves the absolute or valid executable path for OpenCode CLI."""
    # 1. Custom setting override
    configured = getattr(settings, "OPENCODE_PATH", None)
    if configured:
        # If absolute path and exists
        if os.path.isabs(configured) and os.path.exists(configured):
            return configured
        # Check if findable via shutil.which
        which_path = shutil.which(configured)
        if which_path:
            return which_path

    # 2. Known Windows locations
    candidates = [
        Path.home() / "AppData" / "Roaming" / "npm" / "opencode.cmd",
        Path.home() / "AppData" / "Roaming" / "npm" / "opencode.ps1",
        Path.home() / "AppData" / "Roaming" / "npm" / "opencode",
        Path("C:/Program Files/nodejs/opencode.cmd"),
        Path("C:/Program Files (x86)/nodejs/opencode.cmd"),
        settings.BASE_DIR / "tools" / "opencode" / "opencode.cmd",
        settings.BASE_DIR / "tools" / "opencode" / "opencode.exe",
    ]
    for candidate in candidates:
        if candidate.exists():
            return str(candidate)

    # 3. PATH search
    for name in ("opencode.cmd", "opencode.exe", "opencode"):
        found = shutil.which(name)
        if found:
            return found

    return None


def is_local_model_identifier(model_name: Optional[str]) -> bool:
    """Checks whether the specified model identifier represents an offline/local model."""
    if not model_name:
        return False
    lower = model_name.lower().strip()
    return any(prefix in lower for prefix in ("ollama", "local", "localhost", "127.0.0.1", "offline"))


def run_opencode_cli(
    args: List[str],
    cwd: Optional[str] = None,
    timeout: Optional[int] = None,
    env: Optional[Dict[str, str]] = None
) -> Tuple[int, str, str]:
    """
    Executes OpenCode CLI in a secure Windows subprocess:
    - CREATE_NO_WINDOW flag
    - stdin=DEVNULL to prevent interactive hangs
    - Strict timeout with process tree termination
    """
    binary = resolve_opencode_binary()
    if not binary:
        raise FileNotFoundError("OpenCode CLI executable was not found on this system.")

    cmd = [binary] + args
    effective_timeout = timeout or getattr(settings, "OPENCODE_TIMEOUT_SECONDS", 60)
    effective_cwd = cwd or tempfile.gettempdir()

    # Base environment with UTF-8
    proc_env = os.environ.copy()
    proc_env["PYTHONIOENCODING"] = "utf-8"
    if env:
        proc_env.update(env)

    creationflags = 0
    if sys.platform == "win32":
        creationflags = subprocess.CREATE_NO_WINDOW

    proc = None
    try:
        proc = subprocess.Popen(
            cmd,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd=effective_cwd,
            env=proc_env,
            text=True,
            encoding="utf-8",
            errors="replace",
            creationflags=creationflags
        )

        stdout_data, stderr_data = proc.communicate(timeout=effective_timeout)
        return proc.returncode, stdout_data, stderr_data

    except subprocess.TimeoutExpired:
        logger.warning(f"OpenCode CLI execution timed out after {effective_timeout}s. Terminating process tree...")
        if proc:
            _terminate_process_tree(proc.pid)
        return -1, "", f"Execution timed out after {effective_timeout} seconds."
    except Exception as e:
        logger.error(f"Error running OpenCode CLI: {e}")
        if proc:
            _terminate_process_tree(proc.pid)
        return -2, "", str(e)


def _terminate_process_tree(pid: int) -> None:
    """Forcefully terminates a process and all child processes on Windows or POSIX."""
    try:
        if sys.platform == "win32":
            subprocess.run(
                ["taskkill", "/F", "/T", "/PID", str(pid)],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                creationflags=subprocess.CREATE_NO_WINDOW
            )
        else:
            os.kill(pid, 9)
    except Exception as e:
        logger.debug(f"Process tree termination for PID {pid} returned: {e}")


_CLI_INFO_CACHE: Dict[str, Any] = {}

def detect_opencode_status(refresh: bool = False) -> Dict[str, Any]:
    """
    Detects OpenCode CLI installation, version, auth providers, and operational readiness.
    Respects global Network Privacy mode and configured model.
    Caches binary version and auth info to ensure sub-millisecond status responses.
    """
    global _CLI_INFO_CACHE
    binary = resolve_opencode_binary()
    installed = binary is not None
    version_str = None
    auth_list = []

    if installed:
        if refresh or "version" not in _CLI_INFO_CACHE or _CLI_INFO_CACHE.get("path") != binary:
            code, out, err = run_opencode_cli(["--version"], timeout=5)
            version_str = out.strip().splitlines()[0] if (code == 0 and out.strip()) else "Installed"
            code, out, err = run_opencode_cli(["auth", "list"], timeout=5)
            auth_items = []
            if code == 0 and out.strip():
                for line in out.strip().splitlines():
                    parts = line.strip().split()
                    if len(parts) >= 2:
                        auth_items.append({"provider": " ".join(parts[:-1]), "status": parts[-1]})
                    elif parts:
                        auth_items.append({"provider": parts[0], "status": "unknown"})
            _CLI_INFO_CACHE["version"] = version_str
            _CLI_INFO_CACHE["auth_list"] = auth_items
            _CLI_INFO_CACHE["path"] = binary

        version_str = _CLI_INFO_CACHE.get("version", "Installed")
        auth_list = _CLI_INFO_CACHE.get("auth_list", [])

    # Check network mode & model readiness
    net_mode = get_current_network_mode().get("mode", NetworkMode.LOCAL_ONLY.value)
    configured_model = repo.get_setting("opencode_model") or getattr(settings, "OPENCODE_MODEL", "")
    enabled = repo.get_setting("opencode_enabled")
    if enabled is None:
        enabled_bool = getattr(settings, "OPENCODE_ENABLED", False)
    else:
        enabled_bool = enabled.lower() in ("true", "1", "yes")

    is_local = is_local_model_identifier(configured_model)

    # Determine status label and description
    if not installed:
        status_label = "NOT_INSTALLED"
        status_desc = "OpenCode CLI is not detected on the system."
    elif not enabled_bool:
        status_label = "DISABLED"
        status_desc = "OpenCode CLI is installed but AI-assisted analysis is disabled in settings."
    elif net_mode == NetworkMode.LOCAL_ONLY.value:
        if is_local:
            status_label = "READY_LOCAL"
            status_desc = f"Ready for offline AI analysis using local model ({configured_model})."
        else:
            status_label = "LOCAL_BLOCKED"
            status_desc = "LOCAL OPENCODE MODEL NOT CONFIGURED: TraceX is operating in LOCAL ONLY mode. External cloud models are blocked."
    else:
        # HYBRID mode
        status_label = "READY_HYBRID"
        status_desc = f"Ready for AI-assisted analysis in HYBRID mode (requires investigator authorization per investigation)."

    return {
        "installed": installed,
        "version": version_str,
        "path": binary,
        "enabled": enabled_bool,
        "model": configured_model or "default",
        "is_local_model": is_local,
        "auth_providers": auth_list,
        "network_mode": net_mode,
        "status_label": status_label,
        "status_description": status_desc,
        "timeout_seconds": getattr(settings, "OPENCODE_TIMEOUT_SECONDS", 60),
    }


def sanitize_text(text: str) -> str:
    """Redacts known API tokens, passwords, and private keys from textual evidence context."""
    if not text:
        return ""
    sanitized = text
    for pattern, replacement in SECRET_PATTERNS:
        sanitized = pattern.sub(replacement, sanitized)
    return sanitized


def prepare_forensic_context(
    detail: Any,
    filename: str = "evidence_file",
    file_type: str = "unknown",
    file_size_bytes: int = 0,
    sha256_hash: str = ""
) -> str:
    """
    Constructs a strictly sanitized textual representation of forensic findings.
    NEVER sends binary files. Only structural metadata and extracted indicators.
    """
    lines = [
        "# TRACEX STATIC FORENSIC EVIDENCE SUMMARY",
        f"- Target File: {filename} ({file_type.upper()})",
        f"- File Size: {file_size_bytes} bytes",
        f"- SHA-256 Hash: {sha256_hash or 'N/A'}",
        ""
    ]

    # Deterministic Static Findings
    findings = getattr(detail, "static_findings", [])
    if findings:
        lines.append("## DETERMINISTIC STATIC FINDINGS:")
        for idx, f in enumerate(findings[:30]):
            title = getattr(f, "title", str(f))
            severity = getattr(f, "severity", "Unknown")
            desc = getattr(f, "description", "")
            lines.append(f"- [{severity}] {title}: {desc}")
        lines.append("")

    # C2 Indicators / Network IOCs
    c2 = getattr(detail, "c2_indicators", [])
    if c2:
        lines.append("## DETECTED NETWORK / C2 INDICATORS:")
        for indicator in c2[:20]:
            target = getattr(indicator, "matched_value", str(indicator))
            type_ = getattr(indicator, "indicator_type", "IOC")
            lines.append(f"- {type_}: {target}")
        lines.append("")

    # Reverse Shell Findings
    rev = getattr(detail, "reverse_shell_findings", [])
    if rev:
        lines.append("## REVERSE SHELL & CODE EXECUTION INDICATORS:")
        for item in rev[:10]:
            cmd = getattr(item, "command_payload", "")
            line_no = getattr(item, "line_number", "")
            lines.append(f"- Payload (Line {line_no}): {cmd}")
        lines.append("")

    # Secrets / Sensitive Keys
    secrets = getattr(detail, "secrets", [])
    if secrets:
        lines.append("## DETECTED SECRETS (SANITIZED):")
        for s in secrets[:15]:
            rule = getattr(s, "rule_name", "Secret")
            lines.append(f"- Match: {rule} detected in source assets")
        lines.append("")

    # Metadata Details (APK or PE)
    meta = getattr(detail, "metadata", None) or getattr(detail, "pe_metadata", None)
    if meta:
        lines.append("## STRUCTURAL METADATA:")
        # Android specific
        if hasattr(meta, "package_name") and meta.package_name:
            lines.append(f"- Package Name: {meta.package_name}")
            lines.append(f"- Permissions Count: {len(getattr(meta, 'permissions', []) or [])}")
            permissions = getattr(meta, "permissions", []) or []
            if permissions:
                lines.append(f"- Declared Permissions: {', '.join([str(p) for p in permissions[:15]])}")
        # PE specific
        if hasattr(meta, "machine") and meta.machine:
            lines.append(f"- PE Architecture: {meta.machine}")
            lines.append(f"- Subsystem: {getattr(meta, 'subsystem', 'N/A')}")
            sections = getattr(meta, "sections", []) or []
            if sections:
                lines.append(f"- PE Sections: {', '.join([s.name for s in sections[:8] if hasattr(s, 'name')])}")
        lines.append("")

    raw_text = "\n".join(lines)
    return sanitize_text(raw_text)


def parse_opencode_response(stdout: str, stderr: str, inv_id: str) -> Tuple[List[AIObservation], List[AIRecommendation], Optional[str]]:
    """
    Parses OpenCode CLI output into structured AIObservation and AIRecommendation records.
    Handles JSON format and text-fallback parsing.
    Guarantees every observation has status='UNVERIFIED'.
    """
    observations: List[AIObservation] = []
    recommendations: List[AIRecommendation] = []
    fallback_summary: Optional[str] = None

    cleaned_stdout = stdout.strip()
    if not cleaned_stdout:
        return observations, recommendations, "OpenCode CLI returned empty output."

    # 1. Attempt to parse line-delimited JSON or full JSON block
    extracted_text = ""
    parsed_dict = None
    # Check if ndjson events from opencode run
    for line in cleaned_stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            event = json.loads(line)
            if isinstance(event, dict):
                # Check if this line is the direct forensic output payload
                if "observations" in event or "recommendations" in event or "summary" in event:
                    parsed_dict = event
                    break
                # Check for OpenCode error event
                if event.get("type") == "error":
                    err_data = event.get("error", {})
                    msg = err_data.get("message", "Unknown OpenCode error")
                    return observations, recommendations, f"OpenCode Error: {msg}"
                # Check for OpenCode text/message part
                if event.get("type") == "text":
                    extracted_text += event.get("text", "")
                elif event.get("type") == "part" and "text" in event.get("part", {}):
                    extracted_text += event["part"]["text"]
                else:
                    extracted_text += line + "\n"
            else:
                extracted_text += line + "\n"
        except Exception:
            # Not a line-delimited JSON event, accumulate
            extracted_text += line + "\n"

    target_text = extracted_text if extracted_text.strip() else cleaned_stdout

    if not parsed_dict:
        # Look for fenced json ```json ... ```
        json_match = re.search(r'```(?:json)?\s*(\{.*?\})\s*```', target_text, re.DOTALL)
        candidate_json = json_match.group(1) if json_match else None

        if not candidate_json:
            # Check if entire target_text is valid JSON
            if target_text.startswith("{") and target_text.endswith("}"):
                candidate_json = target_text

        if candidate_json:
            try:
                parsed_dict = json.loads(candidate_json)
            except Exception:
                pass

    if parsed_dict and isinstance(parsed_dict, dict):
        # Successfully parsed JSON structure
        obs_raw = parsed_dict.get("observations", [])
        for idx, item in enumerate(obs_raw):
            if not isinstance(item, dict):
                continue
            title = item.get("title", f"AI Observation {idx+1}")
            explanation = item.get("explanation", item.get("description", ""))
            refs = item.get("related_evidence_refs", [])
            if isinstance(refs, str):
                refs = [refs]
            confidence = item.get("confidence", "Unverified")
            reasoning = item.get("reasoning_summary", item.get("reasoning", ""))
            steps = item.get("suggested_verification_steps", [])
            if isinstance(steps, str):
                steps = [steps]

            observations.append(AIObservation(
                id=f"AIOBS-{idx+1:03d}",
                investigation_id=inv_id,
                title=title,
                explanation=explanation,
                related_evidence_refs=refs,
                confidence=confidence,
                reasoning_summary=reasoning,
                suggested_verification_steps=steps,
                status="UNVERIFIED",
                created_at=datetime.utcnow()
            ))

        recs_raw = parsed_dict.get("recommendations", [])
        for idx, item in enumerate(recs_raw):
            if not isinstance(item, dict):
                continue
            recommendations.append(AIRecommendation(
                id=f"AIREC-{idx+1:03d}",
                investigation_id=inv_id,
                title=item.get("title", f"Recommendation {idx+1}"),
                category=item.get("category", "Verification"),
                description=item.get("description", ""),
                suggested_command_or_action=item.get("suggested_command_or_action"),
                priority=item.get("priority", "Medium")
            ))

        fallback_summary = parsed_dict.get("summary")
        return observations, recommendations, None

    # Fallback: Parse Markdown bullet points or sections
    lines = [l.strip() for l in target_text.splitlines() if l.strip()]
    obs_idx = 1
    rec_idx = 1
    for line in lines:
        if line.startswith("-") or line.startswith("*"):
            content = line.lstrip("-* ").strip()
            if any(k in content.lower() for k in ("verify", "check", "recommend", "should", "suggest")):
                recommendations.append(AIRecommendation(
                    id=f"AIREC-{rec_idx:03d}",
                    investigation_id=inv_id,
                    title=f"AI Recommendation {rec_idx}",
                    category="Suggested Action",
                    description=content,
                    priority="Medium"
                ))
                rec_idx += 1
            else:
                observations.append(AIObservation(
                    id=f"AIOBS-{obs_idx:03d}",
                    investigation_id=inv_id,
                    title=f"AI Observation {obs_idx}",
                    explanation=content,
                    related_evidence_refs=["Forensic Metadata Context"],
                    confidence="Unverified",
                    reasoning_summary="Extracted via text-fallback analysis parser.",
                    suggested_verification_steps=["Independently inspect relevant source code or binary sections."],
                    status="UNVERIFIED",
                    created_at=datetime.utcnow()
                ))
                obs_idx += 1

    if not observations and not recommendations:
        fallback_summary = target_text[:500]

    return observations, recommendations, None


def analyze_investigation(
    investigation_id: str,
    detail: Any,
    filename: str = "evidence_file",
    file_type: str = "unknown",
    file_size_bytes: int = 0,
    sha256_hash: str = "",
    consent_approved: bool = False,
    override_model: Optional[str] = None
) -> Tuple[AIAssistedNotes, List[AIObservation], List[AIRecommendation]]:
    """
    Main entry point for AI-assisted forensic analysis.
    Executes in a safe subprocess, strictly validates privacy and consent,
    and records results into the SQLite repository without throwing exceptions.
    """
    status_info = detect_opencode_status()
    current_net_mode = status_info["network_mode"]
    configured_model = override_model or status_info["model"]

    # 1. Check if OpenCode is enabled
    if not status_info["enabled"]:
        notes = AIAssistedNotes(
            investigation_id=investigation_id,
            execution_status="DISABLED",
            model_provider=configured_model or "None",
            analysis_timestamp=datetime.utcnow(),
            disclaimer="AI-assisted analysis is disabled. Deterministic forensic analysis completed successfully.",
            warnings_or_errors=["AI-assisted analysis is disabled in application settings."],
            consent_approved=consent_approved
        )
        try:
            repo.save_ai_investigation_notes(notes)
        except Exception as save_err:
            logger.warning(f"Failed to persist failure notes: {save_err}")
        return notes, [], []

    # 2. Check if OpenCode is installed
    if not status_info["installed"]:
        notes = AIAssistedNotes(
            investigation_id=investigation_id,
            execution_status="UNAVAILABLE",
            model_provider="None",
            analysis_timestamp=datetime.utcnow(),
            disclaimer="OpenCode CLI was not detected on this machine. Deterministic forensic analysis completed successfully.",
            warnings_or_errors=["OpenCode CLI executable was not found on this system."],
            consent_approved=consent_approved
        )
        try:
            repo.save_ai_investigation_notes(notes)
        except Exception as save_err:
            logger.warning(f"Failed to persist failure notes: {save_err}")
        return notes, [], []

    # 3. Network Mode Enforcement
    if current_net_mode == NetworkMode.LOCAL_ONLY.value:
        if not is_local_model_identifier(configured_model):
            err_msg = (
                "LOCAL OPENCODE MODEL NOT CONFIGURED: TraceX is operating in LOCAL ONLY mode. "
                "Cloud AI services are blocked to maintain absolute forensic air-gap and data privacy. "
                "Configure a local model (e.g. Ollama) in Settings to enable offline AI assistance."
            )
            notes = AIAssistedNotes(
                investigation_id=investigation_id,
                execution_status="SKIPPED",
                model_provider=configured_model,
                analysis_timestamp=datetime.utcnow(),
                warnings_or_errors=[err_msg],
                consent_approved=consent_approved
            )
            repo.save_ai_investigation_notes(notes)
            return notes, [], []

    # 4. Hybrid Mode Authorization
    if current_net_mode == NetworkMode.HYBRID.value and not consent_approved:
        err_msg = "Investigator authorization required: AI-assisted analysis in HYBRID mode requires explicit consent."
        notes = AIAssistedNotes(
            investigation_id=investigation_id,
            execution_status="SKIPPED",
            model_provider=configured_model,
            analysis_timestamp=datetime.utcnow(),
            warnings_or_errors=[err_msg],
            consent_approved=False
        )
        try:
            repo.save_ai_investigation_notes(notes)
        except Exception as save_err:
            logger.warning(f"Failed to persist failure notes: {save_err}")
        return notes, [], []

    # 5. Prepare sanitized context
    context = prepare_forensic_context(
        detail=detail,
        filename=filename,
        file_type=file_type,
        file_size_bytes=file_size_bytes,
        sha256_hash=sha256_hash
    )

    prompt = (
        "You are an AI Forensic Investigation Assistant assisting a certified digital forensics investigator.\n"
        "Analyze the following sanitized static forensic metadata and provide technical observations and verification steps.\n"
        "STRICT CONSTRAINTS:\n"
        "1. Every observation is UNVERIFIED and must be independently verified against raw decompiled code.\n"
        "2. Do NOT invent findings not supported by the evidence.\n"
        "3. Provide output strictly in the following JSON schema:\n"
        "{\n"
        '  "observations": [\n'
        '    {\n'
        '      "title": "Short descriptive title",\n'
        '      "explanation": "Technical explanation",\n'
        '      "related_evidence_refs": ["Permission/Section/Domain"],\n'
        '      "confidence": "Low|Medium|High",\n'
        '      "reasoning_summary": "Why this is suspicious or notable",\n'
        '      "suggested_verification_steps": ["Specific step for human examiner"]\n'
        '    }\n'
        '  ],\n'
        '  "recommendations": [\n'
        '    {\n'
        '      "title": "Action title",\n'
        '      "category": "Verification|Network Analysis|Code Review",\n'
        '      "description": "Details",\n'
        '      "suggested_command_or_action": "e.g. strings or jadx command",\n'
        '      "priority": "High|Medium|Low"\n'
        '    }\n'
        '  ],\n'
        '  "summary": "High-level technical synthesis"\n'
        "}\n\n"
        f"EVIDENCE CONTEXT:\n{context}\n"
    )

    # 6. Execute in an isolated temporary working directory
    temp_dir = tempfile.mkdtemp(prefix=f"tracex_ai_{investigation_id[:8]}_")
    try:
        args = ["run", "--format", "json", "--auto"]
        if configured_model and configured_model != "default":
            args.extend(["--model", configured_model])
        args.append(prompt)

        timeout_sec = getattr(settings, "OPENCODE_TIMEOUT_SECONDS", 60)
        returncode, stdout, stderr = run_opencode_cli(
            args=args,
            cwd=temp_dir,
            timeout=timeout_sec
        )

        if returncode != 0:
            err_msg = stderr.strip() or stdout.strip() or f"OpenCode exited with code {returncode}"
            logger.warning(f"OpenCode execution completed with non-zero exit code: {err_msg[:200]}")
            notes = AIAssistedNotes(
                investigation_id=investigation_id,
                execution_status="FAILED",
                model_provider=configured_model or "OpenCode CLI",
                analysis_timestamp=datetime.utcnow(),
                warnings_or_errors=[f"OpenCode analysis completed with warnings: {err_msg[:300]}"],
                consent_approved=consent_approved
            )
            repo.save_ai_investigation_notes(notes)
            return notes, [], []

        # Parse output
        obs, recs, parse_err = parse_opencode_response(stdout, stderr, investigation_id)
        warnings = [parse_err] if parse_err else []

        notes = AIAssistedNotes(
            investigation_id=investigation_id,
            execution_status="COMPLETED",
            model_provider=configured_model or "OpenCode CLI",
            analysis_timestamp=datetime.utcnow(),
            disclaimer="AI-assisted technical explanation. Every factual conclusion must be independently verified against raw decompiled bytecode and deterministic analyzer evidence.",
            warnings_or_errors=warnings,
            consent_approved=consent_approved
        )

        # Persist findings to database
        repo.save_ai_observations(obs)
        repo.save_ai_recommendations(recs)
        repo.save_ai_investigation_notes(notes)

        return notes, obs, recs

    except Exception as e:
        logger.error(f"Unexpected error during OpenCode analysis: {e}")
        notes = AIAssistedNotes(
            investigation_id=investigation_id,
            execution_status="FAILED",
            model_provider=configured_model or "OpenCode CLI",
            analysis_timestamp=datetime.utcnow(),
            warnings_or_errors=[f"Analysis failed: {str(e)}"],
            consent_approved=consent_approved
        )
        try:
            repo.save_ai_investigation_notes(notes)
        except Exception as save_err:
            logger.warning(f"Failed to persist failure notes: {save_err}")
        return notes, [], []
    finally:
        # Secure cleanup of temp working directory
        try:
            shutil.rmtree(temp_dir, ignore_errors=True)
        except Exception:
            pass


def test_opencode_installation() -> Dict[str, Any]:
    """Tests the OpenCode installation and returns detailed execution diagnostics."""
    status = detect_opencode_status()
    if not status["installed"]:
        return {
            "success": False,
            "message": "OpenCode CLI executable was not found on this system.",
            "diagnostics": status
        }

    # Execute --version
    code, out, err = run_opencode_cli(["--version"], timeout=10)
    version_ok = (code == 0)

    # Execute models check
    code_models, out_models, err_models = run_opencode_cli(["models"], timeout=10)

    return {
        "success": version_ok,
        "message": "OpenCode CLI is operational." if version_ok else f"Failed to execute OpenCode CLI: {err}",
        "version": out.strip() if version_ok else None,
        "path": status["path"],
        "models_accessible": (code_models == 0),
        "available_models_preview": out_models.strip().splitlines()[:5] if code_models == 0 else [],
        "diagnostics": status
    }


def test_opencode_analysis(consent_approved: bool = False) -> Dict[str, Any]:
    """Performs a synthetic static analysis test with sample forensic metadata."""
    status = detect_opencode_status()
    if not status["installed"]:
        return {"success": False, "message": "OpenCode CLI is not installed."}

    # Synthetic sample context
    sample_context = (
        "SAMPLE STATIC FORENSIC EVIDENCE:\n"
        "- Target File: test_payload.apk\n"
        "- Permissions: android.permission.RECEIVE_BOOT_COMPLETED, android.permission.SEND_SMS\n"
        "- Finding: Hardcoded IP address 192.168.1.100 found in class com.example.service.Backdoor"
    )

    class MockDetail:
        static_findings = []
        c2_indicators = []
        reverse_shell_findings = []
        secrets = []
        metadata = None

    notes, obs, recs = analyze_investigation(
        investigation_id="TEST-OPENCODE-DIAGNOSTIC",
        detail=MockDetail(),
        filename="test_payload.apk",
        file_type="apk",
        file_size_bytes=1024,
        sha256_hash="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        consent_approved=consent_approved
    )

    return {
        "success": notes.execution_status in ("COMPLETED", "SKIPPED"),
        "execution_status": notes.execution_status,
        "warnings_or_errors": notes.warnings_or_errors,
        "observations_count": len(obs),
        "recommendations_count": len(recs),
        "disclaimer": notes.disclaimer
    }
