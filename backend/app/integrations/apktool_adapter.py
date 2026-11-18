import shutil
import time
from pathlib import Path
from datetime import datetime
from backend.app.config import settings
from backend.app.core.security import safe_run_command
from backend.app.core.models import ToolExecution

def run_apktool_decode(apk_path: Path, output_dir: Path) -> ToolExecution:
    """
    Executes Apktool if installed or configured in settings.
    Disassembles resources and XML manifests.
    """
    apktool_cmd = settings.APKTOOL_PATH or shutil.which("apktool")
    if not apktool_cmd:
        return ToolExecution(
            tool_name="Apktool",
            installed=False,
            status="skipped",
            errors_warnings="Apktool executable not found in PATH or settings. Disassembly skipped.",
            limitations="Install apktool to decode Android resources, raw XML, and smali."
        )

    output_dir.mkdir(parents=True, exist_ok=True)
    start_time = datetime.utcnow()
    t0 = time.time()

    cmd_args = [
        apktool_cmd,
        "d",
        "-f",
        "-o", str(output_dir),
        str(apk_path)
    ]

    retcode, stdout, stderr = safe_run_command(cmd_args, timeout=settings.TOOL_TIMEOUT_SECONDS)
    duration = time.time() - t0
    end_time = datetime.utcnow()

    status = "completed" if retcode == 0 else "failed"
    errors = stderr if retcode != 0 else None

    # Count decoded files
    files_count = len(list(output_dir.rglob("*")))

    return ToolExecution(
        tool_name="Apktool",
        installed=True,
        status=status,
        version="CLI",
        start_time=start_time,
        end_time=end_time,
        duration_seconds=round(duration, 2),
        exit_code=retcode,
        output_path=str(output_dir),
        errors_warnings=errors,
        findings_count=files_count
    )
