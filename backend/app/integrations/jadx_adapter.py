import shutil
import time
from pathlib import Path
from datetime import datetime
from typing import Tuple
from backend.app.config import settings
from backend.app.core.security import safe_run_command
from backend.app.core.models import ToolExecution

def run_jadx_decompiler(apk_path: Path, output_dir: Path) -> ToolExecution:
    """
    Executes JADX CLI decompiler if installed or configured in settings.
    Saves decompiled Java sources to output_dir.
    """
    from backend.app.integrations.tool_registry import _resolve_jadx_executables
    cli_path, _, _, _ = _resolve_jadx_executables()
    jadx_cmd = cli_path or settings.JADX_PATH or shutil.which("jadx")
    if not jadx_cmd or not Path(jadx_cmd).is_file():
        return ToolExecution(
            tool_name="JADX Decompiler",
            installed=False,
            status="skipped",
            errors_warnings="JADX CLI executable not found in PATH or settings. Decompilation skipped.",
            limitations="Install JADX (e.g., via scoop, apt, or direct zip) to enable full Java decompilation."
        )

    output_dir.mkdir(parents=True, exist_ok=True)
    start_time = datetime.utcnow()
    t0 = time.time()
    
    cmd_args = [
        jadx_cmd,
        "-d", str(output_dir),
        "--no-res", # Resources decoded separately
        "--show-bad-code",
        str(apk_path)
    ]

    retcode, stdout, stderr = safe_run_command(cmd_args, timeout=settings.TOOL_TIMEOUT_SECONDS)
    duration = time.time() - t0
    end_time = datetime.utcnow()

    status = "completed" if retcode == 0 else "failed"
    errors = stderr if retcode != 0 else None

    # Count decompiled java files
    java_files_count = len(list(output_dir.rglob("*.java")))

    return ToolExecution(
        tool_name="JADX Decompiler",
        installed=True,
        status=status,
        version="CLI",
        start_time=start_time,
        end_time=end_time,
        duration_seconds=round(duration, 2),
        exit_code=retcode,
        output_path=str(output_dir),
        errors_warnings=errors,
        findings_count=java_files_count
    )
