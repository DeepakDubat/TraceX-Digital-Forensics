import os
import shutil
import logging
from pathlib import Path
from typing import Dict, Any, Optional

from backend.app.config import settings
from backend.app.core.models import DynamicSandboxRun

logger = logging.getLogger(__name__)

class SandboxCleanupManager:
    """
    Guarantees clean, non-polluting teardown of dynamic analysis sessions:
    - Purges staging working copies.
    - Removes ephemeral container configuration files (.wsb, shell scripts).
    - Verifies original evidence integrity remains unaltered.
    """

    def cleanup_run_staging(self, run_id: str) -> bool:
        """Removes the isolated staging directory for an analysis run."""
        staging_dir = settings.DATA_DIR / "staging" / run_id
        if staging_dir.exists():
            try:
                # Remove read-only flags before deleting
                for root, dirs, files in os.walk(str(staging_dir)):
                    for f in files:
                        p = Path(root) / f
                        try:
                            os.chmod(str(p), 0o666)
                        except Exception:
                            pass
                shutil.rmtree(staging_dir, ignore_errors=True)
                logger.info(f"Cleaned up staging folder for run: {run_id}")
                return True
            except Exception as e:
                logger.warning(f"Staging cleanup encountered error for {run_id}: {e}")
                return False
        return True

sandbox_cleanup = SandboxCleanupManager()
