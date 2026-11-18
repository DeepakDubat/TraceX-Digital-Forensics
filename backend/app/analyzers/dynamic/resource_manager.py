"""
TraceX VM Resource & Concurrency Manager
Universal Digital Forensics & Evidence Intelligence Platform v2.0.0

Monitors and controls host and VM resource utilization (RAM, CPU, Disk)
to prevent hypervisor resource exhaustion during dynamic analysis execution.
"""

import os
import shutil
import logging
from typing import Dict, Any, List, Optional
from datetime import datetime

from backend.app.config import settings
from backend.app.analyzers.dynamic.vm_detector import vm_detector

logger = logging.getLogger(__name__)


class ResourceExhaustionError(Exception):
    """Raised when host/manager VM computing resources are insufficient to launch a worker."""
    pass


class VMResourceManager:
    """
    Guarantees that dynamic analysis workers operate within strict host/VM resource budgets.
    """

    MIN_FREE_RAM_MB: int = 1536  # Require at least 1.5 GB free RAM to boot worker
    MIN_FREE_DISK_GB: float = 3.0  # Require at least 3 GB free disk space
    DEFAULT_MAX_CONCURRENT_WORKERS: int = 1

    def __init__(self):
        self._max_concurrent = getattr(settings, "MAX_CONCURRENT_WORKERS", self.DEFAULT_MAX_CONCURRENT_WORKERS)
        self._active_worker_runs: Dict[str, Dict[str, Any]] = {}

    def get_resource_status(self) -> Dict[str, Any]:
        """Queries live resource capacity from vm_detector."""
        env_info = vm_detector.get_environment_info(force_refresh=True)
        mem = env_info.get("memory_resources", {})
        disk = env_info.get("storage_resources", {})
        cpu = env_info.get("cpu_virtualization", {})

        available_ram = mem.get("available_ram_mb", 0)
        free_disk = disk.get("free_disk_gb", 0.0)

        active_count = len(self._active_worker_runs)
        capacity_available = (
            available_ram >= self.MIN_FREE_RAM_MB and
            free_disk >= self.MIN_FREE_DISK_GB and
            active_count < self._max_concurrent
        )

        return {
            "capacity_available": capacity_available,
            "active_worker_count": active_count,
            "max_concurrent_workers": self._max_concurrent,
            "memory": {
                "total_ram_mb": mem.get("total_ram_mb", 0),
                "available_ram_mb": available_ram,
                "required_min_mb": self.MIN_FREE_RAM_MB,
                "is_sufficient": available_ram >= self.MIN_FREE_RAM_MB
            },
            "storage": {
                "workspace_drive": disk.get("workspace_drive", "C:"),
                "total_disk_gb": disk.get("total_disk_gb", 0.0),
                "free_disk_gb": free_disk,
                "required_min_gb": self.MIN_FREE_DISK_GB,
                "is_sufficient": free_disk >= self.MIN_FREE_DISK_GB
            },
            "cpu": {
                "physical_cores": cpu.get("physical_cores", 1),
                "logical_processors": cpu.get("logical_processors", 1),
                "cpu_name": cpu.get("cpu_name", "Unknown")
            },
            "checked_at_utc": datetime.utcnow().isoformat()
        }

    def allocate_worker_resources(self, run_id: str, required_ram_mb: int = 2048) -> bool:
        """
        Validates resource budgets and reserves concurrency slot before worker launch.
        Raises ResourceExhaustionError if capacity is exceeded.
        """
        status = self.get_resource_status()

        if status["active_worker_count"] >= self._max_concurrent:
            raise ResourceExhaustionError(
                f"Worker concurrency limit reached ({status['active_worker_count']}/{self._max_concurrent}). "
                "Wait for active dynamic analysis to complete before starting another worker."
            )

        if not status["memory"]["is_sufficient"]:
            raise ResourceExhaustionError(
                f"Insufficient free RAM ({status['memory']['available_ram_mb']} MB available, "
                f"minimum {self.MIN_FREE_RAM_MB} MB required). Close other applications to proceed."
            )

        if not status["storage"]["is_sufficient"]:
            raise ResourceExhaustionError(
                f"Insufficient disk space ({status['storage']['free_disk_gb']} GB available, "
                f"minimum {self.MIN_FREE_DISK_GB} GB required) on analysis drive."
            )

        # Allocate slot
        self._active_worker_runs[run_id] = {
            "run_id": run_id,
            "allocated_ram_mb": required_ram_mb,
            "allocated_at_iso": datetime.utcnow().isoformat()
        }
        logger.info(f"Allocated worker resource slot for run {run_id}")
        return True

    def release_worker_resources(self, run_id: str):
        """Releases concurrency slot and records completion."""
        if run_id in self._active_worker_runs:
            del self._active_worker_runs[run_id]
            logger.info(f"Released worker resource slot for run {run_id}")

    def prune_stale_staging(self, max_age_hours: int = 24) -> int:
        """Cleans up abandoned staging directories older than max_age_hours."""
        staging_root = settings.DATA_DIR / "staging"
        if not staging_root.exists():
            return 0

        pruned = 0
        now = datetime.utcnow().timestamp()
        for item in staging_root.iterdir():
            if item.is_dir() and item.name.startswith("RUN-"):
                try:
                    mtime = item.stat().st_mtime
                    if (now - mtime) > (max_age_hours * 3600):
                        shutil.rmtree(item, ignore_errors=True)
                        pruned += 1
                except Exception:
                    pass
        return pruned


vm_resource_manager = VMResourceManager()

