import shutil
from pathlib import Path
from typing import Dict, Any
from backend.app.config import settings
from backend.app.core.security import calculate_hashes

class WorkspaceManager:
    """Manages isolated per-investigation forensic workspaces."""
    
    def __init__(self, base_data_dir: Path = settings.DATA_DIR):
        self.base_dir = base_data_dir
        self.base_dir.mkdir(parents=True, exist_ok=True)
        
    def get_investigation_dir(self, investigation_id: str) -> Path:
        return self.base_dir / investigation_id
        
    def create_workspace(self, investigation_id: str) -> Dict[str, Path]:
        """Creates directory structure for an isolated investigation."""
        inv_dir = self.get_investigation_dir(investigation_id)
        dirs = {
            "root": inv_dir,
            "original": inv_dir / "original",
            "working": inv_dir / "working",
            "extracted": inv_dir / "extracted",
            "decompile": inv_dir / "decompile",
            "reports": inv_dir / "reports"
        }
        for d in dirs.values():
            d.mkdir(parents=True, exist_ok=True)
        return dirs
        
    def stage_artifact(self, investigation_id: str, uploaded_temp_file: Path, sanitized_filename: str) -> Dict[str, Any]:
        """
        Store original artifact untouched, calculate its hashes, and produce
        an identical working copy for static analysis tools to operate upon.
        Supports both APK and PE/EXE files.
        """
        dirs = self.create_workspace(investigation_id)
        original_path = dirs["original"] / sanitized_filename
        working_path = dirs["working"] / sanitized_filename
        
        # Move/copy uploaded file to original directory
        shutil.copy2(uploaded_temp_file, original_path)
        
        # Calculate hashes on original artifact
        hashes = calculate_hashes(original_path)
        original_size = original_path.stat().st_size
        
        # Create identical working copy
        shutil.copy2(original_path, working_path)
        
        # Verify working copy hash matches original artifact
        working_hashes = calculate_hashes(working_path)
        if working_hashes["sha256"] != hashes["sha256"]:
            raise ValueError("Integrity failure: Working copy hash mismatch.")
            
        return {
            "original_path": original_path,
            "working_path": working_path,
            "original_apk": original_path, # Backward compatibility
            "working_apk": working_path,   # Backward compatibility
            "hashes": hashes,
            "size": original_size,
            "dirs": dirs
        }

    def stage_apk(self, investigation_id: str, uploaded_temp_file: Path, sanitized_filename: str) -> Dict[str, Any]:
        """Backward-compatible wrapper for staging APK artifacts."""
        return self.stage_artifact(investigation_id, uploaded_temp_file, sanitized_filename)
        
    def verify_original_integrity(self, investigation_id: str, expected_sha256: str) -> bool:
        """Verifies that the original artifact in storage has remained strictly unaltered."""
        inv_dir = self.get_investigation_dir(investigation_id)
        original_dir = inv_dir / "original"
        if not original_dir.exists():
            return False
        files = [f for f in original_dir.iterdir() if f.is_file()]
        if not files:
            return False
        current_hashes = calculate_hashes(files[0])
        return current_hashes["sha256"] == expected_sha256

    def delete_workspace(self, investigation_id: str) -> bool:
        """Completely and safely remove an investigation workspace from disk."""
        inv_dir = self.get_investigation_dir(investigation_id)
        if inv_dir.exists():
            shutil.rmtree(inv_dir, ignore_errors=True)
            return True
        return False

    def get_total_disk_usage_mb(self) -> float:
        """Calculates total disk usage in MB of the workspace."""
        total_bytes = sum(f.stat().st_size for f in self.base_dir.rglob('*') if f.is_file())
        return round(total_bytes / (1024 * 1024), 2)

workspace_mgr = WorkspaceManager()
