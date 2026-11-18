"""
Unit tests for OS shell integration actions in download_manager.
"""

from unittest.mock import patch
from pathlib import Path
import pytest
from backend.app.reporting.download_manager import (
    open_report_in_system,
    show_report_in_file_explorer,
    get_reports_root_dir
)

def test_open_report_action_triggers_system_handler():
    root = get_reports_root_dir()
    test_file = root / "action_test.txt"
    test_file.write_text("test", encoding="utf-8")
    try:
        with patch("os.startfile") as mock_start:
            res = open_report_in_system(str(test_file))
            assert res["status"] == "success"
            assert mock_start.called
    finally:
        if test_file.exists():
            test_file.unlink()

def test_show_in_folder_action_triggers_explorer():
    root = get_reports_root_dir()
    test_file = root / "action_test_folder.txt"
    test_file.write_text("test", encoding="utf-8")
    try:
        with patch("subprocess.Popen") as mock_popen:
            res = show_report_in_file_explorer(str(test_file))
            assert res["status"] == "success"
            assert mock_popen.called
            call_args = mock_popen.call_args[0][0]
            assert "explorer" in str(call_args).lower()
    finally:
        if test_file.exists():
            test_file.unlink()
