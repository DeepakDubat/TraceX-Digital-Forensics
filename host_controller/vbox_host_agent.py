#!/usr/bin/env python3
"""
TraceX VirtualBox Host Controller Agent (Standalone Host Deployment)
Universal Digital Forensics & Evidence Intelligence Platform v2.0.0

Place this file on the physical Windows host that runs Oracle VirtualBox.
It runs as a background service or scheduled task and interfaces with VBoxManage.
"""

import sys
from pathlib import Path

# Add project root to sys.path if available
project_root = Path(__file__).resolve().parent.parent
if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))

from backend.app.analyzers.dynamic.vbox_host_agent import (
    HostAgentConfig,
    HostControllerService,
    run_host_agent
)

if __name__ == "__main__":
    run_host_agent()

