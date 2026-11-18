import logging
from typing import Dict, Any, List, Optional

from backend.app.core.models import ProcessTreeNode, DynamicTelemetryEvent
from backend.app.database.repository import repo

logger = logging.getLogger(__name__)

class ProcessMonitor:
    """
    Analyzes process creation telemetry, reconstructs parent-child execution hierarchies,
    and identifies suspicious process execution patterns.
    """

    SUSPICIOUS_WIN_PROCESSES = {
        "cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe",
        "certutil.exe", "reg.exe", "schtasks.exe", "rundll32.exe", "mshta.exe",
        "bitsadmin.exe", "vssadmin.exe", "wmic.exe", "net.exe", "net1.exe"
    }

    SUSPICIOUS_DROID_PROCESSES = {
        "su", "sh", "busybox", "daemonsu", "magisk", "frida-server"
    }

    def build_process_tree(self, investigation_id: str, run_id: Optional[str] = None) -> List[ProcessTreeNode]:
        """
        Reconstructs the process tree from stored telemetry events.
        """
        events = repo.list_telemetry_events(investigation_id, run_id=run_id)
        process_events = [e for e in events if e.event_category == "PROCESS" and e.process_id]

        if not process_events:
            return []

        nodes_by_pid: Dict[int, ProcessTreeNode] = {}
        all_pids = set()
        child_pids = set()

        for ev in process_events:
            pid = ev.process_id
            if not pid:
                continue
            all_pids.add(pid)
            pname = ev.process_name or "unknown.exe"
            is_susp = (
                pname.lower() in self.SUSPICIOUS_WIN_PROCESSES or
                pname.lower() in self.SUSPICIOUS_DROID_PROCESSES
            )

            node = ProcessTreeNode(
                pid=pid,
                name=pname,
                parent_pid=ev.parent_process_id,
                parent_name=ev.parent_process_name,
                command_line=ev.command_line,
                timestamp_utc=ev.timestamp_utc,
                is_suspicious=is_susp,
                children=[]
            )
            nodes_by_pid[pid] = node

        # Link parent-child nodes
        for pid, node in nodes_by_pid.items():
            ppid = node.parent_pid
            if ppid and ppid in nodes_by_pid and ppid != pid:
                nodes_by_pid[ppid].children.append(node)
                child_pids.add(pid)

        # Roots are nodes that are not children of any other node in this set
        root_pids = all_pids - child_pids
        roots = [nodes_by_pid[pid] for pid in root_pids if pid in nodes_by_pid]

        return roots

process_monitor = ProcessMonitor()
