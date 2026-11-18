import re
from typing import List, Dict, Any, Tuple
from backend.app.core.models import ReverseShellFinding

def analyze_reverse_shell_indicators(
    dex_methods: List[str],
    dex_strings: List[str],
    c2_indicators: List[Any]
) -> List[ReverseShellFinding]:
    """
    Dedicated analyzer for Remote Access and Reverse-Shell capabilities.
    Correlates Process execution, socket connections, and I/O stream piping.
    """
    findings: List[ReverseShellFinding] = []
    counter = 1

    all_methods_text = " ".join(dex_methods)
    all_strings_text = " ".join(dex_strings)
    combined_text = all_methods_text + " " + all_strings_text

    # 1. Check for Process Execution APIs
    has_runtime_exec = (
        "Runtime->exec" in combined_text or
        "Runtime.getRuntime().exec" in combined_text or
        "Runtime;->exec" in combined_text
    )
    has_process_builder = "ProcessBuilder" in combined_text
    
    # 2. Check for Shell Binaries
    shell_binaries = []
    for sb in ["/system/bin/sh", "/bin/sh", "/system/xbin/su", "/sbin/su", "busybox", "toybox"]:
        if sb in combined_text:
            shell_binaries.append(sb)

    # 3. Check for Network Sockets
    has_sockets = "java/net/Socket" in combined_text or "Socket->getInputStream" in combined_text or "Socket" in combined_text

    # 4. Check for Stream Piping
    has_stream_piping = (
        ("getInputStream" in combined_text and "getOutputStream" in combined_text) or
        ("Process->getInputStream" in combined_text and "Socket->getOutputStream" in combined_text)
    )

    # Correlate Chain
    execution_chain = []
    if has_sockets:
        execution_chain.append("1. Network socket opened (java.net.Socket)")
    if has_runtime_exec or has_process_builder:
        exec_mech = "ProcessBuilder" if has_process_builder else "Runtime.getRuntime().exec"
        execution_chain.append(f"2. Local shell process spawned ({exec_mech})")
    if shell_binaries:
        execution_chain.append(f"3. Target shell binary targeted: {', '.join(shell_binaries)}")
    if has_stream_piping:
        execution_chain.append("4. Stream redirection detected (Process I/O connected to Socket streams)")

    # Decision Matrix
    if has_sockets and (has_runtime_exec or has_process_builder) and has_stream_piping and shell_binaries:
        # Probable / Confirmed Reverse Shell Pattern
        findings.append(ReverseShellFinding(
            id=f"REV-SHELL-{counter:03d}",
            pattern_type="socket_command_chain",
            title="Probable Reverse-Shell Implementation Detected",
            severity="Critical",
            confidence="Probable Reverse-Shell",
            code_references=[m[:120] for m in dex_methods if any(k in m for k in ["Socket", "Process", "exec"])][:5],
            execution_chain=execution_chain,
            evidence_snippet=f"Shells: {shell_binaries} | Sockets: True | Stream Redirect: True",
            explanation="The decompiled bytecode contains the complete functional chain of an interactive reverse shell: a network socket is created, an interactive shell process (/system/bin/sh) is spawned, and the socket streams are piped directly to the process standard input and output.",
            limitations="Static analysis verifies the presence of the reverse shell code structure; live runtime connectivity was not initiated in compliance with safe forensic protocol."
        ))
        counter += 1

    elif (has_runtime_exec or has_process_builder) and shell_binaries and has_sockets:
        # Possible Remote Command Execution
        findings.append(ReverseShellFinding(
            id=f"REV-SHELL-{counter:03d}",
            pattern_type="process_builder",
            title="Possible Remote Command Execution (Process Spawning with Network Access)",
            severity="High",
            confidence="Possible Remote Command Execution",
            code_references=[m[:120] for m in dex_methods if any(k in m for k in ["ProcessBuilder", "exec"])][:4],
            execution_chain=execution_chain,
            evidence_snippet=f"Shell: {shell_binaries} | Process Exec API present alongside Network Socket",
            explanation="The application spawns command-line shell processes while simultaneously containing direct TCP socket communication logic.",
            limitations="Stream redirection between socket and process could not be stochastically verified from static cross-references alone."
        ))
        counter += 1

    elif (has_runtime_exec or has_process_builder) and shell_binaries:
        # Suspicious Command Execution API
        findings.append(ReverseShellFinding(
            id=f"REV-SHELL-{counter:03d}",
            pattern_type="shell_binary",
            title="Local Shell Command Execution via Shell Interpreter",
            severity="Medium",
            confidence="Suspicious API",
            code_references=[m[:120] for m in dex_methods if "exec" in m][:3],
            execution_chain=[f"Spawns {sb}" for sb in shell_binaries],
            evidence_snippet=f"Referenced shells: {', '.join(shell_binaries)}",
            explanation="Spawns interactive shell binaries (/system/bin/sh or su) locally, which can be leveraged for local privilege escalation or executing scripted system modifications.",
            limitations="No direct network stream redirection was identified linked to this execution call."
        ))
        counter += 1

    return findings
