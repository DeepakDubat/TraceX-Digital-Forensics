import React from 'react';
import {
  TerminalSquare,
  ShieldAlert,
  ArrowRight,
  Lock,
  Layers,
  AlertTriangle,
  Info,
  CheckCircle2,
  Cpu,
  Bookmark,
  Calendar,
  Terminal,
  FolderGit2
} from 'lucide-react';
import { InvestigationDetail, ReverseShellFinding, PePersistenceFinding } from '../types';
import { SeverityBadge } from '../components/SeverityBadge';

interface ReverseShellPageProps {
  detail: InvestigationDetail;
}

export const ReverseShellPage: React.FC<ReverseShellPageProps> = ({ detail }) => {
  const isExe = detail.record.file_type === 'exe';

  // APK Findings
  const reverseShellFindings = detail.reverse_shell_findings || [];
  // EXE Persistence Findings
  const persistenceFindings = detail.persistence_findings || [];

  if (isExe) {
    const regCount = persistenceFindings.filter(f => f.mechanism.toLowerCase().includes('registry')).length;
    const srvCount = persistenceFindings.filter(f => f.mechanism.toLowerCase().includes('service')).length;
    const taskCount = persistenceFindings.filter(f => f.mechanism.toLowerCase().includes('scheduled')).length;
    const cmdCount = persistenceFindings.filter(f => f.mechanism.toLowerCase().includes('injection') || f.mechanism.toLowerCase().includes('powershell')).length;

    return (
      <div className="p-4 sm:p-6 md:p-8 space-y-6">
        {/* Header */}
        <div className="border-b border-app pb-4 flex flex-col md:flex-row md:items-center justify-between gap-4">
          <div>
            <h1 className="text-xl md:text-2xl font-bold text-app-primary tracking-tight flex flex-wrap items-center gap-2.5">
              <span>Windows Persistence & Execution Indicators</span>
              {persistenceFindings.length > 0 ? (
                <span className="text-xs bg-amber-50 dark:bg-amber-950 text-amber-800 dark:text-amber-300 border border-amber-300 dark:border-amber-800 px-2.5 py-1 rounded-md font-bold">
                  {persistenceFindings.length} MECHANISMS DETECTED
                </span>
              ) : (
                <span className="text-xs bg-emerald-50 dark:bg-emerald-950 text-emerald-800 dark:text-emerald-300 border border-emerald-300 dark:border-emerald-800 px-2.5 py-1 rounded-md font-medium">
                  NO PERSISTENCE PATTERNS IDENTIFIED
                </span>
              )}
            </h1>
            <p className="text-xs md:text-sm text-app-secondary mt-1">
              Passive extraction of Registry Run keys, Windows Service hooks, Scheduled Tasks, DLL injection APIs, and PowerShell execution vectors.
            </p>
          </div>

          {/* Safety Disclaimer */}
          <div className="flex items-center gap-2 bg-rose-50 dark:bg-rose-950/40 border border-rose-300 dark:border-rose-800 px-3 py-1.5 rounded-lg text-xs font-semibold text-rose-800 dark:text-rose-300 shrink-0 shadow-sm">
            <Lock className="w-4 h-4 text-rose-600 dark:text-rose-400" />
            <span>STATIC CORRELATION ONLY</span>
          </div>
        </div>

        {/* Mechanism Stat Badges */}
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
          <div className="forensics-card p-3.5 rounded-xl">
            <div className="text-app-muted text-[11px] font-semibold uppercase">Registry Autostart</div>
            <div className="text-xl font-bold text-cyan-600 dark:text-cyan-400 font-mono mt-0.5">{regCount}</div>
            <div className="text-xs text-app-muted mt-0.5">Run / RunOnce / Winlogon</div>
          </div>
          <div className="forensics-card p-3.5 rounded-xl">
            <div className="text-app-muted text-[11px] font-semibold uppercase">Windows Services</div>
            <div className="text-xl font-bold text-indigo-600 dark:text-indigo-400 font-mono mt-0.5">{srvCount}</div>
            <div className="text-xs text-app-muted mt-0.5">Service Control Manager</div>
          </div>
          <div className="forensics-card p-3.5 rounded-xl">
            <div className="text-app-muted text-[11px] font-semibold uppercase">Scheduled Tasks</div>
            <div className="text-xl font-bold text-amber-600 dark:text-amber-400 font-mono mt-0.5">{taskCount}</div>
            <div className="text-xs text-app-muted mt-0.5">schtasks / TaskScheduler</div>
          </div>
          <div className="forensics-card p-3.5 rounded-xl">
            <div className="text-app-muted text-[11px] font-semibold uppercase">CLI & Injection</div>
            <div className="text-xl font-bold text-rose-600 dark:text-rose-400 font-mono mt-0.5">{cmdCount}</div>
            <div className="text-xs text-app-muted mt-0.5">PowerShell / RemoteThread</div>
          </div>
        </div>

        {persistenceFindings.length === 0 ? (
          <div className="p-12 text-center text-app-muted border border-dashed border-app rounded-xl space-y-3 bg-surface">
            <Bookmark className="w-10 h-10 mx-auto text-app-muted" />
            <h3 className="text-sm font-semibold text-app-primary">No Persistence or Execution Artifacts Flagged</h3>
            <p className="text-xs text-app-secondary max-w-lg mx-auto leading-relaxed">
              Static analysis did not identify Windows autostart registry keys, service creation API sequences, scheduled task commands, or memory injection APIs in the target PE executable.
            </p>
          </div>
        ) : (
          <div className="space-y-4">
            {persistenceFindings.map((finding, idx) => {
              const findingKey = finding.id || `persist-${idx}`;
              return (
                <div
                  key={idx}
                  className="forensics-card rounded-xl p-5 space-y-4 shadow-sm hover:border-slate-400 dark:hover:border-[#303e54] transition-all"
                >
                  {/* Card Header */}
                  <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-app pb-3">
                    <div className="flex flex-wrap items-center gap-2">
                      <span className="text-xs font-bold uppercase px-2.5 py-0.5 rounded-md bg-surface border border-app text-cyan-700 dark:text-cyan-300 font-mono">
                        {finding.mechanism}
                      </span>
                      <h2 className="text-sm md:text-base font-bold text-app-primary tracking-wide">{finding.title}</h2>
                    </div>

                    <div className="flex flex-wrap items-center gap-2 shrink-0">
                      <span className="text-[11px] text-app-secondary bg-surface border border-app px-2 py-0.5 rounded-md">
                        TYPE: <strong className="text-cyan-700 dark:text-cyan-400 font-mono">{finding.indicator_type}</strong>
                      </span>
                      <span className="text-[11px] text-app-secondary bg-surface border border-app px-2 py-0.5 rounded-md">
                        CONFIDENCE: <strong className="text-amber-700 dark:text-amber-400 font-mono">{finding.confidence.toUpperCase()}</strong>
                      </span>
                      <SeverityBadge severity={finding.severity as any} size="sm" />
                    </div>
                  </div>

                  {/* Indicator Box */}
                  <div className="bg-surface border border-app rounded-lg p-3 text-xs font-mono">
                    <span className="text-app-muted select-none block text-[11px] font-semibold uppercase mb-1">
                      EXTRACTED SOURCE EVIDENCE / PATTERN
                    </span>
                    <span className="text-cyan-700 dark:text-cyan-300 font-semibold break-all">{finding.source_evidence}</span>
                  </div>

                  {/* Explanation & Relevance */}
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs bg-surface p-3.5 rounded-lg border border-app">
                    <div>
                      <span className="text-[11px] text-cyan-700 dark:text-cyan-400 font-bold uppercase block mb-1">
                        Forensic Explanation & Mechanism
                      </span>
                      <p className="text-app-secondary leading-relaxed text-xs">{finding.details}</p>
                    </div>
                    <div>
                      <span className="text-[11px] text-amber-700 dark:text-amber-400 font-bold uppercase block mb-1">
                        Analytical Limitation
                      </span>
                      <p className="text-app-secondary leading-relaxed text-xs">{finding.limitations}</p>
                    </div>
                  </div>
                </div>
              );
            })}
          </div>
        )}
      </div>
    );
  }

  // APK Remote Access & Reverse-Shell View
  return (
    <div className="p-4 sm:p-6 md:p-8 space-y-6">
      {/* Header */}
      <div className="border-b border-app pb-4 flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <h1 className="text-xl md:text-2xl font-bold text-app-primary tracking-tight flex flex-wrap items-center gap-2.5">
            <span>Remote Access & Reverse-Shell Detector</span>
            {reverseShellFindings.length > 0 ? (
              <span className="text-xs bg-rose-50 dark:bg-rose-950 text-rose-800 dark:text-rose-300 border border-rose-300 dark:border-rose-800 px-2.5 py-1 rounded-md font-bold animate-pulse">
                CRITICAL MALWARE PATTERNS DETECTED
              </span>
            ) : (
              <span className="text-xs bg-emerald-50 dark:bg-emerald-950 text-emerald-800 dark:text-emerald-300 border border-emerald-300 dark:border-emerald-800 px-2.5 py-1 rounded-md font-medium">
                NO REVERSE-SHELL CHAINS
              </span>
            )}
          </h1>
          <p className="text-xs md:text-sm text-app-secondary mt-1">
            Detects ProcessBuilder, Runtime.exec, socket creation, stream redirection, and command dispatch loops.
          </p>
        </div>

        {/* Safety Disclaimer */}
        <div className="flex items-center gap-2 bg-rose-50 dark:bg-rose-950/40 border border-rose-300 dark:border-rose-800 px-3 py-1.5 rounded-lg text-xs font-semibold text-rose-800 dark:text-rose-300 shrink-0 shadow-sm">
          <Lock className="w-4 h-4 text-rose-600 dark:text-rose-400" />
          <span>PASSIVE CORRELATION ONLY</span>
        </div>
      </div>

      {reverseShellFindings.length === 0 ? (
        <div className="p-12 text-center text-app-muted border border-dashed border-app rounded-xl space-y-3 bg-surface">
          <TerminalSquare className="w-10 h-10 mx-auto text-app-muted" />
          <h3 className="text-sm font-semibold text-app-primary">No Interactive Reverse-Shell Chains Identified</h3>
          <p className="text-xs text-app-secondary max-w-lg mx-auto leading-relaxed">
            Bytecode analysis did not identify concurrent execution of interactive shell processes (/system/bin/sh, su) coupled directly to TCP socket input/output streams.
          </p>
        </div>
      ) : (
        <div className="space-y-6">
          {reverseShellFindings.map((finding, idx) => (
            <div
              key={idx}
              className="forensics-card border-rose-300 dark:border-rose-900/60 rounded-xl p-5 md:p-6 space-y-5 shadow-md relative overflow-hidden"
            >
              {/* Card Header */}
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-app pb-4">
                <div className="flex flex-wrap items-center gap-2.5">
                  <span className="text-xs text-rose-800 dark:text-rose-300 font-bold bg-rose-50 dark:bg-rose-950/80 border border-rose-300 dark:border-rose-800 px-2.5 py-0.5 rounded-md font-mono">
                    {finding.id}
                  </span>
                  <h2 className="text-sm md:text-base font-bold text-app-primary tracking-wide">{finding.title}</h2>
                </div>

                <div className="flex items-center gap-2 shrink-0">
                  <span className="text-[11px] text-amber-800 dark:text-amber-300 bg-amber-50 dark:bg-amber-950/60 border border-amber-300 dark:border-amber-800 px-2.5 py-0.5 rounded-md font-bold font-mono">
                    CONFIDENCE: {finding.confidence.toUpperCase()}
                  </span>
                  <SeverityBadge severity={finding.severity} size="sm" />
                </div>
              </div>

              {/* Execution Chain Visualization */}
              <div className="space-y-2">
                <span className="text-[11px] text-cyan-700 dark:text-cyan-400 font-bold uppercase tracking-wider block">
                  Reconstructed Execution Chain
                </span>
                <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3">
                  {finding.execution_chain.map((step, sIdx) => (
                    <div
                      key={sIdx}
                      className="bg-surface border border-app rounded-xl p-3 text-xs flex flex-col justify-between"
                    >
                      <div className="flex items-center justify-between text-app-muted text-[11px] font-semibold mb-1">
                        <span>STAGE {sIdx + 1}</span>
                        <ArrowRight className="w-3.5 h-3.5 text-cyan-600 dark:text-cyan-400" />
                      </div>
                      <span className="text-app-primary font-semibold text-xs">{step}</span>
                    </div>
                  ))}
                </div>
              </div>

              {/* Evidence Snippet */}
              {finding.evidence_snippet && (
                <div className="bg-surface border border-app rounded-xl p-3 text-xs font-mono text-cyan-700 dark:text-cyan-300">
                  <span className="text-app-muted select-none block text-[11px] font-semibold uppercase mb-1">
                    EVIDENTIARY ARTIFACTS
                  </span>
                  {finding.evidence_snippet}
                </div>
              )}

              {/* Code References */}
              {finding.code_references && finding.code_references.length > 0 && (
                <div className="space-y-1.5">
                  <span className="text-[11px] text-app-muted uppercase font-semibold block">
                    Bytecode Method References
                  </span>
                  <div className="space-y-1">
                    {finding.code_references.map((ref, rIdx) => (
                      <div
                        key={rIdx}
                        className="bg-surface border border-app px-3 py-1.5 rounded-md text-xs font-mono text-app-primary truncate"
                      >
                        {ref}
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* Rationale and Limitation */}
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs bg-surface p-4 rounded-xl border border-app">
                <div>
                  <span className="text-[11px] text-rose-700 dark:text-rose-400 font-bold uppercase block mb-1">
                    Forensic Explanation
                  </span>
                  <p className="text-app-secondary leading-relaxed text-xs">{finding.explanation}</p>
                </div>
                <div>
                  <span className="text-[11px] text-app-muted font-bold uppercase block mb-1">
                    Analytical Limitation
                  </span>
                  <p className="text-app-secondary leading-relaxed text-xs">{finding.limitations}</p>
                </div>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
};
