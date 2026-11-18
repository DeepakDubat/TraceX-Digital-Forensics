import React, { useEffect, useState, useRef } from 'react';
import {
  Activity,
  CheckCircle2,
  AlertOctagon,
  Shield,
  Radio,
  FileCode2,
  ArrowRight,
  Download,
  Clock,
  RefreshCw,
  Eye,
  AlertTriangle,
  Layers,
  Database
} from 'lucide-react';
import { api } from '../api';
import { SeverityBadge } from '../components/SeverityBadge';

interface AnalysisProgressPageProps {
  investigationId: string;
  onAnalysisCompleted: () => void;
  onViewReport: () => void;
}

const PIPELINE_STAGES = [
  { id: 1, name: 'Case Initialization', minPct: 5, desc: 'Database allocation and chain of custody instantiation' },
  { id: 2, name: 'Evidence Ingestion & Custody', minPct: 20, desc: 'Write-protection, sandbox copying, and intake logging' },
  { id: 3, name: 'Format Identification & Hashes', minPct: 35, desc: 'Magic bytes, MD5, SHA-1, SHA-256 calculation' },
  { id: 4, name: 'Multi-Engine Static Analysis', minPct: 65, desc: 'Specialized parser execution (APK/PE/ELF/PDF/Office/ZIP/EML)' },
  { id: 5, name: 'Findings Extraction & Rules', minPct: 75, desc: 'YARA heuristics, suspicious API calls, and secret detection' },
  { id: 6, name: 'Indicator Correlation & Timeline', minPct: 85, desc: 'Temporal sequence synthesis and IOC clustering' },
  { id: 7, name: 'Multi-Dimensional Risk Assessment', minPct: 90, desc: 'Deterministic threat scoring and posture scoring' },
  { id: 8, name: 'Master Forensic Report Generation', minPct: 95, desc: 'Tamper-evident audit document synthesis' },
  { id: 9, name: 'Final Persistence & Sealing', minPct: 100, desc: 'Forensic state write and evidence sealing' },
];

const resolveActiveStageId = (
  backendStageIndex?: number,
  progress: number = 0,
  stageDesc: string = '',
  completed: boolean = false
): number => {
  if (completed) return 9;
  if (backendStageIndex && backendStageIndex >= 1 && backendStageIndex <= 9) {
    return backendStageIndex;
  }
  const desc = stageDesc.toLowerCase();
  if (desc.includes('complete') || desc.includes('persistence') || progress >= 100) return 9;
  if (desc.includes('master report') || desc.includes('report generation') || progress >= 95) return 8;
  if (desc.includes('risk assessment') || desc.includes('evaluating') || progress >= 90) return 7;
  if (desc.includes('correlation') || desc.includes('timeline') || progress >= 85) return 6;
  if (desc.includes('findings extraction') || desc.includes('normalizing') || progress >= 75) return 5;
  if (desc.includes('static analysis') || desc.includes('deep static') || desc.includes('multi-engine') || progress > 35) return 4;
  if (desc.includes('format identification') || desc.includes('hashes') || desc.includes('magic') || progress > 20) return 3;
  if (desc.includes('custody') || desc.includes('ingestion') || desc.includes('staged') || progress > 5) return 2;
  return 1;
};

export const AnalysisProgressPage: React.FC<AnalysisProgressPageProps> = ({
  investigationId,
  onAnalysisCompleted,
  onViewReport,
}) => {
  const [statusData, setStatusData] = useState<{
    id: string;
    status: string;
    progress: number;
    stage_index?: number;
    current_stage: string;
    last_heartbeat?: string;
    error_message?: string;
    total_findings?: number;
    severity?: string;
  } | null>(null);

  const [elapsedSeconds, setElapsedSeconds] = useState<number>(0);
  const [isStalled, setIsStalled] = useState<boolean>(false);
  const [isRefreshing, setIsRefreshing] = useState<boolean>(false);
  const [isCancelling, setIsCancelling] = useState<boolean>(false);

  const lastProgressRef = useRef<number>(0);
  const lastProgressTimeRef = useRef<number>(Date.now());
  const timerRef = useRef<any>(null);

  const fetchStatus = async () => {
    try {
      setIsRefreshing(true);
      const res = await api.getInvestigationStatus(investigationId);
      setStatusData(res);

      const normalizedStatus = (res.status || '').toLowerCase();
      if (normalizedStatus === 'completed' || normalizedStatus === 'completed_with_warnings') {
        onAnalysisCompleted();
      }

      // Check progress advancement
      const currentProgress = res.progress || 0;
      if (currentProgress > lastProgressRef.current) {
        lastProgressRef.current = currentProgress;
        lastProgressTimeRef.current = Date.now();
        setIsStalled(false);
      } else if (
        normalizedStatus !== 'completed' &&
        normalizedStatus !== 'completed_with_warnings' &&
        normalizedStatus !== 'failed' &&
        normalizedStatus !== 'cancelled'
      ) {
        // If progress hasn't advanced in 20 seconds, mark as stalled advisory
        if (Date.now() - lastProgressTimeRef.current > 20000) {
          setIsStalled(true);
        }
      }
    } catch (err) {
      console.error('Failed to poll status', err);
    } finally {
      setIsRefreshing(false);
    }
  };

  const handleCancel = async () => {
    if (!window.confirm('Are you sure you want to stop/cancel this investigation?')) {
      return;
    }
    try {
      setIsCancelling(true);
      await api.cancelInvestigation(investigationId);
      await fetchStatus();
    } catch (err) {
      console.error('Failed to cancel investigation', err);
    } finally {
      setIsCancelling(false);
    }
  };

  // Status Poller
  useEffect(() => {
    lastProgressRef.current = 0;
    lastProgressTimeRef.current = Date.now();
    setIsStalled(false);
    setElapsedSeconds(0);

    fetchStatus();
    const pollInterval = setInterval(fetchStatus, 1500);

    return () => clearInterval(pollInterval);
  }, [investigationId]);

  // Elapsed Time Counter
  useEffect(() => {
    timerRef.current = setInterval(() => {
      const normalizedStatus = (statusData?.status || '').toLowerCase();
      if (
        normalizedStatus !== 'completed' &&
        normalizedStatus !== 'completed_with_warnings' &&
        normalizedStatus !== 'failed'
      ) {
        setElapsedSeconds((prev) => prev + 1);

        // Check stall condition every second
        if (Date.now() - lastProgressTimeRef.current > 15000) {
          setIsStalled(true);
        }
      }
    }, 1000);

    return () => clearInterval(timerRef.current);
  }, [statusData?.status]);

  if (!statusData) {
    return (
      <div className="p-8 flex items-center justify-center h-full text-app-secondary font-mono">
        <Activity className="w-5 h-5 animate-spin mr-3 text-cyan-600 dark:text-cyan-400" />
        Connecting to forensic pipeline telemetry...
      </div>
    );
  }

  const rawStatus = (statusData.status || '').toLowerCase();
  const isCompleted = rawStatus === 'completed' || rawStatus === 'completed_with_warnings';
  const hasWarnings = rawStatus === 'completed_with_warnings';
  const isFailed = rawStatus === 'failed';
  const isCancelled = rawStatus === 'cancelled';
  const currentPct = statusData.progress || 0;

  const formatElapsed = (sec: number) => {
    const mins = Math.floor(sec / 60);
    const secs = sec % 60;
    return `${mins.toString().padStart(2, '0')}:${secs.toString().padStart(2, '0')}`;
  };

  return (
    <div className="p-4 sm:p-6 md:p-8 max-w-4xl mx-auto space-y-6">
      {/* Header */}
      <div className="border-b border-app pb-4 flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h1 className="text-xl md:text-2xl font-bold text-app-primary tracking-tight flex flex-wrap items-center gap-2.5">
            <span>Forensic Pipeline Execution</span>
            <span className="text-xs bg-surface text-cyan-700 dark:text-cyan-300 border border-app px-2.5 py-1 rounded-md font-mono font-medium">
              {statusData.id}
            </span>
          </h1>
          <p className="text-xs md:text-sm text-app-secondary mt-1">
            Autonomous multi-engine static reverse engineering, signature matching, and risk analysis.
          </p>
        </div>

        <div className="flex items-center gap-3 shrink-0">
          {/* Heartbeat Status Indicator */}
          {!isCompleted && !isFailed && !isCancelled && (
            <div className="flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg bg-emerald-50 dark:bg-emerald-950/60 border border-emerald-300 dark:border-emerald-800 text-emerald-800 dark:text-emerald-300 text-xs font-mono" title="Pipeline Telemetry Heartbeat Active">
              <span className="w-2 h-2 rounded-full bg-emerald-500 animate-pulse inline-block" />
              <span>Heartbeat: Active</span>
            </div>
          )}

          {/* Elapsed Timer Pill */}
          <div className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-surface border border-app text-app-secondary text-xs font-mono">
            <Clock className="w-3.5 h-3.5 text-cyan-500" />
            <span>Elapsed: {formatElapsed(elapsedSeconds)}</span>
          </div>

          {/* Status Badge */}
          {isCompleted && !hasWarnings && (
            <span className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-emerald-50 dark:bg-emerald-950/80 border border-emerald-300 dark:border-emerald-800 text-emerald-800 dark:text-emerald-300 text-xs font-bold tracking-wide">
              <CheckCircle2 className="w-4 h-4 text-emerald-600 dark:text-emerald-400" />
              ANALYSIS COMPLETE
            </span>
          )}
          {hasWarnings && (
            <span className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-amber-50 dark:bg-amber-950/80 border border-amber-300 dark:border-amber-800 text-amber-800 dark:text-amber-300 text-xs font-bold tracking-wide">
              <AlertTriangle className="w-4 h-4 text-amber-600 dark:text-amber-400" />
              COMPLETE WITH WARNINGS
            </span>
          )}
          {isCancelled && (
            <span className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-100 dark:bg-slate-800 border border-slate-300 dark:border-slate-700 text-slate-800 dark:text-slate-300 text-xs font-bold tracking-wide">
              <AlertOctagon className="w-4 h-4 text-slate-500" />
              CANCELLED
            </span>
          )}
          {isFailed && (
            <span className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-rose-50 dark:bg-rose-950/80 border border-rose-300 dark:border-rose-800 text-rose-800 dark:text-rose-300 text-xs font-bold tracking-wide">
              <AlertOctagon className="w-4 h-4 text-rose-600 dark:text-rose-400" />
              EXECUTION FAILED
            </span>
          )}
          {!isCompleted && !isFailed && !isCancelled && (
            <span className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-indigo-50 dark:bg-indigo-950/80 border border-indigo-300 dark:border-indigo-800 text-indigo-800 dark:text-indigo-300 text-xs font-bold animate-pulse">
              <Activity className="w-4 h-4 animate-spin text-cyan-600 dark:text-cyan-400" />
              IN PROGRESS
            </span>
          )}
        </div>
      </div>

      {/* Main Radar & Progress Card */}
      <div className="forensics-card p-6 md:p-8 rounded-2xl relative overflow-hidden shadow-lg space-y-6">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2">
            <Layers className="w-4 h-4 text-cyan-500" />
            <span className="text-xs text-app-secondary font-bold uppercase tracking-wider font-mono">
              Static Forensic Pipeline Progress
            </span>
          </div>
          <div className="flex items-center gap-3">
            {!isCompleted && !isFailed && !isCancelled && (
              <button
                type="button"
                onClick={handleCancel}
                disabled={isCancelling}
                className="text-xs px-2.5 py-1 rounded-md border border-rose-300 dark:border-rose-800 bg-rose-50 dark:bg-rose-950/40 text-rose-700 dark:text-rose-300 hover:bg-rose-100 dark:hover:bg-rose-900/50 transition-colors font-mono cursor-pointer"
                title="Halt analysis pipeline"
              >
                {isCancelling ? 'Halting...' : 'Halt Pipeline'}
              </button>
            )}
            <button
              onClick={fetchStatus}
              disabled={isRefreshing}
              className="text-xs text-app-muted hover:text-cyan-500 transition-colors p-1 rounded cursor-pointer"
              title="Refresh status manually"
            >
              <RefreshCw className={`w-3.5 h-3.5 ${isRefreshing ? 'animate-spin' : ''}`} />
            </button>
            <span className="text-3xl font-extrabold text-cyan-600 dark:text-cyan-400 font-mono">
              {currentPct}%
            </span>
          </div>
        </div>

        {/* Progress Bar */}
        <div className="w-full bg-slate-200 dark:bg-[#151b26] h-3.5 rounded-full overflow-hidden border border-app">
          <div
            className="h-full bg-gradient-to-r from-cyan-600 via-indigo-600 to-emerald-500 dark:from-cyan-500 dark:via-indigo-500 dark:to-emerald-400 transition-all duration-500 shadow-sm"
            style={{ width: `${Math.min(100, Math.max(currentPct, 5))}%` }}
          />
        </div>

        {/* Current Stage Telemetry */}
        <div className="bg-surface border border-app rounded-xl p-4 flex items-start gap-3.5">
          <div className="p-2.5 rounded-lg bg-cyan-100 dark:bg-cyan-950/60 border border-cyan-300 dark:border-cyan-800 text-cyan-700 dark:text-cyan-400 mt-0.5 shrink-0">
            <Radio className={`w-4 h-4 ${!isCompleted && !isFailed ? 'animate-pulse' : ''}`} />
          </div>
          <div className="min-w-0 flex-1">
            <div className="text-[11px] font-semibold text-app-muted uppercase tracking-wider">
              Current Pipeline Stage
            </div>
            <div className="text-sm font-semibold text-app-primary mt-0.5 font-mono">
              {statusData.current_stage || 'Initializing...'}
            </div>
            {statusData.error_message && (
              <div className="text-xs text-rose-600 dark:text-rose-400 mt-1 font-mono">
                Error Details: {statusData.error_message}
              </div>
            )}
          </div>
          {statusData.total_findings !== undefined && statusData.total_findings > 0 && (
            <div className="text-right shrink-0">
              <span className="text-[11px] text-app-muted block uppercase font-mono">Findings</span>
              <span className="text-lg font-bold font-mono text-cyan-600 dark:text-cyan-400">
                {statusData.total_findings}
              </span>
            </div>
          )}
        </div>

        {/* Stalled Stage Advisory & Recovery Controls */}
        {isStalled && !isCompleted && !isFailed && (
          <div className="bg-amber-50 dark:bg-amber-950/40 border border-amber-300 dark:border-amber-800/80 rounded-xl p-4 flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3 text-xs text-amber-900 dark:text-amber-200">
            <div className="flex items-start gap-2.5">
              <AlertTriangle className="w-4 h-4 text-amber-600 dark:text-amber-400 shrink-0 mt-0.5" />
              <div>
                <span className="font-bold">In-Depth Stage Processing Active:</span>
                <p className="text-app-secondary dark:text-slate-300 mt-0.5 text-[11px]">
                  The engine is conducting deep disassembly, decompilation, or heuristic signature matching. The pipeline is actively progressing.
                </p>
              </div>
            </div>
            <div className="flex items-center gap-2 shrink-0 self-end sm:self-center">
              <button
                type="button"
                onClick={fetchStatus}
                className="px-3 py-1.5 rounded-lg border border-app bg-surface hover:bg-slate-200 dark:hover:bg-[#1e2736] text-app-primary text-xs font-mono font-medium flex items-center gap-1.5 transition-all cursor-pointer"
              >
                <RefreshCw className={`w-3.5 h-3.5 ${isRefreshing ? 'animate-spin' : ''}`} />
                <span>Refresh Status</span>
              </button>
              <button
                type="button"
                onClick={onViewReport}
                className="px-3 py-1.5 rounded-lg bg-amber-600 hover:bg-amber-700 text-white text-xs font-mono font-medium flex items-center gap-1.5 shadow-sm transition-all cursor-pointer"
              >
                <Eye className="w-3.5 h-3.5" />
                <span>Inspect Partial Results</span>
              </button>
            </div>
          </div>
        )}

        {/* Post-Completion Summary */}
        {isCompleted && (
          <div className="pt-5 border-t border-app flex flex-col sm:flex-row sm:items-center justify-between gap-4">
            <div className="flex items-center gap-3">
              <span className="text-xs font-medium text-app-secondary">Total Findings:</span>
              <span className="text-sm font-bold text-app-primary font-mono">{statusData.total_findings || 0}</span>
              {statusData.severity && (
                <SeverityBadge severity={statusData.severity} size="sm" />
              )}
            </div>

            <div className="flex flex-wrap items-center gap-3">
              <a
                href={api.getTxtReportUrl(statusData.id)}
                download
                className="bg-surface hover:bg-slate-200 dark:hover:bg-[#1e2736] border border-app text-app-primary text-xs px-3.5 py-2.5 rounded-lg font-bold flex items-center gap-1.5 transition-all shadow-sm"
              >
                <Download className="w-4 h-4 text-app-secondary" />
                <span>DOWNLOAD TXT REPORT</span>
              </a>
              <button
                onClick={onViewReport}
                className="bg-cyan-600 hover:bg-cyan-700 dark:bg-cyan-600 dark:hover:bg-cyan-500 text-white text-xs px-4 py-2.5 rounded-lg font-bold flex items-center gap-2 shadow-md hover:shadow-cyan-500/20 transition-all cursor-pointer"
              >
                <span>VIEW FULL REPORT</span>
                <ArrowRight className="w-4 h-4" />
              </button>
            </div>
          </div>
        )}
      </div>

      {/* Forensic Pipeline Stage Checklist */}
      <div className="bg-card border border-app rounded-2xl p-5 md:p-6 shadow-sm space-y-4">
        <div className="flex items-center justify-between border-b border-app pb-3">
          <div className="flex items-center gap-2">
            <Database className="w-4 h-4 text-cyan-500" />
            <h3 className="text-xs font-mono font-bold text-app-primary uppercase tracking-wider">
              Forensic Stage Execution Checklist
            </h3>
          </div>
          <span className="text-[11px] font-mono text-app-muted">
            9 Monotonic Pipeline Stages
          </span>
        </div>

        <div className="space-y-2">
          {(() => {
            const activeStageId = resolveActiveStageId(
              statusData.stage_index,
              currentPct,
              statusData.current_stage,
              isCompleted
            );

            return PIPELINE_STAGES.map((stage) => {
              const isStageDone = isCompleted || stage.id < activeStageId;
              const isStageActive = !isCompleted && !isFailed && !isCancelled && stage.id === activeStageId;
              const isStagePending = stage.id > activeStageId;

              return (
                <div
                  key={stage.id}
                  className={`flex items-center justify-between p-3 rounded-xl border text-xs font-mono transition-all ${
                    isStageDone
                      ? 'border-emerald-300/40 dark:border-emerald-900/40 bg-emerald-50/30 dark:bg-emerald-950/20 text-emerald-900 dark:text-emerald-300'
                      : isStageActive
                      ? 'border-cyan-500/50 dark:border-cyan-700/50 bg-cyan-50/40 dark:bg-cyan-950/30 text-cyan-900 dark:text-cyan-300 shadow-sm'
                      : 'border-app bg-surface/50 text-app-muted opacity-60'
                  }`}
                >
                  <div className="flex items-center gap-3 min-w-0">
                    <div className="shrink-0">
                      {isStageDone ? (
                        <CheckCircle2 className="w-4 h-4 text-emerald-600 dark:text-emerald-400" />
                      ) : isStageActive ? (
                        <Activity className="w-4 h-4 text-cyan-600 dark:text-cyan-400 animate-spin" />
                      ) : (
                        <div className="w-4 h-4 rounded-full border border-app flex items-center justify-center text-[10px] text-app-muted">
                          {stage.id}
                        </div>
                      )}
                    </div>
                    <div className="min-w-0">
                      <span className="font-bold">{stage.name}</span>
                      <span className="hidden md:inline text-[11px] text-app-muted ml-2 font-sans">
                        — {stage.desc}
                      </span>
                    </div>
                  </div>

                  <div className="shrink-0 flex items-center gap-2">
                    <span className="text-[10px] font-semibold px-2 py-0.5 rounded bg-surface border border-app">
                      {stage.minPct}%
                    </span>
                    {isStageDone && (
                      <span className="text-[10px] uppercase font-bold text-emerald-600 dark:text-emerald-400 hidden sm:inline">
                        VERIFIED
                      </span>
                    )}
                    {isStageActive && (
                      <span className="text-[10px] uppercase font-bold text-cyan-600 dark:text-cyan-400 animate-pulse hidden sm:inline">
                        PROCESSING
                      </span>
                    )}
                  </div>
                </div>
              );
            });
          })()}
        </div>
      </div>
    </div>
  );
};
