import React from 'react';
import {
  ShieldAlert,
  RadioTower,
  KeyRound,
  TerminalSquare,
  Activity,
  Files,
  ArrowRight,
  Download,
  AlertTriangle,
  FolderOpen
} from 'lucide-react';
import { DashboardStats, InvestigationRecord } from '../types';
import { SeverityBadge } from '../components/SeverityBadge';
import { api } from '../api';

interface DashboardPageProps {
  stats: DashboardStats | null;
  loading: boolean;
  onSelectInvestigation: (id: string) => void;
  onNavigateNew: () => void;
}

export const DashboardPage: React.FC<DashboardPageProps> = ({
  stats,
  loading,
  onSelectInvestigation,
  onNavigateNew,
}) => {
  if (loading || !stats) {
    return (
      <div className="p-8 flex items-center justify-center h-full text-app-secondary font-mono">
        <Activity className="w-5 h-5 animate-spin mr-3 text-cyan-600 dark:text-cyan-400" />
        Loading forensic workstation statistics...
      </div>
    );
  }

  const totalPersist = (stats.detected_reverse_shell_indicators || 0) + (stats.detected_persistence_indicators || 0);

  const statCards = [
    {
      title: 'TOTAL INVESTIGATIONS',
      value: stats.total_investigations,
      desc: `${stats.apk_files_analyzed} APK / ${stats.exe_files_analyzed || 0} EXE`,
      icon: Files,
      color: 'text-cyan-600 dark:text-cyan-400',
      badgeBg: 'bg-cyan-50 dark:bg-cyan-950/40 text-cyan-700 dark:text-cyan-300 border-cyan-200 dark:border-cyan-800',
    },
    {
      title: 'SUSPICIOUS SAMPLES',
      value: stats.files_with_suspicious_indicators,
      desc: 'APK & EXE exhibiting anomalies',
      icon: AlertTriangle,
      color: 'text-amber-600 dark:text-amber-400',
      badgeBg: 'bg-amber-50 dark:bg-amber-950/40 text-amber-700 dark:text-amber-300 border-amber-200 dark:border-amber-800',
    },
    {
      title: 'HIGH-CONFIDENCE MALWARE',
      value: stats.high_confidence_malware_findings,
      desc: 'Critical/High risk assessments',
      icon: ShieldAlert,
      color: 'text-rose-600 dark:text-rose-400',
      badgeBg: 'bg-rose-50 dark:bg-rose-950/40 text-rose-700 dark:text-rose-300 border-rose-200 dark:border-rose-800',
    },
    {
      title: 'C2 CONFIGURATIONS',
      value: stats.potential_c2_configurations,
      desc: 'Hardcoded / Dynamic C2 endpoints',
      icon: RadioTower,
      color: 'text-indigo-600 dark:text-indigo-400',
      badgeBg: 'bg-indigo-50 dark:bg-indigo-950/40 text-indigo-700 dark:text-indigo-300 border-indigo-200 dark:border-indigo-800',
    },
    {
      title: 'REV-SHELL & PERSISTENCE',
      value: totalPersist,
      desc: `${stats.detected_reverse_shell_indicators || 0} Shell / ${stats.detected_persistence_indicators || 0} Persist`,
      icon: TerminalSquare,
      color: totalPersist > 0 ? 'text-rose-600 dark:text-rose-400' : 'text-app-muted',
      badgeBg: totalPersist > 0 ? 'bg-rose-50 dark:bg-rose-950/40 text-rose-700 dark:text-rose-300 border-rose-200 dark:border-rose-800' : 'bg-surface text-app-secondary border-app',
    },
    {
      title: 'EXTRACTED SECRETS',
      value: stats.detected_secrets_count,
      desc: 'API keys, tokens, credentials',
      icon: KeyRound,
      color: 'text-sky-600 dark:text-sky-400',
      badgeBg: 'bg-sky-50 dark:bg-sky-950/40 text-sky-700 dark:text-sky-300 border-sky-200 dark:border-sky-800',
    },
  ];

  return (
    <div className="p-6 md:p-8 space-y-6">
      {/* Station Title Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-app pb-5">
        <div>
          <h1 className="text-2xl font-bold text-app-primary tracking-tight flex items-center gap-3">
            <span>Forensic Examination Dashboard</span>
            <span className="text-xs bg-surface text-app-secondary border border-app px-2.5 py-1 rounded-md font-mono font-medium">
              LOCAL WORKSTATION
            </span>
          </h1>
          <p className="text-sm text-app-secondary mt-1">
            Multi-platform forensic investigation records (Android APK & Windows PE EXE), threat intelligence metrics, and passive analysis summaries.
          </p>
        </div>

        <button
          onClick={onNavigateNew}
          type="button"
          className="bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-mono px-4 py-2.5 rounded-lg font-bold tracking-wider flex items-center gap-2 shadow-sm transition-all cursor-pointer w-fit"
        >
          <span>INGEST TARGET (APK / EXE)</span>
          <ArrowRight className="w-4 h-4" />
        </button>
      </div>

      {/* Forensic Stat Grid */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-6 gap-4">
        {statCards.map((card, idx) => {
          const Icon = card.icon;
          return (
            <div
              key={idx}
              className="forensics-card p-4 flex flex-col justify-between"
            >
              <div className="flex items-center justify-between">
                <span className="text-[11px] uppercase font-mono tracking-wider text-app-muted font-bold truncate">
                  {card.title}
                </span>
                <div className={`p-1.5 rounded-md border ${card.badgeBg}`}>
                  <Icon className={`w-4 h-4 ${card.color}`} />
                </div>
              </div>
              <div className="mt-3">
                <div className="text-2xl font-bold font-mono tracking-tight text-app-primary">
                  {card.value}
                </div>
                <p className="text-xs text-app-secondary mt-0.5 truncate font-mono">{card.desc}</p>
              </div>
            </div>
          );
        })}
      </div>

      {/* Recent Investigations Table */}
      <div className="forensics-card overflow-hidden">
        <div className="p-4 border-b border-app bg-surface flex items-center justify-between">
          <div className="flex items-center gap-2.5">
            <Files className="w-4 h-4 text-cyan-600 dark:text-cyan-400" />
            <h2 className="text-sm font-bold text-app-primary font-mono tracking-wide">
              RECENT FORENSIC INVESTIGATIONS
            </h2>
          </div>
          <span className="text-xs text-app-secondary font-mono">
            {stats.recent_investigations.length} Records
          </span>
        </div>

        {stats.recent_investigations.length === 0 ? (
          <div className="p-12 text-center text-app-secondary space-y-3">
            <FolderOpen className="w-10 h-10 mx-auto text-app-muted" />
            <p className="text-sm font-medium text-app-primary">No investigations conducted yet.</p>
            <p className="text-xs text-app-secondary max-w-md mx-auto">
              Upload a target APK or Windows EXE to begin cryptographic hashing, PE validation, decompilation, C2 extraction, and risk assessment.
            </p>
            <button
              onClick={onNavigateNew}
              className="mt-2 text-cyan-600 dark:text-cyan-400 hover:underline text-xs font-semibold cursor-pointer"
            >
              Start first investigation →
            </button>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="forensics-table">
              <thead>
                <tr>
                  <th>Format</th>
                  <th>Investigation ID</th>
                  <th>Target Binary</th>
                  <th>SHA-256 Hash</th>
                  <th>Severity</th>
                  <th>C2 / Secrets</th>
                  <th>Shell / Persist</th>
                  <th>Status</th>
                  <th className="text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-app">
                {stats.recent_investigations.map((inv) => (
                  <tr
                    key={inv.id}
                    className="hover:bg-card-hover transition-colors cursor-pointer"
                    onClick={() => onSelectInvestigation(inv.id)}
                  >
                    <td>
                      {inv.file_type === 'exe' ? (
                        <span className="text-[11px] font-bold bg-amber-100 text-amber-900 border border-amber-300 dark:bg-amber-950 dark:text-amber-300 dark:border-amber-800 px-2 py-0.5 rounded font-mono">
                          EXE
                        </span>
                      ) : (
                        <span className="text-[11px] font-bold bg-cyan-100 text-cyan-900 border border-cyan-300 dark:bg-cyan-950 dark:text-cyan-300 dark:border-cyan-800 px-2 py-0.5 rounded font-mono">
                          APK
                        </span>
                      )}
                    </td>
                    <td className="font-bold text-cyan-600 dark:text-cyan-400 truncate max-w-[130px] font-mono">
                      {inv.id}
                    </td>
                    <td>
                      <div className="font-semibold text-app-primary truncate max-w-[200px]">
                        {inv.filename}
                      </div>
                      <div className="text-xs text-app-muted truncate max-w-[200px]">
                        {inv.file_type === 'exe'
                          ? (inv.package_name || 'Windows PE Executable')
                          : (inv.package_name || 'Android Package')}
                      </div>
                    </td>
                    <td className="text-app-secondary truncate max-w-[130px] font-mono text-xs">
                      {inv.sha256 ? `${inv.sha256.slice(0, 14)}...` : 'N/A'}
                    </td>
                    <td>
                      <SeverityBadge severity={inv.severity} size="sm" />
                    </td>
                    <td className="text-app-secondary font-mono text-xs">
                      <span className="text-amber-600 dark:text-amber-400 font-semibold">{inv.c2_count} C2</span> /{' '}
                      <span className="text-sky-600 dark:text-sky-400 font-semibold">{inv.secret_count} Sec</span>
                    </td>
                    <td>
                      {inv.reverse_shell_detected ? (
                        <span className="text-rose-700 bg-rose-100 border border-rose-300 dark:bg-rose-950/80 dark:text-rose-300 dark:border-rose-800 px-2 py-0.5 rounded text-[11px] font-bold font-mono">
                          {inv.file_type === 'exe' ? 'PERSISTENCE' : 'REV-SHELL'}
                        </span>
                      ) : (
                        <span className="text-app-muted text-xs font-mono">None</span>
                      )}
                    </td>
                    <td>
                      <span
                        className={`text-[11px] px-2 py-0.5 rounded uppercase font-semibold font-mono ${
                          inv.status === 'completed'
                            ? 'bg-emerald-100 text-emerald-800 border border-emerald-300 dark:bg-emerald-950/60 dark:text-emerald-400 dark:border-emerald-800'
                            : inv.status === 'analyzing'
                            ? 'bg-indigo-100 text-indigo-800 border border-indigo-300 dark:bg-indigo-950/60 dark:text-indigo-400 dark:border-indigo-800 animate-pulse'
                            : 'bg-surface text-app-secondary border border-app'
                        }`}
                      >
                        {inv.status}
                      </span>
                    </td>
                    <td className="text-right space-x-2" onClick={(e) => e.stopPropagation()}>
                      <button
                        onClick={() => onSelectInvestigation(inv.id)}
                        className="text-cyan-600 dark:text-cyan-400 hover:underline font-semibold text-xs cursor-pointer font-mono"
                      >
                        Examine
                      </button>
                      <a
                        href={api.getTxtReportUrl(inv.id)}
                        download
                        className="text-app-secondary hover:text-app-primary inline-flex items-center gap-1 text-xs border border-app bg-surface px-2 py-0.5 rounded hover:bg-card-hover font-mono"
                        title="Download TXT Report"
                      >
                        <Download className="w-3 h-3" />
                        <span>TXT</span>
                      </a>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
};

