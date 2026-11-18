import React from 'react';
import {
  Globe,
  ShieldCheck,
  ShieldAlert,
  AlertTriangle,
  ExternalLink,
  Lock,
  RefreshCw,
  Search,
  CheckCircle2,
  XCircle
} from 'lucide-react';
import { InvestigationDetail, ThreatIntelResult } from '../types';

interface ThreatIntelPageProps {
  detail: InvestigationDetail;
}

export const ThreatIntelPage: React.FC<ThreatIntelPageProps> = ({ detail }) => {
  const intelResults = detail.threat_intel || [];
  const rec = detail.record;

  const getStatusBadge = (status: string) => {
    switch (status) {
      case 'malicious':
        return (
          <span className="text-[11px] bg-rose-50 dark:bg-rose-950 text-rose-800 dark:text-rose-300 border border-rose-300 dark:border-rose-800 px-2.5 py-0.5 rounded font-bold uppercase flex items-center gap-1.5 font-mono">
            <XCircle className="w-3.5 h-3.5 text-rose-600 dark:text-rose-400" /> MALICIOUS
          </span>
        );
      case 'suspicious':
        return (
          <span className="text-[11px] bg-amber-50 dark:bg-amber-950 text-amber-800 dark:text-amber-300 border border-amber-300 dark:border-amber-800 px-2.5 py-0.5 rounded font-bold uppercase flex items-center gap-1.5 font-mono">
            <AlertTriangle className="w-3.5 h-3.5 text-amber-600 dark:text-amber-400" /> SUSPICIOUS
          </span>
        );
      case 'clean':
        return (
          <span className="text-[11px] bg-emerald-50 dark:bg-emerald-950 text-emerald-800 dark:text-emerald-300 border border-emerald-300 dark:border-emerald-800 px-2.5 py-0.5 rounded font-bold uppercase flex items-center gap-1.5 font-mono">
            <CheckCircle2 className="w-3.5 h-3.5 text-emerald-600 dark:text-emerald-400" /> CLEAN
          </span>
        );
      case 'not_found':
        return (
          <span className="text-[11px] bg-surface text-app-muted border border-app px-2.5 py-0.5 rounded font-medium uppercase font-mono">
            NOT FOUND (UNINDEXED)
          </span>
        );
      case 'rate_limited':
        return (
          <span className="text-[11px] bg-yellow-50 dark:bg-yellow-950 text-yellow-800 dark:text-yellow-400 border border-yellow-300 dark:border-yellow-800 px-2.5 py-0.5 rounded font-medium uppercase font-mono">
            RATE LIMITED
          </span>
        );
      case 'skipped':
        return (
          <span className="text-[11px] bg-surface text-app-muted border border-app px-2.5 py-0.5 rounded font-medium uppercase font-mono">
            SKIPPED / UNCONFIGURED
          </span>
        );
      default:
        return (
          <span className="text-[11px] bg-surface text-app-secondary px-2.5 py-0.5 rounded font-medium uppercase font-mono border border-app">
            {status}
          </span>
        );
    }
  };

  return (
    <div className="p-4 sm:p-6 md:p-8 space-y-6">
      {/* Header */}
      <div className="border-b border-app pb-4 flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <h1 className="text-xl md:text-2xl font-bold text-app-primary tracking-tight flex flex-wrap items-center gap-2.5">
            <span>Threat Intelligence Enrichment</span>
            <span className="text-xs bg-surface text-cyan-700 dark:text-cyan-400 border border-app px-2.5 py-1 rounded-md font-mono font-medium">
              Passive Reputation Logs
            </span>
          </h1>
          <p className="text-xs md:text-sm text-app-secondary mt-1">
            Correlated telemetry across VirusTotal, AbuseIPDB, AlienVault OTX, URLhaus, and MalwareBazaar.
          </p>
        </div>

        {/* Upload Protection Banner */}
        <div className="flex items-center gap-2 bg-cyan-50 dark:bg-cyan-950/40 border border-cyan-300 dark:border-cyan-800 px-3 py-1.5 rounded-lg text-xs font-semibold text-cyan-800 dark:text-cyan-300 shrink-0 shadow-sm">
          <Lock className="w-4 h-4 text-cyan-600 dark:text-cyan-400" />
          <span>PASSIVE AIR-GAPPED QUERIES ONLY</span>
        </div>
      </div>

      {/* Primary Hash Quick Lookup Links */}
      <div className="forensics-card rounded-xl p-5 space-y-3.5 shadow-sm">
        <span className="text-xs font-bold text-app-primary uppercase tracking-wider block">
          Investigator Reputation Resource Shortcuts
        </span>
        <div className="flex flex-wrap items-center gap-3 text-xs">
          <a
            href={`https://www.virustotal.com/gui/file/${rec.sha256}`}
            target="_blank"
            rel="noreferrer"
            className="bg-surface hover:bg-slate-200 dark:hover:bg-[#1e2736] border border-app text-cyan-700 dark:text-cyan-400 px-3.5 py-2 rounded-lg font-bold flex items-center gap-2 transition-all shadow-sm"
          >
            <Globe className="w-4 h-4" />
            <span>Search VirusTotal by SHA-256</span>
            <ExternalLink className="w-3.5 h-3.5 text-app-muted" />
          </a>

          <a
            href={`https://bazaar.abuse.ch/sample/${rec.sha256}/`}
            target="_blank"
            rel="noreferrer"
            className="bg-surface hover:bg-slate-200 dark:hover:bg-[#1e2736] border border-app text-app-primary px-3.5 py-2 rounded-lg font-bold flex items-center gap-2 transition-all shadow-sm"
          >
            <Globe className="w-4 h-4" />
            <span>MalwareBazaar Lookup</span>
            <ExternalLink className="w-3.5 h-3.5 text-app-muted" />
          </a>

          <a
            href={`https://otx.alienvault.com/indicator/file/${rec.sha256}`}
            target="_blank"
            rel="noreferrer"
            className="bg-surface hover:bg-slate-200 dark:hover:bg-[#1e2736] border border-app text-app-primary px-3.5 py-2 rounded-lg font-bold flex items-center gap-2 transition-all shadow-sm"
          >
            <Globe className="w-4 h-4" />
            <span>AlienVault OTX Pulse</span>
            <ExternalLink className="w-3.5 h-3.5 text-app-muted" />
          </a>
        </div>
      </div>

      {/* Threat Intel Query Log Table */}
      <div className="forensics-card rounded-xl overflow-hidden shadow-sm">
        <div className="p-4 border-b border-app bg-surface flex items-center justify-between">
          <span className="text-xs font-bold text-app-primary uppercase">Recorded Threat Intelligence Results</span>
          <span className="text-xs text-app-muted font-medium">{intelResults.length} Queries Recorded</span>
        </div>

        {intelResults.length === 0 ? (
          <div className="p-12 text-center text-app-muted space-y-2">
            <Globe className="w-10 h-10 mx-auto text-app-muted" />
            <p className="text-sm font-medium text-app-primary">No external threat intelligence queries recorded.</p>
            <p className="text-xs text-app-secondary">
              Either Local-Only Mode was enforced during analysis or API keys were not configured in Settings.
            </p>
          </div>
        ) : (
          <div className="divide-y divide-app">
            {intelResults.map((ti, idx) => (
              <div key={idx} className="p-4 text-xs space-y-2.5 hover:bg-surface/50 transition-colors">
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                  <div className="flex flex-wrap items-center gap-2">
                    <span className="font-bold text-app-primary text-sm font-mono">{ti.provider}</span>
                    <span className="text-[11px] bg-surface text-app-secondary border border-app px-2 py-0.5 rounded font-mono uppercase">
                      TYPE: {ti.indicator_type}
                    </span>
                  </div>

                  <div className="flex items-center gap-2 shrink-0">
                    {getStatusBadge(ti.status)}
                    <span className="text-app-primary font-bold font-mono">
                      {ti.detections} / {ti.total_engines} Engines
                    </span>
                  </div>
                </div>

                <div className="text-cyan-700 dark:text-cyan-400 break-all font-mono text-xs font-semibold">
                  Indicator: {ti.indicator}
                </div>

                {ti.details && Object.keys(ti.details).length > 0 && (
                  <div className="bg-surface border border-app p-3 rounded-lg text-xs text-app-secondary font-mono overflow-x-auto">
                    {JSON.stringify(ti.details)}
                  </div>
                )}

                {ti.error_message && (
                  <div className="text-xs text-rose-600 dark:text-rose-400 font-mono">Notice: {ti.error_message}</div>
                )}

                <div className="text-[11px] text-app-muted">
                  Queried at: {new Date(ti.query_time).toUTCString()}
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
};
