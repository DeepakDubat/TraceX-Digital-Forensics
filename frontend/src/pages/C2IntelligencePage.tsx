import React, { useState } from 'react';
import {
  RadioTower,
  ShieldAlert,
  Globe,
  Server,
  Filter,
  ExternalLink,
  Lock,
  Terminal,
  AlertTriangle,
  Info
} from 'lucide-react';
import { InvestigationDetail, C2Indicator } from '../types';
import { SeverityBadge } from '../components/SeverityBadge';

interface C2IntelligencePageProps {
  detail: InvestigationDetail;
}

export const C2IntelligencePage: React.FC<C2IntelligencePageProps> = ({ detail }) => {
  const [filterClass, setFilterClass] = useState<string>('all');
  const [search, setSearch] = useState('');

  const indicators = detail.c2_indicators || [];

  const filtered = indicators.filter((ind) => {
    const matchesFilter = filterClass === 'all' || ind.classification === filterClass;
    const matchesSearch =
      ind.value.toLowerCase().includes(search.toLowerCase()) ||
      ind.why_suspicious.toLowerCase().includes(search.toLowerCase()) ||
      ind.source_file.toLowerCase().includes(search.toLowerCase());
    return matchesFilter && matchesSearch;
  });

  const getClassificationColor = (cls: string) => {
    switch (cls) {
      case 'potential_c2':
      case 'reported_malicious':
        return 'bg-rose-100 dark:bg-rose-950/80 text-rose-800 dark:text-rose-300 border-rose-300 dark:border-rose-800 animate-pulse';
      case 'suspicious_destination':
        return 'bg-amber-100 dark:bg-amber-950/80 text-amber-800 dark:text-amber-300 border-amber-300 dark:border-amber-800';
      case 'third_party':
      case 'benign':
        return 'bg-slate-100 dark:bg-slate-800 text-slate-700 dark:text-slate-300 border-slate-300 dark:border-slate-700';
      case 'private_ip':
        return 'bg-blue-100 dark:bg-blue-950/80 text-blue-800 dark:text-blue-300 border-blue-300 dark:border-blue-800';
      default:
        return 'bg-surface text-app-secondary border-app';
    }
  };

  return (
    <div className="p-4 sm:p-6 md:p-8 space-y-6">
      {/* Header */}
      <div className="border-b border-app pb-4 flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <h1 className="text-xl md:text-2xl font-bold text-app-primary tracking-tight flex flex-wrap items-center gap-2.5">
            <span>C2 Configuration & Infrastructure</span>
            <span className="text-xs bg-surface text-amber-700 dark:text-amber-400 border border-app px-2.5 py-1 rounded-md font-mono font-medium">
              {indicators.length} Extracted Endpoints
            </span>
          </h1>
          <p className="text-xs md:text-sm text-app-secondary mt-1">
            Reconstructed remote command-and-control hostnames, hardcoded IPs, non-standard ports, and Dynamic DNS.
          </p>
        </div>

        {/* Passive Safe Analysis Pill */}
        <div className="flex items-center gap-2 bg-amber-50 dark:bg-[#10141d] border border-amber-300 dark:border-amber-800 px-3 py-1.5 rounded-lg text-xs font-semibold text-amber-800 dark:text-amber-300 shrink-0 shadow-sm">
          <Lock className="w-4 h-4 text-amber-600 dark:text-amber-400" />
          <span>PASSIVE AIR-GAPPED EVALUATION</span>
        </div>
      </div>

      {/* Filter and Search Bar */}
      <div className="flex flex-col sm:flex-row items-center gap-3">
        <input
          type="text"
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          placeholder="Search endpoints by domain, IP, path, or source..."
          className="forensics-input w-full sm:flex-1"
        />

        <div className="flex items-center gap-1 bg-surface p-1 border border-app rounded-xl text-xs overflow-x-auto w-full sm:w-auto shadow-sm">
          {['all', 'potential_c2', 'suspicious_destination', 'third_party', 'private_ip'].map((cls) => (
            <button
              key={cls}
              onClick={() => setFilterClass(cls)}
              className={`px-3 py-1.5 rounded-lg capitalize font-semibold transition-all cursor-pointer whitespace-nowrap ${
                filterClass === cls
                  ? 'bg-cyan-600 text-white shadow-sm'
                  : 'text-app-secondary hover:text-app-primary'
              }`}
            >
              {cls.replace('_', ' ')}
            </button>
          ))}
        </div>
      </div>

      {/* C2 Indicators Cards/Table */}
      {filtered.length === 0 ? (
        <div className="p-12 text-center text-app-muted border border-dashed border-app rounded-xl space-y-3 bg-surface">
          <RadioTower className="w-10 h-10 mx-auto text-app-muted" />
          <p className="text-xs md:text-sm font-medium">No C2 indicators matching the selected filter criteria.</p>
        </div>
      ) : (
        <div className="space-y-4">
          {filtered.map((ind, idx) => (
            <div
              key={idx}
              className="forensics-card p-5 space-y-3.5 rounded-xl hover:border-slate-400 dark:hover:border-[#303e54] transition-all"
            >
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2.5 border-b border-app pb-3">
                <div className="flex flex-wrap items-center gap-2 min-w-0">
                  <span className="text-xs text-app-muted font-bold font-mono bg-surface px-2 py-0.5 rounded border border-app">
                    {ind.id}
                  </span>
                  <span className="text-xs text-cyan-700 dark:text-cyan-300 font-bold uppercase bg-cyan-50 dark:bg-cyan-950/60 border border-cyan-300 dark:border-cyan-800 px-2 py-0.5 rounded-md">
                    {ind.indicator_type}
                  </span>
                  <span className="text-sm md:text-base font-bold text-app-primary font-mono tracking-wide truncate">
                    {ind.normalized_value}
                  </span>
                </div>

                <div className="flex items-center gap-2 shrink-0">
                  <span
                    className={`text-[11px] uppercase font-bold px-2.5 py-0.5 rounded-md border tracking-wider ${getClassificationColor(
                      ind.classification
                    )}`}
                  >
                    {ind.classification.replace('_', ' ')}
                  </span>
                  <SeverityBadge severity={ind.confidence === 'High' ? 'High' : 'Medium'} size="sm" />
                </div>
              </div>

              {/* Indicator Detail Grid */}
              <div className="grid grid-cols-1 md:grid-cols-3 gap-3 text-xs">
                <div>
                  <span className="text-[11px] text-app-muted uppercase font-semibold block">Source File / Context</span>
                  <p className="text-app-primary font-mono text-xs truncate mt-0.5">{ind.source_file}</p>
                  {ind.code_reference && (
                    <p className="text-xs text-cyan-600 dark:text-cyan-400 font-mono truncate mt-0.5">
                      Method: {ind.code_reference}
                    </p>
                  )}
                </div>

                <div>
                  <span className="text-[11px] text-app-muted uppercase font-semibold block">Port / Protocol</span>
                  <p className="text-app-primary font-medium text-xs mt-0.5">
                    {ind.port ? `${ind.port} (${ind.protocol?.toUpperCase() || 'TCP'})` : 'Default / Not Specified'}
                  </p>
                  {ind.encoding_steps && (
                    <p className="text-xs text-amber-600 dark:text-amber-400 font-mono mt-0.5">
                      {ind.encoding_steps}
                    </p>
                  )}
                </div>

                <div>
                  <span className="text-[11px] text-app-muted uppercase font-semibold block">Threat Intel Status</span>
                  <p className="text-app-secondary text-xs mt-0.5 font-medium">{ind.threat_intel_status}</p>
                </div>
              </div>

              {/* Analytical Rationale & Validation */}
              <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-xs bg-surface p-3.5 rounded-lg border border-app">
                <div>
                  <span className="text-[11px] text-amber-700 dark:text-amber-400 font-bold uppercase block mb-1">
                    Analytical Rationale
                  </span>
                  <p className="text-app-secondary text-xs leading-relaxed">{ind.why_suspicious}</p>
                </div>
                <div>
                  <span className="text-[11px] text-app-muted font-bold uppercase block mb-1">
                    Recommended Validation Procedure
                  </span>
                  <p className="text-app-secondary text-xs leading-relaxed">{ind.recommended_validation}</p>
                </div>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
};
