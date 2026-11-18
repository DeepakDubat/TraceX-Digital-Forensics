import React, { useState, useMemo } from 'react';
import {
  FileCode2,
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  Layers,
  Award,
  Box,
  Cpu,
  Search,
  ExternalLink,
  Info,
  Monitor,
  Binary,
  Lock,
  Hash,
  CheckCircle2,
  Flame,
  FileCheck,
  ChevronDown,
  ChevronUp,
  Copy,
  Check,
  Filter
} from 'lucide-react';
import { InvestigationDetail, StaticFinding, PeSection, ImportedDll } from '../types';
import { SeverityBadge } from '../components/SeverityBadge';
import { api } from '../api';

interface StaticAnalysisPageProps {
  detail: InvestigationDetail;
}

export const StaticAnalysisPage: React.FC<StaticAnalysisPageProps> = ({ detail }) => {
  const isExe = detail.record.file_type === 'exe';
  const [searchTerm, setSearchTerm] = useState('');
  const [severityFilter, setSeverityFilter] = useState<string>('all');
  const [categoryFilter, setCategoryFilter] = useState<string>('all');
  const [classificationFilter, setClassificationFilter] = useState<string>('all');
  const [expandedFindings, setExpandedFindings] = useState<Record<string, boolean>>({});
  const [copiedId, setCopiedId] = useState<string | null>(null);

  // OpenCode AI-assisted observations state
  const [aiObservations, setAiObservations] = useState(detail.ai_observations || []);
  const [aiRecommendations, setAiRecommendations] = useState(detail.ai_recommendations || []);
  const [aiNotes, setAiNotes] = useState(detail.ai_notes || null);
  const [isAiRunning, setIsAiRunning] = useState(false);
  const [consentApproved, setConsentApproved] = useState(false);
  const [reviewNoteInputs, setReviewNoteInputs] = useState<Record<string, string>>({});
  const [aiActionMessage, setAiActionMessage] = useState<string | null>(null);

  // Tab state: adaptive for APK vs EXE
  const [activeTab, setActiveTab] = useState<string>('findings');

  const meta = detail.metadata;
  const peMeta = detail.pe_metadata;
  const findings = detail.static_findings || [];

  const categoriesList = useMemo(() => {
    const set = new Set<string>();
    findings.forEach((f) => {
      if (f.category) set.add(f.category);
    });
    return Array.from(set).sort();
  }, [findings]);

  const stats = useMemo(() => {
    let critical = 0;
    let high = 0;
    let medium = 0;
    let low = 0;
    let info = 0;
    let confirmedFact = 0;
    let suspiciousInd = 0;
    let heuristicDet = 0;

    findings.forEach((f) => {
      const sev = (f.severity || '').toLowerCase();
      if (sev === 'critical') critical++;
      else if (sev === 'high') high++;
      else if (sev === 'medium') medium++;
      else if (sev === 'low') low++;
      else info++;

      const cls = (f.classification || '').toUpperCase();
      if (cls === 'CONFIRMED FACT') confirmedFact++;
      else if (cls === 'SUSPICIOUS INDICATOR') suspiciousInd++;
      else heuristicDet++;
    });

    return {
      total: findings.length,
      critical,
      high,
      medium,
      low,
      info,
      confirmedFact,
      suspiciousInd,
      heuristicDet,
    };
  }, [findings]);

  const toggleExpand = (id: string) => {
    setExpandedFindings((prev) => ({
      ...prev,
      [id]: !prev[id],
    }));
  };

  const handleCopySafeEvidence = (finding: StaticFinding) => {
    const text = [
      `[TraceX Static Forensic Finding]`,
      `ID: ${finding.finding_id || finding.id}`,
      `Title: ${finding.title}`,
      `Severity: ${finding.severity} | Confidence: ${finding.confidence}`,
      `Classification: ${finding.classification || 'HEURISTIC DETECTION'}`,
      `Category: ${finding.category}`,
      `File: ${finding.file_path || finding.source_file || 'N/A'}`,
      `Reference: ${finding.offset_or_reference || finding.code_reference || 'N/A'}`,
      `Evidence Excerpt: ${finding.supporting_evidence || finding.evidence_snippet || 'N/A'}`,
      `Reason: ${finding.reason_for_detection || finding.description}`,
      `Potential Impact: ${finding.potential_impact || 'N/A'}`,
      `Forensic Guidance: ${finding.remediation || finding.remediation_advice || 'N/A'}`
    ].join('\n');

    navigator.clipboard.writeText(text);
    setCopiedId(finding.id);
    setTimeout(() => setCopiedId(null), 2000);
  };

  const handleReviewObservation = async (obsId: string, status: 'ACCEPTED' | 'REJECTED' | 'UNVERIFIED') => {
    try {
      const notes = reviewNoteInputs[obsId] || '';
      const res = await api.reviewAIObservation(detail.record.id, obsId, status, notes);
      setAiObservations((prev) =>
        prev.map((o) => (o.id === obsId ? { ...o, status, reviewer: 'Examiner', review_notes: notes } : o))
      );
      setAiActionMessage(`Observation ${obsId} status updated to ${status}.`);
      setTimeout(() => setAiActionMessage(null), 4000);
    } catch (err: any) {
      setAiActionMessage(`Failed to update observation: ${err.message}`);
      setTimeout(() => setAiActionMessage(null), 5000);
    }
  };

  const handleTriggerAIAnalysis = async () => {
    setIsAiRunning(true);
    setAiActionMessage(null);
    try {
      const res = await api.triggerAIAnalysis(detail.record.id, consentApproved);
      if (res.notes) setAiNotes(res.notes);
      if (res.observations) setAiObservations(res.observations);
      if (res.recommendations) setAiRecommendations(res.recommendations);
      setAiActionMessage(
        res.success
          ? 'AI-assisted analysis completed successfully.'
          : (res.notes?.warnings_or_errors?.[0] || 'AI analysis skipped or completed with warnings.')
      );
    } catch (err: any) {
      setAiActionMessage(`AI Analysis Error: ${err.message}`);
    } finally {
      setIsAiRunning(false);
      setTimeout(() => setAiActionMessage(null), 6000);
    }
  };

  const filteredFindings = useMemo(() => {
    return findings.filter((f) => {
      if (severityFilter !== 'all' && f.severity.toLowerCase() !== severityFilter.toLowerCase()) {
        return false;
      }
      if (categoryFilter !== 'all' && f.category.toLowerCase() !== categoryFilter.toLowerCase()) {
        return false;
      }
      if (classificationFilter !== 'all') {
        const cls = (f.classification || 'HEURISTIC DETECTION').toUpperCase();
        if (cls !== classificationFilter.toUpperCase()) return false;
      }
      if (searchTerm.trim()) {
        const q = searchTerm.toLowerCase();
        const matchTitle = (f.title || '').toLowerCase().includes(q);
        const matchDesc = (f.description || '').toLowerCase().includes(q);
        const matchCat = (f.category || '').toLowerCase().includes(q);
        const matchId = (f.finding_id || f.id || '').toLowerCase().includes(q);
        const matchFile = (f.file_path || f.source_file || '').toLowerCase().includes(q);
        const matchRef = (f.offset_or_reference || f.code_reference || '').toLowerCase().includes(q);
        if (!matchTitle && !matchDesc && !matchCat && !matchId && !matchFile && !matchRef) {
          return false;
        }
      }
      return true;
    });
  }, [findings, severityFilter, categoryFilter, classificationFilter, searchTerm]);

  return (
    <div className="p-4 sm:p-6 md:p-8 space-y-6">
      {/* Header */}
      <div className="border-b border-app pb-4 flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <h1 className="text-xl md:text-2xl font-bold text-app-primary tracking-tight flex flex-wrap items-center gap-2.5">
            <span>{isExe ? 'Windows PE Static Forensics' : 'Static Forensic Analysis'}</span>
            <span className="text-xs bg-surface text-cyan-700 dark:text-cyan-300 border border-app px-2.5 py-1 rounded-md font-mono font-medium truncate max-w-xs">
              {detail.record.filename}
            </span>
            <span className={`text-[11px] px-2.5 py-0.5 rounded-full font-bold uppercase border ${
              isExe
                ? 'bg-cyan-50 dark:bg-cyan-950/80 text-cyan-700 dark:text-cyan-300 border-cyan-300 dark:border-cyan-800'
                : 'bg-emerald-50 dark:bg-emerald-950/80 text-emerald-700 dark:text-emerald-300 border-emerald-300 dark:border-emerald-800'
            }`}>
              {isExe ? 'PE32 / PE32+' : 'Android APK'}
            </span>
          </h1>
          <p className="text-xs md:text-sm text-app-secondary mt-1">
            {isExe
              ? 'Structural inspection, headers, section entropy, API capability mapping, and version resources.'
              : 'Manifest inspection, dangerous permissions, exported components, certificates, and DEX bytecode findings.'}
          </p>
        </div>

        {/* Tab Navigation */}
        <div className="flex items-center gap-1 bg-surface p-1 border border-app rounded-xl text-xs overflow-x-auto shrink-0 shadow-sm">
          <button
            onClick={() => setActiveTab('findings')}
            className={`px-3 py-1.5 rounded-lg font-semibold transition-all cursor-pointer ${
              activeTab === 'findings'
                ? 'bg-cyan-600 text-white shadow-sm'
                : 'text-app-secondary hover:text-app-primary'
            }`}
          >
            Findings ({findings.length})
          </button>

          {isExe ? (
            <>
              <button
                onClick={() => setActiveTab('pe_metadata')}
                className={`px-3 py-1.5 rounded-lg font-semibold transition-all cursor-pointer whitespace-nowrap ${
                  activeTab === 'pe_metadata'
                    ? 'bg-cyan-600 text-white shadow-sm'
                    : 'text-app-secondary hover:text-app-primary'
                }`}
              >
                PE Headers & Meta
              </button>
              <button
                onClick={() => setActiveTab('pe_sections')}
                className={`px-3 py-1.5 rounded-lg font-semibold transition-all cursor-pointer whitespace-nowrap ${
                  activeTab === 'pe_sections'
                    ? 'bg-cyan-600 text-white shadow-sm'
                    : 'text-app-secondary hover:text-app-primary'
                }`}
              >
                Sections & Entropy ({peMeta?.sections.length || 0})
              </button>
              <button
                onClick={() => setActiveTab('pe_imports')}
                className={`px-3 py-1.5 rounded-lg font-semibold transition-all cursor-pointer whitespace-nowrap ${
                  activeTab === 'pe_imports'
                    ? 'bg-cyan-600 text-white shadow-sm'
                    : 'text-app-secondary hover:text-app-primary'
                }`}
              >
                Imported APIs ({peMeta?.imports.length || 0})
              </button>
              <button
                onClick={() => setActiveTab('pe_signature')}
                className={`px-3 py-1.5 rounded-lg font-semibold transition-all cursor-pointer ${
                  activeTab === 'pe_signature'
                    ? 'bg-cyan-600 text-white shadow-sm'
                    : 'text-app-secondary hover:text-app-primary'
                }`}
              >
                Signature
              </button>
            </>
          ) : (
            <>
              <button
                onClick={() => setActiveTab('permissions')}
                className={`px-3 py-1.5 rounded-lg font-semibold transition-all cursor-pointer whitespace-nowrap ${
                  activeTab === 'permissions'
                    ? 'bg-cyan-600 text-white shadow-sm'
                    : 'text-app-secondary hover:text-app-primary'
                }`}
              >
                Permissions ({meta?.permissions.length || 0})
              </button>
              <button
                onClick={() => setActiveTab('components')}
                className={`px-3 py-1.5 rounded-lg font-semibold transition-all cursor-pointer ${
                  activeTab === 'components'
                    ? 'bg-cyan-600 text-white shadow-sm'
                    : 'text-app-secondary hover:text-app-primary'
                }`}
              >
                Components
              </button>
              <button
                onClick={() => setActiveTab('certs')}
                className={`px-3 py-1.5 rounded-lg font-semibold transition-all cursor-pointer whitespace-nowrap ${
                  activeTab === 'certs'
                    ? 'bg-cyan-600 text-white shadow-sm'
                    : 'text-app-secondary hover:text-app-primary'
                }`}
              >
                Certificates ({meta?.certificates.length || 0})
              </button>
              <button
                onClick={() => setActiveTab('binaries')}
                className={`px-3 py-1.5 rounded-lg font-semibold transition-all cursor-pointer whitespace-nowrap ${
                  activeTab === 'binaries'
                    ? 'bg-cyan-600 text-white shadow-sm'
                    : 'text-app-secondary hover:text-app-primary'
                }`}
              >
                Binaries & DEX
              </button>
            </>
          )}

          <button
            onClick={() => setActiveTab('ai_observations')}
            className={`px-3 py-1.5 rounded-lg font-semibold transition-all cursor-pointer whitespace-nowrap flex items-center gap-1.5 ${
              activeTab === 'ai_observations'
                ? 'bg-indigo-600 text-white shadow-sm'
                : 'text-app-secondary hover:text-app-primary'
            }`}
          >
            <Cpu className="w-3.5 h-3.5" />
            <span>AI Observations ({aiObservations.length})</span>
          </button>
        </div>
      </div>

      {/* QUICK SUMMARY CARDS */}
      {isExe && peMeta ? (
        <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-3">
          <div className="forensics-card p-3.5 rounded-xl">
            <span className="text-[11px] font-semibold text-app-muted uppercase">Architecture</span>
            <div className="font-bold text-app-primary truncate mt-1 text-sm">{peMeta.machine}</div>
          </div>
          <div className="forensics-card p-3.5 rounded-xl">
            <span className="text-[11px] font-semibold text-app-muted uppercase">PE Format</span>
            <div className="font-bold text-cyan-600 dark:text-cyan-400 truncate mt-1 text-sm font-mono">{peMeta.magic}</div>
          </div>
          <div className="forensics-card p-3.5 rounded-xl">
            <span className="text-[11px] font-semibold text-app-muted uppercase">Entry Point (RVA)</span>
            <div className="font-bold text-emerald-600 dark:text-emerald-400 font-mono truncate mt-1 text-sm">{peMeta.entry_point_rva}</div>
          </div>
          <div className="forensics-card p-3.5 rounded-xl">
            <span className="text-[11px] font-semibold text-app-muted uppercase">Sections Count</span>
            <div className="font-bold text-app-primary truncate mt-1 text-sm">{peMeta.number_of_sections} sections</div>
          </div>
          <div className="forensics-card p-3.5 rounded-xl">
            <span className="text-[11px] font-semibold text-app-muted uppercase">Packer Status</span>
            <div className={`font-bold mt-1 text-xs truncate ${peMeta.packer_detected ? 'text-rose-600 dark:text-rose-400 animate-pulse' : 'text-emerald-600 dark:text-emerald-400'}`}>
              {peMeta.packer_detected ? 'PACKER DETECTED' : 'UNPACKED / NORMAL'}
            </div>
          </div>
          <div className="forensics-card p-3.5 rounded-xl">
            <span className="text-[11px] font-semibold text-app-muted uppercase">Digital Signature</span>
            <div className={`font-bold mt-1 text-xs truncate ${peMeta.is_signed ? 'text-emerald-600 dark:text-emerald-400' : 'text-amber-600 dark:text-amber-400'}`}>
              {peMeta.is_signed ? 'AUTHENTICODE SIGNED' : 'UNSIGNED BINARY'}
            </div>
          </div>
        </div>
      ) : meta ? (
        <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-3">
          <div className="forensics-card p-3.5 rounded-xl">
            <span className="text-[11px] font-semibold text-app-muted uppercase">Package Name</span>
            <div className="font-bold text-app-primary truncate mt-1 text-xs font-mono">{meta.package_name || 'N/A'}</div>
          </div>
          <div className="forensics-card p-3.5 rounded-xl">
            <span className="text-[11px] font-semibold text-app-muted uppercase">Version Name / Code</span>
            <div className="font-bold text-app-primary truncate mt-1 text-sm">
              {meta.version_name || '1.0'} ({meta.version_code || '1'})
            </div>
          </div>
          <div className="forensics-card p-3.5 rounded-xl">
            <span className="text-[11px] font-semibold text-app-muted uppercase">Target / Min SDK</span>
            <div className="font-bold text-cyan-600 dark:text-cyan-400 truncate mt-1 text-sm">
              API {meta.target_sdk_version || 'N/A'} (Min: {meta.min_sdk_version || 'N/A'})
            </div>
          </div>
          <div className="forensics-card p-3.5 rounded-xl">
            <span className="text-[11px] font-semibold text-app-muted uppercase">Debuggable</span>
            <div className={`font-bold mt-1 text-xs truncate ${meta.is_debuggable ? 'text-rose-600 dark:text-rose-400' : 'text-emerald-600 dark:text-emerald-400'}`}>
              {meta.is_debuggable ? 'TRUE (RISK)' : 'FALSE'}
            </div>
          </div>
          <div className="forensics-card p-3.5 rounded-xl">
            <span className="text-[11px] font-semibold text-app-muted uppercase">Cleartext HTTP</span>
            <div className={`font-bold mt-1 text-xs truncate ${meta.uses_cleartext_traffic ? 'text-amber-600 dark:text-amber-400' : 'text-emerald-600 dark:text-emerald-400'}`}>
              {meta.uses_cleartext_traffic ? 'ALLOWED' : 'ENFORCED TLS'}
            </div>
          </div>
          <div className="forensics-card p-3.5 rounded-xl">
            <span className="text-[11px] font-semibold text-app-muted uppercase">Launcher Activity</span>
            <div className="font-bold text-app-secondary truncate mt-1 text-xs font-mono">
              {meta.launcher_activity ? meta.launcher_activity.split('.').pop() : 'None / Headless'}
            </div>
          </div>
        </div>
      ) : null}

      {/* 1. FINDINGS TAB (Shared for APK and EXE) */}
      {activeTab === 'findings' && (
        <div className="space-y-5">
          {/* Findings Dashboard Counters */}
          <div className="grid grid-cols-2 sm:grid-cols-4 lg:grid-cols-8 gap-2.5">
            <div className="forensics-card p-3 rounded-xl border border-app text-center">
              <span className="text-[10px] text-app-muted uppercase font-mono block">TOTAL</span>
              <span className="text-xl font-bold font-mono text-app-primary">{stats.total}</span>
            </div>
            <div className="forensics-card p-3 rounded-xl border border-rose-300/40 dark:border-rose-900/40 text-center bg-rose-50/20 dark:bg-rose-950/20">
              <span className="text-[10px] text-rose-600 dark:text-rose-400 uppercase font-mono block">CRITICAL</span>
              <span className="text-xl font-bold font-mono text-rose-600 dark:text-rose-400">{stats.critical}</span>
            </div>
            <div className="forensics-card p-3 rounded-xl border border-amber-300/40 dark:border-amber-900/40 text-center bg-amber-50/20 dark:bg-amber-950/20">
              <span className="text-[10px] text-amber-600 dark:text-amber-400 uppercase font-mono block">HIGH</span>
              <span className="text-xl font-bold font-mono text-amber-600 dark:text-amber-400">{stats.high}</span>
            </div>
            <div className="forensics-card p-3 rounded-xl border border-sky-300/40 dark:border-sky-900/40 text-center bg-sky-50/20 dark:bg-sky-950/20">
              <span className="text-[10px] text-sky-600 dark:text-sky-400 uppercase font-mono block">MEDIUM</span>
              <span className="text-xl font-bold font-mono text-sky-600 dark:text-sky-400">{stats.medium}</span>
            </div>
            <div className="forensics-card p-3 rounded-xl border border-cyan-300/40 dark:border-cyan-900/40 text-center">
              <span className="text-[10px] text-cyan-600 dark:text-cyan-400 uppercase font-mono block">LOW</span>
              <span className="text-xl font-bold font-mono text-cyan-600 dark:text-cyan-400">{stats.low}</span>
            </div>
            <div className="forensics-card p-3 rounded-xl border border-slate-300/40 dark:border-slate-800 text-center">
              <span className="text-[10px] text-app-muted uppercase font-mono block">INFO</span>
              <span className="text-xl font-bold font-mono text-slate-500">{stats.info}</span>
            </div>
            <div className="forensics-card p-3 rounded-xl border border-emerald-300/40 dark:border-emerald-900/40 text-center bg-emerald-50/20 dark:bg-emerald-950/20">
              <span className="text-[10px] text-emerald-600 dark:text-emerald-400 uppercase font-mono block">FACTS</span>
              <span className="text-xl font-bold font-mono text-emerald-600 dark:text-emerald-400">{stats.confirmedFact}</span>
            </div>
            <div className="forensics-card p-3 rounded-xl border border-orange-300/40 dark:border-orange-900/40 text-center bg-orange-50/20 dark:bg-orange-950/20">
              <span className="text-[10px] text-orange-600 dark:text-orange-400 uppercase font-mono block">SUSPICIOUS</span>
              <span className="text-xl font-bold font-mono text-orange-600 dark:text-orange-400">{stats.suspiciousInd}</span>
            </div>
          </div>

          {/* Filter Bar */}
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3 bg-surface p-3.5 rounded-xl border border-app">
            {/* Search */}
            <div className="relative">
              <Search className="w-4 h-4 text-app-muted absolute left-3 top-2.5" />
              <input
                type="text"
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
                placeholder="Search ID, title, file, code..."
                className="forensics-input pl-9 pr-3 py-1.5 text-xs w-full font-mono"
              />
            </div>

            {/* Severity Filter */}
            <div className="flex items-center gap-1.5">
              <Filter className="w-3.5 h-3.5 text-app-muted shrink-0" />
              <select
                value={severityFilter}
                onChange={(e) => setSeverityFilter(e.target.value)}
                aria-label="Filter findings by severity"
                className="forensics-input text-xs py-1.5 px-2.5 w-full font-mono cursor-pointer"
              >
                <option value="all">All Severities ({findings.length})</option>
                <option value="Critical">Critical ({stats.critical})</option>
                <option value="High">High ({stats.high})</option>
                <option value="Medium">Medium ({stats.medium})</option>
                <option value="Low">Low ({stats.low})</option>
                <option value="Informational">Informational ({stats.info})</option>
              </select>
            </div>

            {/* Classification Filter */}
            <div>
              <select
                value={classificationFilter}
                onChange={(e) => setClassificationFilter(e.target.value)}
                aria-label="Filter findings by classification"
                className="forensics-input text-xs py-1.5 px-2.5 w-full font-mono cursor-pointer"
              >
                <option value="all">All Classifications</option>
                <option value="CONFIRMED FACT">Confirmed Fact ({stats.confirmedFact})</option>
                <option value="SUSPICIOUS INDICATOR">Suspicious Indicator ({stats.suspiciousInd})</option>
                <option value="HEURISTIC DETECTION">Heuristic Detection ({stats.heuristicDet})</option>
                <option value="NOT VERIFIED">Not Verified</option>
                <option value="NOT APPLICABLE">Not Applicable</option>
              </select>
            </div>

            {/* Category Filter */}
            <div>
              <select
                value={categoryFilter}
                onChange={(e) => setCategoryFilter(e.target.value)}
                aria-label="Filter findings by category"
                className="forensics-input text-xs py-1.5 px-2.5 w-full font-mono cursor-pointer"
              >
                <option value="all">All Categories ({categoriesList.length})</option>
                {categoriesList.map((cat) => (
                  <option key={cat} value={cat}>
                    {cat}
                  </option>
                ))}
              </select>
            </div>
          </div>

          {/* Findings List (Expandable Cards) */}
          <div className="space-y-3">
            {filteredFindings.length === 0 ? (
              <div className="p-8 text-center text-app-muted border border-dashed border-app rounded-xl bg-surface">
                No matching forensic findings found for the active criteria.
              </div>
            ) : (
              filteredFindings.map((f, idx) => {
                const fid = f.finding_id || f.id || `FINDING-${idx}`;
                const isExpanded = Boolean(expandedFindings[fid]);
                const classification = f.classification || 'HEURISTIC DETECTION';

                return (
                  <div
                    key={fid}
                    className="forensics-card rounded-xl border border-app hover:border-slate-400 dark:hover:border-[#303e54] transition-all overflow-hidden"
                  >
                    {/* Header Row */}
                    <div className="p-4 sm:p-5 flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-app/60 bg-surface/40">
                      <div className="flex flex-wrap items-center gap-2 cursor-pointer flex-1" onClick={() => toggleExpand(fid)}>
                        <button
                          type="button"
                          className="p-1 rounded hover:bg-slate-200 dark:hover:bg-slate-800 transition-colors text-app-muted mr-1"
                          title={isExpanded ? "Collapse" : "Expand"}
                        >
                          {isExpanded ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}
                        </button>
                        <span className="text-xs font-bold text-cyan-700 dark:text-cyan-300 bg-cyan-50 dark:bg-cyan-950/60 border border-cyan-300 dark:border-cyan-800 px-2 py-0.5 rounded-md font-mono">
                          {fid}
                        </span>
                        <h3 className="text-sm font-bold text-app-primary tracking-tight">{f.title}</h3>
                      </div>

                      <div className="flex items-center gap-2 flex-wrap shrink-0">
                        {/* Classification Badge */}
                        <span className={`text-[10px] font-bold px-2 py-0.5 rounded font-mono uppercase border ${
                          classification === 'CONFIRMED FACT'
                            ? 'bg-emerald-50 dark:bg-emerald-950/80 text-emerald-700 dark:text-emerald-300 border-emerald-300 dark:border-emerald-800'
                            : classification === 'SUSPICIOUS INDICATOR'
                            ? 'bg-amber-50 dark:bg-amber-950/80 text-amber-700 dark:text-amber-300 border-amber-300 dark:border-amber-800'
                            : 'bg-purple-50 dark:bg-purple-950/80 text-purple-700 dark:text-purple-300 border-purple-300 dark:border-purple-800'
                        }`}>
                          {classification}
                        </span>

                        {/* Category Badge */}
                        <span className="text-[10px] text-app-secondary uppercase bg-surface px-2 py-0.5 rounded-md border border-app font-mono">
                          {f.category}
                        </span>

                        {/* Confidence Badge */}
                        <span className="text-[10px] font-mono text-cyan-600 dark:text-cyan-400 bg-cyan-50 dark:bg-cyan-950/40 border border-cyan-200 dark:border-cyan-800/60 px-1.5 py-0.5 rounded">
                          {f.confidence}
                        </span>

                        {/* Severity Badge */}
                        <SeverityBadge severity={f.severity} size="sm" />

                        {/* Copy Button */}
                        <button
                          type="button"
                          onClick={() => handleCopySafeEvidence(f)}
                          className="inline-flex items-center gap-1 text-[11px] font-medium px-2 py-1 rounded bg-slate-100 hover:bg-slate-200 dark:bg-slate-800 dark:hover:bg-slate-700 text-app-primary border border-app transition-colors ml-1 cursor-pointer"
                          title="Copy safe redacted evidence for chain of custody reporting"
                        >
                          {copiedId === f.id ? (
                            <>
                              <Check className="w-3 h-3 text-emerald-500" />
                              <span className="text-emerald-500 font-bold">Copied</span>
                            </>
                          ) : (
                            <>
                              <Copy className="w-3 h-3 text-app-muted" />
                              <span>Copy</span>
                            </>
                          )}
                        </button>
                      </div>
                    </div>

                    {/* Summary Excerpt when collapsed */}
                    {!isExpanded && (
                      <div className="px-5 py-3 text-xs text-app-secondary flex items-center justify-between cursor-pointer hover:bg-slate-500/5 transition-colors" onClick={() => toggleExpand(fid)}>
                        <p className="truncate max-w-2xl">{f.description}</p>
                        <span className="text-[11px] text-cyan-600 dark:text-cyan-400 font-medium shrink-0 ml-2">
                          View 16-Field Technical Evidence &rarr;
                        </span>
                      </div>
                    )}

                    {/* Expanded Technical Details (16 Structured Forensic Fields) */}
                    {isExpanded && (
                      <div className="p-5 space-y-4 bg-surface/20">
                        {/* Section 1: Overview & Potential Impact */}
                        <div className="space-y-2">
                          <p className="text-xs md:text-sm text-app-secondary leading-relaxed">{f.description}</p>
                          {f.potential_impact && (
                            <div className="p-2.5 bg-amber-500/10 border border-amber-500/30 rounded-lg text-xs text-amber-700 dark:text-amber-300">
                              <span className="font-bold uppercase tracking-wider text-[10px] block mb-0.5">
                                Potential Impact Assessment:
                              </span>
                              {f.potential_impact}
                            </div>
                          )}
                        </div>

                        {/* Section 2: Technical Artifact Evidence */}
                        <div className="bg-surface border border-app rounded-lg p-3.5 space-y-2 text-xs">
                          <div className="flex flex-wrap items-center justify-between gap-2 border-b border-app/60 pb-2 font-mono text-[11px]">
                            <div>
                              <span className="text-app-muted">Evidence Source: </span>
                              <span className="text-app-primary font-bold">{f.evidence_source || f.source_file || 'Ingested Binary Stream'}</span>
                            </div>
                            <div>
                              <span className="text-app-muted">File: </span>
                              <span className="text-cyan-600 dark:text-cyan-300">{f.file_path || f.source_file || 'evidence_artifact'}</span>
                            </div>
                            {(f.offset_or_reference || f.code_reference) && (
                              <div>
                                <span className="text-app-muted">Offset / Ref: </span>
                                <span className="text-app-secondary">{f.offset_or_reference || f.code_reference}</span>
                              </div>
                            )}
                          </div>

                          {(f.supporting_evidence || f.evidence_snippet) && (
                            <div className="bg-slate-950 p-3 rounded border border-slate-800 font-mono text-xs text-cyan-300 overflow-x-auto select-all">
                              <span className="text-slate-500 select-none">// Safe Redacted Evidence Snippet: </span>
                              {f.supporting_evidence || f.evidence_snippet}
                            </div>
                          )}
                        </div>

                        {/* Section 3: Forensic Analysis & False Positive Considerations */}
                        <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-xs bg-surface p-3.5 rounded-lg border border-app">
                          <div>
                            <span className="text-[11px] text-app-muted uppercase font-bold block mb-1">
                              Analytical Rationale &amp; Detection Method
                            </span>
                            <p className="text-app-secondary text-xs leading-relaxed">
                              {f.technical_explanation || f.explanation || f.reason_for_detection || 'Static heuristic pattern match.'}
                            </p>
                            <span className="text-[10px] text-app-muted block mt-2 font-mono">
                              Engine: {f.detection_method || 'Static Parser'}
                            </span>
                          </div>
                          <div>
                            <span className="text-[11px] text-app-muted uppercase font-bold block mb-1">
                              False Positive Considerations
                            </span>
                            <p className="text-app-secondary text-xs leading-relaxed">
                              {f.false_positive_considerations || 'Verify whether identified pattern originates from legitimate OS vendor components or compiled third-party advertising/telemetry SDKs.'}
                            </p>
                          </div>
                        </div>

                        {/* Section 4: Forensic Guidance & Remediation */}
                        <div className="p-3 bg-emerald-500/10 border border-emerald-500/30 rounded-lg text-xs text-emerald-800 dark:text-emerald-300">
                          <span className="text-[10px] uppercase font-bold tracking-wider block mb-0.5">
                            Recommended Forensic Follow-up &amp; Remediation:
                          </span>
                          <p>{f.remediation || f.remediation_advice || 'Preserve evidence image, extract corroborating memory/pcap artifacts, and correlate indicators across authorized repositories.'}</p>
                        </div>
                      </div>
                    )}
                  </div>
                );
              })
            )}
          </div>
        </div>
      )}

      {/* 2. PE METADATA TAB (EXE Only) */}
      {isExe && activeTab === 'pe_metadata' && peMeta && (
        <div className="space-y-6">
          <div className="forensics-card p-5 space-y-4 rounded-xl">
            <h3 className="text-xs font-bold text-cyan-700 dark:text-cyan-300 uppercase tracking-wider flex items-center gap-2">
              <Cpu className="w-4 h-4" />
              <span>COFF File & Optional Header Details</span>
            </h3>

            <div className="grid grid-cols-1 md:grid-cols-3 gap-4 text-xs">
              <div className="bg-surface p-3.5 rounded-lg border border-app">
                <span className="text-app-muted text-[11px] font-semibold block uppercase">Compilation Timestamp</span>
                <span className="text-app-primary font-bold font-mono text-sm">{peMeta.compilation_timestamp || 'N/A'}</span>
                <p className="text-xs text-app-secondary mt-1">{peMeta.timestamp_assessment}</p>
              </div>

              <div className="bg-surface p-3.5 rounded-lg border border-app">
                <span className="text-app-muted text-[11px] font-semibold block uppercase">Image Base Address</span>
                <span className="text-cyan-700 dark:text-cyan-400 font-mono font-bold text-sm">{peMeta.image_base}</span>
                <p className="text-xs text-app-secondary mt-1">Preferred load address in virtual memory</p>
              </div>

              <div className="bg-surface p-3.5 rounded-lg border border-app">
                <span className="text-app-muted text-[11px] font-semibold block uppercase">Subsystem</span>
                <span className="text-app-primary font-bold text-sm">{peMeta.subsystem}</span>
                <p className="text-xs text-app-secondary mt-1">Target Windows runtime environment</p>
              </div>

              <div className="bg-surface p-3.5 rounded-lg border border-app">
                <span className="text-app-muted text-[11px] font-semibold block uppercase">Size of Image & Headers</span>
                <span className="text-app-primary font-bold font-mono text-sm">{peMeta.size_of_image.toLocaleString()} bytes</span>
                <p className="text-xs text-app-secondary mt-1">Headers: {peMeta.size_of_headers} bytes</p>
              </div>

              <div className="bg-surface p-3.5 rounded-lg border border-app">
                <span className="text-app-muted text-[11px] font-semibold block uppercase">Declared Checksum</span>
                <span className="text-cyan-700 dark:text-cyan-400 font-mono font-bold text-sm">{peMeta.checksum}</span>
                <p className="text-xs text-app-secondary mt-1">PE optional header checksum</p>
              </div>

              <div className="bg-surface p-3.5 rounded-lg border border-app">
                <span className="text-app-muted text-[11px] font-semibold block uppercase">Data Directories Declared</span>
                <span className="text-app-primary font-bold text-sm">{peMeta.number_of_data_directories}</span>
                <p className="text-xs text-app-secondary mt-1">Import, Export, Security, Relocation dirs</p>
              </div>
            </div>

            {/* DLL Characteristics */}
            <div className="pt-2">
              <span className="text-[11px] text-app-muted uppercase font-bold block mb-2">DLL Characteristics (Security Mitigations)</span>
              <div className="flex flex-wrap gap-2">
                {peMeta.dll_characteristics.length === 0 ? (
                  <span className="text-app-muted text-xs">No DLL characteristics flags declared (e.g. ASLR or DEP may be disabled).</span>
                ) : (
                  peMeta.dll_characteristics.map((dc, idx) => (
                    <span key={idx} className="bg-surface text-cyan-700 dark:text-cyan-300 border border-app px-2.5 py-1 rounded-md text-xs font-mono font-medium">
                      {dc}
                    </span>
                  ))
                )}
              </div>
            </div>
          </div>

          {/* Version Resources Table */}
          <div className="forensics-card rounded-xl overflow-hidden shadow-sm">
            <div className="p-4 border-b border-app bg-surface flex items-center justify-between text-xs">
              <span className="font-bold text-app-primary uppercase flex items-center gap-2">
                <FileCheck className="w-4 h-4 text-cyan-600 dark:text-cyan-400" />
                Embedded Version Resources (VS_VERSIONINFO)
              </span>
              <span className="text-amber-600 dark:text-amber-400 text-xs font-medium">Note: Version info can be forged by malware</span>
            </div>
            {Object.keys(peMeta.version_info).length === 0 ? (
              <div className="p-6 text-center text-app-muted text-xs">
                No embedded Version Information resources found in PE file.
              </div>
            ) : (
              <div className="divide-y divide-app text-xs">
                {Object.entries(peMeta.version_info).map(([key, val], idx) => (
                  <div key={idx} className="p-3.5 flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                    <span className="text-app-secondary font-bold sm:w-1/3">{key}</span>
                    <span className="text-app-primary font-mono break-all sm:w-2/3">{val}</span>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      )}

      {/* 3. PE SECTIONS TAB (EXE Only) */}
      {isExe && activeTab === 'pe_sections' && peMeta && (
        <div className="space-y-4">
          <div className="forensics-card rounded-xl overflow-hidden shadow-sm">
            <div className="p-4 border-b border-app bg-surface flex items-center justify-between text-xs">
              <span className="font-bold text-app-primary uppercase flex items-center gap-2">
                <Binary className="w-4 h-4 text-cyan-600 dark:text-cyan-400" />
                PE Section Headers, Permissions & Shannon Entropy
              </span>
              <span className="text-app-secondary font-medium">{peMeta.sections.length} Sections Total</span>
            </div>
            <div className="overflow-x-auto">
              <table className="forensics-table text-left">
                <thead>
                  <tr>
                    <th>Section</th>
                    <th>Virtual Address</th>
                    <th>Virtual Size</th>
                    <th>Raw Offset</th>
                    <th>Raw Size</th>
                    <th>Shannon Entropy</th>
                    <th>Perms</th>
                    <th>Anomalies</th>
                  </tr>
                </thead>
                <tbody>
                  {peMeta.sections.map((sec, idx) => {
                    const isHighEntropy = sec.entropy > 7.2;
                    const isWx = sec.writable && sec.executable;
                    return (
                      <tr key={idx}>
                        <td className="font-bold text-app-primary font-mono">{sec.name}</td>
                        <td className="font-mono text-cyan-600 dark:text-cyan-400">{sec.virtual_address}</td>
                        <td>{sec.virtual_size.toLocaleString()} B</td>
                        <td className="font-mono text-app-secondary">{hex(sec.raw_data_offset)}</td>
                        <td>{sec.raw_data_size.toLocaleString()} B</td>
                        <td>
                          <div className="flex items-center gap-2">
                            <span className={`font-bold font-mono ${isHighEntropy ? 'text-amber-600 dark:text-amber-400' : 'text-app-primary'}`}>
                              {sec.entropy.toFixed(2)}
                            </span>
                            <div className="w-16 bg-slate-200 dark:bg-slate-800 h-2 rounded-full overflow-hidden">
                              <div
                                className={`h-full ${isHighEntropy ? 'bg-amber-500' : 'bg-cyan-500'}`}
                                style={{ width: `${Math.min(100, (sec.entropy / 8.0) * 100)}%` }}
                              />
                            </div>
                          </div>
                        </td>
                        <td>
                          <span className={`px-2 py-0.5 rounded text-[11px] font-bold font-mono ${
                            isWx
                              ? 'bg-rose-100 dark:bg-rose-950 text-rose-700 dark:text-rose-300 border border-rose-300 dark:border-rose-800 animate-pulse'
                              : 'bg-surface text-app-secondary border border-app'
                          }`}>
                            {sec.readable ? 'R' : '-'}{sec.writable ? 'W' : '-'}{sec.executable ? 'X' : '-'}
                          </span>
                        </td>
                        <td>
                          {sec.suspicious_indicators.length > 0 ? (
                            <span className="text-amber-600 dark:text-amber-400 text-xs font-semibold">
                              {sec.suspicious_indicators.join('; ')}
                            </span>
                          ) : (
                            <span className="text-emerald-600 dark:text-emerald-400 text-xs">Clean</span>
                          )}
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}

      {/* 4. PE IMPORTS TAB (EXE Only) */}
      {isExe && activeTab === 'pe_imports' && peMeta && (
        <div className="space-y-4">
          <div className="flex items-center justify-between text-xs text-app-secondary">
            <span>Imported Dynamic Link Libraries ({peMeta.imports.length} DLLs)</span>
            <span>Win32 API Behavioral Capabilities</span>
          </div>

          <div className="space-y-4">
            {peMeta.imports.length === 0 ? (
              <div className="p-8 text-center text-app-muted border border-dashed border-app rounded-xl bg-surface text-xs">
                No imported functions found in the PE import table (binary may be statically linked or packed).
              </div>
            ) : (
              peMeta.imports.map((dll, idx) => {
                const securityApis = dll.functions.filter((f) => f.category !== 'System / General');
                return (
                  <div key={idx} className="forensics-card rounded-xl overflow-hidden shadow-sm">
                    <div className="p-3.5 bg-surface border-b border-app flex items-center justify-between">
                      <div className="flex items-center gap-2">
                        <Monitor className="w-4 h-4 text-cyan-600 dark:text-cyan-400" />
                        <span className="font-bold text-app-primary text-xs font-mono">{dll.dll_name}</span>
                        <span className="text-xs text-app-muted">({dll.functions.length} functions)</span>
                      </div>
                      {securityApis.length > 0 && (
                        <span className="text-[11px] bg-amber-50 dark:bg-amber-950/80 text-amber-700 dark:text-amber-300 border border-amber-300 dark:border-amber-800 px-2 py-0.5 rounded font-bold">
                          {securityApis.length} SECURITY-RELEVANT
                        </span>
                      )}
                    </div>

                    <div className="p-4 space-y-2 text-xs divide-y divide-app">
                      {dll.functions.map((fn, fIdx) => (
                        <div key={fIdx} className="pt-2 flex flex-col md:flex-row md:items-center justify-between gap-2">
                          <div className="flex flex-wrap items-center gap-2">
                            <span className="font-mono font-bold text-app-primary">{fn.name}</span>
                            {fn.category !== 'System / General' && (
                              <span className="text-[11px] bg-cyan-50 dark:bg-cyan-950 text-cyan-700 dark:text-cyan-300 border border-cyan-300 dark:border-cyan-800 px-2 py-0.5 rounded font-medium">
                                {fn.category}
                              </span>
                            )}
                          </div>
                          {fn.why_relevant && fn.category !== 'System / General' && (
                            <span className="text-app-secondary text-xs">{fn.why_relevant}</span>
                          )}
                        </div>
                      ))}
                    </div>
                  </div>
                );
              })
            )}
          </div>
        </div>
      )}

      {/* 5. PE SIGNATURE TAB (EXE Only) */}
      {isExe && activeTab === 'pe_signature' && peMeta && (
        <div className="forensics-card rounded-xl p-6 space-y-4 text-xs">
          <div className="flex items-center gap-3 border-b border-app pb-4">
            <Lock className={`w-8 h-8 ${peMeta.is_signed ? 'text-emerald-600 dark:text-emerald-400' : 'text-amber-600 dark:text-amber-400'}`} />
            <div>
              <h3 className="text-sm md:text-base font-bold text-app-primary uppercase">
                Authenticode Digital Signature Verification
              </h3>
              <p className="text-app-secondary mt-0.5 text-xs">
                Checks presence of the PE Certificate Table (IMAGE_DIRECTORY_ENTRY_SECURITY).
              </p>
            </div>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div className="bg-surface p-4 rounded-lg border border-app space-y-2">
              <span className="text-app-muted uppercase text-[11px] font-semibold block">Signature Presence</span>
              <div className={`text-base font-bold ${peMeta.is_signed ? 'text-emerald-600 dark:text-emerald-400' : 'text-amber-600 dark:text-amber-400'}`}>
                {peMeta.is_signed ? 'DIGITAL SIGNATURE PRESENT' : 'UNSIGNED EXECUTABLE'}
              </div>
              <p className="text-app-secondary text-xs leading-relaxed">
                {peMeta.signature_info.assessment || 'No digital signature certificate table found.'}
              </p>
            </div>

            <div className="bg-surface p-4 rounded-lg border border-app space-y-2">
              <span className="text-app-muted uppercase text-[11px] font-semibold block">Security Directory Metrics</span>
              <div className="space-y-1 font-mono text-xs text-app-primary">
                <div>RVA Offset: <span className="text-cyan-600 dark:text-cyan-400">{peMeta.signature_info.security_directory_rva || '0x0'}</span></div>
                <div>Size: <span>{peMeta.signature_info.security_directory_size || 0} bytes</span></div>
              </div>
              <p className="text-app-muted text-xs pt-1">
                Forensic Note: Malware authors frequently sign malicious binaries using stolen, purchased, or expired certificates. A digital signature alone does not establish safety.
              </p>
            </div>
          </div>
        </div>
      )}

      {/* ANDROID TABS (APK Only) */}
      {!isExe && activeTab === 'permissions' && meta && (
        <div className="space-y-4">
          {/* Permission Summary Dashboard */}
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 text-xs">
            <div className="forensics-card p-3 rounded-xl border border-app bg-surface">
              <div className="text-app-muted text-[11px] uppercase font-bold">Total Declared</div>
              <div className="text-lg font-bold text-app-primary mt-0.5">{meta.permissions.length}</div>
              <div className="text-[10px] text-app-muted mt-0.5">AndroidManifest.xml</div>
            </div>
            <div className="forensics-card p-3 rounded-xl border border-rose-300 dark:border-rose-900 bg-rose-50/50 dark:bg-rose-950/20">
              <div className="text-rose-600 dark:text-rose-400 text-[11px] uppercase font-bold">Dangerous Perms</div>
              <div className="text-lg font-bold text-rose-600 dark:text-rose-400 mt-0.5">
                {meta.permissions.filter((p: any) => p.is_dangerous).length}
              </div>
              <div className="text-[10px] text-app-muted mt-0.5">Requires runtime grant</div>
            </div>
            <div className="forensics-card p-3 rounded-xl border border-emerald-300 dark:border-emerald-900 bg-emerald-50/50 dark:bg-emerald-950/20">
              <div className="text-emerald-600 dark:text-emerald-400 text-[11px] uppercase font-bold">Normal Perms</div>
              <div className="text-lg font-bold text-emerald-600 dark:text-emerald-400 mt-0.5">
                {meta.permissions.filter((p: any) => !p.is_dangerous).length}
              </div>
              <div className="text-[10px] text-app-muted mt-0.5">Granted automatically</div>
            </div>
            <div className="forensics-card p-3 rounded-xl border border-cyan-300 dark:border-cyan-900 bg-cyan-50/50 dark:bg-cyan-950/20">
              <div className="text-cyan-600 dark:text-cyan-400 text-[11px] uppercase font-bold">Runtime Status</div>
              <div className="text-xs font-bold text-cyan-700 dark:text-cyan-300 mt-1">UNVERIFIED (STATIC)</div>
              <div className="text-[10px] text-app-muted mt-0.5">Static analysis only</div>
            </div>
          </div>

          <div className="forensics-card rounded-xl overflow-hidden shadow-sm">
            <div className="p-4 border-b border-app bg-surface flex items-center justify-between">
              <span className="text-xs font-bold text-app-primary uppercase tracking-wide">Android Permission Intelligence Matrix</span>
              <span className="text-xs text-app-muted font-medium">{meta?.permissions.length || 0} Declared</span>
            </div>
            <div className="divide-y divide-app">
              {meta?.permissions.length === 0 ? (
                <div className="p-8 text-center text-app-muted text-xs">
                  No permissions declared or requested in AndroidManifest.xml.
                </div>
              ) : (
                meta?.permissions.map((p: any, idx: number) => (
                  <div key={idx} className="p-4 flex flex-col md:flex-row md:items-start justify-between gap-3 text-xs">
                    <div className="flex-1">
                      <div className="flex items-center gap-2.5">
                        <span
                          className={`text-[10px] font-bold px-2 py-0.5 rounded border uppercase ${
                            p.is_dangerous
                              ? 'bg-rose-50 dark:bg-rose-950 text-rose-700 dark:text-rose-300 border-rose-300 dark:border-rose-800'
                              : 'bg-surface text-app-secondary border-app'
                          }`}
                        >
                          {p.is_dangerous ? 'DANGEROUS' : 'NORMAL'}
                        </span>
                        <span className="font-bold text-app-primary font-mono text-xs">{p.name}</span>
                      </div>
                      <p className="text-xs text-app-secondary mt-1.5 leading-relaxed">{p.description || 'Standard application capability request.'}</p>
                      <div className="flex items-center gap-3 mt-2 text-[11px] text-app-muted">
                        <span>Source: <strong className="text-app-primary">AndroidManifest.xml</strong></span>
                        <span>•</span>
                        <span>Evidence State: <strong className="text-cyan-600 dark:text-cyan-400">Declared (Passive)</strong></span>
                      </div>
                    </div>
                  </div>
                ))
              )}
            </div>
          </div>
        </div>
      )}

      {!isExe && activeTab === 'components' && meta && (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs">
          <div className="forensics-card rounded-xl p-4 space-y-3">
            <div className="flex items-center justify-between border-b border-app pb-2 font-bold text-app-primary">
              <span>ACTIVITIES ({meta?.activities.length || 0})</span>
            </div>
            <div className="space-y-1.5 max-h-72 overflow-y-auto">
              {meta?.activities.map((act: any, i: number) => (
                <div key={i} className="p-2.5 bg-surface rounded-lg border border-app flex items-center justify-between gap-2">
                  <span className="truncate text-app-primary font-mono text-xs">{act.name}</span>
                  {act.exported && (
                    <span className="text-[11px] text-amber-700 dark:text-amber-400 bg-amber-50 dark:bg-amber-950/60 border border-amber-300 dark:border-amber-800 px-2 py-0.5 rounded font-bold shrink-0">
                      EXPORTED
                    </span>
                  )}
                </div>
              ))}
            </div>
          </div>

          <div className="forensics-card rounded-xl p-4 space-y-3">
            <div className="flex items-center justify-between border-b border-app pb-2 font-bold text-app-primary">
              <span>SERVICES ({meta?.services.length || 0})</span>
            </div>
            <div className="space-y-1.5 max-h-72 overflow-y-auto">
              {meta?.services.map((srv: any, i: number) => (
                <div key={i} className="p-2.5 bg-surface rounded-lg border border-app flex items-center justify-between gap-2">
                  <span className="truncate text-app-primary font-mono text-xs">{srv.name}</span>
                  {srv.exported && (
                    <span className="text-[11px] text-amber-700 dark:text-amber-400 bg-amber-50 dark:bg-amber-950/60 border border-amber-300 dark:border-amber-800 px-2 py-0.5 rounded font-bold shrink-0">
                      EXPORTED
                    </span>
                  )}
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

      {!isExe && activeTab === 'certs' && meta && (
        <div className="space-y-4">
          {meta?.certificates.map((c: any, i: number) => (
            <div key={i} className="forensics-card rounded-xl p-5 space-y-3 text-xs">
              <div className="flex items-center justify-between border-b border-app pb-2">
                <div className="flex items-center gap-2">
                  <Award className="w-4 h-4 text-cyan-600 dark:text-cyan-400" />
                  <span className="font-bold text-app-primary">SIGNING CERTIFICATE #{i + 1}</span>
                </div>
                {c.is_self_signed && (
                  <span className="text-[11px] bg-amber-50 dark:bg-amber-950 text-amber-700 dark:text-amber-300 border border-amber-300 dark:border-amber-800 px-2 py-0.5 rounded font-bold">
                    SELF-SIGNED
                  </span>
                )}
              </div>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div>
                  <span className="text-[11px] text-app-muted uppercase font-bold block mb-1">SUBJECT</span>
                  <p className="text-app-primary font-mono break-all">{JSON.stringify(c.subject)}</p>
                </div>
                <div>
                  <span className="text-[11px] text-app-muted uppercase font-bold block mb-1">ISSUER</span>
                  <p className="text-app-primary font-mono break-all">{JSON.stringify(c.issuer)}</p>
                </div>
              </div>
            </div>
          ))}
        </div>
      )}

      {!isExe && activeTab === 'binaries' && meta && (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs">
          <div className="forensics-card rounded-xl p-4 space-y-3">
            <span className="font-bold text-app-primary block border-b border-app pb-2 uppercase">
              DEX Bytecode Files ({meta?.dex_files.length || 0})
            </span>
            <div className="space-y-2">
              {meta?.dex_files.map((d: any, i: number) => (
                <div key={i} className="p-3 bg-surface rounded-lg border border-app flex items-center justify-between">
                  <span className="font-bold text-app-primary font-mono">{d.name}</span>
                  <span className="text-app-secondary text-xs font-mono">
                    {(d.size / (1024 * 1024)).toFixed(2)} MB
                  </span>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

      {activeTab === 'ai_observations' && (
        <div className="space-y-6">
          {/* AI Header & Disclaimer Advisory */}
          <div className="bg-slate-900 border border-indigo-900/60 rounded-xl p-5 shadow-sm text-xs space-y-3">
            <div className="flex flex-col md:flex-row md:items-center justify-between gap-3 border-b border-indigo-950 pb-3">
              <div className="flex items-center gap-2.5">
                <div className="p-2 bg-indigo-600/30 rounded-lg border border-indigo-500/40">
                  <Cpu className="w-5 h-5 text-indigo-400" />
                </div>
                <div>
                  <h3 className="text-sm font-bold text-indigo-100 flex items-center gap-2">
                    OpenCode AI-Assisted Forensic Observations
                    <span className="text-[10px] bg-amber-500/20 text-amber-300 border border-amber-500/30 px-2 py-0.5 rounded font-mono font-bold">
                      STRICTLY UNVERIFIED
                    </span>
                  </h3>
                  <div className="text-[11px] text-indigo-300/80 font-mono mt-0.5">
                    Engine: {aiNotes?.model_provider || 'OpenCode CLI'} &bull; Status: {aiNotes?.execution_status || (aiObservations.length ? 'COMPLETED' : 'NOT EXECUTED')}
                  </div>
                </div>
              </div>

              {/* Action Message Alert */}
              {aiActionMessage && (
                <div className="text-xs px-3 py-1.5 rounded-lg bg-indigo-950 text-indigo-200 border border-indigo-800">
                  {aiActionMessage}
                </div>
              )}

              {/* On-demand Trigger / Re-run */}
              <div className="flex items-center gap-3">
                <label className="flex items-center gap-1.5 text-indigo-200 text-[11px] cursor-pointer">
                  <input
                    type="checkbox"
                    checked={consentApproved}
                    onChange={(e) => setConsentApproved(e.target.checked)}
                    className="rounded border-indigo-800 text-indigo-600 focus:ring-0 cursor-pointer"
                  />
                  <span>Authorize Hybrid Cloud (if applicable)</span>
                </label>
                <button
                  type="button"
                  onClick={handleTriggerAIAnalysis}
                  disabled={isAiRunning}
                  className="px-3 py-1.5 rounded-lg bg-indigo-600 hover:bg-indigo-700 text-white font-semibold text-xs flex items-center gap-1.5 disabled:opacity-50 transition-colors cursor-pointer shadow-sm"
                >
                  <Cpu className={`w-3.5 h-3.5 ${isAiRunning ? 'animate-spin' : ''}`} />
                  <span>{isAiRunning ? 'Synthesizing...' : 'Run OpenCode AI Analysis'}</span>
                </button>
              </div>
            </div>

            <p className="text-[11px] text-indigo-200/90 leading-relaxed font-sans">
              <strong>Forensic Caveat:</strong> {aiNotes?.disclaimer || 'AI-assisted technical explanation. Every factual conclusion must be independently verified against raw decompiled bytecode and deterministic analyzer evidence.'}
            </p>

            {aiNotes?.warnings_or_errors && aiNotes.warnings_or_errors.length > 0 && (
              <div className="bg-amber-950/40 border border-amber-800/60 rounded-lg p-2.5 text-amber-200 text-[11px] space-y-1">
                <strong>Diagnostics / Warnings:</strong>
                {aiNotes.warnings_or_errors.map((w, idx) => (
                  <div key={idx}>&bull; {w}</div>
                ))}
              </div>
            )}
          </div>

          {/* Observations List */}
          <div className="space-y-4">
            <div className="flex items-center justify-between text-xs text-app-secondary">
              <span className="font-bold uppercase tracking-wider">Unverified AI Observations ({aiObservations.length})</span>
              <span>Must be reviewed by forensic examiner before formal attestation</span>
            </div>

            {aiObservations.length === 0 ? (
              <div className="forensics-card rounded-xl p-8 text-center space-y-3">
                <Cpu className="w-10 h-10 text-indigo-400 mx-auto opacity-50" />
                <h4 className="font-bold text-sm text-app-primary">No AI Observations Generated</h4>
                <p className="text-xs text-app-muted max-w-md mx-auto">
                  AI-assisted analysis was not requested during ingestion, or OpenCode CLI was disabled. Click "Run OpenCode AI Analysis" above to generate unverified observations.
                </p>
              </div>
            ) : (
              aiObservations.map((obs) => {
                const statusColor =
                  obs.status === 'ACCEPTED'
                    ? 'border-emerald-500 bg-emerald-950/20 text-emerald-300'
                    : obs.status === 'REJECTED'
                    ? 'border-rose-500 bg-rose-950/20 text-rose-300'
                    : 'border-amber-500 bg-amber-950/20 text-amber-300';

                return (
                  <div key={obs.id} className="forensics-card rounded-xl p-5 space-y-3 text-xs border border-app shadow-sm">
                    <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-app pb-2.5">
                      <div className="flex items-center gap-2">
                        <span className="font-mono text-[11px] text-app-muted font-bold">{obs.id}</span>
                        <h4 className="font-bold text-sm text-app-primary">{obs.title}</h4>
                      </div>
                      <div className="flex items-center gap-2">
                        <span className="px-2 py-0.5 rounded font-mono text-[10px] bg-surface text-app-secondary border border-app">
                          Confidence: {obs.confidence}
                        </span>
                        <span className={`px-2 py-0.5 rounded font-mono text-[10px] font-bold border ${statusColor}`}>
                          {obs.status}
                        </span>
                      </div>
                    </div>

                    <p className="text-xs text-app-primary leading-relaxed">{obs.explanation}</p>

                    {obs.related_evidence_refs && obs.related_evidence_refs.length > 0 && (
                      <div className="flex items-center gap-1.5 flex-wrap text-[11px]">
                        <span className="text-app-muted font-bold">Evidence Refs:</span>
                        {obs.related_evidence_refs.map((ref, idx) => (
                          <span key={idx} className="bg-surface px-2 py-0.5 rounded font-mono text-cyan-600 dark:text-cyan-400 border border-app">
                            {ref}
                          </span>
                        ))}
                      </div>
                    )}

                    <div className="bg-surface p-3 rounded-lg border border-app space-y-1">
                      <span className="font-bold text-[11px] text-app-secondary">Reasoning Summary:</span>
                      <p className="text-[11px] text-app-primary">{obs.reasoning_summary}</p>
                    </div>

                    {obs.suggested_verification_steps && obs.suggested_verification_steps.length > 0 && (
                      <div className="p-3 bg-indigo-950/30 border border-indigo-900/50 rounded-lg space-y-1">
                        <span className="font-bold text-[11px] text-indigo-300">Suggested Verification Steps:</span>
                        <ul className="list-disc list-inside space-y-0.5 text-[11px] text-indigo-200/90 font-mono">
                          {obs.suggested_verification_steps.map((step, idx) => (
                            <li key={idx}>{step}</li>
                          ))}
                        </ul>
                      </div>
                    )}

                    {/* Human Examiner Review Section */}
                    <div className="pt-3 border-t border-app flex flex-col md:flex-row md:items-center justify-between gap-3">
                      <div className="flex-1">
                        <input
                          type="text"
                          placeholder="Optional reviewer notes for chain of custody..."
                          value={reviewNoteInputs[obs.id] || ''}
                          onChange={(e) => setReviewNoteInputs({ ...reviewNoteInputs, [obs.id]: e.target.value })}
                          className="w-full text-xs px-2.5 py-1.5 rounded bg-surface border border-app text-app-primary placeholder:text-app-muted focus:ring-0 focus:outline-none"
                        />
                      </div>
                      <div className="flex items-center gap-2 shrink-0">
                        <button
                          type="button"
                          onClick={() => handleReviewObservation(obs.id, 'ACCEPTED')}
                          className="px-2.5 py-1 rounded bg-emerald-600 hover:bg-emerald-700 text-white font-bold text-xs flex items-center gap-1 transition-colors cursor-pointer"
                        >
                          <CheckCircle2 className="w-3.5 h-3.5" />
                          <span>Accept &amp; Verify</span>
                        </button>
                        <button
                          type="button"
                          onClick={() => handleReviewObservation(obs.id, 'REJECTED')}
                          className="px-2.5 py-1 rounded bg-rose-600 hover:bg-rose-700 text-white font-bold text-xs flex items-center gap-1 transition-colors cursor-pointer"
                        >
                          <AlertTriangle className="w-3.5 h-3.5" />
                          <span>Reject Observation</span>
                        </button>
                      </div>
                    </div>

                    {obs.reviewer && (
                      <div className="text-[10px] text-app-muted font-mono flex items-center gap-2 pt-1">
                        <span>Reviewed by: {obs.reviewer}</span>
                        {obs.reviewed_at && <span>&bull; {new Date(obs.reviewed_at).toLocaleString()}</span>}
                        {obs.review_notes && <span>&bull; Notes: {obs.review_notes}</span>}
                      </div>
                    )}
                  </div>
                );
              })
            )}
          </div>

          {/* Recommendations List */}
          {aiRecommendations.length > 0 && (
            <div className="space-y-4 pt-4 border-t border-app">
              <span className="font-bold text-xs uppercase tracking-wider text-app-secondary">
                AI Suggested Investigation Actions ({aiRecommendations.length})
              </span>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                {aiRecommendations.map((rec) => (
                  <div key={rec.id} className="forensics-card rounded-xl p-4 space-y-2 border border-app text-xs">
                    <div className="flex items-center justify-between border-b border-app pb-2">
                      <span className="font-bold text-app-primary">{rec.title}</span>
                      <span className="px-2 py-0.5 rounded font-mono text-[10px] bg-surface text-app-secondary border border-app">
                        {rec.priority} Priority
                      </span>
                    </div>
                    <p className="text-app-muted leading-relaxed">{rec.description}</p>
                    {rec.suggested_command_or_action && (
                      <div className="p-2 bg-surface rounded border border-app font-mono text-[11px] text-cyan-600 dark:text-cyan-400 break-all">
                        {rec.suggested_command_or_action}
                      </div>
                    )}
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
};

function hex(val: number): string {
  if (val === undefined || val === null) return '0x0';
  return '0x' + val.toString(16).toUpperCase();
}
