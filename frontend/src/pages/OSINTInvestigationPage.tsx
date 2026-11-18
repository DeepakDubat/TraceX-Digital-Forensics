import React, { useState, useEffect } from 'react';
import {
  Globe,
  Sparkles,
  GitFork,
  RefreshCw,
  Filter,
  CheckCircle,
  Copy,
  Check,
  ExternalLink,
  ShieldAlert,
  Key,
  Radio,
  Database,
  Search,
  Download,
  AlertTriangle,
  FolderOpen,
  ArrowRight
} from 'lucide-react';
import { api } from '../api';
import {
  InvestigationDetail,
  InvestigationRecord,
  OSINTIndicator,
  OSINTObservation,
  SecretExposureFinding
} from '../types';

interface OSINTInvestigationPageProps {
  currentDetail: InvestigationDetail | null;
  onSelectInvestigation: (id: string) => void;
}

export const OSINTInvestigationPage: React.FC<OSINTInvestigationPageProps> = ({
  currentDetail,
  onSelectInvestigation,
}) => {
  const [investigationsList, setInvestigationsList] = useState<InvestigationRecord[]>([]);
  const [selectedInvId, setSelectedInvId] = useState<string>(currentDetail?.record?.id || '');
  const [osintIndicators, setOsintIndicators] = useState<OSINTIndicator[]>([]);
  const [osintObservations, setOsintObservations] = useState<OSINTObservation[]>([]);
  const [secretFindings, setSecretFindings] = useState<SecretExposureFinding[]>([]);
  const [loading, setLoading] = useState(false);
  const [activeSubTab, setActiveSubTab] = useState<'osint' | 'secrets'>('osint');

  // Operation states
  const [isCollecting, setIsCollecting] = useState(false);
  const [isEnriching, setIsEnriching] = useState(false);
  const [isPivoting, setIsPivoting] = useState(false);
  const [pivotMaxDepth, setPivotMaxDepth] = useState(3);
  const [pivotBudget, setPivotBudget] = useState(50);
  const [indicatorFilter, setIndicatorFilter] = useState('all');
  const [copiedHash, setCopiedHash] = useState<string | null>(null);

  // Sync selectedInvId when currentDetail changes
  useEffect(() => {
    if (currentDetail?.record?.id && currentDetail.record.id !== selectedInvId) {
      setSelectedInvId(currentDetail.record.id);
    }
  }, [currentDetail?.record?.id]);

  // Load list of available investigations for dropdown
  useEffect(() => {
    const fetchInvs = async () => {
      try {
        const list = await api.listInvestigations();
        setInvestigationsList(list);
        if (!selectedInvId && list.length > 0) {
          setSelectedInvId(list[0].id);
        }
      } catch (err) {
        console.error('Failed to list investigations:', err);
      }
    };
    fetchInvs();
  }, []);

  // Fetch OSINT data for the selected investigation
  const fetchOSINTData = async (invId: string) => {
    if (!invId) return;
    setLoading(true);
    try {
      const [inds, obss, secs] = await Promise.all([
        api.getOSINTIndicators(invId, true).catch(() => []),
        api.getOSINTObservations(invId).catch(() => []),
        api.getSecretExposures(invId).catch(() => []),
      ]);
      setOsintIndicators(inds);
      setOsintObservations(obss);
      setSecretFindings(secs);
    } catch (err) {
      console.error('Failed to load OSINT data:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    if (selectedInvId) {
      fetchOSINTData(selectedInvId);
    }
  }, [selectedInvId]);

  const handleInvestigationChange = (id: string) => {
    setSelectedInvId(id);
    onSelectInvestigation(id);
  };

  const handleCollectOSINT = async () => {
    if (!selectedInvId) return;
    setIsCollecting(true);
    try {
      await api.collectOSINT(selectedInvId);
      await fetchOSINTData(selectedInvId);
    } catch (err: any) {
      alert(`Indicator collection failed: ${err.message}`);
    } finally {
      setIsCollecting(false);
    }
  };

  const handleEnrichAll = async () => {
    if (!selectedInvId) return;
    setIsEnriching(true);
    try {
      await api.enrichOSINT(selectedInvId, undefined, false);
      await fetchOSINTData(selectedInvId);
    } catch (err: any) {
      alert(`Enrichment failed: ${err.message}`);
    } finally {
      setIsEnriching(false);
    }
  };

  const handleEnrichSingle = async (indId: string) => {
    if (!selectedInvId) return;
    try {
      await api.enrichOSINT(selectedInvId, [indId], true);
      await fetchOSINTData(selectedInvId);
    } catch (err: any) {
      alert(`Enrichment failed: ${err.message}`);
    }
  };

  const handleRunPivot = async () => {
    if (!selectedInvId) return;
    setIsPivoting(true);
    try {
      await api.runRecursivePivot(selectedInvId, pivotMaxDepth, pivotBudget);
      await fetchOSINTData(selectedInvId);
    } catch (err: any) {
      alert(`Recursive pivot failed: ${err.message}`);
    } finally {
      setIsPivoting(false);
    }
  };

  const copyToClipboard = (text: string, id: string) => {
    navigator.clipboard.writeText(text);
    setCopiedHash(id);
    setTimeout(() => setCopiedHash(null), 2000);
  };

  const filteredIndicators = osintIndicators.filter(
    (ind) => indicatorFilter === 'all' || ind.indicator_type.toLowerCase() === indicatorFilter
  );

  const totalDetections = osintObservations.filter(
    (o) => o.status === 'SUCCESS' && (o.normalized_data?.detections > 0 || o.normalized_data?.verdict === 'malicious')
  ).length;

  const maxObsDepth = Math.max(0, ...osintIndicators.map((i) => i.pivot_depth || 0));

  return (
    <div className="p-6 md:p-8 max-w-7xl mx-auto space-y-6">
      {/* Header & Target Selector */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-app pb-5">
        <div>
          <div className="flex items-center gap-3">
            <div className="p-2.5 rounded-xl bg-cyan-950/40 text-cyan-400 border border-cyan-800/60 shadow-sm">
              <Globe className="w-6 h-6" />
            </div>
            <div>
              <h1 className="text-xl md:text-2xl font-bold text-app-primary flex items-center gap-2">
                <span>OSINT Investigation & Recursive Pivot Engine</span>
                <span className="text-[11px] font-mono uppercase bg-cyan-950 text-cyan-400 border border-cyan-800 px-2 py-0.5 rounded font-bold">
                  PASSIVE ONLY
                </span>
              </h1>
              <p className="text-xs text-app-secondary mt-0.5">
                Passive DNS, RDAP, ASN intelligence, Certificate Transparency, and threat intelligence pivoting.
              </p>
            </div>
          </div>
        </div>

        {/* Investigation Switcher Dropdown */}
        <div className="flex items-center gap-2">
          <label className="text-xs font-mono text-app-muted whitespace-nowrap">Target Case:</label>
          <select
            value={selectedInvId}
            onChange={(e) => handleInvestigationChange(e.target.value)}
            className="forensics-input text-xs font-mono py-1.5 px-3 min-w-[240px]"
          >
            {investigationsList.map((inv) => (
              <option key={inv.id} value={inv.id}>
                {inv.id} — {inv.filename} ({inv.file_type?.toUpperCase() || 'APK'})
              </option>
            ))}
          </select>
        </div>
      </div>

      {/* KPI Cards */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-4 font-mono">
        <div className="bg-card border border-app rounded-xl p-4 shadow-sm">
          <div className="text-xs text-app-muted font-bold">TOTAL INDICATORS</div>
          <div className="text-2xl font-bold text-cyan-500 mt-1">{osintIndicators.length}</div>
          <div className="text-[11px] text-app-muted mt-0.5">Extracted from evidence</div>
        </div>

        <div className="bg-card border border-app rounded-xl p-4 shadow-sm">
          <div className="text-xs text-app-muted font-bold">THREAT INTEL HITS</div>
          <div className="text-2xl font-bold text-rose-500 mt-1">{totalDetections}</div>
          <div className="text-[11px] text-app-muted mt-0.5">Across passive feeds</div>
        </div>

        <div className="bg-card border border-app rounded-xl p-4 shadow-sm">
          <div className="text-xs text-app-muted font-bold">MAX PIVOT DEPTH</div>
          <div className="text-2xl font-bold text-purple-400 mt-1">Depth {maxObsDepth}</div>
          <div className="text-[11px] text-app-muted mt-0.5">Derived infrastructure</div>
        </div>

        <div className="bg-card border border-app rounded-xl p-4 shadow-sm">
          <div className="text-xs text-app-muted font-bold">SECRET EXPOSURES</div>
          <div className="text-2xl font-bold text-amber-500 mt-1">{secretFindings.length}</div>
          <div className="text-[11px] text-app-muted mt-0.5">Masked & isolated</div>
        </div>
      </div>

      {/* Action Toolbar */}
      <div className="bg-surface border border-app rounded-xl p-3 flex flex-wrap items-center justify-between gap-3 shadow-sm">
        <div className="flex flex-wrap items-center gap-2">
          <button
            onClick={handleCollectOSINT}
            disabled={isCollecting || !selectedInvId}
            className="btn-secondary text-xs flex items-center gap-1.5 cursor-pointer disabled:opacity-50"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${isCollecting ? 'animate-spin text-cyan-400' : ''}`} />
            <span>{isCollecting ? 'Scanning Evidence...' : 'Extract Evidence Indicators'}</span>
          </button>

          <button
            onClick={handleEnrichAll}
            disabled={isEnriching || osintIndicators.length === 0 || !selectedInvId}
            className="btn-primary text-xs flex items-center gap-1.5 cursor-pointer disabled:opacity-50"
          >
            <Sparkles className={`w-3.5 h-3.5 ${isEnriching ? 'animate-spin' : ''}`} />
            <span>{isEnriching ? 'Enriching Feeds...' : 'Enrich All Indicators (Passive)'}</span>
          </button>
        </div>

        {/* Recursive Pivot Form */}
        <div className="flex items-center gap-2 bg-card border border-app p-1.5 rounded-lg text-xs font-mono">
          <div className="flex items-center gap-1 text-app-secondary px-1">
            <GitFork className="w-3.5 h-3.5 text-purple-400" />
            <span>Pivot:</span>
          </div>
          <select
            value={pivotMaxDepth}
            onChange={(e) => setPivotMaxDepth(Number(e.target.value))}
            className="forensics-input py-1 px-2 text-xs"
          >
            <option value={1}>Depth 1</option>
            <option value={2}>Depth 2</option>
            <option value={3}>Depth 3 (Standard)</option>
          </select>
          <select
            value={pivotBudget}
            onChange={(e) => setPivotBudget(Number(e.target.value))}
            className="forensics-input py-1 px-2 text-xs"
          >
            <option value={25}>25 Queries</option>
            <option value={50}>50 Queries</option>
            <option value={100}>100 Queries</option>
          </select>
          <button
            onClick={handleRunPivot}
            disabled={isPivoting || osintIndicators.length === 0 || !selectedInvId}
            className="px-3 py-1 bg-purple-600 hover:bg-purple-500 text-white rounded font-bold flex items-center gap-1 cursor-pointer transition disabled:opacity-50"
          >
            <RefreshCw className={`w-3 h-3 ${isPivoting ? 'animate-spin' : ''}`} />
            <span>{isPivoting ? 'Pivoting...' : 'Run Pivot'}</span>
          </button>
        </div>
      </div>

      {/* Sub Tabs */}
      <div className="flex border-b border-app space-x-6 text-xs font-mono">
        <button
          onClick={() => setActiveSubTab('osint')}
          className={`pb-3 font-bold border-b-2 transition-colors cursor-pointer ${
            activeSubTab === 'osint'
              ? 'border-cyan-500 text-cyan-500'
              : 'border-transparent text-app-muted hover:text-app-primary'
          }`}
        >
          OSINT INDICATORS & OBSERVATIONS ({osintIndicators.length})
        </button>
        <button
          onClick={() => setActiveSubTab('secrets')}
          className={`pb-3 font-bold border-b-2 transition-colors cursor-pointer flex items-center gap-1.5 ${
            activeSubTab === 'secrets'
              ? 'border-rose-500 text-rose-500'
              : 'border-transparent text-app-muted hover:text-app-primary'
          }`}
        >
          <span>SECRETS & TOKEN CONTAINMENT</span>
          {secretFindings.length > 0 && (
            <span className="px-1.5 py-0.2 rounded-full bg-rose-950 text-rose-300 text-[10px] border border-rose-800">
              {secretFindings.length}
            </span>
          )}
        </button>
      </div>

      {/* TAB CONTENT: OSINT Indicators & Observations */}
      {activeSubTab === 'osint' && (
        <div className="space-y-6">
          {/* Indicators Table */}
          <div className="bg-card border border-app rounded-xl overflow-hidden shadow-sm">
            <div className="p-4 border-b border-app flex items-center justify-between">
              <div className="flex items-center gap-2">
                <Filter className="w-4 h-4 text-cyan-400" />
                <h3 className="text-sm font-bold text-app-primary">
                  Extracted Indicators Inventory ({filteredIndicators.length})
                </h3>
              </div>
              <div className="flex gap-1 text-xs font-mono">
                {['all', 'domain', 'ip', 'url', 'hash', 'telegram_username'].map((t) => (
                  <button
                    key={t}
                    onClick={() => setIndicatorFilter(t)}
                    className={`px-2.5 py-1 rounded capitalize transition cursor-pointer ${
                      indicatorFilter === t
                        ? 'bg-cyan-600 text-white font-semibold'
                        : 'bg-surface text-app-secondary hover:text-app-primary border border-app'
                    }`}
                  >
                    {t === 'all' ? 'All' : t.replace('_', ' ')}
                  </button>
                ))}
              </div>
            </div>

            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs text-app-primary">
                <thead className="bg-surface text-app-muted uppercase tracking-wider border-b border-app font-mono text-[11px]">
                  <tr>
                    <th className="py-2.5 px-4">Type</th>
                    <th className="py-2.5 px-4">Indicator Value</th>
                    <th className="py-2.5 px-4">Provenance</th>
                    <th className="py-2.5 px-4">Source Location</th>
                    <th className="py-2.5 px-4">Extractor / Provider</th>
                    <th className="py-2.5 px-4 text-right">Actions</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-app font-mono">
                  {filteredIndicators.map((ind) => {
                    const isSecret = ind.is_sensitive_secret;
                    const displayVal = isSecret ? ind.masked_value : ind.value;
                    const typeBadgeColor =
                      ind.indicator_type === 'domain'
                        ? 'bg-cyan-950 text-cyan-300 border-cyan-800'
                        : ind.indicator_type === 'ip'
                        ? 'bg-indigo-950 text-indigo-300 border-indigo-800'
                        : ind.indicator_type === 'url'
                        ? 'bg-blue-950 text-blue-300 border-blue-800'
                        : ind.indicator_type === 'hash'
                        ? 'bg-purple-950 text-purple-300 border-purple-800'
                        : ind.indicator_type === 'telegram_username'
                        ? 'bg-sky-950 text-sky-300 border-sky-800'
                        : 'bg-rose-950 text-rose-300 border-rose-800';

                    return (
                      <tr key={ind.id} className="hover:bg-card-hover transition-colors">
                        <td className="py-2.5 px-4">
                          <span className={`px-2 py-0.5 rounded text-[10px] font-bold border uppercase ${typeBadgeColor}`}>
                            {ind.indicator_type}
                          </span>
                        </td>
                        <td className="py-2.5 px-4">
                          <div className="flex items-center gap-1.5 font-bold text-app-primary">
                            <span>{displayVal}</span>
                            {!isSecret && (
                              <button
                                onClick={() => copyToClipboard(ind.value, ind.id)}
                                className="text-app-muted hover:text-cyan-400 transition cursor-pointer"
                                title="Copy"
                              >
                                {copiedHash === ind.id ? (
                                  <Check className="w-3.5 h-3.5 text-emerald-400" />
                                ) : (
                                  <Copy className="w-3.5 h-3.5" />
                                )}
                              </button>
                            )}
                          </div>
                          {ind.limitations && (
                            <div className="text-[10px] text-app-muted font-sans">{ind.limitations}</div>
                          )}
                        </td>
                        <td className="py-2.5 px-4 font-sans">
                          {ind.pivot_depth === 0 ? (
                            <span className="text-emerald-500 text-xs font-semibold flex items-center gap-1">
                              <CheckCircle className="w-3.5 h-3.5" /> Direct Evidence
                            </span>
                          ) : (
                            <span className="text-purple-400 text-xs font-semibold flex items-center gap-1">
                              <GitFork className="w-3.5 h-3.5" /> Pivot (Depth {ind.pivot_depth})
                            </span>
                          )}
                        </td>
                        <td className="py-2.5 px-4 font-sans text-app-secondary">
                          {ind.source_location || ind.source_filename || 'Evidence Payload'}
                        </td>
                        <td className="py-2.5 px-4 font-sans text-app-secondary">
                          {ind.extractor_or_provider}
                        </td>
                        <td className="py-2.5 px-4 text-right">
                          {!isSecret && (
                            <button
                              onClick={() => handleEnrichSingle(ind.id)}
                              className="px-2 py-1 bg-surface hover:bg-card-hover border border-app text-cyan-500 rounded text-[11px] font-sans font-medium transition cursor-pointer"
                            >
                              Enrich
                            </button>
                          )}
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
              {filteredIndicators.length === 0 && (
                <div className="text-center py-8 text-app-muted text-xs">
                  No indicators matching the selected filter. Click "Extract Evidence Indicators" to analyze the evidence binary.
                </div>
              )}
            </div>
          </div>

          {/* Observations Ledger */}
          <div className="bg-card border border-app rounded-xl overflow-hidden shadow-sm">
            <div className="p-4 border-b border-app flex items-center justify-between">
              <div className="flex items-center gap-2">
                <Database className="w-4 h-4 text-blue-400" />
                <h3 className="text-sm font-bold text-app-primary">
                  Passive OSINT Observations Ledger ({osintObservations.length})
                </h3>
              </div>
              <span className="text-xs text-app-muted font-mono">STRICTLY PASSIVE EXTERNAL QUERIES</span>
            </div>

            <div className="p-4 grid grid-cols-1 md:grid-cols-2 gap-4">
              {osintObservations.map((obs) => {
                const statusColor =
                  obs.status === 'SUCCESS'
                    ? 'text-emerald-400 bg-emerald-950/60 border-emerald-800'
                    : obs.status === 'SKIPPED_LOCAL_ONLY'
                    ? 'text-amber-400 bg-amber-950/60 border-amber-800'
                    : obs.status === 'NO_DATA'
                    ? 'text-slate-400 bg-slate-900 border-slate-800'
                    : 'text-rose-400 bg-rose-950/60 border-rose-800';

                return (
                  <div
                    key={obs.id}
                    className="bg-surface border border-app rounded-lg p-4 flex flex-col justify-between"
                  >
                    <div>
                      <div className="flex items-center justify-between mb-2">
                        <div className="flex items-center gap-2">
                          <span className="font-bold text-sm text-app-primary">{obs.provider}</span>
                          <span className="text-[11px] px-1.5 py-0.5 rounded bg-card text-app-muted border border-app font-mono">
                            {obs.indicator_type.toUpperCase()}
                          </span>
                        </div>
                        <span className={`px-2 py-0.5 rounded text-[10px] font-bold border font-mono ${statusColor}`}>
                          {obs.status}
                        </span>
                      </div>

                      <div className="font-mono text-xs text-cyan-400 mb-2 truncate">
                        {obs.indicator_value}
                      </div>

                      {/* Normalized Summary Content */}
                      <div className="text-xs text-app-secondary space-y-1 bg-card p-2.5 rounded border border-app">
                        {obs.provider === 'DNS' && obs.normalized_data.resolved_ips && (
                          <div>
                            <strong>Resolved IPs:</strong> {obs.normalized_data.resolved_ips.join(', ') || 'None'}
                          </div>
                        )}
                        {obs.provider === 'ReverseDNS' && obs.normalized_data.resolved_hostnames && (
                          <div>
                            <strong>Hostnames:</strong> {obs.normalized_data.resolved_hostnames.join(', ') || 'None'}
                          </div>
                        )}
                        {obs.provider === 'NetworkInfo' && (
                          <>
                            <div><strong>ASN:</strong> {obs.normalized_data.asn || 'N/A'}</div>
                            <div><strong>Organization:</strong> {obs.normalized_data.as_org || 'N/A'}</div>
                            <div>
                              <strong>Country:</strong> {obs.normalized_data.country || 'N/A'}{' '}
                              {obs.normalized_data.city ? `(${obs.normalized_data.city})` : ''}
                            </div>
                          </>
                        )}
                        {obs.provider === 'CertTransparency' && (
                          <>
                            <div>
                              <strong>Logged Certs:</strong> {obs.normalized_data.total_logged_certificates || 0}
                            </div>
                            {obs.normalized_data.discovered_subdomains?.length > 0 && (
                              <div>
                                <strong>Discovered Subdomains:</strong>{' '}
                                {obs.normalized_data.discovered_subdomains.slice(0, 4).join(', ')}...
                              </div>
                            )}
                          </>
                        )}
                        {obs.provider === 'RDAP' && (
                          <>
                            <div>
                              <strong>Registrar / Org:</strong>{' '}
                              {obs.normalized_data.registrar || obs.normalized_data.organization || 'Privacy Protected'}
                            </div>
                            {obs.normalized_data.registration_date && (
                              <div><strong>Registered:</strong> {obs.normalized_data.registration_date}</div>
                            )}
                          </>
                        )}
                        {['VirusTotal', 'AbuseIPDB', 'AlienVault OTX', 'MalwareBazaar', 'URLhaus'].includes(obs.provider) && (
                          <>
                            <div>
                              <strong>Detections:</strong> {obs.normalized_data.detections || 0} /{' '}
                              {obs.normalized_data.total_engines || 0}
                            </div>
                            <div><strong>Verdict:</strong> {obs.normalized_data.verdict || 'clean'}</div>
                          </>
                        )}
                        {obs.error_message && (
                          <div className="text-rose-400 font-sans">{obs.error_message}</div>
                        )}
                      </div>
                    </div>

                    <div className="mt-3 pt-2 border-t border-app flex items-center justify-between text-[11px] text-app-muted font-mono">
                      <span>Data: {obs.data_freshness}</span>
                      {obs.permalink && (
                        <a
                          href={obs.permalink}
                          target="_blank"
                          rel="noopener noreferrer"
                          className="text-cyan-400 hover:text-cyan-300 flex items-center gap-1 transition"
                        >
                          Source Record <ExternalLink className="w-3 h-3" />
                        </a>
                      )}
                    </div>
                  </div>
                );
              })}
              {osintObservations.length === 0 && (
                <div className="col-span-2 text-center py-6 text-app-muted text-xs">
                  No external observations logged yet. Click "Enrich All Indicators" to initiate passive queries.
                </div>
              )}
            </div>
          </div>
        </div>
      )}

      {/* TAB CONTENT: Secrets & Token Containment */}
      {activeSubTab === 'secrets' && (
        <div className="space-y-6">
          {/* Safeguard Attestation Banner */}
          <div className="p-4 bg-emerald-950/30 border border-emerald-800/60 rounded-xl flex items-start gap-3">
            <ShieldAlert className="w-5 h-5 text-emerald-400 shrink-0 mt-0.5" />
            <div>
              <h4 className="text-sm font-bold text-emerald-200">
                Strict Cryptographic Secret Containment Attestation
              </h4>
              <p className="text-xs text-emerald-300/80 mt-1 leading-relaxed">
                All recovered Telegram Bot API tokens, cloud access keys, and credentials discovered in digital evidence are
                strictly isolated. The workbench <strong>never transmits tokens to Telegram servers, webhook endpoints, or external verification services</strong>.
                Tokens are masked in all presentations and exports to prevent compromise.
              </p>
            </div>
          </div>

          <div className="space-y-4">
            {secretFindings.map((sec) => (
              <div
                key={sec.id}
                className="bg-card border border-app rounded-xl p-5 border-l-4 border-l-rose-500 shadow-sm"
              >
                <div className="flex items-center justify-between mb-3">
                  <div className="flex items-center gap-2">
                    <Key className="w-5 h-5 text-rose-400" />
                    <span className="font-bold text-app-primary text-sm uppercase">
                      {sec.secret_type.replace(/_/g, ' ')}
                    </span>
                  </div>
                  <span className="px-2.5 py-1 rounded text-xs font-bold bg-rose-950 text-rose-300 border border-rose-800 font-mono">
                    {sec.risk_level.toUpperCase()} RISK
                  </span>
                </div>

                <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mb-4">
                  <div className="bg-surface p-3 rounded-lg border border-app font-mono text-xs">
                    <div className="text-app-muted text-[11px] font-sans mb-1">Masked Secret Value:</div>
                    <div className="text-rose-400 font-bold tracking-wider">{sec.masked_token}</div>
                  </div>

                  <div className="bg-surface p-3 rounded-lg border border-app text-xs">
                    <div className="text-app-muted text-[11px] mb-1">Evidence Provenance:</div>
                    <div className="text-app-secondary">{sec.source_filename} ({sec.source_location})</div>
                  </div>
                </div>

                {sec.independently_found_public_identities?.length > 0 && (
                  <div className="mb-4 bg-sky-950/30 border border-sky-800/40 p-3 rounded-lg text-xs">
                    <div className="text-sky-300 font-semibold mb-1 flex items-center gap-1.5 font-sans">
                      <Radio className="w-3.5 h-3.5" /> Correlated Public Identities in Evidence:
                    </div>
                    <div className="flex flex-wrap gap-2 mt-1">
                      {sec.independently_found_public_identities.map((idVal, idx) => (
                        <span
                          key={idx}
                          className="px-2 py-0.5 rounded bg-sky-900/60 text-sky-200 font-mono text-xs border border-sky-700"
                        >
                          {idVal}
                        </span>
                      ))}
                    </div>
                  </div>
                )}

                <div className="bg-surface p-3.5 rounded-lg border border-app space-y-2 text-xs">
                  <div>
                    <strong className="text-app-primary">Observation: </strong>
                    <span className="text-app-secondary">{sec.observation}</span>
                  </div>
                  <div>
                    <strong className="text-app-primary">Forensic Interpretation: </strong>
                    <span className="text-app-secondary">{sec.interpretation}</span>
                  </div>
                  <div className="pt-2 border-t border-app text-emerald-400 text-[11px]">
                    <strong>Safety Attestation: </strong> {sec.safety_attestation}
                  </div>
                </div>
              </div>
            ))}

            {secretFindings.length === 0 && (
              <div className="bg-card border border-app rounded-xl p-8 text-center text-app-muted text-xs">
                No secret exposures or hardcoded API tokens detected in the evidence files of this case.
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
};
