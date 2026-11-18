import React, { useState, useEffect, useMemo } from 'react';
import {
  Globe,
  Search,
  Filter,
  ShieldCheck,
  ShieldAlert,
  AlertTriangle,
  Download,
  ExternalLink,
  FolderOpen,
  RefreshCw,
  Server,
  MapPin,
  Building,
  Lock,
  FileText,
  Check,
  Copy,
  X,
  Terminal,
  Cpu,
  Database,
  CheckCircle2,
  HardDrive
} from 'lucide-react';
import { api } from '../api';
import {
  InvestigationDetail,
  InvestigationIPsSummary,
  IPDetailRecord,
  SavedReportResult
} from '../types';

interface IpDetailsPageProps {
  detail: InvestigationDetail;
  networkMode?: 'LOCAL_ONLY' | 'HYBRID';
}

export const IpDetailsPage: React.FC<IpDetailsPageProps> = ({ detail, networkMode: propNetworkMode }) => {
  const [summary, setSummary] = useState<InvestigationIPsSummary | null>(null);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // Filter & Search states
  const [searchQuery, setSearchQuery] = useState('');
  const [versionFilter, setVersionFilter] = useState<'ALL' | 'IPv4' | 'IPv6'>('ALL');
  const [threatFilter, setThreatFilter] = useState<'ALL' | 'CLEAN' | 'SUSPICIOUS' | 'MALICIOUS' | 'UNKNOWN'>('ALL');
  const [scopeFilter, setScopeFilter] = useState<'ALL' | 'PUBLIC' | 'PRIVATE' | 'CLOUD'>('ALL');

  // Modal / Selected IP Report
  const [selectedIp, setSelectedIp] = useState<IPDetailRecord | null>(null);

  // Export action states
  const [exportingFormat, setExportingFormat] = useState<string | null>(null);
  const [exportResult, setExportResult] = useState<SavedReportResult | null>(null);
  const [exportError, setExportError] = useState<string | null>(null);
  const [copiedIp, setCopiedIp] = useState<string | null>(null);
  const [copiedPath, setCopiedPath] = useState(false);

  const loadIpData = async (forceRefresh: boolean = false) => {
    if (forceRefresh) setRefreshing(true);
    else setLoading(true);
    setError(null);
    try {
      const data = await api.getInvestigationIpDetails(detail.record.id, forceRefresh);
      setSummary(data);
      // If modal is open, refresh selected IP as well
      if (selectedIp) {
        const updated = data.ips.find(i => i.ip_address === selectedIp.ip_address);
        if (updated) setSelectedIp(updated);
      }
    } catch (err: any) {
      console.error(err);
      setError(err.message || 'Failed to extract and enrich IP details.');
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  };

  useEffect(() => {
    loadIpData(false);
  }, [detail.record.id, propNetworkMode]);

  const handleCopy = (text: string, id: string) => {
    navigator.clipboard.writeText(text);
    setCopiedIp(id);
    setTimeout(() => setCopiedIp(null), 2000);
  };

  const handleCopyFilePath = async (path: string) => {
    if (!path) return;
    try {
      // Confirm the file exists on the filesystem before copying
      const verified = await api.verifyReportPath(path);
      if (verified && verified.filepath) {
        await navigator.clipboard.writeText(verified.filepath);
        setCopiedPath(true);
        setTimeout(() => setCopiedPath(false), 2000);
      }
    } catch (e: any) {
      console.error('Failed to copy verified file path to clipboard', e);
      alert(`Could not copy path: ${e.message || e}`);
    }
  };

  // Filtered IP records
  const filteredIps = useMemo(() => {
    if (!summary?.ips) return [];
    return summary.ips.filter(rec => {
      // Search matching
      if (searchQuery.trim()) {
        const q = searchQuery.toLowerCase().trim();
        const ipMatch = rec.ip_address.toLowerCase().includes(q);
        const countryMatch = (rec.geolocation_info.country || '').toLowerCase().includes(q);
        const orgMatch = (rec.organization_info.organization || '').toLowerCase().includes(q);
        const asnMatch = (rec.routing_asn_info.asn || '').toLowerCase().includes(q);
        const cloudMatch = (rec.hosting_server_info.cloud_provider || '').toLowerCase().includes(q);
        const ptrMatch = (rec.domain_dns_info.reverse_dns || '').toLowerCase().includes(q);
        if (!ipMatch && !countryMatch && !orgMatch && !asnMatch && !cloudMatch && !ptrMatch) {
          return false;
        }
      }

      // Version filter
      if (versionFilter !== 'ALL' && rec.ip_version !== versionFilter) {
        return false;
      }

      // Threat filter
      if (threatFilter !== 'ALL' && rec.threat_info.threat_status.toUpperCase() !== threatFilter) {
        return false;
      }

      // Scope filter
      if (scopeFilter === 'PUBLIC' && (rec.classification.is_private || rec.classification.is_loopback)) {
        return false;
      }
      if (scopeFilter === 'PRIVATE' && !(rec.classification.is_private || rec.classification.is_loopback)) {
        return false;
      }
      if (scopeFilter === 'CLOUD' && !rec.classification.is_cloud) {
        return false;
      }

      return true;
    });
  }, [summary, searchQuery, versionFilter, threatFilter, scopeFilter]);

  // Export Individual IP
  const handleExportIndividual = async (ipRecord: IPDetailRecord, format: string) => {
    setExportingFormat(`IND_${format}_${ipRecord.ip_address}`);
    setExportError(null);
    setExportResult(null);
    try {
      const res = await api.exportSingleIpReport(detail.record.id, ipRecord.ip_address, format, true);
      setExportResult(res);
    } catch (err: any) {
      setExportError(err.message || `Failed to export ${format.toUpperCase()} report.`);
    } finally {
      setExportingFormat(null);
    }
  };

  // Export All IPs Dossier
  const handleExportAll = async (format: string) => {
    setExportingFormat(`ALL_${format}`);
    setExportError(null);
    setExportResult(null);
    try {
      const res = await api.exportAllIpsReport(detail.record.id, format, true);
      setExportResult(res);
    } catch (err: any) {
      setExportError(err.message || `Failed to export all-IP ${format.toUpperCase()} dossier.`);
    } finally {
      setExportingFormat(null);
    }
  };

  const handleOpenFile = async (filepath: string) => {
    try {
      await api.openReportFile(filepath);
    } catch (err: any) {
      alert(`Could not open file: ${err.message || err}`);
    }
  };

  const handleShowInFolder = async (filepath: string) => {
    try {
      await api.showReportInFolder(filepath);
    } catch (err: any) {
      alert(`Could not locate folder: ${err.message || err}`);
    }
  };

  return (
    <div className="p-4 sm:p-6 md:p-8 space-y-6">
      {/* Top Header */}
      <div className="border-b border-app pb-4 flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <h1 className="text-xl md:text-2xl font-bold text-app-primary tracking-tight flex flex-wrap items-center gap-2.5">
            <span>IP Details &amp; Network Intelligence</span>
            <span className="text-xs bg-cyan-50 dark:bg-cyan-950/60 text-cyan-700 dark:text-cyan-300 border border-cyan-300 dark:border-cyan-800 px-2.5 py-1 rounded-md font-mono font-medium">
              Law-Enforcement RDAP &amp; BGP Dossier
            </span>
          </h1>
          <p className="text-xs md:text-sm text-app-secondary mt-1">
            Comprehensive individual WHOIS/RDAP, Geolocation, ASN, Cloud, and Threat intelligence for every IP extracted during APK analysis.
          </p>
        </div>

        {/* Global Actions */}
        <div className="flex flex-wrap items-center gap-2.5">
          <button
            onClick={() => loadIpData(true)}
            disabled={refreshing || loading}
            className="bg-surface hover:bg-slate-200 dark:hover:bg-[#1e2736] border border-app text-app-primary text-xs px-3 py-2 rounded-lg font-bold flex items-center gap-1.5 transition-all shadow-sm cursor-pointer disabled:opacity-50"
            title="Re-run extraction and refresh enrichment"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${refreshing ? 'animate-spin' : ''}`} />
            <span>REFRESH</span>
          </button>

          {/* Export All Dropdown / Buttons */}
          <div className="flex items-center gap-1 bg-surface border border-app rounded-lg p-1 shadow-sm">
            <span className="text-[11px] font-mono text-app-muted px-2 select-none uppercase font-bold">Export All:</span>
            <button
              onClick={() => handleExportAll('pdf')}
              disabled={!!exportingFormat || !summary?.ips?.length}
              className="bg-rose-600 hover:bg-rose-700 text-white text-[11px] px-2.5 py-1 rounded font-bold transition-all cursor-pointer disabled:opacity-50"
              title="Export complete investigation IP dossier to PDF"
            >
              PDF
            </button>
            <button
              onClick={() => handleExportAll('html')}
              disabled={!!exportingFormat || !summary?.ips?.length}
              className="bg-emerald-600 hover:bg-emerald-700 text-white text-[11px] px-2.5 py-1 rounded font-bold transition-all cursor-pointer disabled:opacity-50"
              title="Export complete investigation IP dossier to HTML"
            >
              HTML
            </button>
            <button
              onClick={() => handleExportAll('json')}
              disabled={!!exportingFormat || !summary?.ips?.length}
              className="bg-indigo-600 hover:bg-indigo-700 text-white text-[11px] px-2.5 py-1 rounded font-bold transition-all cursor-pointer disabled:opacity-50"
              title="Export complete investigation IP dossier to JSON"
            >
              JSON
            </button>
          </div>
        </div>
      </div>

      {/* Network Privacy Notice Bar */}
      {(() => {
        const activeMode = propNetworkMode || summary?.network_mode || 'LOCAL_ONLY';
        return (
          <div className={`p-3 rounded-xl border text-xs flex items-center justify-between shadow-sm ${
            activeMode === 'LOCAL_ONLY'
              ? 'bg-amber-50 dark:bg-amber-950/40 border-amber-300 dark:border-amber-800 text-amber-900 dark:text-amber-200'
              : 'bg-emerald-50 dark:bg-emerald-950/40 border-emerald-300 dark:border-emerald-800 text-emerald-900 dark:text-emerald-200'
          }`}>
            <div className="flex items-center gap-2">
              <Lock className="w-4 h-4 shrink-0" />
              <span>
                <strong>Network Privacy Mode: {activeMode}</strong> —{' '}
                {activeMode === 'LOCAL_ONLY'
                  ? 'External RDAP and threat lookups are blocked. Displaying deterministic offline subnets and APK code references.'
                  : 'Authoritative RDAP, PTR DNS, and Geolocation lookups active with examiner consent.'}
              </span>
            </div>
            <span className="font-mono text-[11px] uppercase font-bold opacity-90">
              {activeMode}
            </span>
          </div>
        );
      })()}

      {/* Export Feedback / Notification Card */}
      {exportResult && (
        <div className="p-4 bg-emerald-50 dark:bg-emerald-950/60 border border-emerald-300 dark:border-emerald-800 rounded-2xl text-emerald-950 dark:text-emerald-100 shadow-md space-y-2.5">
          <div className="flex items-center justify-between border-b border-emerald-200 dark:border-emerald-800/80 pb-2">
            <div className="flex items-center gap-2">
              <CheckCircle2 className="w-4 h-4 text-emerald-600 dark:text-emerald-400 shrink-0" />
              <span className="font-bold text-xs">
                Report Successfully Generated &amp; Verified on Disk ({exportResult.format.toUpperCase()})
              </span>
            </div>
            <div className="flex items-center gap-2">
              <button
                onClick={() => handleOpenFile(exportResult.filepath)}
                className="bg-emerald-700 hover:bg-emerald-800 text-white text-xs px-3 py-1 rounded-md font-bold flex items-center gap-1 cursor-pointer"
              >
                <ExternalLink className="w-3 h-3" />
                <span>Open Report</span>
              </button>
              <button
                onClick={() => handleShowInFolder(exportResult.filepath)}
                className="bg-surface hover:bg-slate-200 dark:hover:bg-[#1e2736] border border-app text-app-primary text-xs px-3 py-1 rounded-md font-bold flex items-center gap-1 cursor-pointer"
              >
                <FolderOpen className="w-3 h-3 text-cyan-600" />
                <span>Show in Folder</span>
              </button>
              <button onClick={() => setExportResult(null)} className="text-xs text-app-muted hover:text-app-primary ml-1 cursor-pointer">
                <X className="w-3.5 h-3.5" />
              </button>
            </div>
          </div>
          <div className="flex items-center justify-between text-xs font-mono">
            <div className="truncate text-app-secondary" title={exportResult.filepath}>
              <span className="text-app-muted">File: </span>{exportResult.filename} ({exportResult.file_size_formatted})
            </div>
            <button
              onClick={() => handleCopyFilePath(exportResult.filepath)}
              className="text-xs text-cyan-600 hover:underline flex items-center gap-1 cursor-pointer"
            >
              {copiedPath ? <Check className="w-3 h-3 text-emerald-600" /> : <Copy className="w-3 h-3" />}
              <span>{copiedPath ? 'Copied' : 'Copy Path'}</span>
            </button>
          </div>
        </div>
      )}

      {/* KPI Summary Cards */}
      {summary && (
        <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-3">
          <div className="forensics-card p-3 rounded-xl border border-app shadow-xs">
            <div className="text-[11px] font-mono text-app-muted uppercase">Total Unique IPs</div>
            <div className="text-xl font-bold font-mono text-app-primary mt-1">{summary.total_unique_ips}</div>
            <div className="text-[10px] text-app-secondary mt-0.5">{summary.ipv4_count} IPv4 • {summary.ipv6_count} IPv6</div>
          </div>

          <div className="forensics-card p-3 rounded-xl border border-app shadow-xs">
            <div className="text-[11px] font-mono text-app-muted uppercase">Public Routable</div>
            <div className="text-xl font-bold font-mono text-cyan-600 dark:text-cyan-400 mt-1">{summary.public_ip_count}</div>
            <div className="text-[10px] text-app-secondary mt-0.5">Internet Facing</div>
          </div>

          <div className="forensics-card p-3 rounded-xl border border-app shadow-xs">
            <div className="text-[11px] font-mono text-app-muted uppercase">Private / RFC</div>
            <div className="text-xl font-bold font-mono text-slate-500 dark:text-slate-400 mt-1">{summary.private_ip_count}</div>
            <div className="text-[10px] text-app-secondary mt-0.5">Local / Air-Gapped</div>
          </div>

          <div className="forensics-card p-3 rounded-xl border border-app shadow-xs">
            <div className="text-[11px] font-mono text-app-muted uppercase">Cloud Hosted</div>
            <div className="text-xl font-bold font-mono text-indigo-600 dark:text-indigo-400 mt-1">{summary.cloud_ip_count}</div>
            <div className="text-[10px] text-app-secondary mt-0.5">AWS, Azure, GCP, Cloudflare</div>
          </div>

          <div className="forensics-card p-3 rounded-xl border border-app shadow-xs">
            <div className="text-[11px] font-mono text-app-muted uppercase">Malicious / Flagged</div>
            <div className="text-xl font-bold font-mono text-rose-600 dark:text-rose-400 mt-1">{summary.malicious_ip_count}</div>
            <div className="text-[10px] text-app-secondary mt-0.5">{summary.suspicious_ip_count} Suspicious</div>
          </div>

          <div className="forensics-card p-3 rounded-xl border border-app shadow-xs">
            <div className="text-[11px] font-mono text-app-muted uppercase">Verified Clean</div>
            <div className="text-xl font-bold font-mono text-emerald-600 dark:text-emerald-400 mt-1">{summary.clean_ip_count}</div>
            <div className="text-[10px] text-app-secondary mt-0.5">{summary.unknown_ip_count} Unchecked</div>
          </div>
        </div>
      )}

      {/* Search and Filters Toolbar */}
      <div className="forensics-card p-3.5 rounded-xl border border-app flex flex-col md:flex-row items-stretch md:items-center justify-between gap-3 text-xs shadow-xs">
        {/* Search */}
        <div className="flex items-center gap-2 flex-1 max-w-md bg-surface px-3 py-1.5 rounded-lg border border-app">
          <Search className="w-4 h-4 text-app-secondary dark:text-slate-400 shrink-0" />
          <input
            type="text"
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            placeholder="Search by IP, Country, ASN, Org, Cloud..."
            className="w-full bg-transparent text-app-primary placeholder:text-slate-500 dark:placeholder:text-slate-400 focus:outline-none text-xs font-mono font-medium"
          />
          {searchQuery && (
            <button onClick={() => setSearchQuery('')} className="text-app-muted hover:text-app-primary">
              <X className="w-3.5 h-3.5" />
            </button>
          )}
        </div>

        {/* Filter Pills */}
        <div className="flex flex-wrap items-center gap-2 shrink-0">
          {/* Version */}
          <select
            value={versionFilter}
            onChange={(e) => setVersionFilter(e.target.value as any)}
            className="bg-surface border border-app text-app-primary text-xs px-2.5 py-1.5 rounded-lg font-mono focus:outline-none cursor-pointer"
          >
            <option value="ALL">All Versions</option>
            <option value="IPv4">IPv4 Only</option>
            <option value="IPv6">IPv6 Only</option>
          </select>

          {/* Scope */}
          <select
            value={scopeFilter}
            onChange={(e) => setScopeFilter(e.target.value as any)}
            className="bg-surface border border-app text-app-primary text-xs px-2.5 py-1.5 rounded-lg font-mono focus:outline-none cursor-pointer"
          >
            <option value="ALL">All Networks</option>
            <option value="PUBLIC">Public Internet</option>
            <option value="PRIVATE">Private / RFC</option>
            <option value="CLOUD">Cloud / CDN</option>
          </select>

          {/* Threat */}
          <select
            value={threatFilter}
            onChange={(e) => setThreatFilter(e.target.value as any)}
            className="bg-surface border border-app text-app-primary text-xs px-2.5 py-1.5 rounded-lg font-mono focus:outline-none cursor-pointer"
          >
            <option value="ALL">All Reputations</option>
            <option value="CLEAN">Clean Only</option>
            <option value="SUSPICIOUS">Suspicious</option>
            <option value="MALICIOUS">Malicious</option>
            <option value="UNKNOWN">Unknown / Unrated</option>
          </select>
        </div>
      </div>

      {/* Main IP Table */}
      <div className="forensics-card rounded-2xl border border-app shadow-md overflow-hidden">
        {loading ? (
          <div className="p-16 text-center text-app-secondary flex flex-col items-center justify-center gap-2.5 font-mono text-xs">
            <RefreshCw className="w-6 h-6 animate-spin text-cyan-600 dark:text-cyan-400" />
            <span>Scanning artifacts and assembling IP intelligence records...</span>
          </div>
        ) : error ? (
          <div className="p-16 text-center text-rose-600 dark:text-rose-400 font-mono text-xs space-y-2">
            <ShieldAlert className="w-8 h-8 mx-auto text-rose-500 opacity-80 mb-2" />
            <div className="font-semibold text-sm text-app-primary">Failed to Load IP Intelligence Records</div>
            <div className="text-[11px] text-app-secondary max-w-lg mx-auto">{error}</div>
            <button
              onClick={() => loadIpData(true)}
              className="mt-4 px-4 py-1.5 bg-cyan-600 hover:bg-cyan-700 text-white rounded-lg text-xs font-bold transition-all cursor-pointer inline-flex items-center gap-1.5"
            >
              <RefreshCw className="w-3.5 h-3.5" />
              <span>Retry Investigation Extraction</span>
            </button>
          </div>
        ) : !summary || summary.total_unique_ips === 0 ? (
          <div className="p-16 text-center text-app-muted font-mono text-xs space-y-1">
            <Globe className="w-8 h-8 mx-auto text-app-muted opacity-40 mb-2" />
            <div className="font-semibold text-app-primary">No IP Addresses Discovered in Target Artifacts</div>
            <div className="text-[11px]">Static analysis found zero hardcoded IPv4 or IPv6 literals across bytecode, manifest, and configuration files.</div>
          </div>
        ) : filteredIps.length === 0 ? (
          <div className="p-16 text-center text-app-muted font-mono text-xs space-y-1">
            <Filter className="w-8 h-8 mx-auto text-app-muted opacity-40 mb-2" />
            <div className="font-semibold text-app-primary">No IP addresses matching current filters.</div>
            <div className="text-[11px]">
              {summary.total_unique_ips} IP address(es) discovered, but none match the active search query or filter selection. Try resetting filters.
            </div>
            <button
              onClick={() => {
                setSearchQuery('');
                setVersionFilter('ALL');
                setThreatFilter('ALL');
                setScopeFilter('ALL');
              }}
              className="mt-3 px-3 py-1 bg-surface hover:bg-slate-200 dark:hover:bg-[#1e2736] border border-app text-app-primary text-xs rounded-lg font-bold cursor-pointer"
            >
              Reset All Filters
            </button>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full border-collapse text-left text-xs font-mono">
              <thead>
                <tr className="bg-slate-100 dark:bg-[#0c121e] border-b border-app text-app-secondary dark:text-slate-300 font-bold uppercase text-[11px]">
                  <th className="p-3 pl-4">IP Address</th>
                  <th className="p-3">Country &amp; Location</th>
                  <th className="p-3">ISP / Organization</th>
                  <th className="p-3">ASN</th>
                  <th className="p-3">Cloud / Hosting</th>
                  <th className="p-3">Threat Reputation</th>
                  <th className="p-3">APK Evidence</th>
                  <th className="p-3 pr-4 text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-app">
                {filteredIps.map((rec) => {
                  const isPriv = rec.classification.is_private || rec.classification.is_loopback;
                  const threat = rec.threat_info.threat_status.toUpperCase();
                  const badgeColor = threat === 'CLEAN'
                    ? 'text-emerald-700 bg-emerald-50 dark:bg-emerald-950/60 border-emerald-300 dark:border-emerald-800'
                    : (threat === 'MALICIOUS'
                      ? 'text-rose-700 bg-rose-50 dark:bg-rose-950/60 border-rose-300 dark:border-rose-800'
                      : (threat === 'SUSPICIOUS'
                        ? 'text-amber-700 bg-amber-50 dark:bg-amber-950/60 border-amber-300 dark:border-amber-800'
                        : 'text-slate-600 bg-slate-100 dark:bg-slate-900/60 border-slate-300 dark:border-slate-800'));

                  return (
                    <tr key={rec.ip_address} className="hover:bg-slate-50/60 dark:hover:bg-[#0f172a]/40 transition-colors">
                      {/* IP & Version */}
                      <td className="p-3 pl-4 font-semibold text-app-primary">
                        <div className="flex items-center gap-1.5">
                          <span
                            onClick={() => setSelectedIp(rec)}
                            className="text-cyan-700 dark:text-cyan-300 hover:text-cyan-500 hover:underline cursor-pointer select-all font-bold"
                            title="Click to view detailed intelligence profile"
                          >
                            {rec.ip_address}
                          </span>
                          <span className="text-[10px] bg-surface text-app-muted border border-app px-1.5 py-0.5 rounded">
                            {rec.ip_version}
                          </span>
                          <button
                            onClick={() => handleCopy(rec.ip_address, rec.ip_address)}
                            className="text-app-muted hover:text-cyan-600 transition-colors cursor-pointer"
                            title="Copy IP"
                          >
                            {copiedIp === rec.ip_address ? <Check className="w-3 h-3 text-emerald-600" /> : <Copy className="w-3 h-3" />}
                          </button>
                        </div>
                        {rec.domain_dns_info.reverse_dns && (
                          <div className="text-[10px] text-app-muted truncate max-w-xs mt-0.5" title={rec.domain_dns_info.reverse_dns}>
                            PTR: {rec.domain_dns_info.reverse_dns}
                          </div>
                        )}
                      </td>

                      {/* Location */}
                      <td className="p-3 text-app-secondary">
                        {isPriv ? (
                          <span className="text-slate-500 italic">Internal Subnet</span>
                        ) : (
                          <div>
                            <div className="font-medium text-app-primary">{rec.geolocation_info.country || 'Not Available'}</div>
                            <div className="text-[10px] text-app-muted">{rec.geolocation_info.city || rec.geolocation_info.region || 'Approx Location'}</div>
                          </div>
                        )}
                      </td>

                      {/* Organization */}
                      <td className="p-3 text-app-secondary truncate max-w-xs" title={rec.organization_info.organization || rec.routing_asn_info.isp || 'N/A'}>
                        <div className="truncate text-app-primary">{rec.organization_info.organization || rec.routing_asn_info.isp || 'Not Available'}</div>
                        {rec.network_info.net_name && (
                          <div className="text-[10px] text-app-muted truncate">Net: {rec.network_info.net_name}</div>
                        )}
                      </td>

                      {/* ASN */}
                      <td className="p-3 text-app-secondary">
                        {rec.routing_asn_info.asn ? (
                          <span className="text-cyan-700 dark:text-cyan-400 font-bold">{rec.routing_asn_info.asn}</span>
                        ) : (
                          <span className="text-app-muted">N/A</span>
                        )}
                      </td>

                      {/* Cloud / Hosting */}
                      <td className="p-3 text-app-secondary">
                        {rec.hosting_server_info.cloud_provider ? (
                          <span className="inline-flex items-center gap-1 text-[11px] bg-indigo-50 dark:bg-indigo-950/60 text-indigo-700 dark:text-indigo-300 border border-indigo-200 dark:border-indigo-800 px-2 py-0.5 rounded-md font-medium">
                            <Server className="w-3 h-3" />
                            <span>{rec.hosting_server_info.cloud_provider}</span>
                          </span>
                        ) : (
                          <span className="text-app-muted text-[11px]">{rec.classification.classification_label}</span>
                        )}
                      </td>

                      {/* Threat Reputation */}
                      <td className="p-3">
                        <span className={`inline-block text-[11px] px-2 py-0.5 rounded-md border font-bold ${badgeColor}`}>
                          {threat}
                        </span>
                      </td>

                      {/* Evidence Count */}
                      <td className="p-3 text-app-secondary font-mono">
                        <span className="bg-surface border border-app px-2 py-0.5 rounded text-[11px] font-semibold text-app-primary">
                          {rec.evidence_references.length} ref{rec.evidence_references.length !== 1 ? 's' : ''}
                        </span>
                      </td>

                      {/* Actions */}
                      <td className="p-3 pr-4 text-right shrink-0">
                        <div className="inline-flex items-center gap-1.5">
                          <button
                            onClick={() => setSelectedIp(rec)}
                            className="bg-cyan-600 hover:bg-cyan-700 text-white text-[11px] px-2.5 py-1 rounded font-bold transition-all cursor-pointer shadow-xs"
                            title="View comprehensive RDAP, Geolocation, and Evidence details"
                          >
                            View Report
                          </button>
                        </div>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* ==================================================================== */}
      {/* INDIVIDUAL IP FULL REPORT MODAL                                      */}
      {/* ==================================================================== */}
      {selectedIp && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-3 sm:p-6 bg-black/75 backdrop-blur-xs overflow-y-auto">
          <div className="bg-surface border border-app rounded-2xl max-w-4xl w-full max-h-[90vh] flex flex-col shadow-2xl overflow-hidden animate-in fade-in zoom-in-95 duration-150">
            {/* Modal Header */}
            <div className="p-4 sm:p-5 border-b border-app flex items-center justify-between gap-3 bg-slate-100/50 dark:bg-[#0c121e]/50">
              <div className="flex items-center gap-2.5">
                <Globe className="w-5 h-5 text-cyan-600 dark:text-cyan-400 shrink-0" />
                <div>
                  <h2 className="text-base sm:text-lg font-bold text-app-primary flex items-center gap-2 font-mono">
                    <span>IP Intelligence: {selectedIp.ip_address}</span>
                    <span className="text-[11px] bg-surface text-app-muted border border-app px-1.5 py-0.5 rounded font-normal">
                      {selectedIp.ip_version}
                    </span>
                  </h2>
                  <div className="text-xs text-app-secondary">
                    Investigation: {selectedIp.investigation_id} • Status: {selectedIp.lookup_status}
                  </div>
                </div>
              </div>

              {/* Close Button */}
              <button
                onClick={() => setSelectedIp(null)}
                className="p-1.5 rounded-lg text-app-muted hover:text-app-primary hover:bg-slate-200 dark:hover:bg-[#1e2736] transition-colors cursor-pointer"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            {/* Modal Actions Bar */}
            <div className="px-5 py-3 border-b border-app bg-surface flex flex-wrap items-center justify-between gap-3 text-xs">
              <div className="flex items-center gap-2">
                <span className="text-app-muted font-mono font-bold uppercase text-[11px]">Save To Documents:</span>
                <button
                  onClick={() => handleExportIndividual(selectedIp, 'pdf')}
                  disabled={!!exportingFormat}
                  className="bg-rose-600 hover:bg-rose-700 text-white text-[11px] px-2.5 py-1 rounded font-bold transition-all cursor-pointer disabled:opacity-50"
                >
                  PDF
                </button>
                <button
                  onClick={() => handleExportIndividual(selectedIp, 'html')}
                  disabled={!!exportingFormat}
                  className="bg-emerald-600 hover:bg-emerald-700 text-white text-[11px] px-2.5 py-1 rounded font-bold transition-all cursor-pointer disabled:opacity-50"
                >
                  HTML
                </button>
                <button
                  onClick={() => handleExportIndividual(selectedIp, 'txt')}
                  disabled={!!exportingFormat}
                  className="bg-cyan-600 hover:bg-cyan-700 text-white text-[11px] px-2.5 py-1 rounded font-bold transition-all cursor-pointer disabled:opacity-50"
                >
                  TXT
                </button>
                <button
                  onClick={() => handleExportIndividual(selectedIp, 'json')}
                  disabled={!!exportingFormat}
                  className="bg-indigo-600 hover:bg-indigo-700 text-white text-[11px] px-2.5 py-1 rounded font-bold transition-all cursor-pointer disabled:opacity-50"
                >
                  JSON
                </button>
              </div>

              <div className="flex items-center gap-2">
                <span className="font-mono text-[11px] text-app-muted">Location: Documents\TraceX\IP Reports</span>
              </div>
            </div>

            {/* Modal Body (Scrollable) */}
            <div className="p-5 overflow-y-auto space-y-5 text-xs font-mono">
              {/* [1] IP Network Information */}
              <div className="forensics-card p-4 rounded-xl border border-app space-y-2.5">
                <div className="text-xs font-bold text-cyan-600 dark:text-cyan-400 uppercase tracking-wider border-b border-app pb-1">
                  [1] IP Network Information (Authoritative RDAP)
                </div>
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 text-xs">
                  <div><span className="text-app-muted">NetRange: </span><span className="text-app-primary">{selectedIp.network_info.net_range || 'Not Available'}</span></div>
                  <div><span className="text-app-muted">CIDR: </span><span className="text-app-primary">{selectedIp.network_info.cidr || 'Not Available'}</span></div>
                  <div><span className="text-app-muted">NetName: </span><span className="text-app-primary">{selectedIp.network_info.net_name || 'Not Available'}</span></div>
                  <div><span className="text-app-muted">NetHandle: </span><span className="text-app-primary">{selectedIp.network_info.net_handle || 'Not Available'}</span></div>
                  <div><span className="text-app-muted">Origin AS: </span><span className="text-app-primary">{selectedIp.network_info.origin_as || selectedIp.routing_asn_info.asn || 'Not Available'}</span></div>
                  <div><span className="text-app-muted">Registry (RIR): </span><span className="text-app-primary font-bold">{selectedIp.network_info.rir || 'Not Available'}</span></div>
                  <div><span className="text-app-muted">Registration Status: </span><span className="text-app-primary">{selectedIp.network_info.registration_status || 'Active'}</span></div>
                  <div><span className="text-app-muted">Classification: </span><span className="text-app-primary">{selectedIp.classification.classification_label}</span></div>
                </div>
                {selectedIp.network_info.comment && (
                  <div className="p-2 bg-slate-100 dark:bg-[#0c121e] rounded border border-app text-[11px] text-app-secondary whitespace-pre-wrap">
                    {selectedIp.network_info.comment}
                  </div>
                )}
              </div>

              {/* [2] Organization & Geolocation Information */}
              <div className="forensics-card p-4 rounded-xl border border-app space-y-2.5">
                <div className="text-xs font-bold text-cyan-600 dark:text-cyan-400 uppercase tracking-wider border-b border-app pb-1">
                  [2] Organization &amp; Geolocation Intelligence
                </div>
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 text-xs">
                  <div><span className="text-app-muted">Organization: </span><span className="text-app-primary font-bold">{selectedIp.organization_info.organization || 'Not Available'}</span></div>
                  <div><span className="text-app-muted">Country: </span><span className="text-app-primary">{selectedIp.geolocation_info.country || 'Not Available'} ({selectedIp.geolocation_info.country_code || 'N/A'})</span></div>
                  <div><span className="text-app-muted">Region / State: </span><span className="text-app-primary">{selectedIp.geolocation_info.region || 'Not Available'}</span></div>
                  <div><span className="text-app-muted">City: </span><span className="text-app-primary">{selectedIp.geolocation_info.city || 'Not Available'}</span></div>
                  <div><span className="text-app-muted">Approx Coordinates: </span><span className="text-app-primary">{selectedIp.geolocation_info.latitude || 'N/A'}, {selectedIp.geolocation_info.longitude || 'N/A'}</span></div>
                  <div><span className="text-app-muted">ISP / Transit: </span><span className="text-app-primary">{selectedIp.routing_asn_info.isp || 'Not Available'}</span></div>
                </div>
                <div className="p-2 bg-indigo-50 dark:bg-indigo-950/40 rounded border border-indigo-200 dark:border-indigo-800 text-[11px] text-indigo-900 dark:text-indigo-200">
                  {selectedIp.geolocation_info.disclaimer}
                </div>
              </div>

              {/* [3] Hosting, Cloud & DNS PTR */}
              <div className="forensics-card p-4 rounded-xl border border-app space-y-2.5">
                <div className="text-xs font-bold text-cyan-600 dark:text-cyan-400 uppercase tracking-wider border-b border-app pb-1">
                  [3] Infrastructure, Cloud &amp; DNS Records
                </div>
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 text-xs">
                  <div><span className="text-app-muted">Cloud Provider: </span><span className="text-app-primary font-bold">{selectedIp.hosting_server_info.cloud_provider || 'None Detected'}</span></div>
                  <div><span className="text-app-muted">Server Classification: </span><span className="text-app-primary">{selectedIp.hosting_server_info.server_classification}</span></div>
                  <div><span className="text-app-muted">Reverse DNS (PTR): </span><span className="text-app-primary select-all">{selectedIp.domain_dns_info.reverse_dns || 'No PTR Record'}</span></div>
                  <div><span className="text-app-muted">Autonomous System: </span><span className="text-app-primary">{selectedIp.routing_asn_info.asn || 'N/A'} ({selectedIp.routing_asn_info.asn_name || 'N/A'})</span></div>
                </div>
                {selectedIp.domain_dns_info.associated_urls.length > 0 && (
                  <div className="text-[11px] pt-1">
                    <span className="text-app-muted">Associated APK Endpoint(s): </span>
                    <span className="text-app-primary">{selectedIp.domain_dns_info.associated_urls.join(', ')}</span>
                  </div>
                )}
              </div>

              {/* [4] Official Organizational Contacts */}
              <div className="forensics-card p-4 rounded-xl border border-app space-y-2.5">
                <div className="text-xs font-bold text-cyan-600 dark:text-cyan-400 uppercase tracking-wider border-b border-app pb-1">
                  [4] Official Registry Contacts (Privacy-Preserved)
                </div>
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 text-xs">
                  <div><span className="text-app-muted">Abuse Contact Email: </span><span className="text-app-primary">{selectedIp.organization_info.abuse_contact_email || 'Not Available'}</span></div>
                  <div><span className="text-app-muted">Abuse Phone: </span><span className="text-app-primary">{selectedIp.organization_info.abuse_contact_phone || 'Not Available'}</span></div>
                  <div><span className="text-app-muted">Technical Contact Email: </span><span className="text-app-primary">{selectedIp.organization_info.tech_contact_email || 'Not Available'}</span></div>
                  <div><span className="text-app-muted">Technical Phone: </span><span className="text-app-primary">{selectedIp.organization_info.tech_contact_phone || 'Not Available'}</span></div>
                </div>
              </div>

              {/* [5] Threat Intelligence & Reputation */}
              <div className="forensics-card p-4 rounded-xl border border-app space-y-2.5">
                <div className="text-xs font-bold text-cyan-600 dark:text-cyan-400 uppercase tracking-wider border-b border-app pb-1">
                  [5] Threat Intelligence &amp; Reputation Summary
                </div>
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 text-xs">
                  <div><span className="text-app-muted">Threat Classification: </span><span className="text-app-primary font-bold">{selectedIp.threat_info.threat_status}</span></div>
                  <div><span className="text-app-muted">Blacklist Status: </span><span className="text-app-primary">{selectedIp.threat_info.blacklist_status}</span></div>
                  <div><span className="text-app-muted">Engines Flagged Malicious: </span><span className="text-app-primary">{selectedIp.threat_info.malicious_count}</span></div>
                  <div><span className="text-app-muted">Abuse Confidence Score: </span><span className="text-app-primary">{selectedIp.threat_info.abuse_confidence_score !== undefined ? `${selectedIp.threat_info.abuse_confidence_score}%` : 'N/A'}</span></div>
                </div>
              </div>

              {/* [6] Evidence Traceability in APK */}
              <div className="forensics-card p-4 rounded-xl border border-app space-y-2.5">
                <div className="text-xs font-bold text-cyan-600 dark:text-cyan-400 uppercase tracking-wider border-b border-app pb-1">
                  [6] Evidence Traceability in Application Code ({selectedIp.evidence_references.length} Reference(s))
                </div>
                <div className="divide-y divide-app">
                  {selectedIp.evidence_references.map((ref, i) => (
                    <div key={i} className="py-2 space-y-1 text-[11px]">
                      <div className="text-app-primary font-semibold flex items-center gap-2">
                        <span className="text-cyan-600">#{i + 1}</span>
                        <span>{ref.source_file}</span>
                      </div>
                      {(ref.class_name || ref.method_name) && (
                        <div className="text-app-muted">
                          Code: {ref.class_name ? `${ref.class_name} -> ` : ''}{ref.method_name || ''}
                        </div>
                      )}
                      {ref.associated_url && (
                        <div className="text-app-secondary truncate">
                          URL: <span className="text-cyan-600 dark:text-cyan-400 select-all">{ref.associated_url}</span>
                        </div>
                      )}
                      {ref.context_snippet && (
                        <div className="p-1.5 bg-slate-100 dark:bg-[#0c121e] rounded text-app-secondary text-[10px] break-all">
                          {ref.context_snippet}
                        </div>
                      )}
                    </div>
                  ))}
                </div>
              </div>
            </div>

            {/* Modal Footer */}
            <div className="p-4 border-t border-app bg-slate-100/50 dark:bg-[#0c121e]/50 flex items-center justify-between text-xs">
              <span className="text-app-muted font-mono text-[11px]">
                {selectedIp.source_references.length} Intelligence Source Reference(s) Attached
              </span>
              <button
                onClick={() => setSelectedIp(null)}
                className="bg-surface hover:bg-slate-200 dark:hover:bg-[#1e2736] border border-app text-app-primary px-4 py-1.5 rounded-lg font-bold transition-all cursor-pointer"
              >
                Close Report
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
