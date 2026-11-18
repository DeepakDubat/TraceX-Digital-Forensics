import React, { useState, useEffect } from 'react';
import {
  Cpu,
  Radio,
  FileCode,
  Layers,
  UploadCloud,
  CheckCircle2,
  XCircle,
  AlertTriangle,
  RotateCcw,
  Terminal,
  Server,
  Network,
  Activity,
  ShieldAlert,
  FileSearch,
  ExternalLink,
  Lock,
  Box,
  FileCheck
} from 'lucide-react';
import { api } from '../api';
import {
  InvestigationDetail,
  SandboxToolStatus,
  DynamicSandboxRun,
  DynamicTelemetryEvent,
  NetworkFlowRecord
} from '../types';

interface DynamicSandboxPageProps {
  detail: InvestigationDetail;
}

export const DynamicSandboxPage: React.FC<DynamicSandboxPageProps> = ({ detail }) => {
  const invId = detail.record.id;

  const [toolStatuses, setToolStatuses] = useState<SandboxToolStatus[]>([]);
  const [runs, setRuns] = useState<DynamicSandboxRun[]>([]);
  const [selectedRunId, setSelectedRunId] = useState<string>('');
  const [telemetryEvents, setTelemetryEvents] = useState<DynamicTelemetryEvent[]>([]);
  const [networkFlows, setNetworkFlows] = useState<NetworkFlowRecord[]>([]);
  const [loading, setLoading] = useState(false);

  // Tab: 'flows' | 'events' | 'tools'
  const [activeTab, setActiveTab] = useState<'flows' | 'events' | 'tools'>('flows');

  // PCAP upload state
  const [uploadingPcap, setUploadingPcap] = useState(false);
  const [pcapFile, setPcapFile] = useState<File | null>(null);
  const [pcapEnv, setPcapEnv] = useState('Isolated VM Guest');
  const [pcapSimulated, setPcapSimulated] = useState(true);
  const [uploadError, setUploadError] = useState<string | null>(null);

  // Filter state
  const [flowFilter, setFlowFilter] = useState('');
  const [eventCategoryFilter, setEventCategoryFilter] = useState('ALL');

  const loadData = async () => {
    setLoading(true);
    try {
      const [toolsRes, runsRes] = await Promise.all([
        api.getSandboxTools().catch(() => []),
        api.getSandboxRuns(invId).catch(() => [])
      ]);
      setToolStatuses(toolsRes);
      setRuns(runsRes);

      if (runsRes.length > 0 && !selectedRunId) {
        setSelectedRunId(runsRes[0].id);
      }
    } catch (err) {
      console.error('Failed to load sandbox data:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadData();
  }, [invId]);

  // Load telemetry and flows when selectedRunId changes
  useEffect(() => {
    if (!selectedRunId) {
      setTelemetryEvents([]);
      setNetworkFlows([]);
      return;
    }
    const fetchRunData = async () => {
      try {
        const [telemRes, flowsRes] = await Promise.all([
          api.getRunTelemetry(selectedRunId).catch(() => []),
          api.getRunFlows(selectedRunId).catch(() => [])
        ]);
        setTelemetryEvents(telemRes);
        setNetworkFlows(flowsRes);
      } catch (err) {
        console.error('Failed to load telemetry/flows:', err);
      }
    };
    fetchRunData();
  }, [selectedRunId]);

  const handlePcapUpload = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!pcapFile) return;

    setUploadingPcap(true);
    setUploadError(null);
    try {
      const formData = new FormData();
      formData.append('file', pcapFile);
      formData.append('investigation_id', invId);
      formData.append('evidence_id', detail.record.id);
      formData.append('sandbox_environment', pcapEnv);
      formData.append('is_simulated_network', String(pcapSimulated));

      const newRun = await api.uploadSandboxPcap(formData);
      setPcapFile(null);
      await loadData();
      setSelectedRunId(newRun.id);
      setActiveTab('flows');
    } catch (err: any) {
      setUploadError(err.message || 'PCAP processing failed.');
    } finally {
      setUploadingPcap(false);
    }
  };

  const selectedRun = runs.find(r => r.id === selectedRunId);

  const filteredFlows = networkFlows.filter(f => {
    const q = flowFilter.toLowerCase();
    return (
      f.src_ip.toLowerCase().includes(q) ||
      f.dst_ip.toLowerCase().includes(q) ||
      f.protocol.toLowerCase().includes(q) ||
      (f.dns_hostname && f.dns_hostname.toLowerCase().includes(q)) ||
      (f.tls_sni && f.tls_sni.toLowerCase().includes(q)) ||
      (f.http_method && f.http_method.toLowerCase().includes(q))
    );
  });

  const filteredEvents = telemetryEvents.filter(e => {
    if (eventCategoryFilter !== 'ALL' && e.event_category !== eventCategoryFilter) {
      return false;
    }
    return true;
  });

  return (
    <div className="p-4 sm:p-6 md:p-8 space-y-6 max-w-7xl mx-auto">
      {/* Top Banner */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-app pb-4">
        <div>
          <div className="flex items-center gap-3">
            <div className="p-2.5 rounded-xl bg-purple-500/10 text-purple-600 dark:text-purple-400 border border-purple-500/20">
              <Cpu className="w-6 h-6" />
            </div>
            <div>
              <h1 className="text-xl md:text-2xl font-bold text-app-primary tracking-tight flex items-center gap-2">
                Dynamic Sandbox Forensics & Network Telemetry
                <span className="text-xs px-2.5 py-0.5 rounded-full font-semibold uppercase bg-purple-500/10 text-purple-700 dark:text-purple-300 border border-purple-500/30">
                  Zero Host Execution Guarantee
                </span>
              </h1>
              <p className="text-xs md:text-sm text-app-secondary mt-0.5">
                Isolated sandbox execution telemetry, pure-Python PCAP/PCAPNG packet dissector, flow tracking, and DNS/TLS/HTTP extraction.
              </p>
            </div>
          </div>
        </div>

        {/* Global actions */}
        <div className="flex items-center gap-2">
          <button
            onClick={loadData}
            className="px-3 py-1.5 rounded-xl text-xs font-semibold border border-app bg-surface text-app-secondary hover:text-app-primary transition-all flex items-center gap-2 cursor-pointer"
          >
            <RotateCcw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
            Refresh
          </button>
        </div>
      </div>

      {/* Safety Notice */}
      <div className="p-4 rounded-xl border border-app bg-surface text-xs flex items-start gap-3">
        <ShieldAlert className="w-5 h-5 text-purple-600 dark:text-purple-400 shrink-0 mt-0.5" />
        <div className="space-y-1">
          <p className="font-semibold text-app-primary">
            Host Workstation Isolation & Honest Telemetry Semantics
          </p>
          <p className="text-app-secondary">
            Suspicious APKs and EXEs are never executed directly on the host operating system. Runtime captures are ingested from isolated sandbox VMs (such as CAPE Sandbox) or controlled network simulators (FakeNet-NG, INetSim). Simulated network responses are explicitly tagged with <span className="font-bold text-amber-600 dark:text-amber-400">[SIMULATED]</span> and are never presented as confirmed communication with live threat actor servers.
          </p>
        </div>
      </div>

      {/* Sandbox Tools Detection Row */}
      <div className="bg-surface border border-app rounded-2xl p-4 shadow-xs space-y-3">
        <div className="flex items-center justify-between border-b border-app pb-2">
          <span className="text-xs font-bold text-app-primary flex items-center gap-2">
            <Server className="w-4 h-4 text-purple-600 dark:text-purple-400" />
            Configured Dynamic Tools & Network Simulators ({toolStatuses.length})
          </span>
          <span className="text-[11px] text-app-secondary">Real-time status check</span>
        </div>

        <div className="grid grid-cols-2 sm:grid-cols-3 md:grid-cols-6 gap-3">
          {toolStatuses.map((t) => (
            <div
              key={t.tool_name}
              className="p-2.5 rounded-xl border border-app bg-app/50 text-center space-y-1"
            >
              <div className="text-[11px] font-bold text-app-primary truncate" title={t.tool_name}>
                {t.tool_name}
              </div>
              <div>
                <span className={`text-[10px] font-bold px-2 py-0.5 rounded-full uppercase border ${
                  t.status === 'INSTALLED'
                    ? 'bg-emerald-100 text-emerald-800 dark:bg-emerald-950 dark:text-emerald-300 border-emerald-300 dark:border-emerald-800'
                    : t.status === 'NOT_CONFIGURED'
                    ? 'bg-amber-100 text-amber-800 dark:bg-amber-950 dark:text-amber-300 border-amber-300 dark:border-amber-800'
                    : 'bg-zinc-100 text-zinc-600 dark:bg-zinc-800 dark:text-zinc-400 border-zinc-300 dark:border-zinc-700'
                }`}>
                  {t.status.replace('_', ' ')}
                </span>
              </div>
              {t.version && (
                <div className="text-[10px] font-mono text-app-secondary truncate">{t.version}</div>
              )}
            </div>
          ))}
        </div>
      </div>

      {/* PCAP Intake & Run Management */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* PCAP / Telemetry Upload Card */}
        <div className="lg:col-span-1 bg-surface border border-app rounded-2xl p-5 shadow-xs space-y-4">
          <div className="border-b border-app pb-3">
            <h2 className="text-sm font-bold text-app-primary flex items-center gap-2">
              <UploadCloud className="w-4 h-4 text-purple-600 dark:text-purple-400" />
              Ingest PCAP / Capture File
            </h2>
            <p className="text-xs text-app-secondary mt-0.5">
              Upload packet capture (.pcap / .pcapng) from dedicated sandbox VM or network simulator.
            </p>
          </div>

          {uploadError && (
            <div className="p-3 rounded-xl bg-rose-50 dark:bg-rose-950/50 border border-rose-300 dark:border-rose-800 text-rose-800 dark:text-rose-300 text-xs">
              {uploadError}
            </div>
          )}

          <form onSubmit={handlePcapUpload} className="space-y-3 text-xs">
            <div className="space-y-1">
              <label className="font-semibold text-app-secondary">Select Packet Capture File *</label>
              <input
                type="file"
                accept=".pcap,.pcapng,.cap"
                onChange={(e) => setPcapFile(e.target.files?.[0] || null)}
                className="w-full text-xs text-app-primary file:mr-3 file:py-1.5 file:px-3 file:rounded-xl file:border-0 file:text-xs file:font-semibold file:bg-purple-600 file:text-white hover:file:bg-purple-500 cursor-pointer"
                required
              />
            </div>

            <div className="space-y-1">
              <label className="font-semibold text-app-secondary">Sandbox Environment Label</label>
              <input
                type="text"
                value={pcapEnv}
                onChange={(e) => setPcapEnv(e.target.value)}
                className="w-full bg-app border border-app rounded-xl px-3 py-2 text-app-primary text-xs focus:outline-hidden focus:border-purple-500"
              />
            </div>

            <div className="p-3 bg-app rounded-xl border border-app flex items-start gap-2.5">
              <input
                type="checkbox"
                id="isSimulated"
                checked={pcapSimulated}
                onChange={(e) => setPcapSimulated(e.target.checked)}
                className="mt-0.5 rounded text-purple-600 focus:ring-purple-500 cursor-pointer"
              />
              <label htmlFor="isSimulated" className="text-[11px] text-app-secondary cursor-pointer leading-tight">
                <strong className="text-app-primary">Simulated Network Traffic:</strong> Check this if capture was generated with FakeNet-NG / INetSim or an internal non-routed sinkhole.
              </label>
            </div>

            <button
              type="submit"
              disabled={uploadingPcap || !pcapFile}
              className="w-full py-2 rounded-xl bg-purple-600 text-white font-bold text-xs hover:bg-purple-500 transition-all cursor-pointer disabled:opacity-50 flex items-center justify-center gap-2"
            >
              {uploadingPcap ? (
                <>
                  <RotateCcw className="w-4 h-4 animate-spin" />
                  Parsing Packets & Dissecting...
                </>
              ) : (
                <>
                  <FileSearch className="w-4 h-4" />
                  Dissect & Analyze Capture
                </>
              )}
            </button>
          </form>

          {/* Runs List Selector */}
          <div className="pt-3 border-t border-app space-y-2">
            <label className="text-xs font-semibold text-app-secondary uppercase tracking-wider block">
              Recorded Sandbox Runs ({runs.length})
            </label>
            {runs.length === 0 ? (
              <p className="text-xs text-app-secondary text-center py-2">No runs imported yet.</p>
            ) : (
              <div className="space-y-1.5 max-h-48 overflow-y-auto">
                {runs.map((r) => (
                  <button
                    key={r.id}
                    onClick={() => setSelectedRunId(r.id)}
                    className={`w-full text-left p-2.5 rounded-xl border transition-all text-xs cursor-pointer ${
                      selectedRunId === r.id
                        ? 'border-purple-500 bg-purple-500/10 text-app-primary font-bold shadow-xs'
                        : 'border-app bg-app/50 text-app-secondary hover:text-app-primary hover:border-purple-500/50'
                    }`}
                  >
                    <div className="flex items-center justify-between">
                      <span className="truncate max-w-[160px] font-mono">{r.target_binary}</span>
                      <span className={`text-[10px] px-1.5 py-0.2 rounded font-bold uppercase ${
                        r.is_simulated_network
                          ? 'bg-amber-100 text-amber-800 dark:bg-amber-950 dark:text-amber-300'
                          : 'bg-emerald-100 text-emerald-800 dark:bg-emerald-950 dark:text-emerald-300'
                      }`}>
                        {r.is_simulated_network ? 'Simulated' : 'Live'}
                      </span>
                    </div>
                    <div className="text-[11px] text-app-secondary flex items-center justify-between mt-1">
                      <span>{r.network_flow_count} flows</span>
                      <span>{r.process_count} procs</span>
                    </div>
                  </button>
                ))}
              </div>
            )}
          </div>
        </div>

        {/* Telemetry & Flow Explorer Tabs */}
        <div className="lg:col-span-2 space-y-4">
          <div className="bg-surface border border-app rounded-2xl p-5 shadow-xs space-y-4">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-app pb-3">
              <div className="flex items-center gap-2">
                <button
                  onClick={() => setActiveTab('flows')}
                  className={`px-3 py-1.5 rounded-xl text-xs font-bold transition-all cursor-pointer ${
                    activeTab === 'flows'
                      ? 'bg-purple-600 text-white shadow-xs'
                      : 'text-app-secondary hover:text-app-primary'
                  }`}
                >
                  Network Flows ({networkFlows.length})
                </button>
                <button
                  onClick={() => setActiveTab('events')}
                  className={`px-3 py-1.5 rounded-xl text-xs font-bold transition-all cursor-pointer ${
                    activeTab === 'events'
                      ? 'bg-purple-600 text-white shadow-xs'
                      : 'text-app-secondary hover:text-app-primary'
                  }`}
                >
                  Process & OS Events ({telemetryEvents.length})
                </button>
              </div>

              {selectedRun && (
                <div className="text-[11px] font-mono text-app-secondary flex items-center gap-2">
                  <span>PCAP SHA-256:</span>
                  <span className="text-purple-600 dark:text-purple-400 font-bold truncate max-w-xs" title={selectedRun.pcap_sha256 || 'None'}>
                    {selectedRun.pcap_sha256 ? `${selectedRun.pcap_sha256.slice(0, 16)}...` : 'N/A'}
                  </span>
                </div>
              )}
            </div>

            {/* Flows Tab */}
            {activeTab === 'flows' && (
              <div className="space-y-3">
                <div className="flex items-center gap-3">
                  <input
                    type="text"
                    placeholder="Filter flows by IP, protocol, domain, TLS SNI..."
                    value={flowFilter}
                    onChange={(e) => setFlowFilter(e.target.value)}
                    className="w-full bg-app border border-app rounded-xl px-3 py-2 text-xs text-app-primary focus:outline-hidden focus:border-purple-500"
                  />
                </div>

                {filteredFlows.length === 0 ? (
                  <div className="text-center py-10 text-app-secondary text-xs">
                    {networkFlows.length === 0
                      ? 'No network flows captured for this run yet.'
                      : 'No flows matching the current filter.'}
                  </div>
                ) : (
                  <div className="overflow-x-auto max-h-[450px]">
                    <table className="w-full text-left text-xs border-collapse">
                      <thead className="sticky top-0 bg-surface">
                        <tr className="border-b border-app text-app-secondary font-semibold uppercase tracking-wider text-[11px]">
                          <th className="py-2 px-3">Flow Reference</th>
                          <th className="py-2 px-3">Traffic Type</th>
                          <th className="py-2 px-3">Source Endpoint</th>
                          <th className="py-2 px-3">Destination Endpoint</th>
                          <th className="py-2 px-3">Proto</th>
                          <th className="py-2 px-3">Hostname / SNI / Path</th>
                          <th className="py-2 px-3">Bytes</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-app font-mono text-[11px]">
                        {filteredFlows.map((f) => (
                          <tr key={f.id} className="hover:bg-app/50 transition-colors">
                            <td className="py-2 px-3 whitespace-nowrap">
                              <span className="font-bold text-purple-600 dark:text-purple-400">
                                {f.packet_reference || 'Packet'}
                              </span>
                            </td>
                            <td className="py-2 px-3 whitespace-nowrap">
                              <span className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase ${
                                f.is_simulated
                                  ? 'bg-amber-100 text-amber-800 dark:bg-amber-950 dark:text-amber-300'
                                  : 'bg-emerald-100 text-emerald-800 dark:bg-emerald-950 dark:text-emerald-300'
                              }`}>
                                {f.is_simulated ? 'SIMULATED' : 'LIVE'}
                              </span>
                            </td>
                            <td className="py-2 px-3 text-app-secondary whitespace-nowrap">
                              {f.src_ip}:{f.src_port}
                            </td>
                            <td className="py-2 px-3 text-app-primary font-semibold whitespace-nowrap">
                              {f.dst_ip}:{f.dst_port}
                            </td>
                            <td className="py-2 px-3 whitespace-nowrap font-bold">
                              {f.protocol}
                            </td>
                            <td className="py-2 px-3 text-app-secondary max-w-xs truncate" title={f.dns_hostname || f.tls_sni || f.http_method || ''}>
                              {f.dns_hostname && <span className="text-cyan-600 font-bold">DNS: {f.dns_hostname}</span>}
                              {f.tls_sni && <span className="text-emerald-600 font-bold">SNI: {f.tls_sni}</span>}
                              {f.http_method && <span>HTTP {f.http_method}</span>}
                              {!f.dns_hostname && !f.tls_sni && !f.http_method && '-'}
                            </td>
                            <td className="py-2 px-3 text-app-secondary whitespace-nowrap">
                              {f.byte_count} B ({f.packet_count} pkts)
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                )}
              </div>
            )}

            {/* Events Tab */}
            {activeTab === 'events' && (
              <div className="space-y-3">
                <div className="flex items-center gap-3">
                  <select
                    value={eventCategoryFilter}
                    onChange={(e) => setEventCategoryFilter(e.target.value)}
                    className="bg-app border border-app rounded-xl px-3 py-1.5 text-xs text-app-primary focus:outline-hidden focus:border-purple-500"
                  >
                    <option value="ALL">All Categories</option>
                    <option value="PROCESS">Process Events</option>
                    <option value="FILE">File Operations</option>
                    <option value="REGISTRY">Registry Events</option>
                    <option value="DNS_QUERY">DNS Queries</option>
                    <option value="TLS_HANDSHAKE">TLS Handshakes</option>
                    <option value="HTTP_REQUEST">HTTP Requests</option>
                  </select>
                </div>

                {filteredEvents.length === 0 ? (
                  <div className="text-center py-10 text-app-secondary text-xs">
                    No events recorded in this category.
                  </div>
                ) : (
                  <div className="space-y-2 max-h-[450px] overflow-y-auto">
                    {filteredEvents.map((e) => (
                      <div key={e.id} className="p-3 rounded-xl border border-app bg-app/50 text-xs font-mono space-y-1">
                        <div className="flex items-center justify-between">
                          <span className="font-bold text-purple-600 dark:text-purple-400">
                            [{e.event_category}] {e.operation || 'Activity'}
                          </span>
                          <span className="text-app-secondary text-[11px]">
                            {new Date(e.timestamp_utc).toLocaleTimeString()}
                          </span>
                        </div>
                        {e.process_name && (
                          <div className="text-app-primary">
                            Process: <span className="font-bold">{e.process_name}</span> (PID {e.process_id})
                            {e.parent_process_name && (
                              <span className="text-app-secondary"> | Parent: {e.parent_process_name}</span>
                            )}
                          </div>
                        )}
                        {e.command_line && (
                          <div className="text-app-secondary truncate" title={e.command_line}>
                            Cmd: {e.command_line}
                          </div>
                        )}
                        {e.target_path && (
                          <div className="text-app-secondary truncate" title={e.target_path}>
                            Path: {e.target_path}
                          </div>
                        )}
                        {e.details && Object.keys(e.details).length > 0 && (
                          <div className="text-[11px] text-app-secondary bg-surface p-2 rounded-lg border border-app overflow-x-auto">
                            {JSON.stringify(e.details)}
                          </div>
                        )}
                      </div>
                    ))}
                  </div>
                )}
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};
export default DynamicSandboxPage;
