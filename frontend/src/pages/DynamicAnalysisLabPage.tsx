import React, { useState, useEffect, useMemo } from 'react';
import {
  Cpu,
  Monitor,
  Smartphone,
  Activity,
  GitMerge,
  Sliders,
  Play,
  Square,
  AlertTriangle,
  CheckCircle2,
  XCircle,
  HelpCircle,
  RefreshCw,
  Shield,
  ShieldAlert,
  ShieldCheck,
  Terminal,
  FileCode,
  Network,
  Download,
  Search,
  Filter,
  Eye,
  ExternalLink,
  ChevronRight,
  ChevronDown,
  Layers,
  ArrowUpRight,
  Info,
  Clock,
  HardDrive,
  FolderOpen,
  Server
} from 'lucide-react';
import { api } from '../api';
import {
  InvestigationDetail,
  InvestigationRecord,
  SandboxCapabilityMatrix,
  SandboxEnvironmentInfo,
  DynamicDashboardMetrics,
  DynamicObservation,
  DynamicArtifact,
  ProcessTreeNode,
  DynamicReport
} from '../types';

interface DynamicAnalysisLabPageProps {
  detail?: InvestigationDetail | null;
  onSelectInvestigation?: (id: string) => void;
}

type LabTab = 'dashboard' | 'windows_lab' | 'android_lab' | 'behavior_monitor' | 'correlations' | 'sandbox_config' | 'vm_environment';
type MonitorSubTab = 'process_tree' | 'events' | 'network' | 'filesystem' | 'registry' | 'alerts';

export const DynamicAnalysisLabPage: React.FC<DynamicAnalysisLabPageProps> = ({
  detail,
  onSelectInvestigation
}) => {
  // Navigation
  const [activeTab, setActiveTab] = useState<LabTab>('dashboard');
  const [monitorSubTab, setMonitorSubTab] = useState<MonitorSubTab>('process_tree');

  // Capability & Environments
  const [capabilities, setCapabilities] = useState<SandboxCapabilityMatrix | null>(null);
  const [environments, setEnvironments] = useState<SandboxEnvironmentInfo[]>([]);
  const [dashboardMetrics, setDashboardMetrics] = useState<DynamicDashboardMetrics | null>(null);
  const [loadingCapabilities, setLoadingCapabilities] = useState(false);

  // Analyses History & Active Selection
  const [analyses, setAnalyses] = useState<any[]>([]);
  const [selectedRunId, setSelectedRunId] = useState<string>('');
  const [selectedRun, setSelectedRun] = useState<any | null>(null);

  // Telemetry & Behavior Data for Selected Run
  const [processTree, setProcessTree] = useState<ProcessTreeNode[]>([]);
  const [observations, setObservations] = useState<DynamicObservation[]>([]);
  const [networkFlows, setNetworkFlows] = useState<any[]>([]);
  const [artifacts, setArtifacts] = useState<DynamicArtifact[]>([]);
  const [report, setReport] = useState<DynamicReport | null>(null);
  const [loadingRunData, setLoadingRunData] = useState(false);

  // All investigations list (for dropdown selection when not in context)
  const [allInvestigations, setAllInvestigations] = useState<InvestigationRecord[]>([]);
  const [selectedInvestigationId, setSelectedInvestigationId] = useState<string>(
    detail?.record?.id || ''
  );

  // Windows Lab Form
  const [winEnvId, setWinEnvId] = useState<string>('env-wsb-host');
  const [winNetworkMode, setWinNetworkMode] = useState<'DISABLED' | 'ISOLATED_SIMULATION'>('DISABLED');
  const [winTimeout, setWinTimeout] = useState<number>(120);
  const [winStarting, setWinStarting] = useState(false);
  const [showWinConfirmModal, setShowWinConfirmModal] = useState(false);

  // Android Lab Form
  const [androidEnvId, setAndroidEnvId] = useState<string>('env-android-avd');
  const [androidNetworkMode, setAndroidNetworkMode] = useState<string>('OFFLINE');
  const [androidTimeout, setAndroidTimeout] = useState<number>(180);
  const [androidStarting, setAndroidStarting] = useState(false);
  const [showAndroidConfirmModal, setShowAndroidConfirmModal] = useState(false);
  const [logcatFilter, setLogcatFilter] = useState('');

  // Live Event Filter
  const [eventCategoryFilter, setEventCategoryFilter] = useState<string>('ALL');
  const [eventSearchQuery, setEventSearchQuery] = useState<string>('');

  // VM Environment & Two-Plane State
  const [vmEnvironment, setVmEnvironment] = useState<any | null>(null);
  const [loadingVM, setLoadingVM] = useState<boolean>(false);
  const [testingNested, setTestingNested] = useState<boolean>(false);
  const [nestedResult, setNestedResult] = useState<any | null>(null);

  // Status message / toast
  const [actionMessage, setActionMessage] = useState<{ text: string; type: 'success' | 'error' | 'info' } | null>(null);

  const showToast = (text: string, type: 'success' | 'error' | 'info' = 'info') => {
    setActionMessage({ text, type });
    setTimeout(() => setActionMessage(null), 6000);
  };

  const refreshVMData = async (forceRefresh = false) => {
    setLoadingVM(true);
    try {
      const data = await api.getVMEnvironment();
      setVmEnvironment(data);
    } catch (err) {
      console.error('Failed to load VM environment topometry:', err);
    } finally {
      setLoadingVM(false);
    }
  };

  const handleTestNestedVirtualization = async () => {
    setTestingNested(true);
    try {
      const res = await api.testNestedVirtualization();
      setNestedResult(res);
      showToast(
        res.nested_virtualization_active
          ? 'Nested Virtualization (VT-x/AMD-V) is ACTIVE!'
          : 'Nested Virtualization not detected.',
        res.nested_virtualization_active ? 'success' : 'info'
      );
    } catch (err: any) {
      showToast(err.message || 'Failed to test nested virtualization', 'error');
    } finally {
      setTestingNested(false);
    }
  };

  // 1. Initial Load
  const refreshCoreData = async () => {
    setLoadingCapabilities(true);
    try {
      const [capsRes, envsRes, dashRes, invRes] = await Promise.all([
        api.getDynamicCapabilities().catch(() => null),
        api.getDynamicEnvironments().catch(() => []),
        api.getDynamicDashboard().catch(() => null),
        api.listInvestigations().catch(() => [])
      ]);

      if (capsRes) setCapabilities(capsRes);
      if (envsRes) setEnvironments(envsRes);
      if (dashRes) setDashboardMetrics(dashRes);
      if (invRes) setAllInvestigations(invRes);
    } catch (err) {
      console.error('Failed to load dynamic lab core data:', err);
    } finally {
      setLoadingCapabilities(false);
    }
  };

  // Refresh runs for the current investigation or all
  const refreshAnalysesList = async () => {
    try {
      const targetId = selectedInvestigationId || detail?.record?.id;
      const list = await api.listDynamicAnalyses(targetId);
      setAnalyses(list);
      if (list.length > 0 && (!selectedRunId || !list.find(r => r.id === selectedRunId))) {
        setSelectedRunId(list[0].id);
      }
    } catch (err) {
      console.error('Failed to load analyses list:', err);
    }
  };

  useEffect(() => {
    refreshCoreData();
    refreshVMData();
  }, []);

  useEffect(() => {
    if (detail?.record?.id) {
      setSelectedInvestigationId(detail.record.id);
    }
  }, [detail?.record?.id]);

  useEffect(() => {
    refreshAnalysesList();
  }, [selectedInvestigationId]);

  // Load selected run details
  const loadSelectedRunData = async (runId: string) => {
    if (!runId) return;
    setLoadingRunData(true);
    try {
      const [runDetails, tree, obs, flows, arts, rep] = await Promise.all([
        api.getDynamicAnalysis(runId).catch(() => null),
        api.getDynamicProcessTree(runId).catch(() => []),
        api.getDynamicObservations(runId).catch(() => []),
        api.getDynamicNetworkFlows(runId).catch(() => []),
        api.getDynamicArtifacts(runId).catch(() => []),
        api.getDynamicReport(runId).catch(() => null)
      ]);

      setSelectedRun(runDetails);
      setProcessTree(tree);
      setObservations(obs);
      setNetworkFlows(flows);
      setArtifacts(arts);
      setReport(rep);
    } catch (err) {
      console.error('Failed to load selected run data:', err);
    } finally {
      setLoadingRunData(false);
    }
  };

  useEffect(() => {
    if (selectedRunId) {
      loadSelectedRunData(selectedRunId);
    } else {
      setSelectedRun(null);
      setProcessTree([]);
      setObservations([]);
      setNetworkFlows([]);
      setArtifacts([]);
      setReport(null);
    }
  }, [selectedRunId]);

  // Active target sample
  const activeRecord = useMemo(() => {
    if (detail?.record) return detail.record;
    if (selectedInvestigationId) {
      return allInvestigations.find(i => i.id === selectedInvestigationId) || null;
    }
    return null;
  }, [detail, selectedInvestigationId, allInvestigations]);

  // Hardware virtualization restriction flag
  const isVirtDisabled = vmEnvironment?.environment?.cpu_virtualization?.firmware_virtualization_enabled === false;

  // Helper status color
  const getStatusBadge = (status: string, verification?: string) => {
    switch (status) {
      case 'AVAILABLE':
        return <span className="inline-flex items-center px-2 py-0.5 rounded text-xs font-semibold bg-emerald-100 text-emerald-800 dark:bg-emerald-950 dark:text-emerald-300 border border-emerald-300 dark:border-emerald-700"><CheckCircle2 className="w-3 h-3 mr-1" />AVAILABLE</span>;
      case 'CONFIGURED_OFFLINE':
        return <span className="inline-flex items-center px-2 py-0.5 rounded text-xs font-semibold bg-amber-100 text-amber-800 dark:bg-amber-950 dark:text-amber-300 border border-amber-300 dark:border-amber-700"><Clock className="w-3 h-3 mr-1" />OFFLINE</span>;
      case 'UNSUPPORTED_PLATFORM':
        return <span className="inline-flex items-center px-2 py-0.5 rounded text-xs font-semibold bg-rose-100 text-rose-800 dark:bg-rose-950 dark:text-rose-300 border border-rose-300 dark:border-rose-700"><XCircle className="w-3 h-3 mr-1" />UNSUPPORTED HOST</span>;
      case 'NOT_CONFIGURED':
      default:
        return <span className="inline-flex items-center px-2 py-0.5 rounded text-xs font-semibold bg-slate-100 text-slate-700 dark:bg-slate-800 dark:text-slate-300 border border-slate-300 dark:border-slate-700"><HelpCircle className="w-3 h-3 mr-1" />NOT CONFIGURED</span>;
    }
  };

  const getVerificationBadge = (vStatus?: string) => {
    switch (vStatus) {
      case 'VERIFIED':
        return <span className="inline-flex items-center px-2 py-0.5 rounded text-2xs font-mono font-bold uppercase bg-emerald-50 text-emerald-700 dark:bg-emerald-950/60 dark:text-emerald-400 border border-emerald-200 dark:border-emerald-800">VERIFIED</span>;
      case 'MOCKED':
        return <span className="inline-flex items-center px-2 py-0.5 rounded text-2xs font-mono font-bold uppercase bg-purple-50 text-purple-700 dark:bg-purple-950/60 dark:text-purple-400 border border-purple-200 dark:border-purple-800">MOCKED</span>;
      case 'PARTIALLY VERIFIED':
        return <span className="inline-flex items-center px-2 py-0.5 rounded text-2xs font-mono font-bold uppercase bg-amber-50 text-amber-700 dark:bg-amber-950/60 dark:text-amber-400 border border-amber-200 dark:border-amber-800">PARTIALLY VERIFIED</span>;
      case 'NOT TESTED':
        return <span className="inline-flex items-center px-2 py-0.5 rounded text-2xs font-mono font-bold uppercase bg-slate-50 text-slate-700 dark:bg-slate-800 dark:text-slate-400 border border-slate-200 dark:border-slate-700">NOT TESTED</span>;
      default:
        return <span className="inline-flex items-center px-2 py-0.5 rounded text-2xs font-mono font-bold uppercase bg-slate-50 text-slate-600 dark:bg-slate-800 dark:text-slate-400 border border-slate-200">NOT CONFIGURED</span>;
    }
  };

  // Launch Windows Analysis Handler
  const handleLaunchWindowsAnalysis = async () => {
    if (!activeRecord) {
      showToast('Please select an investigation sample first.', 'error');
      return;
    }
    setWinStarting(true);
    setShowWinConfirmModal(false);
    try {
      const created = await api.createDynamicAnalysis({
        investigation_id: activeRecord.id,
        sample_type: 'PE',
        sample_path: `analysis_workspace/samples/${activeRecord.filename || 'sample.exe'}`,
        sample_name: activeRecord.filename || 'sample.exe',
        environment_id: winEnvId,
        network_mode: winNetworkMode,
        timeout_seconds: winTimeout,
        analysis_options: {
          elevated: false,
          record_video: false
        }
      });

      showToast(`Dynamic analysis created (ID: ${created.id}). Initiating sandbox execution...`, 'info');
      await api.startDynamicAnalysis(created.id);
      showToast(`Dynamic execution started in isolated sandbox.`, 'success');
      await refreshAnalysesList();
      setSelectedRunId(created.id);
      setActiveTab('behavior_monitor');
    } catch (err: any) {
      showToast(`Execution halted: ${err.message || 'Sandbox error'}`, 'error');
    } finally {
      setWinStarting(false);
    }
  };

  // Launch Android Analysis Handler
  const handleLaunchAndroidAnalysis = async () => {
    if (!activeRecord) {
      showToast('Please select an APK investigation sample first.', 'error');
      return;
    }
    setAndroidStarting(true);
    setShowAndroidConfirmModal(false);
    try {
      const created = await api.createDynamicAnalysis({
        investigation_id: activeRecord.id,
        sample_type: 'APK',
        sample_path: `analysis_workspace/samples/${activeRecord.filename || 'sample.apk'}`,
        sample_name: activeRecord.filename || 'sample.apk',
        environment_id: androidEnvId,
        network_mode: androidNetworkMode,
        timeout_seconds: androidTimeout,
        analysis_options: {
          capture_logcat: true,
          clear_app_data: true
        }
      });

      showToast(`Android dynamic analysis created (ID: ${created.id}). Initializing emulator...`, 'info');
      await api.startDynamicAnalysis(created.id);
      showToast(`APK installed and dynamic tracing started.`, 'success');
      await refreshAnalysesList();
      setSelectedRunId(created.id);
      setActiveTab('behavior_monitor');
    } catch (err: any) {
      showToast(`Android execution halted: ${err.message || 'Emulator error'}`, 'error');
    } finally {
      setAndroidStarting(false);
    }
  };

  // Stop / Cancel Run
  const handleCancelRun = async (runId: string) => {
    try {
      await api.cancelDynamicAnalysis(runId);
      showToast('Sandbox execution cancelled.', 'info');
      await loadSelectedRunData(runId);
      await refreshAnalysesList();
    } catch (err: any) {
      showToast(`Failed to cancel: ${err.message}`, 'error');
    }
  };

  // Filtered observations
  const filteredObservations = useMemo(() => {
    return observations.filter(obs => {
      if (eventCategoryFilter !== 'ALL' && obs.category !== eventCategoryFilter) return false;
      if (eventSearchQuery) {
        const query = eventSearchQuery.toLowerCase();
        const str = `${obs.event_type} ${obs.source} ${obs.process_name || ''} ${obs.target_path || ''} ${JSON.stringify(obs.details)}`.toLowerCase();
        return str.includes(query);
      }
      return true;
    });
  }, [observations, eventCategoryFilter, eventSearchQuery]);

  // Recursive Process Tree Node Renderer
  const renderProcessNode = (node: ProcessTreeNode, depth: number = 0) => {
    return (
      <div key={`${node.pid}-${depth}`} className="ml-4 border-l-2 border-slate-200 dark:border-slate-800 pl-3 my-1">
        <div className="flex items-center space-x-2 py-1.5 px-2 rounded-md hover:bg-slate-100 dark:hover:bg-slate-800/60 transition-colors">
          <Terminal className={`w-4 h-4 ${node.is_suspicious ? 'text-rose-500' : 'text-cyan-500'}`} />
          <span className="font-mono text-xs font-bold text-slate-800 dark:text-slate-200">{node.name}</span>
          <span className="font-mono text-2xs text-slate-400">PID: {node.pid}</span>
          {node.ppid && <span className="font-mono text-2xs text-slate-400">PPID: {node.ppid}</span>}
          {node.integrity_level && (
            <span className="text-2xs font-mono uppercase px-1.5 py-0.2 rounded bg-slate-200 dark:bg-slate-700 text-slate-600 dark:text-slate-300">
              {node.integrity_level}
            </span>
          )}
          {node.is_suspicious && (
            <span className="inline-flex items-center text-2xs font-bold px-1.5 py-0.5 rounded bg-rose-100 text-rose-700 dark:bg-rose-950/80 dark:text-rose-300 border border-rose-300 dark:border-rose-800">
              SUSPICIOUS
            </span>
          )}
          {node.cmdline && (
            <span className="text-xs text-slate-500 font-mono truncate max-w-md" title={node.cmdline}>
              {node.cmdline}
            </span>
          )}
        </div>
        {node.children && node.children.length > 0 && (
          <div className="space-y-0.5">
            {node.children.map(child => renderProcessNode(child, depth + 1))}
          </div>
        )}
      </div>
    );
  };

  return (
    <div className="h-full flex flex-col bg-slate-50 dark:bg-slate-950 text-slate-900 dark:text-slate-100">
      {/* Top Header & Context Banner */}
      <header className="border-b border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 px-6 py-4 flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <div className="flex items-center space-x-3">
            <div className="p-2 bg-cyan-500/10 text-cyan-600 dark:text-cyan-400 rounded-lg">
              <Cpu className="w-6 h-6" />
            </div>
            <div>
              <div className="flex items-center space-x-2">
                <h1 className="text-xl font-bold tracking-tight text-slate-900 dark:text-white">
                  Dynamic Analysis Lab & Malware Sandbox
                </h1>
                <span className="px-2 py-0.5 text-2xs font-bold font-mono uppercase bg-cyan-100 text-cyan-800 dark:bg-cyan-950 dark:text-cyan-300 rounded border border-cyan-300 dark:border-cyan-800">
                  v2.0 PRO
                </span>
              </div>
              <p className="text-xs text-slate-500 dark:text-slate-400">
                Discover. Analyze. Investigate. — Isolated Execution & Runtime Behavioral Telemetry
              </p>
            </div>
          </div>
        </div>

        {/* Target Sample Switcher / Info */}
        <div className="flex items-center space-x-3">
          <div className="text-right">
            <div className="text-2xs text-slate-400 font-mono uppercase">Target Investigation</div>
            {activeRecord ? (
              <div className="flex items-center space-x-1.5">
                <span className="text-xs font-semibold text-slate-800 dark:text-slate-200 max-w-[200px] truncate" title={activeRecord.filename}>
                  {activeRecord.filename}
                </span>
                <span className="text-2xs font-mono uppercase px-1.5 py-0.2 rounded bg-cyan-100 text-cyan-800 dark:bg-cyan-950 dark:text-cyan-300">
                  {activeRecord.file_type}
                </span>
              </div>
            ) : (
              <select
                aria-label="Select Target Investigation"
                value={selectedInvestigationId}
                onChange={(e) => {
                  setSelectedInvestigationId(e.target.value);
                  if (onSelectInvestigation) onSelectInvestigation(e.target.value);
                }}
                className="text-xs border border-slate-300 dark:border-slate-700 rounded px-2 py-1 bg-white dark:bg-slate-800 text-slate-800 dark:text-slate-200"
              >
                <option value="">-- Select Target Sample --</option>
                {allInvestigations.map(inv => (
                  <option key={inv.id} value={inv.id}>
                    {inv.filename} ({inv.file_type?.toUpperCase()})
                  </option>
                ))}
              </select>
            )}
          </div>

          <button
            onClick={refreshCoreData}
            title="Refresh Environment & Preflight Health"
            disabled={loadingCapabilities}
            className="p-2 text-slate-500 hover:text-slate-900 dark:hover:text-white border border-slate-300 dark:border-slate-700 rounded-lg hover:bg-slate-100 dark:hover:bg-slate-800 transition-colors"
          >
            <RefreshCw className={`w-4 h-4 ${loadingCapabilities ? 'animate-spin' : ''}`} />
          </button>
        </div>
      </header>

      {/* Action Toast / Banner */}
      {actionMessage && (
        <div className={`px-6 py-2.5 text-xs font-medium flex items-center justify-between border-b ${
          actionMessage.type === 'error'
            ? 'bg-rose-50 text-rose-800 border-rose-200 dark:bg-rose-950/60 dark:text-rose-200 dark:border-rose-900'
            : actionMessage.type === 'success'
            ? 'bg-emerald-50 text-emerald-800 border-emerald-200 dark:bg-emerald-950/60 dark:text-emerald-200 dark:border-emerald-900'
            : 'bg-blue-50 text-blue-800 border-blue-200 dark:bg-blue-950/60 dark:text-blue-200 dark:border-blue-900'
        }`}>
          <span>{actionMessage.text}</span>
          <button onClick={() => setActionMessage(null)} className="text-xs font-bold hover:underline">Dismiss</button>
        </div>
      )}

      {/* Firmware Virtualization Disabled Warning Banner */}
      {isVirtDisabled && (
        <div className="bg-amber-500/15 border-b border-amber-500/40 px-6 py-3 flex items-center justify-between text-amber-900 dark:text-amber-200">
          <div className="flex items-center space-x-3">
            <div className="p-1.5 bg-amber-500/20 rounded-md text-amber-600 dark:text-amber-400">
              <AlertTriangle className="w-5 h-5 animate-pulse" />
            </div>
            <div>
              <div className="font-bold text-sm tracking-wide text-amber-900 dark:text-amber-100 flex items-center space-x-2">
                <span>ACTION REQUIRED: Enable Intel VT-x in BIOS/UEFI.</span>
                <span className="text-2xs font-mono font-bold uppercase px-2 py-0.5 bg-amber-200 dark:bg-amber-950 text-amber-800 dark:text-amber-300 border border-amber-300 dark:border-amber-800 rounded">
                  FIRMWARE RESTRICTED
                </span>
              </div>
              <div className="text-xs text-amber-700 dark:text-amber-300 mt-0.5">
                Hardware virtualization (VT-x/AMD-V) is currently disabled in system BIOS/UEFI. Analysis worker VMs and Android emulators cannot execute untrusted code until VT-x or AMD-V is enabled.
              </div>
            </div>
          </div>
          <button
            onClick={() => setActiveTab('vm_environment')}
            className="text-xs font-semibold px-3 py-1.5 rounded-lg bg-amber-600 hover:bg-amber-500 text-white transition-colors flex items-center space-x-1"
          >
            <span>View Remediation</span>
            <ChevronRight className="w-3.5 h-3.5" />
          </button>
        </div>
      )}

      {/* Primary Navigation Tabs */}
      <nav className="border-b border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900/80 px-6 flex items-center space-x-1 overflow-x-auto">
        <button
          onClick={() => setActiveTab('dashboard')}
          className={`flex items-center space-x-2 px-3 py-3 border-b-2 font-medium text-xs whitespace-nowrap transition-colors ${
            activeTab === 'dashboard'
              ? 'border-cyan-500 text-cyan-600 dark:text-cyan-400 font-semibold'
              : 'border-transparent text-slate-500 hover:text-slate-800 dark:hover:text-slate-200'
          }`}
        >
          <Layers className="w-4 h-4" />
          <span>Sandbox Dashboard</span>
        </button>

        <button
          onClick={() => setActiveTab('windows_lab')}
          className={`flex items-center space-x-2 px-3 py-3 border-b-2 font-medium text-xs whitespace-nowrap transition-colors ${
            activeTab === 'windows_lab'
              ? 'border-cyan-500 text-cyan-600 dark:text-cyan-400 font-semibold'
              : 'border-transparent text-slate-500 hover:text-slate-800 dark:hover:text-slate-200'
          }`}
        >
          <Monitor className="w-4 h-4" />
          <span>Windows Executable Lab</span>
        </button>

        <button
          onClick={() => setActiveTab('android_lab')}
          className={`flex items-center space-x-2 px-3 py-3 border-b-2 font-medium text-xs whitespace-nowrap transition-colors ${
            activeTab === 'android_lab'
              ? 'border-cyan-500 text-cyan-600 dark:text-cyan-400 font-semibold'
              : 'border-transparent text-slate-500 hover:text-slate-800 dark:hover:text-slate-200'
          }`}
        >
          <Smartphone className="w-4 h-4" />
          <span>Android Dynamic Lab</span>
        </button>

        <button
          onClick={() => setActiveTab('behavior_monitor')}
          className={`flex items-center space-x-2 px-3 py-3 border-b-2 font-medium text-xs whitespace-nowrap transition-colors ${
            activeTab === 'behavior_monitor'
              ? 'border-cyan-500 text-cyan-600 dark:text-cyan-400 font-semibold'
              : 'border-transparent text-slate-500 hover:text-slate-800 dark:hover:text-slate-200'
          }`}
        >
          <Activity className="w-4 h-4" />
          <span>Live Behavior Monitor</span>
          {observations.length > 0 && (
            <span className="px-1.5 py-0.2 rounded-full text-2xs bg-slate-200 dark:bg-slate-800 font-mono">
              {observations.length}
            </span>
          )}
        </button>

        <button
          onClick={() => setActiveTab('correlations')}
          className={`flex items-center space-x-2 px-3 py-3 border-b-2 font-medium text-xs whitespace-nowrap transition-colors ${
            activeTab === 'correlations'
              ? 'border-cyan-500 text-cyan-600 dark:text-cyan-400 font-semibold'
              : 'border-transparent text-slate-500 hover:text-slate-800 dark:hover:text-slate-200'
          }`}
        >
          <GitMerge className="w-4 h-4" />
          <span>Runtime Findings & Correlations</span>
        </button>

        <button
          onClick={() => setActiveTab('sandbox_config')}
          className={`flex items-center space-x-2 px-3 py-3 border-b-2 font-medium text-xs whitespace-nowrap transition-colors ${
            activeTab === 'sandbox_config'
              ? 'border-cyan-500 text-cyan-600 dark:text-cyan-400 font-semibold'
              : 'border-transparent text-slate-500 hover:text-slate-800 dark:hover:text-slate-200'
          }`}
        >
          <Sliders className="w-4 h-4" />
          <span>Sandbox Configuration & Health</span>
        </button>

        <button
          onClick={() => {
            setActiveTab('vm_environment');
            refreshVMData();
          }}
          className={`flex items-center space-x-2 px-3 py-3 border-b-2 font-medium text-xs whitespace-nowrap transition-colors ${
            activeTab === 'vm_environment'
              ? 'border-cyan-500 text-cyan-600 dark:text-cyan-400 font-semibold'
              : 'border-transparent text-slate-500 hover:text-slate-800 dark:hover:text-slate-200'
          }`}
        >
          <Server className="w-4 h-4" />
          <span>VM & Hypervisors</span>
        </button>
      </nav>

      {/* Main Tab Content Viewport */}
      <main className="flex-1 overflow-y-auto p-6 space-y-6">
        {/* ============================================================== */}
        {/* TAB 1: SANDBOX DASHBOARD */}
        {/* ============================================================== */}
        {activeTab === 'dashboard' && (
          <div className="space-y-6">
            {/* KPI Cards Grid */}
            <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
              <div className="p-4 rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900">
                <div className="flex items-center justify-between">
                  <span className="text-xs font-medium text-slate-500">Total Sandbox Runs</span>
                  <Activity className="w-4 h-4 text-cyan-500" />
                </div>
                <div className="text-2xl font-bold mt-2 text-slate-900 dark:text-white">
                  {dashboardMetrics?.total_analyses ?? analyses.length}
                </div>
                <div className="text-2xs text-slate-400 mt-1 flex space-x-2">
                  <span className="text-emerald-500 font-semibold">
                    {dashboardMetrics?.completed_analyses ?? analyses.filter(a => a.status === 'COMPLETED').length} completed
                  </span>
                  <span>•</span>
                  <span className="text-rose-500 font-semibold">
                    {dashboardMetrics?.failed_analyses ?? analyses.filter(a => a.status === 'FAILED').length} failed
                  </span>
                </div>
              </div>

              <div className="p-4 rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900">
                <div className="flex items-center justify-between">
                  <span className="text-xs font-medium text-slate-500">Available Environments</span>
                  <ShieldCheck className="w-4 h-4 text-emerald-500" />
                </div>
                <div className="text-2xl font-bold mt-2 text-slate-900 dark:text-white">
                  {environments.filter(e => e.status === 'AVAILABLE').length} / {environments.length}
                </div>
                <div className="text-2xs text-slate-400 mt-1">
                  Active providers registered
                </div>
              </div>

              <div className="p-4 rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900">
                <div className="flex items-center justify-between">
                  <span className="text-xs font-medium text-slate-500">Suspicious Events</span>
                  <AlertTriangle className="w-4 h-4 text-amber-500" />
                </div>
                <div className="text-2xl font-bold mt-2 text-slate-900 dark:text-white">
                  {dashboardMetrics?.active_threats_observed ?? 0}
                </div>
                <div className="text-2xs text-slate-400 mt-1">
                  MITRE ATT&CK techniques triggered
                </div>
              </div>

              <div className="p-4 rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900">
                <div className="flex items-center justify-between">
                  <span className="text-xs font-medium text-slate-500">Avg Dynamic Risk Score</span>
                  <ShieldAlert className="w-4 h-4 text-rose-500" />
                </div>
                <div className="text-2xl font-bold mt-2 text-slate-900 dark:text-white">
                  {dashboardMetrics?.average_risk_score ? `${dashboardMetrics.average_risk_score.toFixed(1)}/100` : 'N/A'}
                </div>
                <div className="text-2xs text-slate-400 mt-1">
                  Dimensional threat score
                </div>
              </div>
            </div>

            {/* Environment Status Summary Cards */}
            <div className="space-y-3">
              <h2 className="text-sm font-bold text-slate-900 dark:text-white flex items-center space-x-2">
                <Cpu className="w-4 h-4 text-cyan-500" />
                <span>Isolated Sandbox Environments</span>
              </h2>

              <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                {environments.map((env) => (
                  <div
                    key={env.id}
                    className="p-4 rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 flex flex-col justify-between"
                  >
                    <div>
                      <div className="flex items-start justify-between">
                        <div>
                          <h3 className="text-xs font-bold text-slate-900 dark:text-slate-100">{env.name}</h3>
                          <span className="text-2xs font-mono uppercase text-slate-400">{env.provider_type}</span>
                        </div>
                        {getStatusBadge(env.status)}
                      </div>
                      <p className="text-2xs text-slate-500 dark:text-slate-400 mt-2 line-clamp-2">
                        {env.setup_instructions || 'Dedicated isolated sandbox for untrusted binary execution.'}
                      </p>
                    </div>

                    <div className="mt-4 pt-3 border-t border-slate-100 dark:border-slate-800 flex items-center justify-between text-2xs">
                      <span className="text-slate-400 font-mono">Verification:</span>
                      {getVerificationBadge(env.verification_status)}
                    </div>
                  </div>
                ))}
              </div>
            </div>

            {/* Recent Runs Table */}
            <div className="rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 overflow-hidden">
              <div className="p-4 border-b border-slate-200 dark:border-slate-800 flex items-center justify-between">
                <h3 className="text-xs font-bold text-slate-900 dark:text-slate-100">Recent Dynamic Analyses</h3>
                <button
                  onClick={refreshAnalysesList}
                  className="text-2xs text-cyan-600 dark:text-cyan-400 hover:underline flex items-center space-x-1"
                >
                  <RefreshCw className="w-3 h-3" />
                  <span>Refresh Runs</span>
                </button>
              </div>

              {analyses.length === 0 ? (
                <div className="p-8 text-center text-xs text-slate-400">
                  No dynamic analyses recorded yet. Launch a Windows or Android analysis run from the lab tabs above.
                </div>
              ) : (
                <div className="overflow-x-auto">
                  <table className="w-full text-left text-xs">
                    <thead className="bg-slate-50 dark:bg-slate-800/50 text-slate-500 dark:text-slate-400 font-mono text-2xs uppercase">
                      <tr>
                        <th className="py-2.5 px-4">Run ID</th>
                        <th className="py-2.5 px-4">Sample / Target</th>
                        <th className="py-2.5 px-4">Provider / Env</th>
                        <th className="py-2.5 px-4">Status</th>
                        <th className="py-2.5 px-4">Risk Score</th>
                        <th className="py-2.5 px-4">Execution Time</th>
                        <th className="py-2.5 px-4 text-right">Action</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-100 dark:divide-slate-800">
                      {analyses.map(run => (
                        <tr
                          key={run.id}
                          className={`hover:bg-slate-50 dark:hover:bg-slate-800/40 transition-colors ${
                            selectedRunId === run.id ? 'bg-cyan-50/50 dark:bg-cyan-950/20' : ''
                          }`}
                        >
                          <td className="py-2.5 px-4 font-mono text-2xs text-slate-600 dark:text-slate-400">
                            {run.id.slice(0, 8)}...
                          </td>
                          <td className="py-2.5 px-4 font-medium text-slate-800 dark:text-slate-200">
                            {run.sample_name || 'sample'}
                          </td>
                          <td className="py-2.5 px-4 text-slate-500 font-mono text-2xs">
                            {run.environment_id || 'isolated'}
                          </td>
                          <td className="py-2.5 px-4">
                            <span className={`inline-flex px-2 py-0.5 rounded text-2xs font-bold uppercase font-mono ${
                              run.status === 'COMPLETED'
                                ? 'bg-emerald-100 text-emerald-800 dark:bg-emerald-950 dark:text-emerald-300'
                                : run.status === 'RUNNING'
                                ? 'bg-cyan-100 text-cyan-800 dark:bg-cyan-950 dark:text-cyan-300 animate-pulse'
                                : run.status === 'FAILED'
                                ? 'bg-rose-100 text-rose-800 dark:bg-rose-950 dark:text-rose-300'
                                : 'bg-slate-100 text-slate-700 dark:bg-slate-800 dark:text-slate-300'
                            }`}>
                              {run.status}
                            </span>
                          </td>
                          <td className="py-2.5 px-4 font-mono font-bold text-xs">
                            {run.risk_score !== undefined ? `${run.risk_score}/100` : '—'}
                          </td>
                          <td className="py-2.5 px-4 text-slate-400 text-2xs">
                            {run.created_at_utc ? new Date(run.created_at_utc).toLocaleString() : '—'}
                          </td>
                          <td className="py-2.5 px-4 text-right">
                            <button
                              onClick={() => {
                                setSelectedRunId(run.id);
                                setActiveTab('behavior_monitor');
                              }}
                              className="px-2 py-1 rounded bg-cyan-600 text-white text-2xs font-semibold hover:bg-cyan-500 transition-colors"
                            >
                              Inspect
                            </button>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </div>
          </div>
        )}

        {/* ============================================================== */}
        {/* TAB 2: WINDOWS EXECUTABLE LAB */}
        {/* ============================================================== */}
        {activeTab === 'windows_lab' && (
          <div className="space-y-6">
            {/* Safety Guarantee Notice */}
            <div className="p-4 rounded-xl border border-amber-300 dark:border-amber-800/80 bg-amber-50/50 dark:bg-amber-950/20 flex items-start space-x-3">
              <ShieldAlert className="w-5 h-5 text-amber-600 dark:text-amber-400 flex-shrink-0 mt-0.5" />
              <div className="text-xs">
                <span className="font-bold text-amber-900 dark:text-amber-200">
                  Zero Host Execution Guarantee
                </span>
                <p className="text-amber-800 dark:text-amber-300 mt-0.5">
                  Untrusted Windows binaries (.exe, .dll, .scr) are strictly prohibited from host execution. All dynamic executions are routed into isolated virtualization sandboxes (Windows Sandbox or Hyper-V VM). No host subprocess is ever launched for untrusted code.
                </p>
              </div>
            </div>

            {/* Target Information Card */}
            <div className="p-5 rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 space-y-4">
              <h2 className="text-xs font-bold text-slate-900 dark:text-slate-100 uppercase tracking-wider font-mono">
                Target Binary Information
              </h2>
              {activeRecord ? (
                <div className="grid grid-cols-1 md:grid-cols-4 gap-4 text-xs">
                  <div>
                    <span className="text-slate-400 text-2xs uppercase">Filename</span>
                    <div className="font-semibold text-slate-800 dark:text-slate-200 truncate">{activeRecord.filename}</div>
                  </div>
                  <div>
                    <span className="text-slate-400 text-2xs uppercase">SHA-256 Digest</span>
                    <div className="font-mono text-2xs text-slate-600 dark:text-slate-400 truncate" title={activeRecord.sha256}>
                      {activeRecord.sha256}
                    </div>
                  </div>
                  <div>
                    <span className="text-slate-400 text-2xs uppercase">Target Type</span>
                    <div className="font-semibold text-slate-800 dark:text-slate-200 uppercase">{activeRecord.file_type}</div>
                  </div>
                  <div>
                    <span className="text-slate-400 text-2xs uppercase">Case Reference</span>
                    <div className="font-semibold text-slate-800 dark:text-slate-200">{activeRecord.case_reference || 'DEFAULT-CASE'}</div>
                  </div>
                </div>
              ) : (
                <div className="text-xs text-amber-600 dark:text-amber-400">
                  No target sample currently selected. Please pick an investigation from the header dropdown above.
                </div>
              )}
            </div>

            {/* Sandbox Configuration Form */}
            <div className="p-5 rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 space-y-5">
              <h2 className="text-xs font-bold text-slate-900 dark:text-slate-100 uppercase tracking-wider font-mono">
                Sandbox Environment & Isolation Parameters
              </h2>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                {/* Environment Selector */}
                <div className="space-y-2">
                  <label htmlFor="win-env-selector" className="text-xs font-medium text-slate-700 dark:text-slate-300">
                    Execution Sandbox Provider
                  </label>
                  <select
                    id="win-env-selector"
                    value={winEnvId}
                    onChange={(e) => setWinEnvId(e.target.value)}
                    className="w-full text-xs border border-slate-300 dark:border-slate-700 rounded-lg p-2.5 bg-white dark:bg-slate-800 text-slate-800 dark:text-slate-200"
                  >
                    <option value="env-wsb-host">Windows Sandbox (.wsb Isolated XML Profile)</option>
                    <option value="env-hyperv-default">Hyper-V Dedicated Analysis VM</option>
                    <option value="env-cape-remote">CAPE 2.x Remote API Connector</option>
                    <option value="env-mock-pe">Simulated QA Sandbox (Deterministic Testing)</option>
                  </select>

                  {/* Diagnostic Alert if selected provider is unsupported on this host */}
                  {winEnvId === 'env-wsb-host' && capabilities && !capabilities.windows_sandbox_installed && (
                    <div className="p-3 rounded-lg bg-rose-50 dark:bg-rose-950/40 border border-rose-200 dark:border-rose-900 text-2xs text-rose-700 dark:text-rose-300 flex items-start space-x-2">
                      <XCircle className="w-4 h-4 flex-shrink-0 mt-0.5" />
                      <div>
                        <span className="font-bold">Hardware Virtualization / Windows Sandbox Unavailable</span>
                        <p className="mt-0.5">
                          Host OS ({capabilities.host_edition}) does not have Windows Sandbox enabled. Windows Sandbox requires Windows 10/11 Pro/Enterprise and BIOS virtualization. Select 'Simulated QA Sandbox' for pipeline testing or configure Hyper-V / CAPE.
                        </p>
                      </div>
                    </div>
                  )}
                </div>

                {/* Network Policy */}
                <div className="space-y-2">
                  <label htmlFor="win-net-mode" className="text-xs font-medium text-slate-700 dark:text-slate-300">
                    Network Policy & Simulation
                  </label>
                  <select
                    id="win-net-mode"
                    value={winNetworkMode}
                    onChange={(e) => setWinNetworkMode(e.target.value as any)}
                    className="w-full text-xs border border-slate-300 dark:border-slate-700 rounded-lg p-2.5 bg-white dark:bg-slate-800 text-slate-800 dark:text-slate-200"
                  >
                    <option value="DISABLED">DISABLED (Complete Network Isolation - Default)</option>
                    <option value="ISOLATED_SIMULATION">ISOLATED SIMULATION (FakeNet / INetSim DNS Sinkhole)</option>
                  </select>
                  <p className="text-2xs text-slate-400">
                    All outbound connections are dropped or routed to isolated loopback services. Host NIC bridge is strictly disallowed.
                  </p>
                </div>

                {/* Execution Timeout */}
                <div className="space-y-2">
                  <div className="flex items-center justify-between text-xs">
                    <label htmlFor="win-timeout-range" className="font-medium text-slate-700 dark:text-slate-300">Execution Timeout</label>
                    <span className="font-mono text-cyan-600 dark:text-cyan-400 font-bold">{winTimeout} seconds</span>
                  </div>
                  <input
                    id="win-timeout-range"
                    type="range"
                    min="30"
                    max="600"
                    step="30"
                    value={winTimeout}
                    onChange={(e) => setWinTimeout(Number(e.target.value))}
                    className="w-full accent-cyan-500"
                  />
                  <div className="flex justify-between text-2xs text-slate-400">
                    <span>30s (Rapid triage)</span>
                    <span>120s (Standard)</span>
                    <span>600s (Extended persistence observation)</span>
                  </div>
                </div>

                {/* Staging & Integrity Preflight */}
                <div className="space-y-2">
                  <label className="text-xs font-medium text-slate-700 dark:text-slate-300">
                    Staging & Forensics Integrity
                  </label>
                  <div className="p-3 rounded-lg border border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-slate-800/40 text-2xs space-y-1">
                    <div className="flex items-center text-emerald-600 dark:text-emerald-400">
                      <CheckCircle2 className="w-3.5 h-3.5 mr-1.5" />
                      <span>Original forensic sample is write-locked (READ-ONLY)</span>
                    </div>
                    <div className="flex items-center text-emerald-600 dark:text-emerald-400">
                      <CheckCircle2 className="w-3.5 h-3.5 mr-1.5" />
                      <span>Ephemeral copy created in isolated staging directory</span>
                    </div>
                    <div className="flex items-center text-emerald-600 dark:text-emerald-400">
                      <CheckCircle2 className="w-3.5 h-3.5 mr-1.5" />
                      <span>Chain-of-custody entry logged automatically</span>
                    </div>
                  </div>
                </div>
              </div>

              {/* Execution Action Bar */}
              <div className="pt-4 border-t border-slate-200 dark:border-slate-800 flex items-center justify-between">
                <span className="text-2xs text-slate-400">
                  Confirmation required before sandbox environment launch.
                </span>

                <button
                  onClick={() => setShowWinConfirmModal(true)}
                  disabled={!activeRecord || winStarting || isVirtDisabled}
                  className="px-5 py-2.5 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white font-semibold text-xs flex items-center space-x-2 transition-colors disabled:opacity-50 disabled:cursor-not-allowed shadow-sm"
                >
                  <Play className="w-4 h-4 fill-white" />
                  <span>{winStarting ? 'Starting Sandbox...' : isVirtDisabled ? 'Blocked: Enable Intel VT-x' : 'Launch Isolated Dynamic Analysis'}</span>
                </button>
              </div>
            </div>

            {/* Launch Confirmation Modal */}
            {showWinConfirmModal && (
              <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-xs p-4">
                <div className="max-w-lg w-full bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-xl p-6 space-y-4 shadow-xl">
                  <div className="flex items-center space-x-3 text-amber-600">
                    <AlertTriangle className="w-6 h-6" />
                    <h3 className="text-sm font-bold text-slate-900 dark:text-white">
                      Confirm Isolated Dynamic Sandbox Launch
                    </h3>
                  </div>

                  <p className="text-xs text-slate-600 dark:text-slate-300">
                    You are about to launch dynamic execution of untrusted sample:
                  </p>

                  <div className="p-3 bg-slate-100 dark:bg-slate-800 rounded font-mono text-2xs space-y-1">
                    <div>Sample: <span className="text-slate-900 dark:text-white font-bold">{activeRecord?.filename}</span></div>
                    <div>SHA-256: <span className="text-slate-500 truncate block">{activeRecord?.sha256}</span></div>
                    <div>Sandbox Provider: <span className="text-cyan-600 dark:text-cyan-400 font-bold">{winEnvId}</span></div>
                    <div>Network Isolation: <span className="text-emerald-600 font-bold">{winNetworkMode}</span></div>
                    <div>Timeout: <span className="font-bold">{winTimeout}s</span></div>
                  </div>

                  <p className="text-2xs text-slate-500">
                    Host execution will NOT take place. The binary will run only within the ephemeral isolated guest.
                  </p>

                  <div className="flex justify-end space-x-3 pt-2">
                    <button
                      onClick={() => setShowWinConfirmModal(false)}
                      className="px-4 py-2 rounded-lg border border-slate-300 dark:border-slate-700 text-xs font-semibold text-slate-700 dark:text-slate-300 hover:bg-slate-100 dark:hover:bg-slate-800"
                    >
                      Cancel
                    </button>
                    <button
                      onClick={handleLaunchWindowsAnalysis}
                      disabled={winStarting}
                      className="px-4 py-2 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-semibold"
                    >
                      Confirm & Launch Sandbox
                    </button>
                  </div>
                </div>
              </div>
            )}
          </div>
        )}

        {/* ============================================================== */}
        {/* TAB 3: ANDROID DYNAMIC LAB */}
        {/* ============================================================== */}
        {activeTab === 'android_lab' && (
          <div className="space-y-6">
            {/* Safety Guarantee Notice */}
            <div className="p-4 rounded-xl border border-cyan-300 dark:border-cyan-800/80 bg-cyan-50/50 dark:bg-cyan-950/20 flex items-start space-x-3">
              <Smartphone className="w-5 h-5 text-cyan-600 dark:text-cyan-400 flex-shrink-0 mt-0.5" />
              <div className="text-xs">
                <span className="font-bold text-cyan-900 dark:text-cyan-200">
                  Android Dynamic Sandbox & AVD Instrumentation
                </span>
                <p className="text-cyan-800 dark:text-cyan-300 mt-0.5">
                  Execute Android APKs inside Android Studio AVD emulators, Genymotion, or MobSF Dynamic Analyzer. Automatic APK staging, ADB package installation, logcat stream capture, and network egress monitoring.
                </p>
              </div>
            </div>

            {/* Target APK Info */}
            <div className="p-5 rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 space-y-4">
              <h2 className="text-xs font-bold text-slate-900 dark:text-slate-100 uppercase tracking-wider font-mono">
                Target APK Package Information
              </h2>
              {activeRecord ? (
                <div className="grid grid-cols-1 md:grid-cols-4 gap-4 text-xs">
                  <div>
                    <span className="text-slate-400 text-2xs uppercase">APK Filename</span>
                    <div className="font-semibold text-slate-800 dark:text-slate-200 truncate">{activeRecord.filename}</div>
                  </div>
                  <div>
                    <span className="text-slate-400 text-2xs uppercase">Package Name</span>
                    <div className="font-mono text-2xs text-slate-600 dark:text-slate-400 truncate">
                      {activeRecord.package_name || 'Detected dynamically'}
                    </div>
                  </div>
                  <div>
                    <span className="text-slate-400 text-2xs uppercase">SHA-256 Digest</span>
                    <div className="font-mono text-2xs text-slate-600 dark:text-slate-400 truncate" title={activeRecord.sha256}>
                      {activeRecord.sha256}
                    </div>
                  </div>
                  <div>
                    <span className="text-slate-400 text-2xs uppercase">File Size</span>
                    <div className="font-semibold text-slate-800 dark:text-slate-200">
                      {activeRecord.original_size ? `${(activeRecord.original_size / (1024 * 1024)).toFixed(2)} MB` : 'N/A'}
                    </div>
                  </div>
                </div>
              ) : (
                <div className="text-xs text-amber-600 dark:text-amber-400">
                  No APK investigation currently selected. Please pick an investigation from the header dropdown above.
                </div>
              )}
            </div>

            {/* Android Sandbox Controls */}
            <div className="p-5 rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 space-y-5">
              <h2 className="text-xs font-bold text-slate-900 dark:text-slate-100 uppercase tracking-wider font-mono">
                Emulator & Execution Configuration
              </h2>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                {/* Emulator Selection */}
                <div className="space-y-2">
                  <label htmlFor="android-env-selector" className="text-xs font-medium text-slate-700 dark:text-slate-300">
                    Android Execution Target
                  </label>
                  <select
                    id="android-env-selector"
                    value={androidEnvId}
                    onChange={(e) => setAndroidEnvId(e.target.value)}
                    className="w-full text-xs border border-slate-300 dark:border-slate-700 rounded-lg p-2.5 bg-white dark:bg-slate-800 text-slate-800 dark:text-slate-200"
                  >
                    <option value="env-android-avd">Android Studio AVD (ADB Controller)</option>
                    <option value="env-genymotion">Genymotion Desktop Device</option>
                    <option value="env-mobfs-dynamic">MobSF Dynamic Analyzer REST API</option>
                    <option value="env-mock-apk">Simulated Android Sandbox (Deterministic QA)</option>
                  </select>

                  {/* Diagnostic for Android SDK / AVD */}
                  {capabilities && (
                    <div className="p-3 rounded-lg bg-slate-50 dark:bg-slate-800/40 border border-slate-200 dark:border-slate-800 text-2xs text-slate-600 dark:text-slate-300 space-y-1">
                      <div>ADB Binary: <span className="font-mono text-cyan-600 dark:text-cyan-400">{capabilities.adb_path || 'Not detected in PATH'}</span></div>
                      <div>Configured AVDs: <span className="font-semibold">{capabilities.avd_count > 0 ? capabilities.avd_names.join(', ') : 'None detected'}</span></div>
                    </div>
                  )}
                </div>

                {/* Network Simulation */}
                <div className="space-y-2">
                  <label htmlFor="android-net-mode" className="text-xs font-medium text-slate-700 dark:text-slate-300">
                    Network Simulation Mode
                  </label>
                  <select
                    id="android-net-mode"
                    value={androidNetworkMode}
                    onChange={(e) => setAndroidNetworkMode(e.target.value)}
                    className="w-full text-xs border border-slate-300 dark:border-slate-700 rounded-lg p-2.5 bg-white dark:bg-slate-800 text-slate-800 dark:text-slate-200"
                  >
                    <option value="OFFLINE">OFFLINE (Airplane Mode / Loopback Only)</option>
                    <option value="SINKHOLE_PROXY">SINKHOLE PROXY (Mitmproxy / FakeNet DNS Sinkhole)</option>
                  </select>
                  <p className="text-2xs text-slate-400">
                    Captures all HTTP, HTTPS, and socket connections without exposing host LAN.
                  </p>
                </div>

                {/* Timeout */}
                <div className="space-y-2">
                  <div className="flex items-center justify-between text-xs">
                    <label htmlFor="android-timeout-range" className="font-medium text-slate-700 dark:text-slate-300">Execution Duration</label>
                    <span className="font-mono text-cyan-600 dark:text-cyan-400 font-bold">{androidTimeout} seconds</span>
                  </div>
                  <input
                    id="android-timeout-range"
                    type="range"
                    min="60"
                    max="600"
                    step="30"
                    value={androidTimeout}
                    onChange={(e) => setAndroidTimeout(Number(e.target.value))}
                    className="w-full accent-cyan-500"
                  />
                  <div className="flex justify-between text-2xs text-slate-400">
                    <span>60s (Quick test)</span>
                    <span>180s (Standard run)</span>
                    <span>600s (Deep observation)</span>
                  </div>
                </div>

                {/* Instrumentation Options */}
                <div className="space-y-2">
                  <label className="text-xs font-medium text-slate-700 dark:text-slate-300">
                    Dynamic Instrumentation & Tracing
                  </label>
                  <div className="p-3 rounded-lg border border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-slate-800/40 text-2xs space-y-1">
                    <div className="flex items-center text-emerald-600 dark:text-emerald-400">
                      <CheckCircle2 className="w-3.5 h-3.5 mr-1.5" />
                      <span>Logcat streaming active (Process & System buffers)</span>
                    </div>
                    <div className="flex items-center text-emerald-600 dark:text-emerald-400">
                      <CheckCircle2 className="w-3.5 h-3.5 mr-1.5" />
                      <span>App data cleared before and after analysis</span>
                    </div>
                    <div className="flex items-center text-emerald-600 dark:text-emerald-400">
                      <CheckCircle2 className="w-3.5 h-3.5 mr-1.5" />
                      <span>Dropped files extracted to evidence folder</span>
                    </div>
                  </div>
                </div>
              </div>

              {/* Action Button */}
              <div className="pt-4 border-t border-slate-200 dark:border-slate-800 flex items-center justify-between">
                <span className="text-2xs text-slate-400">
                  Confirmation required before launching Android instrumentation.
                </span>

                <button
                  onClick={() => setShowAndroidConfirmModal(true)}
                  disabled={!activeRecord || androidStarting || isVirtDisabled}
                  className="px-5 py-2.5 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white font-semibold text-xs flex items-center space-x-2 transition-colors disabled:opacity-50 disabled:cursor-not-allowed shadow-sm"
                >
                  <Play className="w-4 h-4 fill-white" />
                  <span>{androidStarting ? 'Starting Emulator...' : isVirtDisabled ? 'Blocked: Enable Intel VT-x' : 'Start Android Dynamic Run'}</span>
                </button>
              </div>
            </div>

            {/* Android Confirm Modal */}
            {showAndroidConfirmModal && (
              <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-xs p-4">
                <div className="max-w-lg w-full bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-xl p-6 space-y-4 shadow-xl">
                  <div className="flex items-center space-x-3 text-cyan-600">
                    <Smartphone className="w-6 h-6" />
                    <h3 className="text-sm font-bold text-slate-900 dark:text-white">
                      Confirm Android Dynamic Analysis Launch
                    </h3>
                  </div>

                  <p className="text-xs text-slate-600 dark:text-slate-300">
                    You are about to install and run APK on an isolated Android environment:
                  </p>

                  <div className="p-3 bg-slate-100 dark:bg-slate-800 rounded font-mono text-2xs space-y-1">
                    <div>Sample: <span className="text-slate-900 dark:text-white font-bold">{activeRecord?.filename}</span></div>
                    <div>Target Environment: <span className="text-cyan-600 font-bold">{androidEnvId}</span></div>
                    <div>Network Mode: <span className="text-emerald-600 font-bold">{androidNetworkMode}</span></div>
                    <div>Duration: <span className="font-bold">{androidTimeout}s</span></div>
                  </div>

                  <div className="flex justify-end space-x-3 pt-2">
                    <button
                      onClick={() => setShowAndroidConfirmModal(false)}
                      className="px-4 py-2 rounded-lg border border-slate-300 dark:border-slate-700 text-xs font-semibold text-slate-700 dark:text-slate-300 hover:bg-slate-100 dark:hover:bg-slate-800"
                    >
                      Cancel
                    </button>
                    <button
                      onClick={handleLaunchAndroidAnalysis}
                      disabled={androidStarting}
                      className="px-4 py-2 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-semibold"
                    >
                      Confirm & Start Android Tracing
                    </button>
                  </div>
                </div>
              </div>
            )}
          </div>
        )}

        {/* ============================================================== */}
        {/* TAB 4: LIVE BEHAVIOR MONITOR */}
        {/* ============================================================== */}
        {activeTab === 'behavior_monitor' && (
          <div className="space-y-6">
            {/* Run Selection Header */}
            <div className="p-4 rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 flex flex-col md:flex-row md:items-center justify-between gap-4">
              <div className="flex items-center space-x-3">
                <Activity className="w-5 h-5 text-cyan-500" />
                <div>
                  <h2 className="text-xs font-bold text-slate-900 dark:text-white uppercase tracking-wider font-mono">
                    Telemetry Stream & Process Tree
                  </h2>
                  <p className="text-2xs text-slate-400">
                    Live and historical execution telemetry collected from sandbox monitors
                  </p>
                </div>
              </div>

              <div className="flex items-center space-x-3">
                <select
                  aria-label="Select Dynamic Analysis Run"
                  value={selectedRunId}
                  onChange={(e) => setSelectedRunId(e.target.value)}
                  className="text-xs border border-slate-300 dark:border-slate-700 rounded-lg px-3 py-1.5 bg-white dark:bg-slate-800 text-slate-800 dark:text-slate-200"
                >
                  <option value="">-- Select Analysis Run --</option>
                  {analyses.map(run => (
                    <option key={run.id} value={run.id}>
                      {run.sample_name || run.id.slice(0, 8)} ({run.status}) - {run.created_at_utc ? new Date(run.created_at_utc).toLocaleTimeString() : ''}
                    </option>
                  ))}
                </select>

                {selectedRun?.status === 'RUNNING' && (
                  <button
                    onClick={() => handleCancelRun(selectedRunId)}
                    className="px-3 py-1.5 rounded-lg bg-rose-600 hover:bg-rose-500 text-white text-xs font-semibold flex items-center space-x-1"
                  >
                    <Square className="w-3 h-3 fill-white" />
                    <span>Stop Run</span>
                  </button>
                )}

                <button
                  onClick={() => loadSelectedRunData(selectedRunId)}
                  disabled={loadingRunData || !selectedRunId}
                  className="p-1.5 text-slate-500 hover:text-slate-900 dark:hover:text-white border border-slate-300 dark:border-slate-700 rounded-lg hover:bg-slate-100 dark:hover:bg-slate-800 transition-colors"
                >
                  <RefreshCw className={`w-4 h-4 ${loadingRunData ? 'animate-spin' : ''}`} />
                </button>
              </div>
            </div>

            {/* Sub-Tabs for Behavior Types */}
            <div className="border-b border-slate-200 dark:border-slate-800 flex items-center space-x-2">
              <button
                onClick={() => setMonitorSubTab('process_tree')}
                className={`px-3 py-2 text-xs font-semibold border-b-2 transition-colors ${
                  monitorSubTab === 'process_tree'
                    ? 'border-cyan-500 text-cyan-600 dark:text-cyan-400'
                    : 'border-transparent text-slate-500 hover:text-slate-800 dark:hover:text-slate-200'
                }`}
              >
                Process Tree ({processTree.length})
              </button>

              <button
                onClick={() => setMonitorSubTab('events')}
                className={`px-3 py-2 text-xs font-semibold border-b-2 transition-colors ${
                  monitorSubTab === 'events'
                    ? 'border-cyan-500 text-cyan-600 dark:text-cyan-400'
                    : 'border-transparent text-slate-500 hover:text-slate-800 dark:hover:text-slate-200'
                }`}
              >
                Telemetry Events ({observations.length})
              </button>

              <button
                onClick={() => setMonitorSubTab('network')}
                className={`px-3 py-2 text-xs font-semibold border-b-2 transition-colors ${
                  monitorSubTab === 'network'
                    ? 'border-cyan-500 text-cyan-600 dark:text-cyan-400'
                    : 'border-transparent text-slate-500 hover:text-slate-800 dark:hover:text-slate-200'
                }`}
              >
                Network Flows ({networkFlows.length})
              </button>

              <button
                onClick={() => setMonitorSubTab('filesystem')}
                className={`px-3 py-2 text-xs font-semibold border-b-2 transition-colors ${
                  monitorSubTab === 'filesystem'
                    ? 'border-cyan-500 text-cyan-600 dark:text-cyan-400'
                    : 'border-transparent text-slate-500 hover:text-slate-800 dark:hover:text-slate-200'
                }`}
              >
                Filesystem Changes ({observations.filter(o => o.category === 'FILE').length})
              </button>

              <button
                onClick={() => setMonitorSubTab('registry')}
                className={`px-3 py-2 text-xs font-semibold border-b-2 transition-colors ${
                  monitorSubTab === 'registry'
                    ? 'border-cyan-500 text-cyan-600 dark:text-cyan-400'
                    : 'border-transparent text-slate-500 hover:text-slate-800 dark:hover:text-slate-200'
                }`}
              >
                Registry Alterations ({observations.filter(o => o.category === 'REGISTRY').length})
              </button>

              <button
                onClick={() => setMonitorSubTab('alerts')}
                className={`px-3 py-2 text-xs font-semibold border-b-2 transition-colors ${
                  monitorSubTab === 'alerts'
                    ? 'border-cyan-500 text-cyan-600 dark:text-cyan-400'
                    : 'border-transparent text-slate-500 hover:text-slate-800 dark:hover:text-slate-200'
                }`}
              >
                Security Detections ({observations.filter(o => o.severity === 'HIGH' || o.severity === 'CRITICAL').length})
              </button>
            </div>

            {/* Sub-Tab Viewport */}
            <div className="rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 p-4">
              {/* 1. Process Tree */}
              {monitorSubTab === 'process_tree' && (
                <div className="space-y-4">
                  <div className="flex items-center justify-between text-2xs text-slate-400 font-mono">
                    <span>HIERARCHICAL PROCESS TREE & INJECTION DETECTION</span>
                    <span>{processTree.length} ROOT NODES</span>
                  </div>

                  {processTree.length === 0 ? (
                    <div className="p-8 text-center text-xs text-slate-400">
                      No process activity recorded for this run. Launch a run or ensure the process monitor is active.
                    </div>
                  ) : (
                    <div className="space-y-2 font-mono text-xs overflow-x-auto">
                      {processTree.map(rootNode => renderProcessNode(rootNode))}
                    </div>
                  )}
                </div>
              )}

              {/* 2. Telemetry Events */}
              {monitorSubTab === 'events' && (
                <div className="space-y-4">
                  {/* Filters */}
                  <div className="flex flex-col md:flex-row gap-3 justify-between items-center text-xs">
                    <div className="flex items-center space-x-2 w-full md:w-auto">
                      <Search className="w-4 h-4 text-slate-400" />
                      <input
                        type="text"
                        placeholder="Search event type, target, process..."
                        value={eventSearchQuery}
                        onChange={(e) => setEventSearchQuery(e.target.value)}
                        className="border border-slate-300 dark:border-slate-700 rounded px-2.5 py-1 text-xs bg-white dark:bg-slate-800 text-slate-800 dark:text-slate-200 w-64"
                      />
                    </div>

                    <div className="flex items-center space-x-2">
                      <Filter className="w-4 h-4 text-slate-400" />
                      <select
                        aria-label="Filter events by category"
                        value={eventCategoryFilter}
                        onChange={(e) => setEventCategoryFilter(e.target.value)}
                        className="border border-slate-300 dark:border-slate-700 rounded px-2.5 py-1 text-xs bg-white dark:bg-slate-800 text-slate-800 dark:text-slate-200"
                      >
                        <option value="ALL">All Categories</option>
                        <option value="PROCESS">Process Events</option>
                        <option value="FILE">File Activity</option>
                        <option value="REGISTRY">Registry Activity</option>
                        <option value="NETWORK">Network Events</option>
                        <option value="API">API Calls</option>
                        <option value="SECURITY">Security / Suspicious</option>
                      </select>
                    </div>
                  </div>

                  {filteredObservations.length === 0 ? (
                    <div className="p-8 text-center text-xs text-slate-400">
                      No matching events found.
                    </div>
                  ) : (
                    <div className="overflow-x-auto">
                      <table className="w-full text-left text-xs">
                        <thead className="bg-slate-50 dark:bg-slate-800/50 text-slate-500 dark:text-slate-400 font-mono text-2xs uppercase">
                          <tr>
                            <th className="py-2 px-3">Timestamp</th>
                            <th className="py-2 px-3">Category</th>
                            <th className="py-2 px-3">Event Type</th>
                            <th className="py-2 px-3">Process</th>
                            <th className="py-2 px-3">Target / Path</th>
                            <th className="py-2 px-3">Severity</th>
                          </tr>
                        </thead>
                        <tbody className="divide-y divide-slate-100 dark:divide-slate-800 font-mono text-2xs">
                          {filteredObservations.map(obs => (
                            <tr key={obs.id} className="hover:bg-slate-50 dark:hover:bg-slate-800/30">
                              <td className="py-2 px-3 text-slate-400">
                                {obs.timestamp_utc ? new Date(obs.timestamp_utc).toLocaleTimeString() : '—'}
                              </td>
                              <td className="py-2 px-3">
                                <span className="px-1.5 py-0.5 rounded bg-slate-100 dark:bg-slate-800 font-bold text-slate-700 dark:text-slate-300">
                                  {obs.category}
                                </span>
                              </td>
                              <td className="py-2 px-3 font-semibold text-slate-800 dark:text-slate-200">
                                {obs.event_type}
                              </td>
                              <td className="py-2 px-3 text-cyan-600 dark:text-cyan-400">
                                {obs.process_name || '—'} {obs.process_id ? `(${obs.process_id})` : ''}
                              </td>
                              <td className="py-2 px-3 max-w-xs truncate text-slate-600 dark:text-slate-400" title={obs.target_path || JSON.stringify(obs.details)}>
                                {obs.target_path || JSON.stringify(obs.details)}
                              </td>
                              <td className="py-2 px-3">
                                <span className={`px-1.5 py-0.5 rounded font-bold uppercase ${
                                  obs.severity === 'CRITICAL' || obs.severity === 'HIGH'
                                    ? 'bg-rose-100 text-rose-800 dark:bg-rose-950 dark:text-rose-300'
                                    : obs.severity === 'MEDIUM'
                                    ? 'bg-amber-100 text-amber-800 dark:bg-amber-950 dark:text-amber-300'
                                    : 'bg-slate-100 text-slate-600 dark:bg-slate-800 dark:text-slate-400'
                                }`}>
                                  {obs.severity}
                                </span>
                              </td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  )}
                </div>
              )}

              {/* 3. Network Flows */}
              {monitorSubTab === 'network' && (
                <div className="space-y-4">
                  {networkFlows.length === 0 ? (
                    <div className="p-8 text-center text-xs text-slate-400">
                      No network flows captured for this run.
                    </div>
                  ) : (
                    <div className="overflow-x-auto">
                      <table className="w-full text-left text-xs font-mono">
                        <thead className="bg-slate-50 dark:bg-slate-800/50 text-slate-500 dark:text-slate-400 text-2xs uppercase">
                          <tr>
                            <th className="py-2 px-3">Timestamp</th>
                            <th className="py-2 px-3">Source</th>
                            <th className="py-2 px-3">Destination</th>
                            <th className="py-2 px-3">Protocol / Port</th>
                            <th className="py-2 px-3">Packets / Bytes</th>
                            <th className="py-2 px-3">Simulated?</th>
                          </tr>
                        </thead>
                        <tbody className="divide-y divide-slate-100 dark:divide-slate-800 text-2xs">
                          {networkFlows.map((flow, i) => (
                            <tr key={i} className="hover:bg-slate-50 dark:hover:bg-slate-800/30">
                              <td className="py-2 px-3 text-slate-400">{flow.timestamp_utc || '—'}</td>
                              <td className="py-2 px-3 text-slate-700 dark:text-slate-300">{flow.source_ip}:{flow.source_port}</td>
                              <td className="py-2 px-3 font-semibold text-cyan-600 dark:text-cyan-400">{flow.destination_ip}:{flow.destination_port}</td>
                              <td className="py-2 px-3">{flow.protocol}</td>
                              <td className="py-2 px-3 text-slate-400">{flow.packet_count || 1} pkts ({flow.byte_count || 0} B)</td>
                              <td className="py-2 px-3">
                                <span className={`px-1.5 py-0.5 rounded font-bold uppercase ${flow.is_simulated ? 'bg-purple-100 text-purple-700 dark:bg-purple-950 dark:text-purple-300' : 'bg-slate-100 text-slate-700'}`}>
                                  {flow.is_simulated ? 'SIMULATED' : 'LIVE'}
                                </span>
                              </td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  )}
                </div>
              )}

              {/* 4. Filesystem Changes */}
              {monitorSubTab === 'filesystem' && (
                <div className="space-y-4">
                  {observations.filter(o => o.category === 'FILE').length === 0 ? (
                    <div className="p-8 text-center text-xs text-slate-400">
                      No filesystem modifications detected.
                    </div>
                  ) : (
                    <div className="space-y-2">
                      {observations.filter(o => o.category === 'FILE').map(obs => (
                        <div key={obs.id} className="p-3 rounded-lg border border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-slate-800/40 font-mono text-2xs space-y-1">
                          <div className="flex items-center justify-between">
                            <span className="font-bold text-cyan-600 dark:text-cyan-400">{obs.event_type}</span>
                            <span className="text-slate-400">{obs.timestamp_utc}</span>
                          </div>
                          <div className="text-slate-800 dark:text-slate-200 truncate">{obs.target_path}</div>
                          {obs.details && (
                            <div className="text-slate-500">
                              Process: {obs.process_name} (PID: {obs.process_id})
                            </div>
                          )}
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              )}

              {/* 5. Registry Changes */}
              {monitorSubTab === 'registry' && (
                <div className="space-y-4">
                  {observations.filter(o => o.category === 'REGISTRY').length === 0 ? (
                    <div className="p-8 text-center text-xs text-slate-400">
                      No registry alterations detected.
                    </div>
                  ) : (
                    <div className="space-y-2">
                      {observations.filter(o => o.category === 'REGISTRY').map(obs => (
                        <div key={obs.id} className="p-3 rounded-lg border border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-slate-800/40 font-mono text-2xs space-y-1">
                          <div className="flex items-center justify-between">
                            <span className="font-bold text-amber-600 dark:text-amber-400">{obs.event_type}</span>
                            <span className="text-slate-400">{obs.timestamp_utc}</span>
                          </div>
                          <div className="text-slate-800 dark:text-slate-200 truncate">{obs.target_path}</div>
                          {obs.details?.value_name && (
                            <div className="text-slate-500">
                              Value: {obs.details.value_name} = {obs.details.value_data}
                            </div>
                          )}
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              )}

              {/* 6. Security Detections */}
              {monitorSubTab === 'alerts' && (
                <div className="space-y-4">
                  {observations.filter(o => o.severity === 'HIGH' || o.severity === 'CRITICAL').length === 0 ? (
                    <div className="p-8 text-center text-xs text-slate-400">
                      No high or critical security alerts flagged for this execution run.
                    </div>
                  ) : (
                    <div className="space-y-3">
                      {observations.filter(o => o.severity === 'HIGH' || o.severity === 'CRITICAL').map(obs => (
                        <div key={obs.id} className="p-4 rounded-lg border border-rose-200 dark:border-rose-900 bg-rose-50/50 dark:bg-rose-950/20 flex items-start space-x-3">
                          <AlertTriangle className="w-5 h-5 text-rose-600 dark:text-rose-400 flex-shrink-0 mt-0.5" />
                          <div className="space-y-1 text-xs">
                            <div className="flex items-center space-x-2">
                              <span className="font-bold text-rose-900 dark:text-rose-200">{obs.event_type}</span>
                              {obs.mitre_technique && (
                                <span className="px-1.5 py-0.2 rounded font-mono text-2xs bg-rose-200 dark:bg-rose-900 text-rose-800 dark:text-rose-200">
                                  {obs.mitre_technique}
                                </span>
                              )}
                            </div>
                            <p className="text-rose-800 dark:text-rose-300 text-2xs font-mono">
                              {obs.target_path || JSON.stringify(obs.details)}
                            </p>
                          </div>
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              )}
            </div>
          </div>
        )}

        {/* ============================================================== */}
        {/* TAB 5: RUNTIME FINDINGS & CORRELATIONS */}
        {/* ============================================================== */}
        {activeTab === 'correlations' && (
          <div className="space-y-6">
            {/* Header & Risk Score Card */}
            <div className="p-5 rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 flex flex-col md:flex-row md:items-center justify-between gap-4">
              <div>
                <h2 className="text-sm font-bold text-slate-900 dark:text-white flex items-center space-x-2">
                  <GitMerge className="w-4 h-4 text-cyan-500" />
                  <span>Static vs. Dynamic Correlation Matrix</span>
                </h2>
                <p className="text-xs text-slate-500 dark:text-slate-400 mt-0.5">
                  5-Tier Classification: Confirmed Runtime Observation, Static Only, Inconclusive, or Environment Limitations
                </p>
              </div>

              {report && (
                <div className="flex items-center space-x-4">
                  <div className="text-right">
                    <span className="text-2xs text-slate-400 uppercase font-mono">Composite Risk</span>
                    <div className="text-xl font-bold text-rose-600 dark:text-rose-400 font-mono">
                      {report.risk_score} / 100 ({report.risk_level})
                    </div>
                  </div>

                  <button
                    onClick={() => {
                      const blob = new Blob([report.markdown_content || ''], { type: 'text/markdown' });
                      const url = URL.createObjectURL(blob);
                      const a = document.createElement('a');
                      a.href = url;
                      a.download = `dynamic_report_${report.run_id}.md`;
                      a.click();
                      URL.revokeObjectURL(url);
                    }}
                    className="px-3 py-2 rounded-lg border border-slate-300 dark:border-slate-700 hover:bg-slate-100 dark:hover:bg-slate-800 text-xs font-semibold flex items-center space-x-1.5 transition-colors"
                  >
                    <Download className="w-4 h-4" />
                    <span>Download Report (.md)</span>
                  </button>
                </div>
              )}
            </div>

            {/* MITRE ATT&CK Matrix Observed */}
            {report && report.mitre_techniques_observed && report.mitre_techniques_observed.length > 0 && (
              <div className="p-4 rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 space-y-3">
                <h3 className="text-xs font-bold text-slate-900 dark:text-slate-100 uppercase tracking-wider font-mono">
                  Observed MITRE ATT&CK Techniques ({report.mitre_techniques_observed.length})
                </h3>
                <div className="flex flex-wrap gap-2">
                  {report.mitre_techniques_observed.map(tech => (
                    <span
                      key={tech}
                      className="px-2.5 py-1 rounded bg-rose-50 dark:bg-rose-950/40 text-rose-700 dark:text-rose-300 border border-rose-200 dark:border-rose-900 font-mono text-2xs font-semibold"
                    >
                      {tech}
                    </span>
                  ))}
                </div>
              </div>
            )}

            {/* Static vs Runtime Correlation Table */}
            <div className="rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 overflow-hidden">
              <div className="p-4 border-b border-slate-200 dark:border-slate-800">
                <h3 className="text-xs font-bold text-slate-900 dark:text-slate-100 uppercase tracking-wider font-mono">
                  Indicator Verification Matrix
                </h3>
              </div>

              {!report || !report.correlations || report.correlations.length === 0 ? (
                <div className="p-8 text-center text-xs text-slate-400">
                  No correlations recorded yet for this run. Select a completed dynamic run with static indicators.
                </div>
              ) : (
                <div className="overflow-x-auto">
                  <table className="w-full text-left text-xs">
                    <thead className="bg-slate-50 dark:bg-slate-800/50 text-slate-500 dark:text-slate-400 font-mono text-2xs uppercase">
                      <tr>
                        <th className="py-2.5 px-4">Indicator</th>
                        <th className="py-2.5 px-4">Static Finding</th>
                        <th className="py-2.5 px-4">Runtime Observation</th>
                        <th className="py-2.5 px-4">Classification</th>
                        <th className="py-2.5 px-4">Confidence</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-100 dark:divide-slate-800 text-xs">
                      {report.correlations.map((corr: any, idx: number) => (
                        <tr key={idx} className="hover:bg-slate-50 dark:hover:bg-slate-800/30">
                          <td className="py-2.5 px-4 font-mono font-bold text-slate-800 dark:text-slate-200">
                            {corr.indicator_value}
                          </td>
                          <td className="py-2.5 px-4 text-slate-600 dark:text-slate-400">
                            {corr.static_finding_title || 'Static Indicator'}
                          </td>
                          <td className="py-2.5 px-4 text-slate-700 dark:text-slate-300">
                            {corr.supporting_event_summary || 'Observed during dynamic tracing'}
                          </td>
                          <td className="py-2.5 px-4">
                            <span className={`px-2 py-0.5 rounded text-2xs font-bold uppercase font-mono ${
                              corr.classification === 'RUNTIME_OBSERVED'
                                ? 'bg-emerald-100 text-emerald-800 dark:bg-emerald-950 dark:text-emerald-300'
                                : corr.classification === 'STATIC_INDICATOR'
                                ? 'bg-amber-100 text-amber-800 dark:bg-amber-950 dark:text-amber-300'
                                : 'bg-slate-100 text-slate-700 dark:bg-slate-800 dark:text-slate-300'
                            }`}>
                              {corr.classification || 'RUNTIME_OBSERVED'}
                            </span>
                          </td>
                          <td className="py-2.5 px-4 font-mono text-2xs">
                            {corr.confidence || 'HIGH'}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </div>
          </div>
        )}

        {/* ============================================================== */}
        {/* TAB 6: SANDBOX CONFIGURATION & HEALTH */}
        {/* ============================================================== */}
        {activeTab === 'sandbox_config' && (
          <div className="space-y-6">
            {/* Host Virtualization Audit */}
            <div className="p-5 rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 space-y-4">
              <div className="flex items-center justify-between">
                <div>
                  <h2 className="text-xs font-bold text-slate-900 dark:text-slate-100 uppercase tracking-wider font-mono">
                    Host Virtualization & Platform Diagnostics
                  </h2>
                  <p className="text-2xs text-slate-400">
                    Live preflight check results from host system configuration
                  </p>
                </div>
                <button
                  onClick={refreshCoreData}
                  disabled={loadingCapabilities}
                  className="px-3 py-1.5 rounded-lg border border-slate-300 dark:border-slate-700 hover:bg-slate-100 dark:hover:bg-slate-800 text-xs font-semibold flex items-center space-x-1"
                >
                  <RefreshCw className={`w-3.5 h-3.5 ${loadingCapabilities ? 'animate-spin' : ''}`} />
                  <span>Run Preflight Diagnostics</span>
                </button>
              </div>

              {capabilities ? (
                <div className="grid grid-cols-1 md:grid-cols-3 gap-4 font-mono text-xs">
                  <div className="p-3 rounded-lg border border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-slate-800/40">
                    <span className="text-2xs text-slate-400 uppercase">Host Operating System</span>
                    <div className="font-bold text-slate-800 dark:text-slate-200 mt-1">{capabilities.host_edition || capabilities.host_os}</div>
                  </div>

                  <div className="p-3 rounded-lg border border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-slate-800/40">
                    <span className="text-2xs text-slate-400 uppercase">Hardware Virtualization</span>
                    <div className={`font-bold mt-1 ${capabilities.virtualization_enabled ? 'text-emerald-600' : 'text-rose-600'}`}>
                      {capabilities.virtualization_enabled ? 'ENABLED IN FIRMWARE' : 'DISABLED / NOT PRESENT'}
                    </div>
                  </div>

                  <div className="p-3 rounded-lg border border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-slate-800/40">
                    <span className="text-2xs text-slate-400 uppercase">Windows Sandbox Status</span>
                    <div className={`font-bold mt-1 ${capabilities.windows_sandbox_installed ? 'text-emerald-600' : 'text-rose-600'}`}>
                      {capabilities.windows_sandbox_installed ? 'INSTALLED & READY' : 'NOT INSTALLED (Home Edition)'}
                    </div>
                  </div>

                  <div className="p-3 rounded-lg border border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-slate-800/40">
                    <span className="text-2xs text-slate-400 uppercase">Android ADB Binary</span>
                    <div className="font-bold text-slate-800 dark:text-slate-200 mt-1 truncate" title={capabilities.adb_path}>
                      {capabilities.adb_path ? 'DETECTED' : 'NOT FOUND IN PATH'}
                    </div>
                  </div>

                  <div className="p-3 rounded-lg border border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-slate-800/40">
                    <span className="text-2xs text-slate-400 uppercase">Android Virtual Devices</span>
                    <div className="font-bold text-slate-800 dark:text-slate-200 mt-1">
                      {capabilities.avd_count} AVDs detected
                    </div>
                  </div>

                  <div className="p-3 rounded-lg border border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-slate-800/40">
                    <span className="text-2xs text-slate-400 uppercase">Network Simulators</span>
                    <div className="font-bold text-slate-800 dark:text-slate-200 mt-1">
                      {capabilities.fakenet_present ? 'FAKENET PRESENT' : 'OFFLINE SIMULATION READY'}
                    </div>
                  </div>
                </div>
              ) : (
                <div className="p-4 text-center text-xs text-slate-400">Loading diagnostic capabilities...</div>
              )}
            </div>

            {/* Provider Verification Legend */}
            <div className="p-5 rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 space-y-3">
              <h3 className="text-xs font-bold text-slate-900 dark:text-slate-100 uppercase tracking-wider font-mono">
                Verification & Honesty Status Legend
              </h3>
              <p className="text-xs text-slate-500">
                TraceX strictly enforces honest capability gating. We never fabricate dynamic execution results.
              </p>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-2xs font-mono">
                <div className="p-2.5 rounded border border-emerald-200 dark:border-emerald-900 bg-emerald-50 dark:bg-emerald-950/30">
                  <span className="font-bold text-emerald-800 dark:text-emerald-300">VERIFIED:</span>
                  <span className="ml-1 text-slate-600 dark:text-slate-400">Sandbox provider is installed, active, and validated in hardware.</span>
                </div>

                <div className="p-2.5 rounded border border-purple-200 dark:border-purple-900 bg-purple-50 dark:bg-purple-950/30">
                  <span className="font-bold text-purple-800 dark:text-purple-300">MOCKED:</span>
                  <span className="ml-1 text-slate-600 dark:text-slate-400">Deterministic pipeline simulation for QA testing on non-virtualized systems.</span>
                </div>

                <div className="p-2.5 rounded border border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-slate-800/40">
                  <span className="font-bold text-slate-800 dark:text-slate-300">NOT CONFIGURED:</span>
                  <span className="ml-1 text-slate-600 dark:text-slate-400">Provider software supported by TraceX but missing guest VMs or API keys.</span>
                </div>

                <div className="p-2.5 rounded border border-rose-200 dark:border-rose-900 bg-rose-50 dark:bg-rose-950/30">
                  <span className="font-bold text-rose-800 dark:text-rose-300">UNSUPPORTED PLATFORM:</span>
                  <span className="ml-1 text-slate-600 dark:text-slate-400">Host operating system edition lacks required hypervisor architecture.</span>
                </div>
              </div>
            </div>

            {/* Quick Setup Instructions */}
            <div className="p-5 rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 space-y-3">
              <h3 className="text-xs font-bold text-slate-900 dark:text-slate-100 uppercase tracking-wider font-mono">
                Environment Setup Instructions
              </h3>

              <div className="space-y-2 text-xs">
                <details className="p-3 rounded-lg border border-slate-200 dark:border-slate-800">
                  <summary className="font-semibold cursor-pointer">Enabling Windows Sandbox (Windows 10/11 Pro or Enterprise)</summary>
                  <p className="mt-2 text-slate-600 dark:text-slate-400 text-2xs">
                    Run PowerShell as Administrator:
                  </p>
                  <pre className="mt-1 p-2 rounded bg-slate-900 text-slate-100 font-mono text-2xs">
                    Enable-WindowsOptionalFeature -Online -FeatureName "Containers-DisposableClientVM" -All
                  </pre>
                </details>

                <details className="p-3 rounded-lg border border-slate-200 dark:border-slate-800">
                  <summary className="font-semibold cursor-pointer">Configuring Android Studio AVD for Tracing</summary>
                  <p className="mt-2 text-slate-600 dark:text-slate-400 text-2xs">
                    Create an AVD without Google Play store (allows root adb remount):
                  </p>
                  <pre className="mt-1 p-2 rounded bg-slate-900 text-slate-100 font-mono text-2xs">
                    avdmanager create avd -n TraceX_Pixel_API33 -k "system-images;android-33;google_apis;x86_64" --device "pixel"
                  </pre>
                </details>
              </div>
            </div>
          </div>
        )}

        {/* ============================================================== */}
        {/* TAB 7: VM ENVIRONMENT & HYPERVISOR MANAGEMENT */}
        {/* ============================================================== */}
        {activeTab === 'vm_environment' && (
          <div className="space-y-6">
            {/* Header with Live Action Buttons */}
            <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3 p-4 rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900">
              <div>
                <div className="flex items-center space-x-2">
                  <Server className="w-5 h-5 text-cyan-600 dark:text-cyan-400" />
                  <h2 className="text-sm font-bold text-slate-900 dark:text-slate-100 uppercase tracking-wider font-mono">
                    Virtual Machine & Hypervisor Topometry
                  </h2>
                </div>
                <p className="mt-1 text-xs text-slate-500">
                  Automated hypervisor discovery, nested virtualization audit, and resource budgeting for VM-native deployment.
                </p>
              </div>

              <div className="flex items-center space-x-2">
                <button
                  onClick={() => refreshVMData(true)}
                  disabled={loadingVM}
                  className="flex items-center space-x-1.5 px-3 py-1.5 rounded-lg border border-slate-200 dark:border-slate-700 bg-slate-50 dark:bg-slate-800 hover:bg-slate-100 dark:hover:bg-slate-700 text-xs font-medium text-slate-700 dark:text-slate-200 transition-colors"
                >
                  <RefreshCw className={`w-3.5 h-3.5 ${loadingVM ? 'animate-spin' : ''}`} />
                  <span>Rescan Topometry</span>
                </button>

                <button
                  onClick={handleTestNestedVirtualization}
                  disabled={testingNested}
                  className="flex items-center space-x-1.5 px-3 py-1.5 rounded-lg bg-cyan-600 hover:bg-cyan-700 text-xs font-semibold text-white shadow-sm transition-colors"
                >
                  <Cpu className={`w-3.5 h-3.5 ${testingNested ? 'animate-spin' : ''}`} />
                  <span>Test Nested VT-x/AMD-V</span>
                </button>
              </div>
            </div>

            {/* Two-Plane Architecture Banner */}
            <div className="p-4 rounded-xl border border-cyan-500/20 bg-gradient-to-r from-cyan-500/5 via-blue-500/5 to-transparent">
              <div className="flex items-start space-x-3">
                <ShieldCheck className="w-5 h-5 text-cyan-500 shrink-0 mt-0.5" />
                <div className="space-y-1 text-xs">
                  <div className="flex items-center space-x-2">
                    <span className="font-bold text-slate-900 dark:text-slate-100">
                      TraceX Two-Plane Architecture Active
                    </span>
                    <span className="px-2 py-0.5 rounded text-2xs font-mono font-bold bg-cyan-500/10 text-cyan-600 dark:text-cyan-400 border border-cyan-500/20">
                      FORENSIC ZERO-HOST-EXECUTION
                    </span>
                  </div>
                  <p className="text-slate-600 dark:text-slate-400">
                    <strong>Manager Plane:</strong> TraceX runs inside a protected environment hosting the forensic database, AI co-pilot, and static analysis tools. It never executes untrusted samples directly.
                    <br />
                    <strong>Analysis Worker Plane:</strong> Untrusted PE and APK binaries detonate exclusively inside disposable, snapshot-reverted child VMs communicating over an authenticated management channel.
                  </p>
                </div>
              </div>
            </div>

            {/* Topometry KPI Cards */}
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
              {/* Card 1: Execution Topometry */}
              <div className="p-4 rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900">
                <div className="flex items-center justify-between text-xs text-slate-500 mb-1">
                  <span>Execution Plane</span>
                  <Monitor className="w-4 h-4 text-slate-400" />
                </div>
                <div className="text-sm font-bold text-slate-900 dark:text-slate-100">
                  {vmEnvironment?.environment?.is_virtual_machine ? 'Guest Virtual Machine' : 'Physical Host / Bare Metal'}
                </div>
                <div className="mt-1 text-2xs text-slate-500 font-mono">
                  {vmEnvironment?.environment?.guest_os?.caption || 'Querying OS...'}
                </div>
              </div>

              {/* Card 2: Parent Hypervisor */}
              <div className="p-4 rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900">
                <div className="flex items-center justify-between text-xs text-slate-500 mb-1">
                  <span>Parent Hypervisor</span>
                  <Server className="w-4 h-4 text-cyan-500" />
                </div>
                <div className="text-sm font-bold text-slate-900 dark:text-slate-100">
                  {vmEnvironment?.environment?.detected_hypervisor || 'Scanning...'}
                </div>
                <div className="mt-1 text-2xs text-slate-500">
                  Manufacturer: {vmEnvironment?.environment?.parent_hypervisor_details?.system_manufacturer || 'N/A'}
                </div>
              </div>

              {/* Card 3: Nested Virtualization */}
              <div className="p-4 rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900">
                <div className="flex items-center justify-between text-xs text-slate-500 mb-1">
                  <span>Nested VT-x / AMD-V</span>
                  <Cpu className="w-4 h-4 text-emerald-500" />
                </div>
                <div className="text-sm font-bold">
                  {vmEnvironment?.environment?.cpu_virtualization?.nested_virtualization_available ? (
                    <span className="text-emerald-600 dark:text-emerald-400 flex items-center space-x-1">
                      <CheckCircle2 className="w-3.5 h-3.5" />
                      <span>EXPOSED & READY</span>
                    </span>
                  ) : (
                    <span className="text-amber-600 dark:text-amber-400 flex items-center space-x-1">
                      <AlertTriangle className="w-3.5 h-3.5" />
                      <span>NOT EXPOSED</span>
                    </span>
                  )}
                </div>
                <div className="mt-1 text-2xs text-slate-500 font-mono">
                  {vmEnvironment?.environment?.cpu_virtualization?.physical_cores || 1} Cores / {vmEnvironment?.environment?.cpu_virtualization?.logical_processors || 1} Threads
                </div>
              </div>

              {/* Card 4: Recommended Mode */}
              <div className="p-4 rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900">
                <div className="flex items-center justify-between text-xs text-slate-500 mb-1">
                  <span>Recommended Deployment</span>
                  <HardDrive className="w-4 h-4 text-indigo-500" />
                </div>
                <div className="text-sm font-bold font-mono">
                  {vmEnvironment?.environment?.deployment_mode?.recommended_mode || 'EVALUATING'}
                </div>
                <div className="mt-1 text-2xs text-slate-500">
                  {vmEnvironment?.environment?.deployment_mode?.supports_mode_a_external
                    ? 'External CLI / API Available'
                    : 'Requires Hypervisor Configuration'}
                </div>
              </div>
            </div>

            {/* Resource Gauges & Quotas */}
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              {/* RAM Budget */}
              <div className="p-5 rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 space-y-3">
                <div className="flex items-center justify-between">
                  <h3 className="text-xs font-bold text-slate-900 dark:text-slate-100 uppercase tracking-wider font-mono flex items-center space-x-2">
                    <Activity className="w-4 h-4 text-cyan-500" />
                    <span>Memory Allocation & Worker Quotas</span>
                  </h3>
                  <span className={`text-2xs font-bold px-2 py-0.5 rounded ${
                    vmEnvironment?.resources?.memory?.is_sufficient
                      ? 'bg-emerald-500/10 text-emerald-600 dark:text-emerald-400 border border-emerald-500/20'
                      : 'bg-rose-500/10 text-rose-600 dark:text-rose-400 border border-rose-500/20'
                  }`}>
                    {vmEnvironment?.resources?.memory?.is_sufficient ? 'CAPACITY SUFFICIENT' : 'LOW MEMORY'}
                  </span>
                </div>

                <div className="space-y-1">
                  <div className="flex justify-between text-xs text-slate-600 dark:text-slate-400">
                    <span>Available Free RAM:</span>
                    <span className="font-mono font-bold text-slate-900 dark:text-slate-100">
                      {vmEnvironment?.resources?.memory?.available_ram_mb || 0} MB / {vmEnvironment?.resources?.memory?.total_ram_mb || 0} MB
                    </span>
                  </div>
                  <div className="w-full bg-slate-200 dark:bg-slate-800 h-2 rounded-full overflow-hidden">
                    <div
                      className="bg-cyan-500 h-full rounded-full transition-all"
                      style={{
                        width: `${Math.min(100, Math.round(((vmEnvironment?.resources?.memory?.available_ram_mb || 0) / (vmEnvironment?.resources?.memory?.total_ram_mb || 1)) * 100))}%`
                      }}
                    />
                  </div>
                  <div className="text-2xs text-slate-500">
                    Minimum required to boot isolated worker VM: <strong>{vmEnvironment?.resources?.memory?.required_min_mb || 1536} MB</strong>. Max concurrent workers: <strong>{vmEnvironment?.resources?.max_concurrent_workers || 1}</strong>.
                  </div>
                </div>
              </div>

              {/* Storage Budget */}
              <div className="p-5 rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 space-y-3">
                <div className="flex items-center justify-between">
                  <h3 className="text-xs font-bold text-slate-900 dark:text-slate-100 uppercase tracking-wider font-mono flex items-center space-x-2">
                    <FolderOpen className="w-4 h-4 text-indigo-500" />
                    <span>Workspace Storage & Snapshot Quota</span>
                  </h3>
                  <span className={`text-2xs font-bold px-2 py-0.5 rounded ${
                    vmEnvironment?.resources?.storage?.is_sufficient
                      ? 'bg-emerald-500/10 text-emerald-600 dark:text-emerald-400 border border-emerald-500/20'
                      : 'bg-rose-500/10 text-rose-600 dark:text-rose-400 border border-rose-500/20'
                  }`}>
                    {vmEnvironment?.resources?.storage?.is_sufficient ? 'STORAGE SUFFICIENT' : 'LOW DISK SPACE'}
                  </span>
                </div>

                <div className="space-y-1">
                  <div className="flex justify-between text-xs text-slate-600 dark:text-slate-400">
                    <span>Drive {vmEnvironment?.resources?.storage?.workspace_drive || 'C:'} Free Space:</span>
                    <span className="font-mono font-bold text-slate-900 dark:text-slate-100">
                      {vmEnvironment?.resources?.storage?.free_disk_gb || 0} GB / {vmEnvironment?.resources?.storage?.total_disk_gb || 0} GB
                    </span>
                  </div>
                  <div className="w-full bg-slate-200 dark:bg-slate-800 h-2 rounded-full overflow-hidden">
                    <div
                      className="bg-indigo-500 h-full rounded-full transition-all"
                      style={{
                        width: `${Math.min(100, Math.round(((vmEnvironment?.resources?.storage?.free_disk_gb || 0) / (vmEnvironment?.resources?.storage?.total_disk_gb || 1)) * 100))}%`
                      }}
                    />
                  </div>
                  <div className="text-2xs text-slate-500">
                    Minimum required for isolated staging & worker snapshots: <strong>{vmEnvironment?.resources?.storage?.required_min_gb || 3} GB</strong>.
                  </div>
                </div>
              </div>
            </div>

            {/* VirtualBox Host Controller & Worker Architecture */}
            <div className="p-5 rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 space-y-4">
              <div className="flex items-center justify-between">
                <h3 className="text-xs font-bold text-slate-900 dark:text-slate-100 uppercase tracking-wider font-mono flex items-center space-x-2">
                  <Server className="w-4 h-4 text-cyan-500" />
                  <span>VirtualBox Host Controller Agent & Worker Topometry</span>
                </h3>
                <span className="text-2xs font-mono font-bold uppercase px-2.5 py-0.5 rounded bg-cyan-100 text-cyan-800 dark:bg-cyan-950 dark:text-cyan-300 border border-cyan-300 dark:border-cyan-800">
                  PLANE 1 &harr; PLANE 2
                </span>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                {/* Host Controller Agent Card */}
                <div className="p-4 rounded-lg bg-slate-50 dark:bg-slate-800/40 border border-slate-200 dark:border-slate-800 space-y-2">
                  <div className="flex items-center justify-between text-xs">
                    <span className="font-bold text-slate-900 dark:text-white flex items-center space-x-1.5">
                      <Shield className="w-3.5 h-3.5 text-cyan-500" />
                      <span>Host Controller Agent</span>
                    </span>
                    <span className="text-2xs font-mono px-1.5 py-0.5 rounded bg-emerald-100 text-emerald-800 dark:bg-emerald-950 dark:text-emerald-300 font-semibold">
                      RESTRICTED
                    </span>
                  </div>
                  <div className="text-2xs space-y-1 font-mono text-slate-600 dark:text-slate-400">
                    <div>Interface: <strong className="text-slate-900 dark:text-slate-200">192.168.56.1:9443</strong> (Host-Only)</div>
                    <div>VirtualBox Version: <strong className="text-slate-900 dark:text-slate-200">7.2.2</strong></div>
                    <div>Authentication: <strong className="text-slate-900 dark:text-slate-200">HMAC-SHA256 Token / mTLS</strong></div>
                    <div>Allowlisted UUIDs: <strong className="text-cyan-600 dark:text-cyan-400">3 VMs Authorized</strong></div>
                  </div>
                  <div className="pt-1 text-2xs text-slate-500 border-t border-slate-200 dark:border-slate-800">
                    Direct arbitrary commands & file access strictly rejected.
                  </div>
                </div>

                {/* Windows Worker VM Card */}
                <div className="p-4 rounded-lg bg-slate-50 dark:bg-slate-800/40 border border-slate-200 dark:border-slate-800 space-y-2">
                  <div className="flex items-center justify-between text-xs">
                    <span className="font-bold text-slate-900 dark:text-white flex items-center space-x-1.5">
                      <Monitor className="w-3.5 h-3.5 text-blue-500" />
                      <span>Windows Analysis Worker</span>
                    </span>
                    <span className="text-2xs font-mono px-1.5 py-0.5 rounded bg-blue-100 text-blue-800 dark:bg-blue-950 dark:text-blue-300 font-semibold">
                      DISPOSABLE
                    </span>
                  </div>
                  <div className="text-2xs space-y-1 font-mono text-slate-600 dark:text-slate-400">
                    <div>Designated VM: <strong className="text-slate-900 dark:text-slate-200">TraceX-Worker-Win10</strong></div>
                    <div>Baseline Snapshot: <strong className="text-emerald-600 dark:text-emerald-400">Clean_Base</strong></div>
                    <div>Shared Clipboard: <strong className="text-emerald-600 dark:text-emerald-400">DISABLED</strong></div>
                    <div>Shared Folders: <strong className="text-emerald-600 dark:text-emerald-400">0 (UNMOUNTED)</strong></div>
                  </div>
                  <div className="pt-1 text-2xs text-slate-500 border-t border-slate-200 dark:border-slate-800">
                    Automatic snapshot revert before and after every execution.
                  </div>
                </div>

                {/* Android Worker & Containment Card */}
                <div className="p-4 rounded-lg bg-slate-50 dark:bg-slate-800/40 border border-slate-200 dark:border-slate-800 space-y-2">
                  <div className="flex items-center justify-between text-xs">
                    <span className="font-bold text-slate-900 dark:text-white flex items-center space-x-1.5">
                      <Smartphone className="w-3.5 h-3.5 text-emerald-500" />
                      <span>Android Worker & Network</span>
                    </span>
                    <span className="text-2xs font-mono px-1.5 py-0.5 rounded bg-purple-100 text-purple-800 dark:bg-purple-950 dark:text-purple-300 font-semibold">
                      AIR-GAPPED
                    </span>
                  </div>
                  <div className="text-2xs space-y-1 font-mono text-slate-600 dark:text-slate-400">
                    <div>Android SDK: <strong className="text-slate-900 dark:text-slate-200">Detected (Platform-Tools)</strong></div>
                    <div>Default Policy: <strong className="text-emerald-600 dark:text-emerald-400">NETWORK = DISABLED</strong></div>
                    <div>Simulation Mode: <strong className="text-slate-900 dark:text-slate-200">ISOLATED_SIMULATION</strong></div>
                    <div>Production LAN: <strong className="text-rose-600 dark:text-rose-400">PROHIBITED</strong></div>
                  </div>
                  <div className="pt-1 text-2xs text-slate-500 border-t border-slate-200 dark:border-slate-800">
                    Untrusted APKs never execute on Manager VM or physical host.
                  </div>
                </div>
              </div>

              {/* Hardware Virtualization Alert Status */}
              {isVirtDisabled && (
                <div className="p-3 rounded-lg bg-amber-500/10 border border-amber-500/30 flex items-center justify-between text-xs text-amber-800 dark:text-amber-200">
                  <div className="flex items-center space-x-2">
                    <AlertTriangle className="w-4 h-4 text-amber-500 shrink-0" />
                    <span className="font-bold font-mono">ACTION REQUIRED: Enable Intel VT-x in BIOS/UEFI.</span>
                    <span className="text-2xs text-amber-700 dark:text-amber-300">
                      Analysis worker VMs cannot be booted headlessly by Host Controller until firmware virtualization is enabled.
                    </span>
                  </div>
                  <span className="text-2xs font-mono uppercase px-2 py-0.5 bg-amber-200 dark:bg-amber-950 text-amber-800 dark:text-amber-300 rounded font-bold">
                    BLOCKED
                  </span>
                </div>
              )}
            </div>

            {/* Hypervisor Providers Matrix */}
            <div className="space-y-3">
              <h3 className="text-xs font-bold text-slate-900 dark:text-slate-100 uppercase tracking-wider font-mono flex items-center space-x-2">
                <Layers className="w-4 h-4 text-cyan-500" />
                <span>Hypervisor Providers & Worker Environments</span>
              </h3>

              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                {environments.map((env) => {
                  const isReady = env.status === 'INSTALLED_AND_READY';
                  const isPartial = env.status === 'PARTIALLY_CONFIGURED' || env.status === 'CONFIGURED_OFFLINE';
                  const isUnsupported = env.status === 'UNSUPPORTED_PLATFORM';

                  return (
                    <div
                      key={env.id}
                      className="p-4 rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 flex flex-col justify-between space-y-3 hover:border-slate-300 dark:hover:border-slate-700 transition-colors"
                    >
                      <div className="space-y-2">
                        <div className="flex items-start justify-between">
                          <div className="flex items-center space-x-2">
                            {env.os_family === 'android' ? (
                              <Smartphone className="w-4 h-4 text-emerald-500" />
                            ) : (
                              <Monitor className="w-4 h-4 text-blue-500" />
                            )}
                            <span className="font-bold text-xs text-slate-900 dark:text-slate-100">
                              {env.name}
                            </span>
                          </div>

                          <span
                            className={`px-2 py-0.5 rounded text-2xs font-mono font-bold ${
                              isReady
                                ? 'bg-emerald-500/10 text-emerald-600 dark:text-emerald-400 border border-emerald-500/20'
                                : isPartial
                                ? 'bg-amber-500/10 text-amber-600 dark:text-amber-400 border border-amber-500/20'
                                : isUnsupported
                                ? 'bg-rose-500/10 text-rose-600 dark:text-rose-400 border border-rose-500/20'
                                : 'bg-slate-500/10 text-slate-600 dark:text-slate-400 border border-slate-500/20'
                            }`}
                          >
                            {env.status.replace(/_/g, ' ')}
                          </span>
                        </div>

                        <p className="text-2xs text-slate-500 line-clamp-2">
                          {env.details?.message || env.details?.isolation_model || 'Analysis worker provider'}
                        </p>

                        {env.details?.hint && (
                          <div className="p-2 rounded bg-slate-50 dark:bg-slate-800/60 text-2xs font-mono text-slate-600 dark:text-slate-400 border border-slate-200 dark:border-slate-800">
                            <strong>Hint:</strong> {env.details.hint}
                          </div>
                        )}
                      </div>

                      <div className="pt-2 border-t border-slate-100 dark:border-slate-800/80 flex items-center justify-between text-2xs text-slate-500">
                        <span>Type: {env.provider_type}</span>
                        <span>{env.details?.snapshot_rollback ? 'Snapshot Revert' : 'Disposable'}</span>
                      </div>
                    </div>
                  );
                })}
              </div>
            </div>

            {/* Platform-Specific Remediation & Enablement Guide */}
            <div className="p-5 rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 space-y-4">
              <h3 className="text-xs font-bold text-slate-900 dark:text-slate-100 uppercase tracking-wider font-mono flex items-center space-x-2">
                <Terminal className="w-4 h-4 text-cyan-500" />
                <span>Hypervisor Setup & Enablement Instructions</span>
              </h3>

              <div className="space-y-3 text-xs">
                {/* VMware Guide */}
                <details className="p-3 rounded-lg border border-slate-200 dark:border-slate-800 bg-slate-50/50 dark:bg-slate-800/30">
                  <summary className="font-semibold cursor-pointer text-slate-900 dark:text-slate-100">
                    VMware Workstation / ESXi: Enabling Nested VT-x/AMD-V
                  </summary>
                  <div className="mt-2 text-2xs space-y-1.5 text-slate-600 dark:text-slate-400">
                    <p>1. Shut down the TraceX Manager VM in VMware.</p>
                    <p>2. Open <strong>VM Settings</strong> -&gt; <strong>Processors</strong>.</p>
                    <p>3. Check: <code>Virtualize Intel VT-x/EPT or AMD-V/RVI</code> and <code>Virtualize IOMMU</code>.</p>
                    <p>4. Power on the VM. TraceX will immediately detect nested hardware acceleration.</p>
                  </div>
                </details>

                {/* VirtualBox Guide */}
                <details className="p-3 rounded-lg border border-slate-200 dark:border-slate-800 bg-slate-50/50 dark:bg-slate-800/30">
                  <summary className="font-semibold cursor-pointer text-slate-900 dark:text-slate-100">
                    Oracle VirtualBox: Enabling Nested Virtualization or Worker Sibling VMs
                  </summary>
                  <div className="mt-2 text-2xs space-y-1.5 text-slate-600 dark:text-slate-400">
                    <p>On the host machine, run via Command Prompt / PowerShell:</p>
                    <pre className="p-2 rounded bg-slate-900 text-slate-100 font-mono text-2xs overflow-x-auto">
                      "C:\Program Files\Oracle\VirtualBox\VBoxManage.exe" modifyvm "&lt;TraceX_VM_Name&gt;" --nested-hw-virt on
                    </pre>
                    <p>To create a disposable analysis worker VM:</p>
                    <pre className="p-2 rounded bg-slate-900 text-slate-100 font-mono text-2xs overflow-x-auto">
                      "C:\Program Files\Oracle\VirtualBox\VBoxManage.exe" createvm --name "TraceX-Worker-Win10" --register
                    </pre>
                  </div>
                </details>

                {/* Hyper-V Guide */}
                <details className="p-3 rounded-lg border border-slate-200 dark:border-slate-800 bg-slate-50/50 dark:bg-slate-800/30">
                  <summary className="font-semibold cursor-pointer text-slate-900 dark:text-slate-100">
                    Microsoft Hyper-V: Enabling Nested Virtualization
                  </summary>
                  <div className="mt-2 text-2xs space-y-1.5 text-slate-600 dark:text-slate-400">
                    <p>On the parent Hyper-V host, run PowerShell as Administrator:</p>
                    <pre className="p-2 rounded bg-slate-900 text-slate-100 font-mono text-2xs overflow-x-auto">
                      Set-VMProcessor -VMName "&lt;TraceX_Manager_VM&gt;" -ExposeVirtualizationExtensions $true
                    </pre>
                    <p>TraceX will automatically detect exposed virtualization upon VM startup.</p>
                  </div>
                </details>
              </div>
            </div>
          </div>
        )}
      </main>
    </div>
  );
};
export default DynamicAnalysisLabPage;
