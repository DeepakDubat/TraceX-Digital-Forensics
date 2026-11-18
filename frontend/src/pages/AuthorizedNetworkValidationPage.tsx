import React, { useState, useEffect } from 'react';
import {
  ShieldCheck,
  ShieldAlert,
  AlertTriangle,
  Play,
  RotateCcw,
  CheckCircle2,
  XCircle,
  Clock,
  Lock,
  Globe,
  Radio,
  PowerOff,
  Terminal,
  FileCheck,
  AlertOctagon,
  Search,
  ExternalLink,
  Info
} from 'lucide-react';
import { api } from '../api';
import {
  InvestigationDetail,
  AuthorizedNetworkScope,
  ActiveValidationResult
} from '../types';

interface AuthorizedNetworkValidationPageProps {
  detail: InvestigationDetail;
}

export const AuthorizedNetworkValidationPage: React.FC<AuthorizedNetworkValidationPageProps> = ({ detail }) => {
  const invId = detail.record.id;

  // Scopes and validation results
  const [scopes, setScopes] = useState<AuthorizedNetworkScope[]>([]);
  const [results, setResults] = useState<ActiveValidationResult[]>([]);
  const [loading, setLoading] = useState(false);
  const [killSwitchActive, setKillSwitchActive] = useState(false);
  const [isLocalOnly, setIsLocalOnly] = useState(detail.record.local_only_mode || false);

  // New scope form state
  const [showCreateModal, setShowCreateModal] = useState(false);
  const [targetInput, setTargetInput] = useState('');
  const [selectedTests, setSelectedTests] = useState<string[]>(['DNS', 'TCP_CONNECT', 'TLS_INSPECT', 'HTTPS_HEAD']);
  const [portsInput, setPortsInput] = useState('80, 443');
  const [authNote, setAuthNote] = useState('');
  const [operatorName, setOperatorName] = useState(detail.record.investigator_name || 'Lead Examiner');
  const [operatorConfirmed, setOperatorConfirmed] = useState(false);
  const [requestBudget, setRequestBudget] = useState(20);
  const [durationHours, setDurationHours] = useState(24);
  const [creatingScope, setCreatingScope] = useState(false);
  const [formError, setFormError] = useState<string | null>(null);

  // Validation execution state
  const [activeScopeId, setActiveScopeId] = useState<string>('');
  const [selectedTarget, setSelectedTarget] = useState<string>('');
  const [executingTest, setExecutingTest] = useState<string | null>(null);
  const [execPort, setExecPort] = useState<number>(443);
  const [executionMessage, setExecutionMessage] = useState<string | null>(null);

  // Load scopes, results, and kill switch status
  const loadData = async () => {
    setLoading(true);
    try {
      const [scopesRes, resultsRes, killRes] = await Promise.all([
        api.getNetworkScopes(invId).catch(() => []),
        api.getValidationResults(invId).catch(() => []),
        api.getKillSwitchStatus().catch(() => ({ kill_switch_active: false, local_only_mode: false }))
      ]);
      setScopes(scopesRes);
      setResults(resultsRes);
      setKillSwitchActive(killRes.kill_switch_active);
      setIsLocalOnly(killRes.local_only_mode);

      if (scopesRes.length > 0 && !activeScopeId) {
        // Pick first unrevoked scope
        const valid = scopesRes.find(s => !s.is_revoked);
        if (valid) {
          setActiveScopeId(valid.id);
          if (valid.authorized_targets.length > 0) {
            setSelectedTarget(valid.authorized_targets[0]);
          }
        }
      }
    } catch (err) {
      console.error('Failed to load network validation data:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadData();
  }, [invId]);

  const handleToggleKillSwitch = async () => {
    const newState = !killSwitchActive;
    try {
      await api.updateKillSwitch(newState, `Manual operator override from Case ${detail.record.case_reference || invId}`);
      setKillSwitchActive(newState);
    } catch (err: any) {
      alert(`Kill switch update failed: ${err.message}`);
    }
  };

  const handleCreateScope = async (e: React.FormEvent) => {
    e.preventDefault();
    setFormError(null);

    const targets = targetInput
      .split('\n')
      .map(t => t.trim())
      .filter(t => t.length > 0);

    if (targets.length === 0) {
      setFormError('At least one authorized target domain or public IP is required.');
      return;
    }
    if (!operatorConfirmed) {
      setFormError('Explicit operator confirmation checkbox is required by forensic safety policy.');
      return;
    }
    if (!authNote || authNote.length < 5) {
      setFormError('An authorization justification note of at least 5 characters is required.');
      return;
    }

    const ports = portsInput
      .split(',')
      .map(p => parseInt(p.trim(), 10))
      .filter(p => !isNaN(p) && p > 0 && p <= 65535);

    setCreatingScope(true);
    try {
      const newScope = await api.createNetworkScope({
        investigation_id: invId,
        case_id: detail.record.case_reference || invId,
        authorized_targets: targets,
        allowed_test_types: selectedTests,
        allowed_ports: ports.length > 0 ? ports : [80, 443],
        authorization_note: authNote,
        operator_name: operatorName,
        operator_confirmed: operatorConfirmed,
        request_budget: requestBudget,
        duration_hours: durationHours
      });

      setShowCreateModal(false);
      setTargetInput('');
      setAuthNote('');
      setOperatorConfirmed(false);
      await loadData();
      setActiveScopeId(newScope.id);
      if (newScope.authorized_targets.length > 0) {
        setSelectedTarget(newScope.authorized_targets[0]);
      }
    } catch (err: any) {
      setFormError(err.message || 'Failed to create authorization scope.');
    } finally {
      setCreatingScope(false);
    }
  };

  const handleRevokeScope = async (scopeId: string) => {
    if (!confirm(`Are you sure you want to permanently revoke authorization scope ${scopeId}? All further active checks will be rejected.`)) {
      return;
    }
    try {
      await api.revokeNetworkScope(scopeId);
      await loadData();
    } catch (err: any) {
      alert(`Scope revocation failed: ${err.message}`);
    }
  };

  const handleRunValidation = async (testType: string) => {
    if (!activeScopeId || !selectedTarget) {
      alert('Please select an active scope and target.');
      return;
    }
    if (killSwitchActive) {
      alert('Active validation blocked: Global external-request kill switch is ACTIVE.');
      return;
    }
    if (isLocalOnly) {
      alert('Active validation blocked: Investigation is in Local-Only Mode.');
      return;
    }

    setExecutingTest(testType);
    setExecutionMessage(null);
    try {
      const res = await api.executeNetworkValidation({
        scope_id: activeScopeId,
        investigation_id: invId,
        target: selectedTarget,
        test_type: testType,
        port: execPort
      });
      setExecutionMessage(`Validation finished: ${res.status} (${res.timing_ms.toFixed(1)}ms). ${res.diagnostic_message || ''}`);
      await loadData();
    } catch (err: any) {
      setExecutionMessage(`Check failed: ${err.message}`);
    } finally {
      setExecutingTest(null);
    }
  };

  const currentScope = scopes.find(s => s.id === activeScopeId);

  return (
    <div className="p-4 sm:p-6 md:p-8 space-y-6 max-w-7xl mx-auto">
      {/* Top Banner & Title */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-app pb-4">
        <div>
          <div className="flex items-center gap-3">
            <div className="p-2.5 rounded-xl bg-cyan-500/10 text-cyan-600 dark:text-cyan-400 border border-cyan-500/20">
              <ShieldCheck className="w-6 h-6" />
            </div>
            <div>
              <h1 className="text-xl md:text-2xl font-bold text-app-primary tracking-tight flex items-center gap-2">
                Authorized Network Validation
                <span className="text-xs px-2.5 py-0.5 rounded-full font-semibold uppercase bg-amber-500/10 text-amber-700 dark:text-amber-400 border border-amber-500/30">
                  Strict Authorization Required
                </span>
              </h1>
              <p className="text-xs md:text-sm text-app-secondary mt-0.5">
                Low-impact active verification (DNS, TCP, TLS inspection, HTTPS HEAD) strictly restricted to approved targets with SSRF and DNS-rebinding protections.
              </p>
            </div>
          </div>
        </div>

        {/* Global Kill Switch & Controls */}
        <div className="flex items-center gap-3">
          <button
            onClick={handleToggleKillSwitch}
            className={`px-3 py-1.5 rounded-xl font-bold text-xs flex items-center gap-2 border transition-all cursor-pointer ${
              killSwitchActive
                ? 'bg-rose-600 text-white border-rose-700 shadow-md animate-pulse'
                : 'bg-surface text-app-secondary border-app hover:border-rose-500/50 hover:text-rose-600'
            }`}
            title={killSwitchActive ? 'Click to Disengage Kill Switch' : 'Click to Emergency Cut-off All External Requests'}
          >
            <PowerOff className="w-4 h-4" />
            {killSwitchActive ? 'KILL SWITCH ENGAGED' : 'Kill Switch Disarmed'}
          </button>

          <button
            onClick={() => setShowCreateModal(true)}
            className="px-4 py-1.5 rounded-xl font-bold text-xs bg-cyan-600 text-white hover:bg-cyan-500 shadow-sm transition-all cursor-pointer flex items-center gap-2"
          >
            <ShieldCheck className="w-4 h-4" />
            Create Scope Record
          </button>
        </div>
      </div>

      {/* Safety Notice Banner */}
      <div className={`p-4 rounded-xl border flex items-start gap-3 text-xs leading-relaxed ${
        killSwitchActive
          ? 'bg-rose-50 dark:bg-rose-950/40 border-rose-300 dark:border-rose-800 text-rose-800 dark:text-rose-300'
          : isLocalOnly
          ? 'bg-amber-50 dark:bg-amber-950/40 border-amber-300 dark:border-amber-800 text-amber-800 dark:text-amber-300'
          : 'bg-cyan-50/50 dark:bg-cyan-950/30 border-cyan-200 dark:border-cyan-800/50 text-app-secondary'
      }`}>
        <AlertOctagon className="w-5 h-5 shrink-0 text-current mt-0.5" />
        <div className="space-y-1">
          <p className="font-semibold text-app-primary">
            {killSwitchActive
              ? 'EMERGENCY KILL SWITCH ENGAGED: All external network requests are strictly halted.'
              : isLocalOnly
              ? 'LOCAL-ONLY ENFORCEMENT: Target communication and external DNS are blocked by investigation policy.'
              : 'Strict Target Scope Boundary & Forensic Audit Enforcement'}
          </p>
          <p>
            Under no circumstances does this module perform broad vulnerability scans, web crawling, brute forcing, or follow HTTP redirects.
            All checks require explicit operator confirmation, predefined request quotas, and are blocked against RFC 1918 private IP ranges, loopback addresses, and cloud metadata endpoints (169.254.169.254).
          </p>
        </div>
      </div>

      {/* Main Grid: Scope Selector + Test Execution Panel */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Left Column: Scope Information & Target Selector */}
        <div className="lg:col-span-1 space-y-4">
          <div className="bg-surface border border-app rounded-2xl p-5 shadow-xs space-y-4">
            <div className="flex items-center justify-between border-b border-app pb-3">
              <h2 className="text-sm font-bold text-app-primary flex items-center gap-2">
                <FileCheck className="w-4 h-4 text-cyan-600 dark:text-cyan-400" />
                Active Scope Records ({scopes.length})
              </h2>
              <button
                onClick={loadData}
                className="text-xs text-app-secondary hover:text-cyan-600 transition-colors cursor-pointer"
                title="Refresh"
              >
                <RotateCcw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
              </button>
            </div>

            {scopes.length === 0 ? (
              <div className="text-center py-6 text-app-secondary text-xs">
                <ShieldAlert className="w-8 h-8 mx-auto text-amber-500 mb-2 opacity-60" />
                No authorized scopes recorded yet.
                <br />
                Create a scope record to validate explicit targets.
              </div>
            ) : (
              <div className="space-y-3">
                <label className="text-xs font-semibold text-app-secondary uppercase tracking-wider block">
                  Select Scope
                </label>
                <select
                  value={activeScopeId}
                  onChange={(e) => {
                    setActiveScopeId(e.target.value);
                    const chosen = scopes.find(s => s.id === e.target.value);
                    if (chosen && chosen.authorized_targets.length > 0) {
                      setSelectedTarget(chosen.authorized_targets[0]);
                    }
                  }}
                  className="w-full bg-app border border-app rounded-xl px-3 py-2 text-xs text-app-primary focus:outline-hidden focus:border-cyan-500"
                >
                  {scopes.map(s => (
                    <option key={s.id} value={s.id}>
                      {s.id} {s.is_revoked ? '[REVOKED]' : `(${s.requests_used}/${s.request_budget} reqs)`}
                    </option>
                  ))}
                </select>

                {currentScope && (
                  <div className="p-3 bg-app rounded-xl border border-app space-y-2 text-xs">
                    <div className="flex justify-between items-center">
                      <span className="text-app-secondary">Operator:</span>
                      <span className="font-semibold text-app-primary">{currentScope.operator_name}</span>
                    </div>
                    <div className="flex justify-between items-center">
                      <span className="text-app-secondary">Expires:</span>
                      <span className="font-mono text-app-primary">
                        {new Date(currentScope.expires_at_utc).toLocaleString()}
                      </span>
                    </div>
                    <div className="flex justify-between items-center">
                      <span className="text-app-secondary">Budget:</span>
                      <span className="font-mono text-cyan-600 dark:text-cyan-400 font-bold">
                        {currentScope.requests_used} / {currentScope.request_budget} used
                      </span>
                    </div>
                    <div className="flex justify-between items-center">
                      <span className="text-app-secondary">Status:</span>
                      <span className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase ${
                        currentScope.is_revoked
                          ? 'bg-rose-100 text-rose-800 dark:bg-rose-950 dark:text-rose-300'
                          : 'bg-emerald-100 text-emerald-800 dark:bg-emerald-950 dark:text-emerald-300'
                      }`}>
                        {currentScope.is_revoked ? 'REVOKED' : 'ACTIVE'}
                      </span>
                    </div>
                    <div className="pt-2 border-t border-app">
                      <span className="text-app-secondary block text-[11px] mb-1">Authorization Note:</span>
                      <p className="italic text-app-primary bg-surface p-2 rounded-lg border border-app">
                        "{currentScope.authorization_note}"
                      </p>
                    </div>

                    {!currentScope.is_revoked && (
                      <button
                        onClick={() => handleRevokeScope(currentScope.id)}
                        className="w-full mt-2 py-1.5 text-xs text-rose-600 hover:text-white hover:bg-rose-600 rounded-lg border border-rose-300 dark:border-rose-900 transition-colors font-semibold cursor-pointer"
                      >
                        Revoke This Scope
                      </button>
                    )}
                  </div>
                )}
              </div>
            )}
          </div>
        </div>

        {/* Right Column: Target Validation Actions */}
        <div className="lg:col-span-2 space-y-4">
          <div className="bg-surface border border-app rounded-2xl p-5 shadow-xs space-y-5">
            <div className="border-b border-app pb-3">
              <h2 className="text-sm font-bold text-app-primary flex items-center gap-2">
                <Radio className="w-4 h-4 text-cyan-600 dark:text-cyan-400" />
                Execute Low-Impact Verification
              </h2>
              <p className="text-xs text-app-secondary mt-0.5">
                Select an approved target from the current scope and run an isolated network check.
              </p>
            </div>

            {currentScope && !currentScope.is_revoked ? (
              <div className="space-y-4">
                {/* Target & Port Selector */}
                <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
                  <div className="sm:col-span-2 space-y-1">
                    <label className="text-xs font-semibold text-app-secondary">Target from Allowlist</label>
                    <select
                      value={selectedTarget}
                      onChange={(e) => setSelectedTarget(e.target.value)}
                      className="w-full bg-app border border-app rounded-xl px-3 py-2 text-xs font-mono text-app-primary focus:outline-hidden focus:border-cyan-500"
                    >
                      {currentScope.authorized_targets.map(t => (
                        <option key={t} value={t}>{t}</option>
                      ))}
                    </select>
                  </div>

                  <div className="space-y-1">
                    <label className="text-xs font-semibold text-app-secondary">Port</label>
                    <select
                      value={execPort}
                      onChange={(e) => setExecPort(parseInt(e.target.value, 10))}
                      className="w-full bg-app border border-app rounded-xl px-3 py-2 text-xs font-mono text-app-primary focus:outline-hidden focus:border-cyan-500"
                    >
                      {currentScope.allowed_ports.map(p => (
                        <option key={p} value={p}>{p}</option>
                      ))}
                    </select>
                  </div>
                </div>

                {/* Action Buttons */}
                <div className="grid grid-cols-2 sm:grid-cols-4 gap-2.5 pt-2">
                  <button
                    onClick={() => handleRunValidation('DNS')}
                    disabled={executingTest !== null || killSwitchActive}
                    className="p-3 rounded-xl border border-app bg-app hover:border-cyan-500 hover:bg-cyan-500/5 transition-all text-left space-y-1 cursor-pointer disabled:opacity-50"
                  >
                    <div className="text-xs font-bold text-app-primary flex items-center justify-between">
                      <span>DNS Query</span>
                      {executingTest === 'DNS' && <RotateCcw className="w-3.5 h-3.5 animate-spin text-cyan-600" />}
                    </div>
                    <p className="text-[11px] text-app-secondary leading-tight">Resolve A/AAAA with SSRF filter.</p>
                  </button>

                  <button
                    onClick={() => handleRunValidation('TCP_CONNECT')}
                    disabled={executingTest !== null || killSwitchActive}
                    className="p-3 rounded-xl border border-app bg-app hover:border-cyan-500 hover:bg-cyan-500/5 transition-all text-left space-y-1 cursor-pointer disabled:opacity-50"
                  >
                    <div className="text-xs font-bold text-app-primary flex items-center justify-between">
                      <span>TCP Connect</span>
                      {executingTest === 'TCP_CONNECT' && <RotateCcw className="w-3.5 h-3.5 animate-spin text-cyan-600" />}
                    </div>
                    <p className="text-[11px] text-app-secondary leading-tight">Handshake & RTT timing (Port {execPort}).</p>
                  </button>

                  <button
                    onClick={() => handleRunValidation('TLS_INSPECT')}
                    disabled={executingTest !== null || killSwitchActive}
                    className="p-3 rounded-xl border border-app bg-app hover:border-cyan-500 hover:bg-cyan-500/5 transition-all text-left space-y-1 cursor-pointer disabled:opacity-50"
                  >
                    <div className="text-xs font-bold text-app-primary flex items-center justify-between">
                      <span>TLS Inspect</span>
                      {executingTest === 'TLS_INSPECT' && <RotateCcw className="w-3.5 h-3.5 animate-spin text-cyan-600" />}
                    </div>
                    <p className="text-[11px] text-app-secondary leading-tight">Inspect cert subject, issuer, validity.</p>
                  </button>

                  <button
                    onClick={() => handleRunValidation('HTTPS_HEAD')}
                    disabled={executingTest !== null || killSwitchActive}
                    className="p-3 rounded-xl border border-app bg-app hover:border-cyan-500 hover:bg-cyan-500/5 transition-all text-left space-y-1 cursor-pointer disabled:opacity-50"
                  >
                    <div className="text-xs font-bold text-app-primary flex items-center justify-between">
                      <span>HTTPS HEAD</span>
                      {executingTest === 'HTTPS_HEAD' && <RotateCcw className="w-3.5 h-3.5 animate-spin text-cyan-600" />}
                    </div>
                    <p className="text-[11px] text-app-secondary leading-tight">Status & headers (no redirects followed).</p>
                  </button>
                </div>

                {executionMessage && (
                  <div className="p-3 rounded-xl bg-app border border-app text-xs font-mono text-cyan-700 dark:text-cyan-300">
                    {executionMessage}
                  </div>
                )}
              </div>
            ) : (
              <div className="p-6 text-center text-app-secondary text-xs">
                {currentScope?.is_revoked
                  ? 'Selected scope is revoked. Please select or create an active scope.'
                  : 'No valid scope active. Create a scope to begin low-impact validation.'}
              </div>
            )}
          </div>
        </div>
      </div>

      {/* Validation Results Audit Log Table */}
      <div className="bg-surface border border-app rounded-2xl p-5 shadow-xs space-y-4">
        <div className="flex items-center justify-between border-b border-app pb-3">
          <div>
            <h2 className="text-sm font-bold text-app-primary flex items-center gap-2">
              <Terminal className="w-4 h-4 text-cyan-600 dark:text-cyan-400" />
              Validation Audit Log & Results ({results.length})
            </h2>
            <p className="text-xs text-app-secondary mt-0.5">
              Auditable record of all active checks, RTT timings, resolved IPs, and scope verifications.
            </p>
          </div>
        </div>

        {results.length === 0 ? (
          <div className="text-center py-8 text-app-secondary text-xs">
            No network checks executed for this investigation yet.
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs border-collapse">
              <thead>
                <tr className="border-b border-app text-app-secondary font-semibold uppercase tracking-wider text-[11px]">
                  <th className="py-2.5 px-3">Timestamp (UTC)</th>
                  <th className="py-2.5 px-3">Target</th>
                  <th className="py-2.5 px-3">Test Type</th>
                  <th className="py-2.5 px-3">Status</th>
                  <th className="py-2.5 px-3">Resolved IPs / Port</th>
                  <th className="py-2.5 px-3">Timing (ms)</th>
                  <th className="py-2.5 px-3">Diagnostic Details</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-app font-mono">
                {results.map((r) => (
                  <tr key={r.id} className="hover:bg-app/50 transition-colors">
                    <td className="py-2.5 px-3 text-app-secondary whitespace-nowrap">
                      {new Date(r.timestamp_utc).toLocaleTimeString()}
                    </td>
                    <td className="py-2.5 px-3 font-semibold text-app-primary whitespace-nowrap">
                      {r.target}
                    </td>
                    <td className="py-2.5 px-3 text-app-secondary whitespace-nowrap">
                      <span className="px-2 py-0.5 rounded bg-surface border border-app font-bold text-[10px]">
                        {r.test_type}
                      </span>
                    </td>
                    <td className="py-2.5 px-3 whitespace-nowrap">
                      <span className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase ${
                        r.status === 'SUCCESS'
                          ? 'bg-emerald-100 text-emerald-800 dark:bg-emerald-950 dark:text-emerald-300'
                          : r.status.includes('BLOCKED')
                          ? 'bg-rose-100 text-rose-800 dark:bg-rose-950 dark:text-rose-300'
                          : 'bg-amber-100 text-amber-800 dark:bg-amber-950 dark:text-amber-300'
                      }`}>
                        {r.status}
                      </span>
                    </td>
                    <td className="py-2.5 px-3 text-app-secondary">
                      {r.resolved_ips && r.resolved_ips.length > 0 ? r.resolved_ips.join(', ') : '-'}
                      {r.port ? ` :${r.port}` : ''}
                    </td>
                    <td className="py-2.5 px-3 text-cyan-600 dark:text-cyan-400 whitespace-nowrap font-bold">
                      {r.timing_ms > 0 ? `${r.timing_ms.toFixed(1)} ms` : '-'}
                    </td>
                    <td className="py-2.5 px-3 text-app-secondary max-w-xs truncate" title={r.diagnostic_message || ''}>
                      {r.http_status ? `HTTP ${r.http_status} | ` : ''}
                      {r.tls_cert_info?.subject ? `CN=${r.tls_cert_info.subject.CN || ''} | ` : ''}
                      {r.diagnostic_message || 'OK'}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Scope Creation Modal */}
      {showCreateModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/60 backdrop-blur-xs">
          <div className="bg-surface border border-app rounded-2xl max-w-xl w-full p-6 shadow-2xl space-y-4 max-h-[90vh] overflow-y-auto">
            <div className="flex items-center justify-between border-b border-app pb-3">
              <h3 className="text-base font-bold text-app-primary flex items-center gap-2">
                <ShieldCheck className="w-5 h-5 text-cyan-600" />
                Create Authorized Investigation Scope
              </h3>
              <button
                onClick={() => setShowCreateModal(false)}
                className="text-app-secondary hover:text-app-primary text-sm font-bold cursor-pointer"
              >
                ✕
              </button>
            </div>

            {formError && (
              <div className="p-3 rounded-xl bg-rose-50 dark:bg-rose-950/50 border border-rose-300 dark:border-rose-800 text-rose-800 dark:text-rose-300 text-xs">
                {formError}
              </div>
            )}

            <form onSubmit={handleCreateScope} className="space-y-4 text-xs">
              <div className="space-y-1">
                <label className="font-semibold text-app-primary">
                  Authorized Domains or Public IPs (One per line) *
                </label>
                <textarea
                  rows={3}
                  value={targetInput}
                  onChange={(e) => setTargetInput(e.target.value)}
                  placeholder="e.g.&#10;api.example-threat.com&#10;93.184.216.34"
                  className="w-full bg-app border border-app rounded-xl p-3 font-mono text-app-primary focus:outline-hidden focus:border-cyan-500"
                  required
                />
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div className="space-y-1">
                  <label className="font-semibold text-app-primary">Operator Name *</label>
                  <input
                    type="text"
                    value={operatorName}
                    onChange={(e) => setOperatorName(e.target.value)}
                    className="w-full bg-app border border-app rounded-xl px-3 py-2 text-app-primary focus:outline-hidden focus:border-cyan-500"
                    required
                  />
                </div>
                <div className="space-y-1">
                  <label className="font-semibold text-app-primary">Allowed Ports (CSV)</label>
                  <input
                    type="text"
                    value={portsInput}
                    onChange={(e) => setPortsInput(e.target.value)}
                    className="w-full bg-app border border-app rounded-xl px-3 py-2 font-mono text-app-primary focus:outline-hidden focus:border-cyan-500"
                  />
                </div>
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div className="space-y-1">
                  <label className="font-semibold text-app-primary">Request Quota / Budget</label>
                  <input
                    type="number"
                    min={1}
                    max={100}
                    value={requestBudget}
                    onChange={(e) => setRequestBudget(parseInt(e.target.value, 10))}
                    className="w-full bg-app border border-app rounded-xl px-3 py-2 text-app-primary focus:outline-hidden focus:border-cyan-500"
                  />
                </div>
                <div className="space-y-1">
                  <label className="font-semibold text-app-primary">Expiration (Hours)</label>
                  <input
                    type="number"
                    min={1}
                    max={168}
                    value={durationHours}
                    onChange={(e) => setDurationHours(parseInt(e.target.value, 10))}
                    className="w-full bg-app border border-app rounded-xl px-3 py-2 text-app-primary focus:outline-hidden focus:border-cyan-500"
                  />
                </div>
              </div>

              <div className="space-y-1">
                <label className="font-semibold text-app-primary">Authorization Justification / Note *</label>
                <textarea
                  rows={2}
                  value={authNote}
                  onChange={(e) => setAuthNote(e.target.value)}
                  placeholder="e.g. Target authorized under warrant / engagement scope ref #2026-CYBER-09"
                  className="w-full bg-app border border-app rounded-xl p-3 text-app-primary focus:outline-hidden focus:border-cyan-500"
                  required
                />
              </div>

              <div className="p-3 bg-app rounded-xl border border-app flex items-start gap-2.5">
                <input
                  type="checkbox"
                  id="confirmScope"
                  checked={operatorConfirmed}
                  onChange={(e) => setOperatorConfirmed(e.target.checked)}
                  className="mt-0.5 rounded text-cyan-600 focus:ring-cyan-500 cursor-pointer"
                  required
                />
                <label htmlFor="confirmScope" className="text-[11px] text-app-secondary cursor-pointer leading-tight">
                  <strong className="text-app-primary">Forensic Authorization Attestation:</strong> I explicitly attest that these targets have been vetted and are legally authorized for low-impact forensic verification. Requests will never be directed against unapproved third parties.
                </label>
              </div>

              <div className="flex justify-end gap-3 pt-2">
                <button
                  type="button"
                  onClick={() => setShowCreateModal(false)}
                  className="px-4 py-2 rounded-xl border border-app text-app-secondary hover:text-app-primary text-xs font-semibold cursor-pointer"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={creatingScope || !operatorConfirmed}
                  className="px-5 py-2 rounded-xl bg-cyan-600 text-white font-bold text-xs hover:bg-cyan-500 transition-all cursor-pointer disabled:opacity-50"
                >
                  {creatingScope ? 'Recording...' : 'Authorize Scope'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
};
export default AuthorizedNetworkValidationPage;
