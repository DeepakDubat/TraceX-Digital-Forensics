import React, { useState } from 'react';
import {
  ShieldCheck,
  Globe,
  Radio,
  CheckCircle2,
  AlertTriangle,
  X,
  Lock,
  ArrowRight,
  RefreshCw,
  Server
} from 'lucide-react';
import { api } from '../api';

interface NetworkPrivacyModalProps {
  isOpen: boolean;
  currentMode: 'LOCAL_ONLY' | 'HYBRID';
  onClose: () => void;
  onModeChanged: (newMode: 'LOCAL_ONLY' | 'HYBRID') => void;
}

export const NetworkPrivacyModal: React.FC<NetworkPrivacyModalProps> = ({
  isOpen,
  currentMode,
  onClose,
  onModeChanged,
}) => {
  const [showHybridConfirm, setShowHybridConfirm] = useState(false);
  const [isLoading, setIsLoading] = useState(false);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  const [successMessage, setSuccessMessage] = useState<string | null>(null);

  if (!isOpen) return null;

  const handleSelectLocalOnly = async () => {
    if (currentMode === 'LOCAL_ONLY') return;
    setIsLoading(true);
    setErrorMessage(null);
    setSuccessMessage(null);
    try {
      const res = await api.setNetworkMode('LOCAL_ONLY');
      setSuccessMessage('Local-Only Mode enabled. Outbound network requests are now blocked.');
      onModeChanged('LOCAL_ONLY');
      setTimeout(() => {
        onClose();
        setSuccessMessage(null);
      }, 1000);
    } catch (err: any) {
      setErrorMessage(err.message || 'Failed to enable Local-Only mode.');
    } finally {
      setIsLoading(false);
    }
  };

  const handleInitiateHybrid = () => {
    if (currentMode === 'HYBRID') return;
    setErrorMessage(null);
    setShowHybridConfirm(true);
  };

  const handleConfirmHybrid = async () => {
    setIsLoading(true);
    setErrorMessage(null);
    setSuccessMessage(null);
    try {
      const res = await api.setNetworkMode('HYBRID');
      setSuccessMessage('Hybrid Mode enabled. Configured threat intelligence & OSINT services are now active.');
      setShowHybridConfirm(false);
      onModeChanged('HYBRID');
      setTimeout(() => {
        onClose();
        setSuccessMessage(null);
      }, 1000);
    } catch (err: any) {
      setErrorMessage(err.message || 'Failed to enable Hybrid mode.');
    } finally {
      setIsLoading(false);
    }
  };

  const handleCancelHybrid = () => {
    setShowHybridConfirm(false);
    setErrorMessage(null);
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/70 backdrop-blur-xs animate-in fade-in duration-200">
      <div
        className="bg-surface border border-app rounded-2xl shadow-2xl w-full max-w-3xl overflow-hidden flex flex-col max-h-[90vh]"
        role="dialog"
        aria-modal="true"
        aria-labelledby="network-privacy-title"
      >
        {/* Header */}
        <div className="flex items-center justify-between px-6 py-4 border-b border-app bg-surface-subtle">
          <div className="flex items-center gap-3">
            <div className="p-2 rounded-xl bg-cyan-500/10 text-cyan-600 dark:text-cyan-400 border border-cyan-500/20">
              <Radio className="w-5 h-5" />
            </div>
            <div>
              <h2 id="network-privacy-title" className="text-base font-bold font-mono text-app tracking-wide uppercase">
                Network Privacy & Connection Settings
              </h2>
              <p className="text-xs text-app-muted">
                Authoritative network connectivity and external intelligence gating
              </p>
            </div>
          </div>
          <button
            onClick={onClose}
            type="button"
            className="p-2 rounded-lg text-app-muted hover:text-app hover:bg-surface-subtle transition-colors cursor-pointer"
            aria-label="Close modal"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Modal Body */}
        <div className="p-6 overflow-y-auto space-y-6">
          {/* Status Banners */}
          {errorMessage && (
            <div className="p-3.5 rounded-xl bg-rose-50 border border-rose-200 text-rose-800 dark:bg-rose-950/60 dark:border-rose-900/60 dark:text-rose-300 text-xs font-mono flex items-center gap-2">
              <AlertTriangle className="w-4 h-4 shrink-0 text-rose-600" />
              <span>{errorMessage}</span>
            </div>
          )}

          {successMessage && (
            <div className="p-3.5 rounded-xl bg-emerald-50 border border-emerald-200 text-emerald-800 dark:bg-emerald-950/60 dark:border-emerald-900/60 dark:text-emerald-300 text-xs font-mono flex items-center gap-2">
              <CheckCircle2 className="w-4 h-4 shrink-0 text-emerald-600" />
              <span>{successMessage}</span>
            </div>
          )}

          {/* Mode Selection Cards Grid */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-5">
            {/* 1. LOCAL ONLY CARD */}
            <div
              className={`relative rounded-xl border p-5 flex flex-col justify-between transition-all ${
                currentMode === 'LOCAL_ONLY'
                  ? 'border-amber-500 bg-amber-500/5 shadow-md shadow-amber-500/10'
                  : 'border-app bg-surface hover:border-app-secondary'
              }`}
            >
              {currentMode === 'LOCAL_ONLY' && (
                <div className="absolute top-3 right-3 flex items-center gap-1.5 px-2.5 py-0.5 rounded-full bg-amber-500/20 text-amber-600 dark:text-amber-400 border border-amber-500/30 text-[10px] font-mono font-bold uppercase">
                  <CheckCircle2 className="w-3 h-3" />
                  CURRENT ACTIVE MODE
                </div>
              )}

              <div>
                <div className="flex items-center gap-2.5 mb-2">
                  <div className="p-2 rounded-lg bg-amber-500/10 text-amber-500 border border-amber-500/20">
                    <ShieldCheck className="w-5 h-5" />
                  </div>
                  <div>
                    <h3 className="font-mono font-bold text-sm text-app tracking-wide uppercase">
                      LOCAL ONLY
                    </h3>
                    <span className="text-[11px] text-app-muted font-mono">
                      Air-Gapped Privacy
                    </span>
                  </div>
                </div>

                <p className="text-xs text-app-secondary mb-4 leading-relaxed font-sans">
                  All forensic processing stays on the local computer.
                </p>

                <div className="space-y-2 mb-6">
                  <span className="text-[10px] font-mono font-bold text-app-muted uppercase tracking-wider block">
                    Features:
                  </span>
                  <ul className="text-xs space-y-1.5 text-app-secondary font-mono">
                    <li className="flex items-start gap-2">
                      <span className="text-amber-500 font-bold shrink-0">•</span>
                      <span>Offline static analysis.</span>
                    </li>
                    <li className="flex items-start gap-2">
                      <span className="text-amber-500 font-bold shrink-0">•</span>
                      <span>Local forensic tools.</span>
                    </li>
                    <li className="flex items-start gap-2">
                      <span className="text-amber-500 font-bold shrink-0">•</span>
                      <span>Local YARA scanning.</span>
                    </li>
                    <li className="flex items-start gap-2">
                      <span className="text-amber-500 font-bold shrink-0">•</span>
                      <span>Offline reports.</span>
                    </li>
                    <li className="flex items-start gap-2">
                      <span className="text-amber-500 font-bold shrink-0">•</span>
                      <span>External API requests blocked.</span>
                    </li>
                    <li className="flex items-start gap-2">
                      <span className="text-amber-500 font-bold shrink-0">•</span>
                      <span>No automatic cloud communication.</span>
                    </li>
                  </ul>
                </div>
              </div>

              <button
                type="button"
                onClick={handleSelectLocalOnly}
                disabled={currentMode === 'LOCAL_ONLY' || isLoading}
                className={`w-full py-2.5 px-4 rounded-lg font-mono text-xs font-bold transition-all flex items-center justify-center gap-2 cursor-pointer ${
                  currentMode === 'LOCAL_ONLY'
                    ? 'bg-amber-500/20 text-amber-700 dark:text-amber-300 border border-amber-500/40 cursor-default'
                    : 'bg-amber-600 hover:bg-amber-500 text-white shadow-sm hover:shadow focus:ring-2 focus:ring-amber-500/40'
                }`}
              >
                {isLoading && currentMode !== 'LOCAL_ONLY' ? (
                  <RefreshCw className="w-3.5 h-3.5 animate-spin" />
                ) : (
                  <Lock className="w-3.5 h-3.5" />
                )}
                <span>{currentMode === 'LOCAL_ONLY' ? 'ACTIVE (LOCAL ONLY)' : 'ENABLE LOCAL ONLY'}</span>
              </button>
            </div>

            {/* 2. HYBRID MODE CARD */}
            <div
              className={`relative rounded-xl border p-5 flex flex-col justify-between transition-all ${
                currentMode === 'HYBRID'
                  ? 'border-emerald-500 bg-emerald-500/5 shadow-md shadow-emerald-500/10'
                  : 'border-app bg-surface hover:border-app-secondary'
              }`}
            >
              {currentMode === 'HYBRID' && (
                <div className="absolute top-3 right-3 flex items-center gap-1.5 px-2.5 py-0.5 rounded-full bg-emerald-500/20 text-emerald-600 dark:text-emerald-400 border border-emerald-500/30 text-[10px] font-mono font-bold uppercase">
                  <CheckCircle2 className="w-3 h-3" />
                  CURRENT ACTIVE MODE
                </div>
              )}

              <div>
                <div className="flex items-center gap-2.5 mb-2">
                  <div className="p-2 rounded-lg bg-emerald-500/10 text-emerald-500 border border-emerald-500/20">
                    <Globe className="w-5 h-5" />
                  </div>
                  <div>
                    <h3 className="font-mono font-bold text-sm text-app tracking-wide uppercase">
                      HYBRID MODE
                    </h3>
                    <span className="text-[11px] text-app-muted font-mono">
                      Target Threat Intel
                    </span>
                  </div>
                </div>

                <p className="text-xs text-app-secondary mb-4 leading-relaxed font-sans">
                  Use local forensic processing together with explicitly configured online integrations.
                </p>

                <div className="space-y-2 mb-6">
                  <span className="text-[10px] font-mono font-bold text-app-muted uppercase tracking-wider block">
                    Features:
                  </span>
                  <ul className="text-xs space-y-1.5 text-app-secondary font-mono">
                    <li className="flex items-start gap-2">
                      <span className="text-emerald-500 font-bold shrink-0">•</span>
                      <span>Local static analysis remains enabled.</span>
                    </li>
                    <li className="flex items-start gap-2">
                      <span className="text-emerald-500 font-bold shrink-0">•</span>
                      <span>VirusTotal.</span>
                    </li>
                    <li className="flex items-start gap-2">
                      <span className="text-emerald-500 font-bold shrink-0">•</span>
                      <span>AlienVault OTX.</span>
                    </li>
                    <li className="flex items-start gap-2">
                      <span className="text-emerald-500 font-bold shrink-0">•</span>
                      <span>AbuseIPDB.</span>
                    </li>
                    <li className="flex items-start gap-2">
                      <span className="text-emerald-500 font-bold shrink-0">•</span>
                      <span>Shodan.</span>
                    </li>
                    <li className="flex items-start gap-2">
                      <span className="text-emerald-500 font-bold shrink-0">•</span>
                      <span>URLhaus.</span>
                    </li>
                    <li className="flex items-start gap-2">
                      <span className="text-emerald-500 font-bold shrink-0">•</span>
                      <span>Other configured OSINT and threat intelligence services.</span>
                    </li>
                  </ul>
                </div>
              </div>

              <button
                type="button"
                onClick={handleInitiateHybrid}
                disabled={currentMode === 'HYBRID' || isLoading}
                className={`w-full py-2.5 px-4 rounded-lg font-mono text-xs font-bold transition-all flex items-center justify-center gap-2 cursor-pointer ${
                  currentMode === 'HYBRID'
                    ? 'bg-emerald-500/20 text-emerald-700 dark:text-emerald-300 border border-emerald-500/40 cursor-default'
                    : 'bg-emerald-600 hover:bg-emerald-500 text-white shadow-sm hover:shadow focus:ring-2 focus:ring-emerald-500/40'
                }`}
              >
                {isLoading && currentMode !== 'HYBRID' ? (
                  <RefreshCw className="w-3.5 h-3.5 animate-spin" />
                ) : (
                  <Globe className="w-3.5 h-3.5" />
                )}
                <span>{currentMode === 'HYBRID' ? 'ACTIVE (HYBRID MODE)' : 'ENABLE HYBRID MODE'}</span>
              </button>
            </div>
          </div>

          {/* TASK 2: HYBRID MODE CONFIRMATION OVERLAY */}
          {showHybridConfirm && (
            <div className="p-5 rounded-xl bg-amber-50 border-2 border-amber-400 dark:bg-amber-950/70 dark:border-amber-600 space-y-4 animate-in slide-in-from-top-2 duration-200">
              <div className="flex items-start gap-3">
                <div className="p-2 rounded-lg bg-amber-500/20 text-amber-600 dark:text-amber-400 shrink-0">
                  <AlertTriangle className="w-5 h-5" />
                </div>
                <div>
                  <h4 className="text-sm font-bold font-mono text-amber-900 dark:text-amber-200 uppercase tracking-wide">
                    Confirm Enable Hybrid Mode
                  </h4>
                  <p className="text-xs text-amber-800 dark:text-amber-300 mt-1 leading-relaxed">
                    Hybrid Mode allows configured integrations to communicate with their external service providers. Original evidence files remain local unless you explicitly approve an upload.
                  </p>
                </div>
              </div>

              <div className="flex items-center justify-end gap-3 pt-2 border-t border-amber-300 dark:border-amber-800/60">
                <button
                  type="button"
                  onClick={handleCancelHybrid}
                  disabled={isLoading}
                  className="px-4 py-2 rounded-lg border border-amber-400 dark:border-amber-700 text-xs font-mono font-bold text-amber-900 dark:text-amber-200 hover:bg-amber-100 dark:hover:bg-amber-900/50 transition-colors cursor-pointer"
                >
                  CANCEL
                </button>
                <button
                  type="button"
                  onClick={handleConfirmHybrid}
                  disabled={isLoading}
                  className="px-4 py-2 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-white text-xs font-mono font-bold shadow-sm flex items-center gap-1.5 transition-colors cursor-pointer"
                >
                  {isLoading ? (
                    <RefreshCw className="w-3.5 h-3.5 animate-spin" />
                  ) : (
                    <CheckCircle2 className="w-3.5 h-3.5" />
                  )}
                  <span>ENABLE HYBRID MODE</span>
                </button>
              </div>
            </div>
          )}
        </div>

        {/* Footer */}
        <div className="px-6 py-3.5 border-t border-app bg-surface-subtle flex items-center justify-between text-xs text-app-muted font-mono">
          <div className="flex items-center gap-2">
            <Server className="w-3.5 h-3.5 text-cyan-500" />
            <span>TraceX Authoritative Mode Controller</span>
          </div>
          <button
            type="button"
            onClick={onClose}
            className="px-3 py-1.5 rounded-md hover:bg-surface border border-transparent hover:border-app text-app-secondary cursor-pointer"
          >
            Close
          </button>
        </div>
      </div>
    </div>
  );
};
