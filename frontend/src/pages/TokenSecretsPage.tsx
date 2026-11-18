import React, { useState } from 'react';
import {
  KeyRound,
  Eye,
  EyeOff,
  ShieldAlert,
  Lock,
  Network,
  AlertTriangle,
  Search,
  CheckCircle2,
  Copy
} from 'lucide-react';
import { InvestigationDetail, SecretFinding } from '../types';
import { SeverityBadge } from '../components/SeverityBadge';
import { api } from '../api';

interface TokenSecretsPageProps {
  detail: InvestigationDetail;
}

export const TokenSecretsPage: React.FC<TokenSecretsPageProps> = ({ detail }) => {
  const [secrets, setSecrets] = useState<SecretFinding[]>(detail.secrets || []);
  const [search, setSearch] = useState('');
  const [unredactedMap, setUnredactedMap] = useState<Record<string, string>>({});
  const [loadingSecretId, setLoadingSecretId] = useState<string | null>(null);
  const [showConfirmModal, setShowConfirmModal] = useState<SecretFinding | null>(null);

  const filtered = secrets.filter(
    (s) =>
      s.token_category.toLowerCase().includes(search.toLowerCase()) ||
      s.rule_matched.toLowerCase().includes(search.toLowerCase()) ||
      s.source_location.toLowerCase().includes(search.toLowerCase())
  );

  const handleRevealClick = (sec: SecretFinding) => {
    if (unredactedMap[sec.id]) {
      // Toggle off
      const copy = { ...unredactedMap };
      delete copy[sec.id];
      setUnredactedMap(copy);
    } else {
      setShowConfirmModal(sec);
    }
  };

  const confirmUnredact = async () => {
    if (!showConfirmModal) return;
    const target = showConfirmModal;
    setShowConfirmModal(null);
    setLoadingSecretId(target.id);

    try {
      const res = await api.unredactSecret(detail.record.id, target.id);
      setUnredactedMap((prev) => ({ ...prev, [target.id]: res.raw_value }));
    } catch (err) {
      console.error(err);
    } finally {
      setLoadingSecretId(null);
    }
  };

  return (
    <div className="p-4 sm:p-6 md:p-8 space-y-6">
      {/* Header */}
      <div className="border-b border-app pb-4 flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <h1 className="text-xl md:text-2xl font-bold text-app-primary tracking-tight flex flex-wrap items-center gap-2.5">
            <span>Token & Secret Investigator</span>
            <span className="text-xs bg-surface text-sky-700 dark:text-sky-300 border border-app px-2.5 py-1 rounded-md font-mono font-medium">
              {secrets.length} Hardcoded Secrets Identified
            </span>
          </h1>
          <p className="text-xs md:text-sm text-app-secondary mt-1">
            API keys, Telegram bot tokens, AWS credentials, JWTs, and private keys extracted with false-positive reduction.
          </p>
        </div>

        {/* Redaction Notice */}
        <div className="flex items-center gap-2 bg-sky-50 dark:bg-sky-950/40 border border-sky-300 dark:border-sky-800 px-3 py-1.5 rounded-lg text-xs font-semibold text-sky-800 dark:text-sky-300 shrink-0 shadow-sm">
          <Lock className="w-4 h-4 text-sky-600 dark:text-sky-400" />
          <span>FORENSIC REDACTION ENFORCED BY DEFAULT</span>
        </div>
      </div>

      {/* Search Bar */}
      <div className="relative">
        <Search className="w-4 h-4 text-app-muted absolute left-3.5 top-3" />
        <input
          type="text"
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          placeholder="Filter secrets by category, rule name, or source file..."
          className="forensics-input pl-10 pr-4"
        />
      </div>

      {/* Secret Cards List */}
      {filtered.length === 0 ? (
        <div className="p-12 text-center text-app-muted border border-dashed border-app rounded-xl space-y-3 bg-surface">
          <KeyRound className="w-10 h-10 mx-auto text-app-muted" />
          <p className="text-xs md:text-sm font-medium">No hardcoded tokens or secrets detected in extracted strings.</p>
        </div>
      ) : (
        <div className="space-y-4">
          {filtered.map((sec, idx) => {
            const isRevealed = Boolean(unredactedMap[sec.id]);
            const displayValue = isRevealed ? unredactedMap[sec.id] : sec.redacted_value;

            return (
              <div
                key={idx}
                className="forensics-card p-5 space-y-3.5 rounded-xl hover:border-slate-400 dark:hover:border-[#303e54] transition-all"
              >
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2.5 border-b border-app pb-3">
                  <div className="flex flex-wrap items-center gap-2">
                    <span className="text-xs text-app-muted font-bold font-mono bg-surface px-2 py-0.5 rounded border border-app">
                      {sec.id}
                    </span>
                    <span className="text-xs text-sky-700 dark:text-sky-300 font-bold uppercase bg-sky-50 dark:bg-sky-950/60 border border-sky-300 dark:border-sky-800 px-2.5 py-0.5 rounded-md font-mono">
                      {sec.token_category}
                    </span>
                    <span className="text-sm font-bold text-app-primary">{sec.rule_matched}</span>
                  </div>

                  <div className="flex items-center gap-2 shrink-0">
                    {sec.in_network_path && (
                      <span className="text-[11px] bg-indigo-50 dark:bg-indigo-950/80 text-indigo-700 dark:text-indigo-300 border border-indigo-300 dark:border-indigo-800 px-2.5 py-1 rounded-md font-bold flex items-center gap-1.5">
                        <Network className="w-3.5 h-3.5 text-indigo-600 dark:text-indigo-400" />
                        NETWORK CODE PATH
                      </span>
                    )}
                    <SeverityBadge severity={sec.confidence} size="sm" />
                  </div>
                </div>

                {/* Token Value Display with Authorized Reveal */}
                <div className="bg-surface border border-app p-3.5 rounded-xl flex flex-col sm:flex-row sm:items-center justify-between gap-3">
                  <div className="flex items-center gap-2 font-mono text-xs overflow-x-auto min-w-0 flex-1">
                    <span className="text-app-muted select-none font-semibold">TOKEN:</span>
                    <span
                      className={`font-bold tracking-wider font-mono truncate ${
                        isRevealed
                          ? 'text-amber-700 dark:text-amber-400 bg-amber-50 dark:bg-amber-950/50 px-2.5 py-1 rounded border border-amber-300 dark:border-amber-800'
                          : 'text-app-primary'
                      }`}
                    >
                      {displayValue}
                    </span>
                  </div>

                  <div className="flex items-center gap-2 shrink-0">
                    <button
                      onClick={() => handleRevealClick(sec)}
                      className={`text-xs px-3.5 py-1.5 rounded-lg font-bold flex items-center gap-1.5 transition-all cursor-pointer shadow-sm ${
                        isRevealed
                          ? 'bg-slate-200 hover:bg-slate-300 dark:bg-slate-800 dark:hover:bg-slate-700 text-slate-800 dark:text-slate-200 border border-slate-300 dark:border-slate-700'
                          : 'bg-cyan-600 hover:bg-cyan-700 dark:bg-cyan-600 dark:hover:bg-cyan-500 text-white'
                      }`}
                    >
                      {isRevealed ? (
                        <>
                          <EyeOff className="w-3.5 h-3.5" />
                          <span>HIDE VALUE</span>
                        </>
                      ) : (
                        <>
                          <Eye className="w-3.5 h-3.5" />
                          <span>REVEAL (AUTHORIZED)</span>
                        </>
                      )}
                    </button>
                  </div>
                </div>

                {/* Evidence Context */}
                <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-xs bg-surface p-3.5 rounded-lg border border-app">
                  <div>
                    <span className="text-[11px] text-app-muted uppercase font-semibold block">Location in Artifact</span>
                    <p className="text-app-primary font-mono text-xs truncate mt-0.5">{sec.source_location}</p>
                    {sec.related_indicator && (
                      <p className="text-xs text-cyan-600 dark:text-cyan-400 mt-1 font-mono">Target Service: {sec.related_indicator}</p>
                    )}
                  </div>
                  <div>
                    <span className="text-[11px] text-app-muted uppercase font-semibold block">Verification Heuristic</span>
                    <p className="text-app-secondary text-xs mt-0.5">{sec.verification_status}</p>
                  </div>
                </div>

                {sec.context_snippet && (
                  <div className="text-xs text-app-secondary font-mono bg-surface p-2.5 rounded-lg border border-app truncate">
                    <span className="text-app-muted select-none">// Code Context: </span>
                    {sec.context_snippet}
                  </div>
                )}
              </div>
            );
          })}
        </div>
      )}

      {/* Confirmation Modal for Unredacting Secret */}
      {showConfirmModal && (
        <div className="fixed inset-0 bg-black/60 backdrop-blur-sm z-50 flex items-center justify-center p-4">
          <div className="forensics-card border-cyan-600/50 rounded-2xl p-6 max-w-md w-full space-y-4 shadow-2xl text-xs">
            <div className="flex items-center gap-2.5 text-cyan-700 dark:text-cyan-400 font-bold text-sm">
              <ShieldAlert className="w-5 h-5 text-amber-500 shrink-0" />
              <span>Authorized Evidence Access Confirmation</span>
            </div>

            <p className="text-app-secondary text-xs leading-relaxed">
              You are requesting to reveal the raw unredacted credential for detection{' '}
              <span className="text-app-primary font-bold font-mono">{showConfirmModal.id}</span> ({showConfirmModal.token_category}).
            </p>

            <div className="bg-surface p-3.5 rounded-xl border border-app text-xs text-app-muted space-y-1.5 font-medium">
              <p>• Do not attempt to authenticate against external services using this token.</p>
              <p>• Never submit extracted credentials to public AI or search engines.</p>
              <p>• Value is logged exclusively to local encrypted investigation records.</p>
            </div>

            <div className="flex items-center justify-end gap-3 pt-2">
              <button
                onClick={() => setShowConfirmModal(null)}
                className="px-4 py-2 rounded-lg bg-surface hover:bg-slate-200 dark:hover:bg-slate-800 text-app-secondary border border-app font-semibold cursor-pointer transition-colors"
              >
                Cancel
              </button>
              <button
                onClick={confirmUnredact}
                className="px-4 py-2 rounded-lg bg-cyan-600 hover:bg-cyan-700 dark:bg-cyan-600 dark:hover:bg-cyan-500 text-white font-bold cursor-pointer transition-colors shadow-sm"
              >
                Confirm & Reveal
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
