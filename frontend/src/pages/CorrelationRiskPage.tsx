import React, { useState, useEffect } from 'react';
import {
  GitMerge,
  ShieldCheck,
  AlertTriangle,
  RotateCcw,
  CheckCircle2,
  XCircle,
  HelpCircle,
  Info,
  Layers,
  ArrowRight,
  Award,
  Flame,
  FileCheck,
  Sparkles,
  Radio
} from 'lucide-react';
import { api } from '../api';
import {
  InvestigationDetail,
  StaticDynamicCorrelation,
  EvidenceRiskAssessment
} from '../types';

interface CorrelationRiskPageProps {
  detail: InvestigationDetail;
}

export const CorrelationRiskPage: React.FC<CorrelationRiskPageProps> = ({ detail }) => {
  const invId = detail.record.id;

  const [correlations, setCorrelations] = useState<StaticDynamicCorrelation[]>([]);
  const [riskAssessment, setRiskAssessment] = useState<EvidenceRiskAssessment | null>(null);
  const [loading, setLoading] = useState(false);
  const [correlating, setCorrelating] = useState(false);
  const [assessing, setAssessing] = useState(false);
  const [actionMessage, setActionMessage] = useState<string | null>(null);

  const loadData = async () => {
    setLoading(true);
    try {
      const [corrRes, riskRes] = await Promise.all([
        api.getCorrelations(invId).catch(() => []),
        api.getRiskAssessment(invId).catch(() => null)
      ]);
      setCorrelations(corrRes);
      setRiskAssessment(riskRes);
    } catch (err) {
      console.error('Failed to load correlation/risk data:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadData();
  }, [invId]);

  const handleRunCorrelation = async () => {
    setCorrelating(true);
    setActionMessage(null);
    try {
      const res = await api.triggerCorrelation(invId);
      setCorrelations(res);
      setActionMessage(`Correlated ${res.length} findings between static artifacts and runtime events.`);
      // Automatically refresh risk assessment after new correlations
      const updatedRisk = await api.triggerRiskAssessment(invId);
      setRiskAssessment(updatedRisk);
    } catch (err: any) {
      setActionMessage(`Correlation failed: ${err.message}`);
    } finally {
      setCorrelating(false);
    }
  };

  const handleRunRiskAssessment = async () => {
    setAssessing(true);
    setActionMessage(null);
    try {
      const res = await api.triggerRiskAssessment(invId);
      setRiskAssessment(res);
      setActionMessage(`Dimensional risk re-assessed: Score ${res.overall_risk_score.toFixed(1)}/10 (${res.severity}, ${res.confidence} confidence).`);
    } catch (err: any) {
      setActionMessage(`Risk assessment failed: ${err.message}`);
    } finally {
      setAssessing(false);
    }
  };

  return (
    <div className="p-4 sm:p-6 md:p-8 space-y-6 max-w-7xl mx-auto">
      {/* Top Banner */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-app pb-4">
        <div>
          <div className="flex items-center gap-3">
            <div className="p-2.5 rounded-xl bg-emerald-500/10 text-emerald-600 dark:text-emerald-400 border border-emerald-500/20">
              <GitMerge className="w-6 h-6" />
            </div>
            <div>
              <h1 className="text-xl md:text-2xl font-bold text-app-primary tracking-tight flex items-center gap-2">
                Static-Dynamic Correlation & Dimensional Risk
                <span className="text-xs px-2.5 py-0.5 rounded-full font-semibold uppercase bg-emerald-500/10 text-emerald-700 dark:text-emerald-300 border border-emerald-500/30">
                  Evidence-Backed
                </span>
              </h1>
              <p className="text-xs md:text-sm text-app-secondary mt-0.5">
                Multi-dimensional forensic evaluation joining static capabilities with observed runtime activity, alternative explanations, and explainable scoring.
              </p>
            </div>
          </div>
        </div>

        {/* Global Action Buttons */}
        <div className="flex items-center gap-2">
          <button
            onClick={handleRunCorrelation}
            disabled={correlating}
            className="px-3.5 py-1.5 rounded-xl bg-emerald-600 text-white font-bold text-xs hover:bg-emerald-500 transition-all flex items-center gap-2 cursor-pointer disabled:opacity-50"
          >
            <GitMerge className={`w-3.5 h-3.5 ${correlating ? 'animate-spin' : ''}`} />
            {correlating ? 'Correlating...' : 'Correlate Static & Dynamic'}
          </button>

          <button
            onClick={handleRunRiskAssessment}
            disabled={assessing}
            className="px-3.5 py-1.5 rounded-xl bg-cyan-600 text-white font-bold text-xs hover:bg-cyan-500 transition-all flex items-center gap-2 cursor-pointer disabled:opacity-50"
          >
            <Award className={`w-3.5 h-3.5 ${assessing ? 'animate-spin' : ''}`} />
            {assessing ? 'Evaluating...' : 'Assess Dimensional Risk'}
          </button>
        </div>
      </div>

      {actionMessage && (
        <div className="p-3 rounded-xl bg-app border border-app text-xs font-mono text-cyan-700 dark:text-cyan-300">
          {actionMessage}
        </div>
      )}

      {/* Dimensional Risk Scorecard */}
      {riskAssessment ? (
        <div className="bg-surface border border-app rounded-2xl p-6 shadow-xs space-y-6">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-app pb-4">
            <div>
              <h2 className="text-base font-bold text-app-primary flex items-center gap-2">
                <Flame className="w-5 h-5 text-amber-500" />
                Evidence-Corroborated Dimensional Risk Score
              </h2>
              <p className="text-xs text-app-secondary mt-0.5">
                Weighted across 6 distinct investigative axes. Avoids false certainty by strictly separating static potential from confirmed runtime actions.
              </p>
            </div>

            <div className="flex items-center gap-4">
              <div className="text-right">
                <div className="text-[11px] uppercase tracking-wider text-app-secondary font-semibold">Overall Verdict</div>
                <div className="flex items-center gap-2">
                  <span className={`text-xs px-2.5 py-0.5 rounded-full font-bold uppercase border ${
                    riskAssessment.severity === 'Critical'
                      ? 'bg-rose-100 text-rose-800 dark:bg-rose-950 dark:text-rose-300 border-rose-300 dark:border-rose-800'
                      : riskAssessment.severity === 'High'
                      ? 'bg-amber-100 text-amber-800 dark:bg-amber-950 dark:text-amber-300 border-amber-300 dark:border-amber-800'
                      : 'bg-emerald-100 text-emerald-800 dark:bg-emerald-950 dark:text-emerald-300 border-emerald-300 dark:border-emerald-800'
                  }`}>
                    {riskAssessment.severity}
                  </span>
                  <span className="text-xs px-2 py-0.5 rounded bg-surface border border-app font-mono font-bold text-app-secondary">
                    {riskAssessment.confidence} Conf.
                  </span>
                </div>
              </div>

              <div className="p-3 bg-app rounded-2xl border border-app text-center min-w-[80px]">
                <div className="text-2xl font-black text-app-primary font-mono">
                  {riskAssessment.overall_risk_score.toFixed(1)}
                </div>
                <div className="text-[10px] text-app-secondary uppercase font-semibold">out of 10</div>
              </div>
            </div>
          </div>

          {/* Dimensional Bar Meters */}
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4">
            {/* Dimension 1: Static Capability */}
            <div className="p-3.5 rounded-xl bg-app/50 border border-app space-y-2">
              <div className="flex justify-between items-center text-xs">
                <span className="font-semibold text-app-primary">Static Capability</span>
                <span className="font-mono font-bold text-cyan-600">{riskAssessment.static_capability_score.toFixed(1)} / 10</span>
              </div>
              <div className="w-full bg-surface rounded-full h-2 overflow-hidden border border-app">
                <div
                  className="bg-cyan-500 h-2 rounded-full transition-all"
                  style={{ width: `${(riskAssessment.static_capability_score / 10) * 100}%` }}
                />
              </div>
              <p className="text-[10px] text-app-secondary leading-tight">Hardcoded C2, tokens, reverse shells, dangerous imports.</p>
            </div>

            {/* Dimension 2: Observed Execution */}
            <div className="p-3.5 rounded-xl bg-app/50 border border-app space-y-2">
              <div className="flex justify-between items-center text-xs">
                <span className="font-semibold text-app-primary">Observed Execution</span>
                <span className="font-mono font-bold text-purple-600">{riskAssessment.observed_execution_score.toFixed(1)} / 10</span>
              </div>
              <div className="w-full bg-surface rounded-full h-2 overflow-hidden border border-app">
                <div
                  className="bg-purple-500 h-2 rounded-full transition-all"
                  style={{ width: `${(riskAssessment.observed_execution_score / 10) * 100}%` }}
                />
              </div>
              <p className="text-[10px] text-app-secondary leading-tight">Runtime process launches, registry mutations, dropped files.</p>
            </div>

            {/* Dimension 3: Observed Network */}
            <div className="p-3.5 rounded-xl bg-app/50 border border-app space-y-2">
              <div className="flex justify-between items-center text-xs">
                <span className="font-semibold text-app-primary">Observed Network</span>
                <span className="font-mono font-bold text-blue-600">{riskAssessment.observed_network_score.toFixed(1)} / 10</span>
              </div>
              <div className="w-full bg-surface rounded-full h-2 overflow-hidden border border-app">
                <div
                  className="bg-blue-500 h-2 rounded-full transition-all"
                  style={{ width: `${(riskAssessment.observed_network_score / 10) * 100}%` }}
                />
              </div>
              <p className="text-[10px] text-app-secondary leading-tight">DNS queries, TCP handshakes, TLS SNI negotiation.</p>
            </div>

            {/* Dimension 4: Protocol Interaction */}
            <div className="p-3.5 rounded-xl bg-app/50 border border-app space-y-2">
              <div className="flex justify-between items-center text-xs">
                <span className="font-semibold text-app-primary">Protocol Interaction</span>
                <span className="font-mono font-bold text-indigo-600">{riskAssessment.successful_protocol_interaction_score.toFixed(1)} / 10</span>
              </div>
              <div className="w-full bg-surface rounded-full h-2 overflow-hidden border border-app">
                <div
                  className="bg-indigo-500 h-2 rounded-full transition-all"
                  style={{ width: `${(riskAssessment.successful_protocol_interaction_score / 10) * 100}%` }}
                />
              </div>
              <p className="text-[10px] text-app-secondary leading-tight">Successful HTTP request-response or TLS handshake completion.</p>
            </div>

            {/* Dimension 5: Confirmed Transfer */}
            <div className="p-3.5 rounded-xl bg-app/50 border border-app space-y-2">
              <div className="flex justify-between items-center text-xs">
                <span className="font-semibold text-app-primary">Confirmed Data Transfer</span>
                <span className="font-mono font-bold text-rose-600">{riskAssessment.confirmed_data_transfer_score.toFixed(1)} / 10</span>
              </div>
              <div className="w-full bg-surface rounded-full h-2 overflow-hidden border border-app">
                <div
                  className="bg-rose-500 h-2 rounded-full transition-all"
                  style={{ width: `${(riskAssessment.confirmed_data_transfer_score / 10) * 100}%` }}
                />
              </div>
              <p className="text-[10px] text-app-secondary leading-tight">Verified byte exfiltration or C2 payload receipt (never inferred).</p>
            </div>

            {/* Dimension 6: Threat Intel */}
            <div className="p-3.5 rounded-xl bg-app/50 border border-app space-y-2">
              <div className="flex justify-between items-center text-xs">
                <span className="font-semibold text-app-primary">Threat Feed Reputation</span>
                <span className="font-mono font-bold text-amber-600">{riskAssessment.threat_intel_reputation_score.toFixed(1)} / 10</span>
              </div>
              <div className="w-full bg-surface rounded-full h-2 overflow-hidden border border-app">
                <div
                  className="bg-amber-500 h-2 rounded-full transition-all"
                  style={{ width: `${(riskAssessment.threat_intel_reputation_score / 10) * 100}%` }}
                />
              </div>
              <p className="text-[10px] text-app-secondary leading-tight">Reputation hits from VirusTotal, AbuseIPDB, URLhaus, OTX.</p>
            </div>
          </div>

          {/* Corroboration & Limitations Notes */}
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 text-xs pt-2">
            <div className="p-3 rounded-xl bg-app border border-app space-y-1.5">
              <span className="font-bold text-app-primary flex items-center gap-1.5 text-emerald-600 dark:text-emerald-400">
                <CheckCircle2 className="w-4 h-4" />
                Corroborating Evidence ({riskAssessment.corroboration_sources.length})
              </span>
              {riskAssessment.corroboration_sources.length === 0 ? (
                <p className="text-app-secondary italic">No corroborating cross-evidence recorded.</p>
              ) : (
                <ul className="list-disc list-inside space-y-0.5 text-app-secondary">
                  {riskAssessment.corroboration_sources.map((c, i) => (
                    <li key={i}>{c}</li>
                  ))}
                </ul>
              )}
            </div>

            <div className="p-3 rounded-xl bg-app border border-app space-y-1.5">
              <span className="font-bold text-app-primary flex items-center gap-1.5 text-amber-600 dark:text-amber-400">
                <AlertTriangle className="w-4 h-4" />
                Forensic Limitations & Missing Evidence ({riskAssessment.known_limitations.length})
              </span>
              {riskAssessment.known_limitations.length === 0 ? (
                <p className="text-app-secondary italic">No explicit limitations noted.</p>
              ) : (
                <ul className="list-disc list-inside space-y-0.5 text-app-secondary">
                  {riskAssessment.known_limitations.map((l, i) => (
                    <li key={i}>{l}</li>
                  ))}
                </ul>
              )}
            </div>
          </div>
        </div>
      ) : (
        <div className="p-8 text-center bg-surface border border-app rounded-2xl text-app-secondary text-xs space-y-2">
          <Award className="w-8 h-8 mx-auto text-cyan-600 opacity-60" />
          <p>No dimensional risk assessment computed yet for this investigation.</p>
          <button
            onClick={handleRunRiskAssessment}
            className="px-4 py-2 rounded-xl bg-cyan-600 text-white font-bold text-xs hover:bg-cyan-500 transition-all cursor-pointer"
          >
            Assess Dimensional Risk Now
          </button>
        </div>
      )}

      {/* Static-Dynamic Correlations Table */}
      <div className="bg-surface border border-app rounded-2xl p-6 shadow-xs space-y-4">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-app pb-3">
          <div>
            <h2 className="text-sm font-bold text-app-primary flex items-center gap-2">
              <GitMerge className="w-4 h-4 text-emerald-600 dark:text-emerald-400" />
              Joined Static-versus-Dynamic Correlations ({correlations.length})
            </h2>
            <p className="text-xs text-app-secondary mt-0.5">
              Verified intersections between static decompilation findings and runtime packet/event observations.
            </p>
          </div>
        </div>

        {correlations.length === 0 ? (
          <div className="text-center py-10 text-app-secondary text-xs">
            No static-dynamic correlations identified yet.
            <br />
            Click <strong className="text-app-primary">"Correlate Static & Dynamic"</strong> above to join extracted artifacts with runtime logs.
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs border-collapse">
              <thead>
                <tr className="border-b border-app text-app-secondary font-semibold uppercase tracking-wider text-[11px]">
                  <th className="py-2.5 px-3">Indicator / Target</th>
                  <th className="py-2.5 px-3">Correlation Method</th>
                  <th className="py-2.5 px-3">Confidence</th>
                  <th className="py-2.5 px-3">Traffic Type</th>
                  <th className="py-2.5 px-3">Runtime Evidence Summary</th>
                  <th className="py-2.5 px-3">Alternative Explanation</th>
                  <th className="py-2.5 px-3">Forensic Limitations</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-app font-mono text-[11px]">
                {correlations.map((c) => (
                  <tr key={c.id} className="hover:bg-app/50 transition-colors">
                    <td className="py-2.5 px-3 font-bold text-app-primary whitespace-nowrap">
                      {c.indicator_value}
                    </td>
                    <td className="py-2.5 px-3 text-app-secondary whitespace-nowrap">
                      <span className="px-2 py-0.5 rounded bg-surface border border-app font-bold text-[10px]">
                        {c.correlation_method}
                      </span>
                    </td>
                    <td className="py-2.5 px-3 whitespace-nowrap">
                      <span className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase ${
                        c.confidence === 'Confirmed'
                          ? 'bg-emerald-100 text-emerald-800 dark:bg-emerald-950 dark:text-emerald-300'
                          : c.confidence === 'High'
                          ? 'bg-cyan-100 text-cyan-800 dark:bg-cyan-950 dark:text-cyan-300'
                          : 'bg-amber-100 text-amber-800 dark:bg-amber-950 dark:text-amber-300'
                      }`}>
                        {c.confidence}
                      </span>
                    </td>
                    <td className="py-2.5 px-3 whitespace-nowrap">
                      <span className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase ${
                        c.is_simulated_event
                          ? 'bg-amber-100 text-amber-800 dark:bg-amber-950 dark:text-amber-300'
                          : 'bg-emerald-100 text-emerald-800 dark:bg-emerald-950 dark:text-emerald-300'
                      }`}>
                        {c.is_simulated_event ? 'SIMULATED' : 'LIVE'}
                      </span>
                    </td>
                    <td className="py-2.5 px-3 text-app-secondary max-w-xs truncate" title={c.supporting_event_summary}>
                      {c.packet_reference && <span className="font-bold text-purple-600 mr-1">[{c.packet_reference}]</span>}
                      {c.supporting_event_summary}
                    </td>
                    <td className="py-2.5 px-3 text-app-secondary max-w-xs truncate italic" title={c.alternative_explanation}>
                      {c.alternative_explanation || 'None'}
                    </td>
                    <td className="py-2.5 px-3 text-app-secondary max-w-xs truncate" title={c.limitations}>
                      {c.limitations || 'None'}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
};
export default CorrelationRiskPage;
