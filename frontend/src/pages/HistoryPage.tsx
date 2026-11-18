import React, { useState, useEffect } from 'react';
import {
  History,
  Search,
  Download,
  Trash2,
  GitCompare,
  FolderOpen,
  ArrowRight,
  RefreshCw,
  AlertOctagon,
  FileText
} from 'lucide-react';
import { InvestigationRecord } from '../types';
import { SeverityBadge } from '../components/SeverityBadge';
import { api } from '../api';

interface HistoryPageProps {
  onSelectInvestigation: (id: string) => void;
}

export const HistoryPage: React.FC<HistoryPageProps> = ({ onSelectInvestigation }) => {
  const [investigations, setInvestigations] = useState<InvestigationRecord[]>([]);
  const [search, setSearch] = useState('');
  const [loading, setLoading] = useState(true);
  const [deleteConfirmId, setDeleteConfirmId] = useState<string | null>(null);
  const [compareModalOpen, setCompareModalOpen] = useState(false);
  const [selectedForCompare, setSelectedForCompare] = useState<string[]>([]);
  const [comparisonResult, setComparisonResult] = useState<any | null>(null);

  const fetchInvestigations = async () => {
    setLoading(true);
    try {
      const data = await api.listInvestigations(search);
      setInvestigations(data);
    } catch (err) {
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchInvestigations();
  }, [search]);

  const handleDelete = async (id: string) => {
    try {
      await api.deleteInvestigation(id);
      setDeleteConfirmId(null);
      fetchInvestigations();
    } catch (err) {
      console.error('Delete failed', err);
    }
  };

  const toggleCompareSelect = (id: string) => {
    if (selectedForCompare.includes(id)) {
      setSelectedForCompare(selectedForCompare.filter((item) => item !== id));
    } else {
      if (selectedForCompare.length < 2) {
        setSelectedForCompare([...selectedForCompare, id]);
      } else {
        setSelectedForCompare([selectedForCompare[1], id]);
      }
    }
  };

  const runCompare = async () => {
    if (selectedForCompare.length !== 2) return;
    try {
      const res = await api.compareInvestigations(selectedForCompare[0], selectedForCompare[1]);
      setComparisonResult(res);
      setCompareModalOpen(true);
    } catch (err) {
      console.error(err);
    }
  };

  return (
    <div className="p-6 md:p-8 space-y-6">
      {/* Header */}
      <div className="border-b border-app pb-5 flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold text-app-primary tracking-tight flex items-center gap-3">
            <span>Historical Investigation Registry</span>
            <span className="text-xs bg-surface text-cyan-600 dark:text-cyan-400 border border-app px-2.5 py-1 rounded-md font-mono font-medium">
              {investigations.length} CASES LOGGED
            </span>
          </h1>
          <p className="text-sm text-app-secondary mt-1">
            Search, reopen, compare artifacts, and manage chain-of-custody records.
          </p>
        </div>

        {selectedForCompare.length === 2 && (
          <button
            onClick={runCompare}
            className="bg-indigo-600 hover:bg-indigo-500 text-white text-xs px-3.5 py-2 rounded-lg font-bold flex items-center gap-1.5 transition-all shadow-sm cursor-pointer font-mono"
          >
            <GitCompare className="w-3.5 h-3.5" />
            <span>COMPARE SELECTED (2) CASES</span>
          </button>
        )}
      </div>

      {/* Search Input */}
      <div className="relative">
        <Search className="w-4 h-4 text-app-muted absolute left-3 top-3" />
        <input
          type="text"
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          placeholder="Search by filename, package name, SHA-256 hash, docket/case reference..."
          className="forensics-input w-full pl-9 pr-4 py-2 text-sm"
        />
      </div>

      {/* Investigations Table */}
      <div className="forensics-card overflow-hidden">
        {loading ? (
          <div className="p-12 text-center text-app-secondary text-sm flex items-center justify-center gap-2">
            <RefreshCw className="w-4 h-4 animate-spin text-cyan-600 dark:text-cyan-400" />
            <span>Querying case records from SQLite database...</span>
          </div>
        ) : investigations.length === 0 ? (
          <div className="p-12 text-center text-app-muted space-y-2">
            <FolderOpen className="w-8 h-8 mx-auto text-app-muted" />
            <p className="text-sm font-medium">No matching investigation records found.</p>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="forensics-table">
              <thead>
                <tr>
                  <th className="w-10">CMP</th>
                  <th>Format</th>
                  <th>Case / ID</th>
                  <th>Artifact / Package</th>
                  <th>SHA-256 Hash</th>
                  <th>Date Ingested</th>
                  <th>Severity</th>
                  <th>Indicators</th>
                  <th className="text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-app">
                {investigations.map((inv) => {
                  const isChecked = selectedForCompare.includes(inv.id);
                  return (
                    <tr
                      key={inv.id}
                      className="hover:bg-card-hover transition-colors cursor-pointer group"
                      onClick={() => onSelectInvestigation(inv.id)}
                    >
                      <td className="w-10" onClick={(e) => e.stopPropagation()}>
                        <input
                          type="checkbox"
                          checked={isChecked}
                          onChange={() => toggleCompareSelect(inv.id)}
                          className="rounded border-app text-cyan-600 focus:ring-0 cursor-pointer"
                        />
                      </td>
                      <td>
                        {inv.file_type === 'exe' ? (
                          <span className="text-[11px] font-bold bg-amber-100 text-amber-900 border border-amber-300 dark:bg-amber-950 dark:text-amber-300 dark:border-amber-800 px-2 py-0.5 rounded font-mono">
                            EXE
                          </span>
                        ) : (
                          <span className="text-[11px] font-bold bg-cyan-100 text-cyan-900 border border-cyan-300 dark:bg-cyan-950 dark:text-cyan-300 dark:border-cyan-800 px-2 py-0.5 rounded font-mono">
                            APK
                          </span>
                        )}
                      </td>
                      <td className="font-bold text-cyan-600 dark:text-cyan-400 truncate max-w-[130px] font-mono text-xs">
                        <div>{inv.id}</div>
                        {inv.case_reference && (
                          <div className="text-xs text-app-muted font-normal truncate">
                            Ref: {inv.case_reference}
                          </div>
                        )}
                      </td>
                      <td>
                        <div className="font-semibold text-app-primary truncate max-w-[200px] text-xs">
                          {inv.filename}
                        </div>
                        <div className="text-xs text-app-muted truncate max-w-[200px]">
                          {inv.package_name || (inv.file_type === 'exe' ? 'Windows Executable' : 'N/A')}
                        </div>
                      </td>
                      <td className="text-app-secondary font-mono text-xs truncate max-w-[120px]">
                        {inv.sha256 ? `${inv.sha256.slice(0, 12)}...` : 'N/A'}
                      </td>
                      <td className="text-app-secondary text-xs font-mono">
                        {new Date(inv.created_at).toLocaleDateString()}
                      </td>
                      <td>
                        <SeverityBadge severity={inv.severity} size="sm" />
                      </td>
                      <td className="text-app-secondary text-xs font-mono">
                        <span className="text-amber-600 dark:text-amber-400 font-semibold">{inv.c2_count} C2</span> /{' '}
                        <span className="text-sky-600 dark:text-sky-400 font-semibold">{inv.secret_count} Sec</span>
                      </td>
                      <td className="text-right space-x-2" onClick={(e) => e.stopPropagation()}>
                        <button
                          onClick={() => onSelectInvestigation(inv.id)}
                          className="text-cyan-600 dark:text-cyan-400 hover:underline font-semibold text-xs cursor-pointer font-mono"
                        >
                          Open
                        </button>
                        <a
                          href={api.getTxtReportUrl(inv.id)}
                          download
                          className="text-app-secondary hover:text-app-primary inline-flex items-center gap-1 text-xs border border-app bg-surface px-2 py-0.5 rounded hover:bg-card-hover font-mono"
                          title="Download TXT Report"
                        >
                          <Download className="w-3 h-3" />
                          <span>TXT</span>
                        </a>
                        <button
                          onClick={() => setDeleteConfirmId(inv.id)}
                          className="text-app-muted hover:text-rose-600 dark:hover:text-rose-400 text-xs p-1 cursor-pointer transition-colors"
                          title="Delete Investigation"
                        >
                          <Trash2 className="w-3.5 h-3.5" />
                        </button>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Delete Confirmation Modal */}
      {deleteConfirmId && (
        <div className="fixed inset-0 bg-black/60 backdrop-blur-xs z-50 flex items-center justify-center p-4">
          <div className="bg-card border border-rose-300 dark:border-rose-800 rounded-xl p-6 max-w-md w-full space-y-4 shadow-2xl text-xs">
            <div className="flex items-center gap-2 text-rose-600 dark:text-rose-400 font-bold text-sm font-mono">
              <AlertOctagon className="w-5 h-5" />
              <span>CONFIRM INVESTIGATION DELETION</span>
            </div>
            <p className="text-app-primary leading-relaxed text-sm">
              Are you sure you want to permanently delete investigation record{' '}
              <span className="font-bold font-mono text-cyan-600 dark:text-cyan-400">{deleteConfirmId}</span>?
            </p>
            <p className="text-app-secondary text-xs leading-relaxed">
              This will permanently delete SQLite case rows, extracted files, decompiled output, and generated forensic reports from workstation disk.
            </p>
            <div className="flex items-center justify-end gap-3 pt-2">
              <button
                onClick={() => setDeleteConfirmId(null)}
                className="px-3.5 py-2 rounded-lg bg-surface border border-app hover:bg-card-hover text-app-secondary font-semibold cursor-pointer text-xs"
              >
                Cancel
              </button>
              <button
                onClick={() => handleDelete(deleteConfirmId)}
                className="px-4 py-2 rounded-lg bg-rose-600 hover:bg-rose-500 text-white font-bold cursor-pointer text-xs"
              >
                Delete Permanently
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Comparison Modal */}
      {compareModalOpen && comparisonResult && (
        <div className="fixed inset-0 bg-black/60 backdrop-blur-xs z-50 flex items-center justify-center p-4">
          <div className="bg-card border border-app rounded-xl p-6 max-w-2xl w-full space-y-4 shadow-2xl text-xs max-h-[85vh] overflow-y-auto">
            <div className="flex items-center justify-between border-b border-app pb-3">
              <div className="flex items-center gap-2 text-indigo-600 dark:text-indigo-400 font-bold text-sm font-mono">
                <GitCompare className="w-5 h-5" />
                <span>CROSS-INVESTIGATION ARTIFACT COMPARISON</span>
              </div>
              <button onClick={() => setCompareModalOpen(false)} className="text-app-secondary hover:text-app-primary text-sm p-1">
                ✕
              </button>
            </div>

            <div className="grid grid-cols-2 gap-4">
              <div className="bg-surface border border-app p-3 rounded-lg space-y-1 font-mono">
                <span className="text-[11px] text-cyan-600 dark:text-cyan-400 font-bold uppercase block">
                  INVESTIGATION #1
                </span>
                <p className="font-bold text-app-primary truncate">{comparisonResult.investigation_1.filename}</p>
                <p className="text-app-secondary text-xs">ID: {comparisonResult.investigation_1.id}</p>
                <p className="text-app-muted text-xs truncate">
                  SHA: {comparisonResult.investigation_1.sha256}
                </p>
                <div className="pt-1">
                  <SeverityBadge severity={comparisonResult.investigation_1.severity} size="sm" />
                </div>
              </div>

              <div className="bg-surface border border-app p-3 rounded-lg space-y-1 font-mono">
                <span className="text-[11px] text-cyan-600 dark:text-cyan-400 font-bold uppercase block">
                  INVESTIGATION #2
                </span>
                <p className="font-bold text-app-primary truncate">{comparisonResult.investigation_2.filename}</p>
                <p className="text-app-secondary text-xs">ID: {comparisonResult.investigation_2.id}</p>
                <p className="text-app-muted text-xs truncate">
                  SHA: {comparisonResult.investigation_2.sha256}
                </p>
                <div className="pt-1">
                  <SeverityBadge severity={comparisonResult.investigation_2.severity} size="sm" />
                </div>
              </div>
            </div>

            {/* Comparison Highlights */}
            <div className="space-y-2 bg-surface p-4 rounded-lg border border-app font-mono text-xs">
              <div className="flex items-center justify-between">
                <span className="text-app-secondary">Cryptographic Hash Match:</span>
                <span className={comparisonResult.same_hash ? 'text-emerald-600 dark:text-emerald-400 font-bold' : 'text-app-primary'}>
                  {comparisonResult.same_hash ? 'YES (Identical Binary Artifacts)' : 'No (Different Hashes)'}
                </span>
              </div>
              <div className="flex items-center justify-between">
                <span className="text-app-secondary">Declared Package Name Match:</span>
                <span className={comparisonResult.same_package ? 'text-cyan-600 dark:text-cyan-400 font-bold' : 'text-app-primary'}>
                  {comparisonResult.same_package ? 'YES (Same Package Declared)' : 'No'}
                </span>
              </div>
              <div className="pt-2 border-t border-app">
                <span className="text-app-secondary block mb-1">
                  Shared Command-and-Control Endpoints ({comparisonResult.shared_c2_indicators.length}):
                </span>
                {comparisonResult.shared_c2_indicators.length === 0 ? (
                  <span className="text-app-muted text-xs">No overlapping C2 indicators between these two artifacts.</span>
                ) : (
                  <div className="space-y-1">
                    {comparisonResult.shared_c2_indicators.map((c: string, idx: number) => (
                      <div key={idx} className="text-amber-700 dark:text-amber-300 text-xs bg-card p-1.5 rounded border border-app">
                        {c}
                      </div>
                    ))}
                  </div>
                )}
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

