import React, { useState, useEffect } from 'react';
import {
  FileText,
  Download,
  Copy,
  Check,
  RefreshCw,
  Search,
  AlertCircle,
  FileCheck,
  Code,
  FolderOpen,
  ExternalLink,
  HardDrive,
  CheckCircle2,
  Folder
} from 'lucide-react';
import { api } from '../api';
import { InvestigationDetail, SavedReportResult, SavedReportItem } from '../types';

interface ReportViewerPageProps {
  detail: InvestigationDetail;
}

type DownloadStage = 'idle' | 'preparing' | 'generating' | 'downloading' | 'completed' | 'failed';

export const ReportViewerPage: React.FC<ReportViewerPageProps> = ({ detail }) => {
  const [reportText, setReportText] = useState<string>('');
  const [loading, setLoading] = useState(true);
  const [copied, setCopied] = useState(false);
  const [copiedPath, setCopiedPath] = useState(false);
  const [searchTerm, setSearchTerm] = useState('');

  // Download state management
  const [downloadStage, setDownloadStage] = useState<DownloadStage>('idle');
  const [downloadingFormat, setDownloadingFormat] = useState<string | null>(null);
  const [downloadError, setDownloadError] = useState<string | null>(null);
  const [lastSavedReport, setLastSavedReport] = useState<SavedReportResult | null>(null);
  const [savedReportsList, setSavedReportsList] = useState<SavedReportItem[]>([]);
  const [actionLoading, setActionLoading] = useState<string | null>(null);

  const fetchReport = async () => {
    setLoading(true);
    try {
      const text = await api.previewReport(detail.record.id);
      setReportText(text);
    } catch (err: any) {
      console.error(err);
      setDownloadError(`Failed to load report preview: ${err.message || err}`);
    } finally {
      setLoading(false);
    }
  };

  const loadSavedReports = async () => {
    try {
      const files = await api.getSavedReports(detail.record.id);
      setSavedReportsList(files);
    } catch (e) {
      // Non-critical background listing
    }
  };

  useEffect(() => {
    fetchReport();
    loadSavedReports();
  }, [detail.record.id]);

  const handleCopy = () => {
    navigator.clipboard.writeText(reportText);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const handleCopyPath = async (path: string) => {
    if (!path) return;
    try {
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

  const executeDownload = async (
    formatCode: string,
    formatLabel: string,
    directUrl: string,
    defaultFilename: string
  ) => {
    if (downloadStage !== 'idle' && downloadStage !== 'completed' && downloadStage !== 'failed') {
      return; // Single flight guard
    }

    setDownloadingFormat(formatLabel);
    setDownloadError(null);

    try {
      // Step 1: Preparing report
      setDownloadStage('preparing');
      await new Promise(r => setTimeout(r, 150));

      // Step 2: Generating report
      setDownloadStage('generating');

      // Step 3: Downloading & Saving directly to %USERPROFILE%\Documents\TraceX\Reports\<ID>\
      setDownloadStage('downloading');
      const savedResult = await api.saveReportToDocuments(
        detail.record.id,
        formatCode,
        false, // unredact
        false  // overwrite
      );

      // Verify returned result has non-zero size and valid path
      if (!savedResult.filepath || savedResult.file_size <= 0) {
        throw new Error('Verification failed: Report file was not written to disk or is 0 bytes.');
      }

      // Step 4: Optional client trigger for in-browser download
      try {
        await api.downloadReportFile(directUrl, defaultFilename);
      } catch (browserErr) {
        // Desktop host may suppress browser download; the file is already verified on disk
      }

      // Step 5: Mark Completed
      setLastSavedReport(savedResult);
      setDownloadStage('completed');
      loadSavedReports();

    } catch (err: any) {
      console.error('Download failure:', err);
      setDownloadStage('failed');
      setDownloadError(err.message || `Failed to download ${formatLabel} report.`);
    } finally {
      setDownloadingFormat(null);
    }
  };

  const handleOpenFile = async (filepath: string) => {
    setActionLoading('open');
    try {
      await api.openReportFile(filepath);
    } catch (err: any) {
      alert(`Could not open report: ${err.message || err}`);
    } finally {
      setActionLoading(null);
    }
  };

  const handleShowInFolder = async (filepath: string) => {
    setActionLoading('folder');
    try {
      await api.showReportInFolder(filepath);
    } catch (err: any) {
      alert(`Could not locate folder: ${err.message || err}`);
    } finally {
      setActionLoading(null);
    }
  };

  return (
    <div className="p-4 sm:p-6 md:p-8 space-y-6">
      {/* Header */}
      <div className="border-b border-app pb-4 flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <h1 className="text-xl md:text-2xl font-bold text-app-primary tracking-tight flex flex-wrap items-center gap-2.5">
            <span>Forensic Report Viewer</span>
            <span className="text-xs bg-surface text-cyan-700 dark:text-cyan-400 border border-app px-2.5 py-1 rounded-md font-mono font-medium">
              Law-Enforcement Digital Forensics Audit
            </span>
          </h1>
          <p className="text-xs md:text-sm text-app-secondary mt-1">
            Generated from verified static findings, permission intelligence, C2 reconstructions, and threat intelligence.
          </p>
        </div>

        {/* Primary Download Buttons */}
        <div className="flex flex-wrap items-center gap-2.5">
          {/* TXT Report */}
          <button
            onClick={() => executeDownload(
              'txt',
              'TXT',
              api.getTxtReportUrl(detail.record.id),
              `Forensic_Report_${detail.record.id}.txt`
            )}
            disabled={downloadStage === 'preparing' || downloadStage === 'generating' || downloadStage === 'downloading'}
            className="bg-cyan-600 hover:bg-cyan-700 dark:bg-cyan-600 dark:hover:bg-cyan-500 text-white text-xs px-3.5 py-2 rounded-lg font-bold flex items-center gap-1.5 shadow-sm transition-all cursor-pointer disabled:opacity-50 disabled:cursor-not-allowed"
            title="Download full plain-text forensic report to Documents\TraceX\Reports"
          >
            {downloadingFormat === 'TXT' ? <RefreshCw className="w-3.5 h-3.5 animate-spin" /> : <Download className="w-3.5 h-3.5" />}
            <span>TXT REPORT</span>
          </button>

          {/* HTML Report */}
          <button
            onClick={() => executeDownload(
              'html',
              'HTML',
              api.getHtmlReportUrl(detail.record.id),
              `Forensic_Report_${detail.record.id}.html`
            )}
            disabled={downloadStage === 'preparing' || downloadStage === 'generating' || downloadStage === 'downloading'}
            className="bg-emerald-600 hover:bg-emerald-700 dark:bg-emerald-600 dark:hover:bg-emerald-500 text-white text-xs px-3.5 py-2 rounded-lg font-bold flex items-center gap-1.5 shadow-sm transition-all cursor-pointer disabled:opacity-50 disabled:cursor-not-allowed"
            title="Download responsive HTML forensic report to Documents\TraceX\Reports"
          >
            {downloadingFormat === 'HTML' ? <RefreshCw className="w-3.5 h-3.5 animate-spin" /> : <Download className="w-3.5 h-3.5" />}
            <span>HTML REPORT</span>
          </button>

          {/* PDF Report */}
          <button
            onClick={() => executeDownload(
              'pdf',
              'PDF',
              api.getPdfReportUrl(detail.record.id),
              `Forensic_Report_${detail.record.id}.pdf`
            )}
            disabled={downloadStage === 'preparing' || downloadStage === 'generating' || downloadStage === 'downloading'}
            className="bg-rose-600 hover:bg-rose-700 dark:bg-rose-600 dark:hover:bg-rose-500 text-white text-xs px-3.5 py-2 rounded-lg font-bold flex items-center gap-1.5 shadow-sm transition-all cursor-pointer disabled:opacity-50 disabled:cursor-not-allowed"
            title="Download printable high-resolution PDF report to Documents\TraceX\Reports"
          >
            {downloadingFormat === 'PDF' ? <RefreshCw className="w-3.5 h-3.5 animate-spin" /> : <Download className="w-3.5 h-3.5" />}
            <span>PDF REPORT</span>
          </button>

          {/* CSV IOCs */}
          <button
            onClick={() => executeDownload(
              'csv',
              'CSV IOCs',
              api.getCsvIocUrl(detail.record.id),
              `IOCs_${detail.record.id}.csv`
            )}
            disabled={downloadStage === 'preparing' || downloadStage === 'generating' || downloadStage === 'downloading'}
            className="bg-surface hover:bg-slate-200 dark:hover:bg-[#1e2736] border border-app text-app-primary text-xs px-3 py-2 rounded-lg font-bold flex items-center gap-1.5 transition-all shadow-sm cursor-pointer disabled:opacity-50"
            title="Download CSV indicators to Documents\TraceX\Reports"
          >
            {downloadingFormat === 'CSV IOCs' ? <RefreshCw className="w-3.5 h-3.5 animate-spin" /> : <Download className="w-3.5 h-3.5 text-amber-600 dark:text-amber-400" />}
            <span>CSV IOCs</span>
          </button>

          {/* Reproducibility ZIP Bundle */}
          <button
            onClick={() => executeDownload(
              'bundle',
              'ZIP Bundle',
              api.getBundleZipUrl(detail.record.id),
              `Forensic_Bundle_${detail.record.id}.zip`
            )}
            disabled={downloadStage === 'preparing' || downloadStage === 'generating' || downloadStage === 'downloading'}
            className="bg-surface hover:bg-slate-200 dark:hover:bg-[#1e2736] border border-app text-app-primary text-xs px-3 py-2 rounded-lg font-bold flex items-center gap-1.5 transition-all shadow-sm cursor-pointer disabled:opacity-50"
            title="Download full reproducibility bundle (.zip) to Documents\TraceX\Reports"
          >
            {downloadingFormat === 'ZIP Bundle' ? <RefreshCw className="w-3.5 h-3.5 animate-spin" /> : <Download className="w-3.5 h-3.5 text-purple-600 dark:text-purple-400" />}
            <span>ZIP BUNDLE</span>
          </button>

          {/* JSON Export */}
          <button
            onClick={() => executeDownload(
              'json',
              'JSON',
              api.getJsonExportUrl(detail.record.id),
              `Evidence_Export_${detail.record.id}.json`
            )}
            disabled={downloadStage === 'preparing' || downloadStage === 'generating' || downloadStage === 'downloading'}
            className="bg-surface hover:bg-slate-200 dark:hover:bg-[#1e2736] border border-app text-app-primary text-xs px-3 py-2 rounded-lg font-bold flex items-center gap-1.5 transition-all shadow-sm cursor-pointer disabled:opacity-50"
            title="Download structured JSON evidence to Documents\TraceX\Reports"
          >
            {downloadingFormat === 'JSON' ? <RefreshCw className="w-3.5 h-3.5 animate-spin" /> : <Download className="w-3.5 h-3.5 text-indigo-600 dark:text-indigo-400" />}
            <span>JSON</span>
          </button>
        </div>
      </div>

      {/* Progress & Live Status Banner */}
      {(downloadStage === 'preparing' || downloadStage === 'generating' || downloadStage === 'downloading') && (
        <div className="p-3.5 bg-cyan-50 dark:bg-cyan-950/40 border border-cyan-300 dark:border-cyan-800 rounded-xl text-cyan-900 dark:text-cyan-200 text-xs flex items-center justify-between shadow-sm animate-pulse">
          <div className="flex items-center gap-2.5 font-medium">
            <RefreshCw className="w-4 h-4 animate-spin text-cyan-600 dark:text-cyan-400" />
            <span>
              {downloadStage === 'preparing' && 'Preparing report request...'}
              {downloadStage === 'generating' && `Generating ${downloadingFormat} forensic document...`}
              {downloadStage === 'downloading' && `Writing and verifying file in Documents\\TraceX\\Reports...`}
            </span>
          </div>
          <span className="font-mono text-[11px] bg-cyan-100 dark:bg-cyan-900/60 px-2 py-0.5 rounded text-cyan-800 dark:text-cyan-300">
            {downloadStage.toUpperCase()}
          </span>
        </div>
      )}

      {/* Download Error Banner */}
      {downloadStage === 'failed' && downloadError && (
        <div className="p-3.5 bg-rose-50 dark:bg-rose-950/60 border border-rose-300 dark:border-rose-800 rounded-xl text-rose-700 dark:text-rose-300 text-xs flex items-center justify-between shadow-sm">
          <div className="flex items-center gap-2.5">
            <AlertCircle className="w-4 h-4 shrink-0 text-rose-600 dark:text-rose-400" />
            <div className="space-y-0.5">
              <div className="font-bold">Download Failed</div>
              <div className="text-[11px] opacity-90">{downloadError}</div>
            </div>
          </div>
          <button
            onClick={() => setDownloadStage('idle')}
            className="text-xs underline hover:text-rose-900 dark:hover:text-rose-100 font-medium cursor-pointer"
          >
            Dismiss
          </button>
        </div>
      )}

      {/* Download Completed & Verified on Disk - Details Card */}
      {downloadStage === 'completed' && lastSavedReport && (
        <div className="p-4 sm:p-5 bg-emerald-50 dark:bg-emerald-950/50 border border-emerald-300 dark:border-emerald-800 rounded-2xl text-emerald-950 dark:text-emerald-100 shadow-md space-y-3.5">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-emerald-200 dark:border-emerald-800/80 pb-3">
            <div className="flex items-center gap-2">
              <CheckCircle2 className="w-5 h-5 text-emerald-600 dark:text-emerald-400 shrink-0" />
              <div>
                <span className="font-bold text-sm text-emerald-900 dark:text-emerald-200">
                  Download Completed & Verified on Disk
                </span>
                <span className="ml-2 text-[11px] font-mono bg-emerald-100 dark:bg-emerald-900/70 text-emerald-800 dark:text-emerald-300 px-2 py-0.5 rounded">
                  {lastSavedReport.format.toUpperCase()}
                </span>
              </div>
            </div>

            {/* Quick Actions: Open Report & Show in Folder */}
            <div className="flex items-center gap-2">
              <button
                onClick={() => handleOpenFile(lastSavedReport.filepath)}
                disabled={actionLoading === 'open'}
                className="bg-emerald-700 hover:bg-emerald-800 text-white text-xs px-3.5 py-1.5 rounded-lg font-bold flex items-center gap-1.5 shadow-sm transition-all cursor-pointer disabled:opacity-50"
                title="Launch in default system viewer"
              >
                {actionLoading === 'open' ? <RefreshCw className="w-3.5 h-3.5 animate-spin" /> : <ExternalLink className="w-3.5 h-3.5" />}
                <span>Open Report</span>
              </button>

              <button
                onClick={() => handleShowInFolder(lastSavedReport.filepath)}
                disabled={actionLoading === 'folder'}
                className="bg-surface hover:bg-slate-200 dark:hover:bg-[#1e2736] border border-app text-app-primary text-xs px-3.5 py-1.5 rounded-lg font-bold flex items-center gap-1.5 shadow-sm transition-all cursor-pointer disabled:opacity-50"
                title="Reveal file in Windows File Explorer"
              >
                {actionLoading === 'folder' ? <RefreshCw className="w-3.5 h-3.5 animate-spin" /> : <FolderOpen className="w-3.5 h-3.5 text-cyan-600 dark:text-cyan-400" />}
                <span>Show in Folder</span>
              </button>
            </div>
          </div>

          {/* Metadata Display */}
          <div className="grid grid-cols-1 md:grid-cols-3 gap-3 text-xs">
            <div className="bg-surface/80 p-2.5 rounded-lg border border-emerald-200 dark:border-emerald-900/40">
              <div className="text-[11px] text-app-muted uppercase font-mono">Report Filename</div>
              <div className="font-bold font-mono text-app-primary truncate mt-0.5" title={lastSavedReport.filename}>
                {lastSavedReport.filename}
              </div>
            </div>

            <div className="bg-surface/80 p-2.5 rounded-lg border border-emerald-200 dark:border-emerald-900/40">
              <div className="text-[11px] text-app-muted uppercase font-mono">File Size</div>
              <div className="font-bold text-app-primary mt-0.5">
                {lastSavedReport.file_size_formatted} ({lastSavedReport.file_size.toLocaleString()} bytes)
              </div>
            </div>

            <div className="bg-surface/80 p-2.5 rounded-lg border border-emerald-200 dark:border-emerald-900/40">
              <div className="text-[11px] text-app-muted uppercase font-mono">Storage Location</div>
              <div className="font-mono text-app-primary text-[11px] truncate mt-0.5" title={lastSavedReport.directory}>
                Documents\TraceX\Reports\{lastSavedReport.investigation_id}
              </div>
            </div>
          </div>

          {/* Full Path with Copy Button */}
          <div className="flex items-center justify-between gap-2 bg-surface p-2.5 rounded-lg border border-app text-xs font-mono">
            <div className="truncate text-app-secondary" title={lastSavedReport.filepath}>
              <span className="text-app-muted select-none">Path: </span>
              <span className="text-app-primary select-all">{lastSavedReport.filepath}</span>
            </div>
            <button
              onClick={() => handleCopyPath(lastSavedReport.filepath)}
              className="text-xs text-cyan-600 hover:text-cyan-700 font-bold shrink-0 flex items-center gap-1 cursor-pointer"
            >
              {copiedPath ? <Check className="w-3.5 h-3.5 text-emerald-600" /> : <Copy className="w-3.5 h-3.5" />}
              <span>{copiedPath ? 'Copied' : 'Copy Path'}</span>
            </button>
          </div>
        </div>
      )}

      {/* Saved Reports Drawer / History */}
      {savedReportsList.length > 0 && (
        <div className="forensics-card p-4 rounded-xl space-y-3">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <Folder className="w-4 h-4 text-cyan-600 dark:text-cyan-400" />
              <h2 className="text-xs font-bold uppercase tracking-wider text-app-primary">
                Saved Reports in Documents ({savedReportsList.length})
              </h2>
            </div>
            <button
              onClick={() => handleShowInFolder(savedReportsList[0].directory)}
              className="text-xs text-cyan-600 hover:underline flex items-center gap-1 font-mono font-medium cursor-pointer"
            >
              <FolderOpen className="w-3.5 h-3.5" />
              <span>Open Reports Folder</span>
            </button>
          </div>

          <div className="divide-y divide-app">
            {savedReportsList.map((file) => (
              <div key={file.filepath} className="py-2.5 flex flex-col sm:flex-row sm:items-center justify-between gap-2 text-xs">
                <div className="flex items-center gap-2.5 min-w-0">
                  <FileText className="w-4 h-4 text-app-muted shrink-0" />
                  <div className="min-w-0">
                    <div className="font-mono font-semibold text-app-primary truncate" title={file.filename}>
                      {file.filename}
                    </div>
                    <div className="text-[11px] text-app-muted font-mono">
                      {file.file_size_formatted} • {file.modified_at ? new Date(file.modified_at).toLocaleTimeString() : ''}
                    </div>
                  </div>
                </div>

                <div className="flex items-center gap-2 shrink-0">
                  <button
                    onClick={() => handleOpenFile(file.filepath)}
                    className="text-xs bg-surface hover:bg-slate-200 dark:hover:bg-[#1e2736] border border-app text-app-primary px-2.5 py-1 rounded font-medium flex items-center gap-1 cursor-pointer"
                    title="Open report in default viewer"
                  >
                    <ExternalLink className="w-3 h-3 text-cyan-600" />
                    <span>Open</span>
                  </button>
                  <button
                    onClick={() => handleShowInFolder(file.filepath)}
                    className="text-xs bg-surface hover:bg-slate-200 dark:hover:bg-[#1e2736] border border-app text-app-primary px-2.5 py-1 rounded font-medium flex items-center gap-1 cursor-pointer"
                    title="Locate in Windows Explorer"
                  >
                    <FolderOpen className="w-3 h-3 text-amber-600" />
                    <span>Show in Folder</span>
                  </button>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Toolbar */}
      <div className="forensics-card p-3 rounded-xl flex flex-col sm:flex-row items-stretch sm:items-center justify-between gap-3 text-xs shadow-sm">
        <div className="flex items-center gap-2.5 flex-1 max-w-md bg-surface px-3 py-1.5 rounded-lg border border-app">
          <Search className="w-4 h-4 text-app-muted shrink-0" />
          <input
            type="text"
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            placeholder="Search within report text..."
            className="w-full bg-transparent text-app-primary focus:outline-none text-xs font-mono"
          />
        </div>

        <div className="flex items-center gap-3 shrink-0">
          <button
            onClick={handleCopy}
            className="text-app-primary hover:text-cyan-600 flex items-center gap-1.5 px-3.5 py-2 rounded-lg bg-surface border border-app transition-all cursor-pointer font-bold font-mono text-xs shadow-sm"
          >
            {copied ? <Check className="w-4 h-4 text-emerald-600 dark:text-emerald-400" /> : <Copy className="w-4 h-4 text-app-secondary" />}
            <span>{copied ? 'COPIED TO CLIPBOARD' : 'COPY REPORT TEXT'}</span>
          </button>
        </div>
      </div>

      {/* Clean Monospace Forensic Report Box */}
      <div className="bg-slate-100 dark:bg-[#080a0f] border border-app rounded-2xl p-4 sm:p-6 shadow-md overflow-hidden">
        {loading ? (
          <div className="p-12 text-center text-app-secondary text-xs flex items-center justify-center gap-2.5 font-mono">
            <RefreshCw className="w-4 h-4 animate-spin text-cyan-600 dark:text-cyan-400" />
            <span>Compiling forensic investigation document...</span>
          </div>
        ) : (
          <pre className="text-slate-800 dark:text-slate-200 text-xs md:text-sm font-mono leading-relaxed overflow-x-auto whitespace-pre selection:bg-cyan-500/30 max-h-[70vh]">
            {reportText}
          </pre>
        )}
      </div>
    </div>
  );
};
