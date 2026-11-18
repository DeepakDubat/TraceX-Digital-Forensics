import React, { useState, useRef } from 'react';
import {
  UploadCloud,
  FileCheck2,
  AlertCircle,
  ShieldAlert,
  ArrowRight,
  Trash2,
  Shield,
  Smartphone,
  Monitor,
  Terminal,
  FileText,
  FileSpreadsheet,
  Archive,
  Mail,
  Wifi,
  Image as ImageIcon,
  Compass,
  CheckCircle2,
  Cpu
} from 'lucide-react';
import { api } from '../api';

interface NewInvestigationPageProps {
  onInvestigationCreated: (id: string) => void;
}

type EvidenceFormat =
  | 'auto'
  | 'apk'
  | 'exe'
  | 'elf'
  | 'pdf'
  | 'office'
  | 'archive'
  | 'email'
  | 'pcap'
  | 'image'
  | 'text';

interface FormatOption {
  id: EvidenceFormat;
  label: string;
  category: string;
  icon: React.ComponentType<{ className?: string }>;
  extensions: string;
}

const FORMAT_OPTIONS: FormatOption[] = [
  { id: 'auto', label: 'Auto-Detect', category: 'Universal', icon: Compass, extensions: 'All Formats (Header inspection)' },
  { id: 'apk', label: 'Android APK', category: 'Mobile', icon: Smartphone, extensions: '.apk, .xapk, .apks' },
  { id: 'exe', label: 'Windows PE', category: 'Desktop', icon: Monitor, extensions: '.exe, .dll, .sys' },
  { id: 'elf', label: 'Linux ELF', category: 'Binary', icon: Terminal, extensions: '.elf, .so, .bin' },
  { id: 'pdf', label: 'PDF Document', category: 'Document', icon: FileText, extensions: '.pdf' },
  { id: 'office', label: 'Office Suite', category: 'Document', icon: FileSpreadsheet, extensions: '.docx, .xlsx, .pptx' },
  { id: 'archive', label: 'Archive Container', category: 'Container', icon: Archive, extensions: '.zip, .7z, .tar, .gz' },
  { id: 'email', label: 'Email Message', category: 'Communication', icon: Mail, extensions: '.eml, .msg' },
  { id: 'pcap', label: 'Packet Capture', category: 'Network', icon: Wifi, extensions: '.pcap, .pcapng' },
  { id: 'image', label: 'Forensic Media', category: 'Media', icon: ImageIcon, extensions: '.jpg, .png, .bmp' },
  { id: 'text', label: 'Script / Log / Text', category: 'Data', icon: FileText, extensions: '.txt, .log, .ps1, .sh' },
];

export const MAX_UPLOAD_SIZE_MB = 200;
export const MAX_UPLOAD_SIZE_BYTES = MAX_UPLOAD_SIZE_MB * 1024 * 1024;

export const NewInvestigationPage: React.FC<NewInvestigationPageProps> = ({
  onInvestigationCreated,
}) => {
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [fileType, setFileType] = useState<EvidenceFormat>('auto');
  const [detectedFormat, setDetectedFormat] = useState<string | null>(null);
  const [caseReference, setCaseReference] = useState('');
  const [investigatorName, setInvestigatorName] = useState('');
  const [description, setDescription] = useState('');
  const [analystNotes, setAnalystNotes] = useState('');
  const [localOnlyMode, setLocalOnlyMode] = useState(false);
  const [aiAssistedAnalysis, setAiAssistedAnalysis] = useState(false);
  const [isUploading, setIsUploading] = useState(false);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  const [isDragging, setIsDragging] = useState(false);

  const fileInputRef = useRef<HTMLInputElement>(null);

  const detectFormatFromFilename = (filename: string): EvidenceFormat => {
    const ext = filename.toLowerCase().split('.').pop() || '';
    if (['apk', 'xapk', 'apks'].includes(ext)) return 'apk';
    if (['exe', 'dll', 'sys', 'scr', 'ocx'].includes(ext)) return 'exe';
    if (['elf', 'so', 'bin', 'axf', 'o'].includes(ext)) return 'elf';
    if (['pdf'].includes(ext)) return 'pdf';
    if (['docx', 'xlsx', 'pptx', 'doc', 'xls', 'ppt'].includes(ext)) return 'office';
    if (['zip', '7z', 'tar', 'gz', 'bz2', 'xz', 'rar'].includes(ext)) return 'archive';
    if (['eml', 'msg'].includes(ext)) return 'email';
    if (['pcap', 'pcapng', 'cap'].includes(ext)) return 'pcap';
    if (['jpg', 'jpeg', 'png', 'gif', 'bmp', 'webp', 'tiff'].includes(ext)) return 'image';
    if (['txt', 'log', 'sh', 'ps1', 'bat', 'cmd', 'py', 'json', 'xml', 'yaml', 'yml', 'ini', 'cfg'].includes(ext)) return 'text';
    return 'auto';
  };

  const handleFileChange = (file: File) => {
    setErrorMessage(null);
    if (file.size > MAX_UPLOAD_SIZE_BYTES) {
      const sizeMB = (file.size / (1024 * 1024)).toFixed(2);
      setErrorMessage(
        `File "${file.name}" (${sizeMB} MB) exceeds the maximum allowed limit of ${MAX_UPLOAD_SIZE_MB} MB per file.`
      );
      setSelectedFile(null);
      setDetectedFormat(null);
      return;
    }
    setSelectedFile(file);
    const detected = detectFormatFromFilename(file.name);
    setDetectedFormat(detected !== 'auto' ? detected : null);
    setFileType(detected);
  };

  const handleDragOver = (e: React.DragEvent) => {
    e.preventDefault();
    setIsDragging(true);
  };

  const handleDragLeave = () => {
    setIsDragging(false);
  };

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault();
    setIsDragging(false);
    if (e.dataTransfer.files && e.dataTransfer.files.length > 0) {
      handleFileChange(e.dataTransfer.files[0]);
    }
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!selectedFile) {
      setErrorMessage('Please select a target evidence artifact for forensic analysis.');
      return;
    }

    if (selectedFile.size > MAX_UPLOAD_SIZE_BYTES) {
      const sizeMB = (selectedFile.size / (1024 * 1024)).toFixed(2);
      setErrorMessage(
        `File "${selectedFile.name}" (${sizeMB} MB) exceeds the maximum allowed limit of ${MAX_UPLOAD_SIZE_MB} MB per file.`
      );
      return;
    }

    setIsUploading(true);
    setErrorMessage(null);

    const formData = new FormData();
    formData.append('file', selectedFile);
    formData.append('file_type', fileType);
    if (caseReference) formData.append('case_reference', caseReference);
    if (investigatorName) formData.append('investigator_name', investigatorName);
    if (description) formData.append('description', description);
    if (analystNotes) formData.append('analyst_notes', analystNotes);
    formData.append('local_only_mode', String(localOnlyMode));
    formData.append('ai_assisted_analysis', String(aiAssistedAnalysis));

    try {
      const res = await api.uploadFile(formData);
      onInvestigationCreated(res.investigation_id);
    } catch (err: any) {
      let msg = err.message || 'Evidence intake failed.';
      const status = err.status || 0;
      if (status === 413 || msg.includes('exceeds maximum') || msg.includes('413')) {
        msg = `Upload rejected: File exceeds the maximum allowed limit of ${MAX_UPLOAD_SIZE_MB} MB per file.`;
      } else if (status === 507 || msg.includes('disk space') || msg.includes('storage')) {
        msg = 'Evidence intake failed: Insufficient disk space on workstation storage.';
      } else if (msg.includes('network') || msg.includes('Failed to fetch') || msg.includes('abort')) {
        msg = 'Upload interrupted: Network connection or desktop communication was interrupted. Please retry.';
      } else if (msg.includes('unsupported') || msg.includes('Invalid file format') || msg.includes('format')) {
        msg = `Unsupported file format or corrupted binary structure: ${msg}`;
      } else {
        msg = `Upload processing failure: ${msg}`;
      }
      setErrorMessage(msg);
      setIsUploading(false);
    }
  };

  return (
    <div className="p-4 sm:p-6 md:p-8 max-w-5xl mx-auto space-y-6">
      {/* Page Header */}
      <div className="border-b border-app pb-5">
        <h1 className="text-2xl font-bold text-app-primary tracking-tight flex items-center gap-3">
          <span>New Forensic Investigation</span>
          <span className="text-xs bg-cyan-950 text-cyan-400 border border-cyan-800 px-2.5 py-1 rounded-md font-mono font-bold">
            STAGE & ANALYZE
          </span>
        </h1>
        <p className="text-sm text-app-secondary mt-1">
          Intake and analyze digital evidence: Mobile APKs, Windows Executables, Linux ELFs, PDFs, Office Documents, Archives, Emails, PCAPs, Images, and System Logs.
        </p>
      </div>

      {/* Safety Notice Banner */}
      <div className="bg-amber-50 dark:bg-amber-950/30 border border-amber-200 dark:border-amber-800/60 rounded-xl p-4 flex items-start gap-3 text-xs text-amber-900 dark:text-amber-200 shadow-sm">
        <ShieldAlert className="w-5 h-5 text-amber-600 dark:text-amber-400 shrink-0 mt-0.5" />
        <div>
          <span className="font-bold font-mono">SCIENTIFIC DIGITAL EVIDENCE INTEGRITY PROTOCOL:</span>
          <p className="text-app-secondary dark:text-slate-300 mt-1 leading-relaxed text-xs">
            The target artifact is write-protected and cryptographically hashed (MD5, SHA-1, SHA-256) immediately upon receipt. Analysis operates exclusively on an isolated working copy. <strong className="text-amber-700 dark:text-amber-300">Artifacts and binaries are never dynamically executed.</strong>
          </p>
        </div>
      </div>

      {errorMessage && (
        <div className="bg-rose-50 dark:bg-rose-950/40 border border-rose-300 dark:border-rose-800 rounded-xl p-4 text-xs text-rose-800 dark:text-rose-300 flex items-start gap-2.5 shadow-sm">
          <AlertCircle className="w-4 h-4 shrink-0 mt-0.5" />
          <span>{errorMessage}</span>
        </div>
      )}

      <form onSubmit={handleSubmit} className="space-y-6">
        {/* Format Selector Grid */}
        <div className="space-y-2">
          <label className="text-xs font-mono font-bold text-app-secondary uppercase tracking-wider block">
            Target Evidence Format Family
          </label>
          <div className="grid grid-cols-2 sm:grid-cols-3 md:grid-cols-4 lg:grid-cols-6 gap-2 text-xs font-mono">
            {FORMAT_OPTIONS.map((opt) => {
              const Icon = opt.icon;
              const isSelected = fileType === opt.id;
              return (
                <button
                  key={opt.id}
                  type="button"
                  onClick={() => setFileType(opt.id)}
                  className={`p-2.5 rounded-xl border flex flex-col items-center justify-center text-center transition-all cursor-pointer ${
                    isSelected
                      ? 'border-cyan-500 bg-cyan-950/30 text-cyan-400 ring-1 ring-cyan-500 font-bold'
                      : 'border-app bg-surface text-app-secondary hover:text-app-primary hover:border-slate-400 dark:hover:border-slate-700'
                  }`}
                >
                  <Icon className={`w-5 h-5 mb-1.5 ${isSelected ? 'text-cyan-400' : 'text-app-muted'}`} />
                  <span className="text-[11px] font-bold leading-tight">{opt.label}</span>
                  <span className="text-[9px] text-app-muted truncate w-full mt-0.5">{opt.category}</span>
                </button>
              );
            })}
          </div>
        </div>

        {/* Drag & Drop Upload Zone */}
        <div
          onDragOver={handleDragOver}
          onDragLeave={handleDragLeave}
          onDrop={handleDrop}
          onClick={() => fileInputRef.current?.click()}
          className={`border-2 border-dashed rounded-2xl p-8 text-center cursor-pointer transition-all ${
            isDragging
              ? 'border-cyan-500 bg-cyan-950/20'
              : selectedFile
              ? 'border-emerald-500/60 bg-emerald-950/10'
              : 'border-app bg-card hover:bg-card-hover'
          }`}
        >
          <input
            ref={fileInputRef}
            type="file"
            accept=".apk,.xapk,.apks,.exe,.dll,.sys,.scr,.elf,.so,.bin,.pdf,.docx,.xlsx,.pptx,.zip,.7z,.tar,.gz,.eml,.msg,.pcap,.cap,.pcapng,.jpg,.jpeg,.png,.bmp,.txt,.log,.sh,.ps1,.bat"
            onChange={(e) => e.target.files && e.target.files[0] && handleFileChange(e.target.files[0])}
            className="hidden"
          />

          {selectedFile ? (
            <div className="space-y-3">
              <div className="w-12 h-12 mx-auto rounded-full bg-emerald-500/20 text-emerald-400 flex items-center justify-center">
                <FileCheck2 className="w-6 h-6" />
              </div>
              <div>
                <div className="font-mono font-bold text-sm text-app-primary">{selectedFile.name}</div>
                <div className="text-xs text-app-muted font-mono mt-1">
                  {(selectedFile.size / (1024 * 1024)).toFixed(2)} MB of {MAX_UPLOAD_SIZE_MB} MB max • Detected Format:{' '}
                  <span className="uppercase text-cyan-400 font-bold">{fileType}</span>
                </div>
              </div>
              <button
                type="button"
                onClick={(e) => {
                  e.stopPropagation();
                  setSelectedFile(null);
                  setDetectedFormat(null);
                }}
                className="inline-flex items-center gap-1 text-xs text-rose-400 hover:text-rose-300 font-mono"
              >
                <Trash2 className="w-3.5 h-3.5" />
                <span>Remove and select different file</span>
              </button>
            </div>
          ) : (
            <div className="space-y-3">
              <div className="w-12 h-12 mx-auto rounded-full bg-surface border border-app text-app-muted flex items-center justify-center">
                <UploadCloud className="w-6 h-6 text-cyan-500" />
              </div>
              <div>
                <div className="font-semibold text-sm text-app-primary">
                  Drag and drop evidence file here
                </div>
                <div className="text-xs font-mono font-bold text-cyan-600 dark:text-cyan-400 mt-1">
                  Maximum File Size: 200 MB per file
                </div>
                <div className="text-[11px] text-app-muted mt-0.5 font-mono">
                  Supports APK, EXE, DLL, ELF, PDF, Office, ZIP, EML, PCAP, Images, and Logs
                </div>
              </div>
            </div>
          )}
        </div>

        {/* Investigation Metadata Form */}
        <div className="bg-card border border-app rounded-xl p-5 space-y-4">
          <h2 className="text-xs font-mono font-bold text-cyan-600 dark:text-cyan-400 uppercase tracking-wider border-b border-app pb-2">
            Case Metadata & Chain of Custody
          </h2>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs font-mono">
            <div className="space-y-1.5">
              <label className="text-app-secondary font-bold">CASE REFERENCE / EVIDENCE TAG</label>
              <input
                type="text"
                value={caseReference}
                onChange={(e) => setCaseReference(e.target.value)}
                placeholder="e.g. CASE-2026-0842"
                className="forensics-input w-full text-xs"
              />
            </div>

            <div className="space-y-1.5">
              <label className="text-app-secondary font-bold">PRIMARY EXAMINER / ANALYST</label>
              <input
                type="text"
                value={investigatorName}
                onChange={(e) => setInvestigatorName(e.target.value)}
                placeholder="e.g. Lead Analyst"
                className="forensics-input w-full text-xs"
              />
            </div>
          </div>

          <div className="space-y-1.5 text-xs font-mono">
            <label className="text-app-secondary font-bold">INVESTIGATION OBJECTIVE / DESCRIPTION</label>
            <input
              type="text"
              value={description}
              onChange={(e) => setDescription(e.target.value)}
              placeholder="e.g. Suspected C2 beaconing and credential harvesting campaign"
              className="forensics-input w-full text-xs"
            />
          </div>

          <div className="space-y-1.5 text-xs font-mono">
            <label className="text-app-secondary font-bold">EXAMINER INTAKE NOTES (OPTIONAL)</label>
            <textarea
              rows={2}
              value={analystNotes}
              onChange={(e) => setAnalystNotes(e.target.value)}
              placeholder="Initial acquisition context, hash chain notes, or preliminary indicators..."
              className="forensics-input w-full text-xs font-sans"
            />
          </div>

          {/* Local-Only Mode Toggle */}
          <div className="pt-2 border-t border-app">
            <label className="flex items-start gap-3 cursor-pointer">
              <input
                type="checkbox"
                checked={localOnlyMode}
                onChange={(e) => setLocalOnlyMode(e.target.checked)}
                className="mt-0.5 rounded border-app text-cyan-600 focus:ring-0 cursor-pointer"
              />
              <div>
                <span className="font-bold text-xs text-app-primary flex items-center gap-1.5">
                  <Shield className="w-3.5 h-3.5 text-emerald-500" />
                  Enable Strict Local-Only Analysis Mode
                </span>
                <p className="text-[11px] text-app-muted mt-0.5 leading-relaxed font-sans">
                  Prohibits all external network queries (VirusTotal, AbuseIPDB, AlienVault OTX, DNS). Analysis will rely strictly on offline static decompilation, YARA rulesets, and local heuristics.
                </p>
              </div>
            </label>
          </div>

          {/* AI-Assisted Analysis Toggle (OpenCode CLI) */}
          <div className="pt-2 border-t border-app">
            <label className="flex items-start gap-3 cursor-pointer">
              <input
                type="checkbox"
                checked={aiAssistedAnalysis}
                onChange={(e) => setAiAssistedAnalysis(e.target.checked)}
                className="mt-0.5 rounded border-app text-indigo-600 focus:ring-0 cursor-pointer"
              />
              <div>
                <span className="font-bold text-xs text-app-primary flex items-center gap-1.5">
                  <Cpu className="w-3.5 h-3.5 text-indigo-500" />
                  AI-Assisted Forensic Analysis (OpenCode CLI Engine)
                </span>
                <p className="text-[11px] text-app-muted mt-0.5 leading-relaxed font-sans">
                  Synthesize unverified AI observations and verification recommendations alongside deterministic findings. In LOCAL ONLY mode, requires an offline model (e.g. Ollama); external cloud calls require explicit authorization.
                </p>
              </div>
            </label>
          </div>
        </div>

        {/* Submit Button */}
        <div className="flex items-center justify-end gap-3 pt-2">
          <button
            type="submit"
            disabled={!selectedFile || isUploading}
            className="btn-primary flex items-center gap-2 text-xs font-bold py-2.5 px-6 shadow-md cursor-pointer disabled:opacity-50"
          >
            {isUploading ? (
              <>
                <div className="w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin" />
                <span>Hashing & Ingesting Evidence...</span>
              </>
            ) : (
              <>
                <span>Begin Forensic Pipeline</span>
                <ArrowRight className="w-4 h-4" />
              </>
            )}
          </button>
        </div>
      </form>
    </div>
  );
};
