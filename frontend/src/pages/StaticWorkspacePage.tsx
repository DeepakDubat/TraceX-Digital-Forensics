import React, { useState } from 'react';
import {
  ShieldCheck,
  FileCode2,
  Binary,
  Layers,
  Lock,
  Search,
  ExternalLink,
  Info,
  CheckCircle2,
  Flame,
  FileCheck,
  Hash,
  AlertTriangle,
  FolderOpen,
  ArrowRight,
  Database,
  Terminal,
  Cpu
} from 'lucide-react';
import { InvestigationDetail, StaticFinding } from '../types';
import { SeverityBadge } from '../components/SeverityBadge';

interface StaticWorkspacePageProps {
  detail: InvestigationDetail | null;
  onSelectInvestigation: (id: string) => void;
  onNavigatePage?: (page: string) => void;
}

export const StaticWorkspacePage: React.FC<StaticWorkspacePageProps> = ({
  detail,
  onSelectInvestigation,
  onNavigatePage
}) => {
  const [activeTab, setActiveTab] = useState<'overview' | 'parsers' | 'safety'>('overview');
  const [filterQuery, setFilterQuery] = useState('');

  const record = detail?.record;
  const isExe = record?.file_type === 'exe';
  const isApk = record?.file_type === 'apk';
  const findings = detail?.static_findings || [];

  const filteredFindings = findings.filter(
    (f) =>
      f.title.toLowerCase().includes(filterQuery.toLowerCase()) ||
      f.description.toLowerCase().includes(filterQuery.toLowerCase()) ||
      f.category.toLowerCase().includes(filterQuery.toLowerCase())
  );

  return (
    <div className="p-4 sm:p-6 md:p-8 space-y-6 max-w-7xl mx-auto">
      {/* Header Banner */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-6 shadow-sm">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
          <div>
            <div className="flex items-center gap-2 mb-1">
              <span className="px-2.5 py-0.5 rounded-full text-xs font-mono font-medium bg-emerald-950 text-emerald-400 border border-emerald-800">
                100% STATIC FORENSICS
              </span>
              <span className="text-xs text-slate-400 font-mono">
                ZERO-EXECUTION GUARANTEED
              </span>
            </div>
            <h1 className="text-2xl font-bold text-white tracking-tight flex items-center gap-2">
              <ShieldCheck className="w-7 h-7 text-emerald-400" />
              TraceX Static Analysis Workspace
            </h1>
            <p className="text-slate-400 text-sm mt-1">
              Discover. Analyze. Investigate. Non-execution forensic inspection for Android APKs, Windows PEs, Linux ELFs, and evidentiary documents.
            </p>
          </div>

          <div className="flex items-center gap-2">
            <button
              onClick={() => setActiveTab('overview')}
              className={`px-3 py-1.5 rounded-lg text-xs font-medium transition-colors ${
                activeTab === 'overview'
                  ? 'bg-emerald-600 text-white'
                  : 'bg-slate-800 text-slate-300 hover:bg-slate-700'
              }`}
            >
              Active Target
            </button>
            <button
              onClick={() => setActiveTab('parsers')}
              className={`px-3 py-1.5 rounded-lg text-xs font-medium transition-colors ${
                activeTab === 'parsers'
                  ? 'bg-emerald-600 text-white'
                  : 'bg-slate-800 text-slate-300 hover:bg-slate-700'
              }`}
            >
              Engine Capabilities
            </button>
            <button
              onClick={() => setActiveTab('safety')}
              className={`px-3 py-1.5 rounded-lg text-xs font-medium transition-colors ${
                activeTab === 'safety'
                  ? 'bg-emerald-600 text-white'
                  : 'bg-slate-800 text-slate-300 hover:bg-slate-700'
              }`}
            >
              Safety Architecture
            </button>
          </div>
        </div>
      </div>

      {/* Tab: Overview / Active Target */}
      {activeTab === 'overview' && (
        <div className="space-y-6">
          {detail ? (
            <>
              {/* Evidence Card */}
              <div className="bg-slate-900 border border-slate-800 rounded-xl p-5">
                <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-slate-800 pb-4">
                  <div className="flex items-center gap-3">
                    <div className="p-3 bg-emerald-950/60 border border-emerald-800/80 rounded-lg text-emerald-400">
                      {isExe ? <Binary className="w-6 h-6" /> : <FileCode2 className="w-6 h-6" />}
                    </div>
                    <div>
                      <h2 className="text-lg font-semibold text-white font-mono">{record?.filename}</h2>
                      <p className="text-xs text-slate-400">
                        Case: <span className="text-slate-200">{record?.case_reference || 'N/A'}</span> • ID:{' '}
                        <span className="text-slate-200">{record?.id}</span> • Examiner:{' '}
                        <span className="text-slate-200">{record?.investigator_name}</span>
                      </p>
                    </div>
                  </div>

                  <div className="flex items-center gap-3">
                    <span className="px-3 py-1 rounded-full text-xs font-mono font-medium bg-slate-800 text-slate-200 border border-slate-700">
                      {(record?.original_size ? (record.original_size / 1024).toFixed(1) : 0)} KB
                    </span>
                    <span className="px-3 py-1 rounded-full text-xs font-mono font-medium bg-emerald-950 text-emerald-300 border border-emerald-800 uppercase">
                      Format: {record?.file_type}
                    </span>
                  </div>
                </div>

                {/* Hashes Grid */}
                <div className="grid grid-cols-1 md:grid-cols-3 gap-3 mt-4 text-xs font-mono">
                  <div className="p-2.5 bg-slate-950/60 rounded-lg border border-slate-800/60">
                    <div className="text-slate-500 text-[10px] uppercase">SHA-256 Digest</div>
                    <div className="text-emerald-400 truncate mt-0.5 select-all">{record?.sha256}</div>
                  </div>
                  <div className="p-2.5 bg-slate-950/60 rounded-lg border border-slate-800/60">
                    <div className="text-slate-500 text-[10px] uppercase">SHA-1 Digest</div>
                    <div className="text-slate-300 truncate mt-0.5 select-all">{record?.sha1}</div>
                  </div>
                  <div className="p-2.5 bg-slate-950/60 rounded-lg border border-slate-800/60">
                    <div className="text-slate-500 text-[10px] uppercase">MD5 Digest</div>
                    <div className="text-slate-300 truncate mt-0.5 select-all">{record?.md5}</div>
                  </div>
                </div>
              </div>

              {/* Findings & Quick Actions */}
              <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
                {/* Findings Column */}
                <div className="lg:col-span-2 bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-4">
                  <div className="flex items-center justify-between border-b border-slate-800 pb-3">
                    <h3 className="text-sm font-semibold text-white uppercase tracking-wider flex items-center gap-2">
                      <Layers className="w-4 h-4 text-emerald-400" />
                      Static Findings ({findings.length})
                    </h3>
                    <div className="relative">
                      <Search className="w-3.5 h-3.5 text-slate-400 absolute left-2.5 top-2" />
                      <input
                        type="text"
                        placeholder="Search findings..."
                        value={filterQuery}
                        onChange={(e) => setFilterQuery(e.target.value)}
                        className="bg-slate-950 border border-slate-800 rounded-lg pl-8 pr-3 py-1 text-xs text-white placeholder-slate-500 focus:outline-none focus:border-emerald-500 w-48"
                      />
                    </div>
                  </div>

                  <div className="space-y-2.5 max-h-[420px] overflow-y-auto pr-1">
                    {filteredFindings.length > 0 ? (
                      filteredFindings.map((f, i) => (
                        <div key={i} className="p-3 bg-slate-950/80 rounded-lg border border-slate-800/80 space-y-1">
                          <div className="flex items-center justify-between gap-2">
                            <span className="text-xs font-medium text-slate-200">{f.title}</span>
                            <SeverityBadge severity={f.severity} />
                          </div>
                          <p className="text-xs text-slate-400">{f.description}</p>
                          <div className="text-[10px] text-slate-500 font-mono flex items-center gap-2 pt-1">
                            <span>Category: {f.category}</span>
                            {f.code_reference && <span>• Ref: {f.code_reference}</span>}
                          </div>
                        </div>
                      ))
                    ) : (
                      <div className="py-12 text-center text-slate-500 text-xs">
                        No static findings matched your filter query.
                      </div>
                    )}
                  </div>
                </div>

                {/* Quick Navigation Column */}
                <div className="space-y-4">
                  <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-3">
                    <h3 className="text-xs font-semibold text-slate-400 uppercase tracking-wider">
                      Specialized Forensics Views
                    </h3>
                    <div className="space-y-2">
                      <button
                        onClick={() => onNavigatePage && onNavigatePage('static_findings')}
                        className="w-full text-left p-2.5 rounded-lg bg-slate-950 hover:bg-slate-800 border border-slate-800 transition-colors flex items-center justify-between group"
                      >
                        <div className="flex items-center gap-2 text-xs text-slate-200">
                          <FileCode2 className="w-4 h-4 text-cyan-400" />
                          <span>{isExe ? 'PE Headers & Sections' : 'Manifest & DEX Analysis'}</span>
                        </div>
                        <ArrowRight className="w-3.5 h-3.5 text-slate-500 group-hover:text-white transition-colors" />
                      </button>

                      <button
                        onClick={() => onNavigatePage && onNavigatePage('c2_intel')}
                        className="w-full text-left p-2.5 rounded-lg bg-slate-950 hover:bg-slate-800 border border-slate-800 transition-colors flex items-center justify-between group"
                      >
                        <div className="flex items-center gap-2 text-xs text-slate-200">
                          <Terminal className="w-4 h-4 text-amber-400" />
                          <span>C2 & Network Infrastructure</span>
                        </div>
                        <ArrowRight className="w-3.5 h-3.5 text-slate-500 group-hover:text-white transition-colors" />
                      </button>

                      <button
                        onClick={() => onNavigatePage && onNavigatePage('secrets')}
                        className="w-full text-left p-2.5 rounded-lg bg-slate-950 hover:bg-slate-800 border border-slate-800 transition-colors flex items-center justify-between group"
                      >
                        <div className="flex items-center gap-2 text-xs text-slate-200">
                          <Lock className="w-4 h-4 text-blue-400" />
                          <span>Tokens & Secret Findings</span>
                        </div>
                        <ArrowRight className="w-3.5 h-3.5 text-slate-500 group-hover:text-white transition-colors" />
                      </button>

                      <button
                        onClick={() => onNavigatePage && onNavigatePage('report_viewer')}
                        className="w-full text-left p-2.5 rounded-lg bg-slate-950 hover:bg-slate-800 border border-slate-800 transition-colors flex items-center justify-between group"
                      >
                        <div className="flex items-center gap-2 text-xs text-slate-200">
                          <FileCheck className="w-4 h-4 text-emerald-400" />
                          <span>Generate Forensic Report</span>
                        </div>
                        <ArrowRight className="w-3.5 h-3.5 text-slate-500 group-hover:text-white transition-colors" />
                      </button>
                    </div>
                  </div>

                  <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-2">
                    <h3 className="text-xs font-semibold text-slate-400 uppercase tracking-wider">
                      Forensic Integrity Check
                    </h3>
                    <div className="p-3 bg-emerald-950/40 border border-emerald-900/60 rounded-lg text-xs space-y-1 text-emerald-300">
                      <div className="flex items-center gap-1.5 font-medium">
                        <CheckCircle2 className="w-4 h-4 text-emerald-400" />
                        <span>Chain-of-Custody Verified</span>
                      </div>
                      <p className="text-[11px] text-emerald-400/80">
                        Original evidence file is immutable and read-only. Analysis was executed strictly on an isolated working copy.
                      </p>
                    </div>
                  </div>
                </div>
              </div>
            </>
          ) : (
            <div className="bg-slate-900 border border-slate-800 rounded-xl p-12 text-center space-y-4">
              <FolderOpen className="w-12 h-12 text-slate-600 mx-auto" />
              <h3 className="text-lg font-semibold text-white">No Target Evidence Loaded</h3>
              <p className="text-slate-400 text-xs max-w-md mx-auto">
                Select an existing investigation from History or ingest a new APK, Windows EXE, Linux ELF, or forensic document to perform deep static inspection.
              </p>
              <div className="pt-2">
                <button
                  onClick={() => onNavigatePage && onNavigatePage('new_investigation')}
                  className="px-4 py-2 bg-emerald-600 hover:bg-emerald-500 text-white rounded-lg text-xs font-medium transition-colors"
                >
                  Start New Ingestion
                </button>
              </div>
            </div>
          )}
        </div>
      )}

      {/* Tab: Engine Capabilities */}
      {activeTab === 'parsers' && (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
          <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-2">
            <div className="flex items-center gap-2 text-emerald-400 font-semibold text-sm">
              <FileCode2 className="w-5 h-5" />
              Android APK Forensics
            </div>
            <p className="text-xs text-slate-400">
              Parses AndroidManifest.xml, activities, services, intent filters, exported components, dangerous permissions, and DEX bytecode methods without runtime execution.
            </p>
            <div className="text-[11px] text-slate-500 font-mono pt-1">
              • Signature scheme detection (v1/v2/v3)<br />
              • SHA-256 certificate fingerprints<br />
              • JADX / Androguard bytecode decompilation
            </div>
          </div>

          <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-2">
            <div className="flex items-center gap-2 text-cyan-400 font-semibold text-sm">
              <Binary className="w-5 h-5" />
              Windows PE / DLL Forensics
            </div>
            <p className="text-xs text-slate-400">
              Inspects DOS/COFF/Optional headers, import tables, exported functions, section characteristics, W+X permissions, Shannon entropy, and Authenticode signatures.
            </p>
            <div className="text-[11px] text-slate-500 font-mono pt-1">
              • Section entropy & packer indicators<br />
              • Win32 API import capability analysis<br />
              • Persistence mechanism detection
            </div>
          </div>

          <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-2">
            <div className="flex items-center gap-2 text-purple-400 font-semibold text-sm">
              <Cpu className="w-5 h-5" />
              Linux ELF Binary Forensics
            </div>
            <p className="text-xs text-slate-400">
              Deconstructs 32/64-bit ELF headers, program header segments, section tables, DT_NEEDED dynamic libraries, symbol tables, and suspicious Linux syscall imports.
            </p>
            <div className="text-[11px] text-slate-500 font-mono pt-1">
              • Executable stack (PT_GNU_STACK) audit<br />
              • W+X segment detection (RWX)<br />
              • Memory injection API detection
            </div>
          </div>

          <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-2">
            <div className="flex items-center gap-2 text-amber-400 font-semibold text-sm">
              <FileCheck className="w-5 h-5" />
              Document & Media Forensics
            </div>
            <p className="text-xs text-slate-400">
              Deep static parsing of PDF objects, /JavaScript actions, /Launch directives, Office OOXML macros, and image EXIF/GPS coordinate metadata.
            </p>
            <div className="text-[11px] text-slate-500 font-mono pt-1">
              • PDF incremental update auditing<br />
              • EXIF camera & geolocation extraction<br />
              • Office VBA macro presence detection
            </div>
          </div>

          <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-2">
            <div className="flex items-center gap-2 text-blue-400 font-semibold text-sm">
              <Database className="w-5 h-5" />
              Container & Archive Triage
            </div>
            <p className="text-xs text-slate-400">
              Decompresses and inspects nested archive members (ZIP, TAR, GZ, 7Z, RAR) with strict Zip-Slip path traversal and decompression bomb defenses.
            </p>
            <div className="text-[11px] text-slate-500 font-mono pt-1">
              • Canonical path boundary enforcement<br />
              • Decompression ratio bounds (max 100:1)<br />
              • Child artifact relationship mapping
            </div>
          </div>

          <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-2">
            <div className="flex items-center gap-2 text-rose-400 font-semibold text-sm">
              <Flame className="w-5 h-5" />
              Signature & YARA Scanning
            </div>
            <p className="text-xs text-slate-400">
              Evaluates compiled YARA rule sets against evidence files. Identifies known ransomware signatures, webshells, packed droppers, and C2 infrastructure patterns.
            </p>
            <div className="text-[11px] text-slate-500 font-mono pt-1">
              • Fast multi-threaded rule matching<br />
              • Custom rule management & updates<br />
              • Immediate finding registration
            </div>
          </div>
        </div>
      )}

      {/* Tab: Safety Architecture */}
      {activeTab === 'safety' && (
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-6 space-y-6">
          <div className="border-b border-slate-800 pb-4">
            <h2 className="text-lg font-bold text-white flex items-center gap-2">
              <ShieldCheck className="w-5 h-5 text-emerald-400" />
              TraceX Zero-Execution Security Guarantees
            </h2>
            <p className="text-xs text-slate-400 mt-1">
              TraceX operates exclusively as a static digital forensics and evidence intelligence platform. Dynamic execution and malware detonation are permanently out of scope.
            </p>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs">
            <div className="p-4 bg-slate-950 rounded-lg border border-slate-800 space-y-2">
              <div className="font-semibold text-slate-200 flex items-center gap-1.5">
                <CheckCircle2 className="w-4 h-4 text-emerald-400" />
                1. No Binary Execution Invariant
              </div>
              <p className="text-slate-400">
                Uploaded executable files (EXE, DLL, APK, ELF, scripts) are never spawned, loaded, or executed by the operating system kernel or any VM worker. All parsing is performed as passive binary stream data reads.
              </p>
            </div>

            <div className="p-4 bg-slate-950 rounded-lg border border-slate-800 space-y-2">
              <div className="font-semibold text-slate-200 flex items-center gap-1.5">
                <CheckCircle2 className="w-4 h-4 text-emerald-400" />
                2. Immutable Original Evidence
              </div>
              <p className="text-slate-400">
                The intake pipeline stores the original evidence artifact in a read-only repository with computed SHA-256, SHA-512, MD5, and SHA-1 digests. All static analyzers operate on an isolated working replica.
              </p>
            </div>

            <div className="p-4 bg-slate-950 rounded-lg border border-slate-800 space-y-2">
              <div className="font-semibold text-slate-200 flex items-center gap-1.5">
                <CheckCircle2 className="w-4 h-4 text-emerald-400" />
                3. Cryptographic Chain-of-Custody
              </div>
              <p className="text-slate-400">
                Every acquisition, hash check, and analysis event is logged to a tamper-verifiable HMAC-SHA256 ledger protected by DPAPI master keys, ensuring court-admissible forensic integrity.
              </p>
            </div>

            <div className="p-4 bg-slate-950 rounded-lg border border-slate-800 space-y-2">
              <div className="font-semibold text-slate-200 flex items-center gap-1.5">
                <CheckCircle2 className="w-4 h-4 text-emerald-400" />
                4. Safe Host Isolation & Air-Gap
              </div>
              <p className="text-slate-400">
                TraceX is strictly 100% static digital forensics. Active network penetration scanning tools are completely excluded from evidence processing. Passive packet dissection (Wireshark/tshark, Zeek, Suricata) parses offline PCAPs without transmitting live packets.
              </p>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
