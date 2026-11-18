import React from 'react';
import { Shield, Radio, Terminal, RefreshCw, Menu } from 'lucide-react';
import { InvestigationRecord } from '../types';
import { ThemeToggle } from './ThemeToggle';

interface NavbarProps {
  currentInvestigation?: InvestigationRecord | null;
  activeJobsCount: number;
  networkMode: 'LOCAL_ONLY' | 'HYBRID';
  onOpenNetworkModal: () => void;
  onRefresh?: () => void;
  onNavigateNew: () => void;
  onToggleSidebar: () => void;
  sidebarCollapsed?: boolean;
}

export const Navbar: React.FC<NavbarProps> = ({
  currentInvestigation,
  activeJobsCount,
  networkMode,
  onOpenNetworkModal,
  onRefresh,
  onNavigateNew,
  onToggleSidebar,
  sidebarCollapsed = false,
}) => {
  return (
    <header className="h-16 border-b border-app bg-topbar/95 backdrop-blur px-4 md:px-6 flex items-center justify-between sticky top-0 z-20 select-none transition-colors">
      {/* Left: Hamburger & Brand */}
      <div className="flex items-center gap-3">
        {/* Three-Line Hamburger Button */}
        <button
          onClick={onToggleSidebar}
          type="button"
          aria-label={sidebarCollapsed ? 'Expand sidebar' : 'Collapse sidebar'}
          aria-expanded={!sidebarCollapsed}
          className="p-2 rounded-lg border border-app bg-surface hover:bg-card-hover text-app-secondary hover:text-app-primary transition-all cursor-pointer flex items-center justify-center focus:outline-none focus:ring-2 focus:ring-cyan-500/40"
          title={sidebarCollapsed ? 'Expand navigation' : 'Collapse navigation'}
        >
          <Menu className="w-5 h-5 text-app-primary" />
        </button>

        {/* Brand Icon & Name */}
        <div className="flex items-center gap-2.5">
          <div className="w-9 h-9 rounded-lg bg-[#0B132B] border border-cyan-500/50 flex items-center justify-center shadow-md shrink-0 overflow-hidden p-1">
            <img src="/tracex_icon.svg" alt="TraceX Logo" className="w-full h-full object-contain" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <span className="font-bold tracking-tight text-app-primary font-mono text-sm">
                Trace<span className="text-cyan-500 dark:text-cyan-400">X</span>
              </span>
              <span className="text-[10px] bg-cyan-100 text-cyan-800 border border-cyan-300 dark:bg-cyan-950/80 dark:text-cyan-300 dark:border-cyan-800 px-1.5 py-0.5 rounded font-mono font-bold">
                FORENSICS
              </span>
            </div>
            <p className="hidden sm:block text-[11px] text-app-muted font-mono truncate max-w-xs md:max-w-none">
              Discover. Analyze. Investigate.
            </p>
          </div>
        </div>
      </div>

      {/* Right: Active Target, Local/Hybrid, Theme Toggle, New Investigation */}
      <div className="flex items-center gap-2.5 sm:gap-3">
        {/* Active Target Chip */}
        {currentInvestigation && (
          <div className="hidden lg:flex items-center gap-2 bg-surface border border-app px-3 py-1 rounded-lg text-xs font-mono">
            <span className="text-app-muted font-bold">TARGET:</span>
            <span className="text-cyan-600 dark:text-cyan-300 font-semibold truncate max-w-[140px] xl:max-w-[200px]">
              {currentInvestigation.filename}
            </span>
            <span className="text-app-muted">|</span>
            <span className="text-[10px] font-bold px-1.5 py-0.2 rounded uppercase bg-surface-subtle border border-app text-app-secondary">
              {currentInvestigation.file_type?.toUpperCase() || 'APK'}
            </span>
          </div>
        )}

        {/* Network Privacy & Connection Mode Interactive Button */}
        <button
          onClick={onOpenNetworkModal}
          type="button"
          aria-label="Configure Network Privacy & Connection Settings"
          title="Click to configure Network Privacy & Connection Mode"
          className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg border text-xs font-mono transition-all cursor-pointer focus:outline-none focus:ring-2 ${
            networkMode === 'LOCAL_ONLY'
              ? 'bg-amber-500/10 border-amber-500/40 text-amber-700 dark:text-amber-300 hover:bg-amber-500/20 focus:ring-amber-500/40'
              : 'bg-emerald-500/10 border-emerald-500/40 text-emerald-700 dark:text-emerald-300 hover:bg-emerald-500/20 focus:ring-emerald-500/40'
          }`}
        >
          <Radio className={`w-3.5 h-3.5 ${networkMode === 'LOCAL_ONLY' ? 'text-amber-500 animate-pulse' : 'text-emerald-500'}`} />
          <span className="font-bold tracking-wider">
            {networkMode === 'LOCAL_ONLY' ? 'LOCAL ONLY' : 'HYBRID'}
          </span>
          <span className="text-[10px] opacity-70 underline ml-0.5 hidden xl:inline">CONFIG</span>
        </button>

        {/* Active Analysis Jobs Counter */}
        {activeJobsCount > 0 && (
          <div className="flex items-center gap-2 px-2.5 py-1 rounded-lg bg-indigo-50 text-indigo-700 border border-indigo-200 dark:bg-indigo-950/70 dark:border-indigo-800 dark:text-indigo-300 text-xs font-mono">
            <RefreshCw className="w-3 h-3 animate-spin text-indigo-500" />
            <span className="font-semibold">{activeJobsCount} PIPELINE</span>
          </div>
        )}

        {/* Light / Dark Mode Toggle */}
        <ThemeToggle />

        {/* New Investigation Button */}
        <button
          onClick={onNavigateNew}
          type="button"
          className="bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-mono px-3 py-2 rounded-lg font-bold tracking-wide flex items-center gap-1.5 shadow-sm transition-all cursor-pointer focus:outline-none focus:ring-2 focus:ring-cyan-500/40"
        >
          <Terminal className="w-3.5 h-3.5 shrink-0" />
          <span className="hidden sm:inline">NEW INVESTIGATION</span>
        </button>
      </div>
    </header>
  );
};

