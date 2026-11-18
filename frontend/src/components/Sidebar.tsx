import React from 'react';
import {
  LayoutDashboard,
  UploadCloud,
  Activity,
  FileCode2,
  RadioTower,
  KeyRound,
  TerminalSquare,
  Globe,
  Network,
  History,
  Sliders,
  FileText,
  X,
  ChevronLeft,
  ChevronRight,
  ShieldAlert,
  Bot,
  Layers,
  Share2,
  ShieldCheck,
  Cpu,
  GitMerge
} from 'lucide-react';

export type PageId =
  | 'dashboard'
  | 'new_investigation'
  | 'progress'
  | 'static_findings'
  | 'c2_intel'
  | 'ip_details'
  | 'secrets'
  | 'reverse_shell'
  | 'threat_intel'
  | 'osint_pivot'
  | 'network_validation'
  | 'static_workspace'
  | 'correlation_risk'
  | 'evidence_graph'
  | 'report_viewer'
  | 'history'
  | 'tool_config';

interface SidebarProps {
  currentPage: PageId;
  onSelectPage: (page: PageId) => void;
  hasActiveTarget: boolean;
  reverseShellDetected?: boolean;
  c2Count?: number;
  ipCount?: number;
  secretCount?: number;
  fileType?: 'apk' | 'exe' | 'multi' | 'generic';
  persistenceCount?: number;
  collapsed?: boolean;
  onToggleCollapse?: () => void;
  isMobile?: boolean;
  onCloseMobile?: () => void;
}

interface NavItem {
  id: PageId;
  label: string;
  icon: any;
  requiresTarget?: boolean;
  badge?: string | number;
  badgeColor?: string;
}

interface NavGroup {
  group: string;
  items: NavItem[];
}

export const Sidebar: React.FC<SidebarProps> = ({
  currentPage,
  onSelectPage,
  hasActiveTarget,
  reverseShellDetected,
  c2Count = 0,
  ipCount = 0,
  secretCount = 0,
  fileType = 'apk',
  persistenceCount = 0,
  collapsed = false,
  onToggleCollapse,
  isMobile = false,
  onCloseMobile,
}) => {
  const isExe = fileType === 'exe';

  const navItems: NavGroup[] = [
    {
      group: 'PRIMARY WORKSPACE',
      items: [
        { id: 'dashboard' as PageId, label: 'Overview Dashboard', icon: LayoutDashboard },
        { id: 'new_investigation' as PageId, label: 'New Investigation', icon: UploadCloud },
        { id: 'static_workspace' as PageId, label: 'Static Analysis Workspace', icon: ShieldCheck, requiresTarget: false },
        { id: 'progress' as PageId, label: 'Analysis Progress', icon: Activity, requiresTarget: true },
        { id: 'history' as PageId, label: 'Investigation History', icon: History },
      ],
    },
    {
      group: isExe ? 'WINDOWS PE EVIDENCE' : 'FORENSIC ANALYSIS',
      items: [
        {
          id: 'static_findings' as PageId,
          label: isExe ? 'PE Headers & Sections' : 'Static Findings',
          icon: FileCode2,
          requiresTarget: true,
        },
        {
          id: 'c2_intel' as PageId,
          label: 'C2 & Network Indicators',
          icon: RadioTower,
          requiresTarget: true,
          badge: c2Count > 0 ? c2Count : undefined,
          badgeColor: 'bg-amber-100 text-amber-900 border-amber-300 dark:bg-amber-950 dark:text-amber-300 dark:border-amber-800',
        },
        {
          id: 'ip_details' as PageId,
          label: 'IP Details',
          icon: Globe,
          requiresTarget: true,
          badge: ipCount > 0 ? ipCount : undefined,
          badgeColor: 'bg-cyan-100 text-cyan-900 border-cyan-300 dark:bg-cyan-950 dark:text-cyan-300 dark:border-cyan-800',
        },
        {
          id: 'secrets' as PageId,
          label: 'Tokens & Secrets',
          icon: KeyRound,
          requiresTarget: true,
          badge: secretCount > 0 ? secretCount : undefined,
          badgeColor: 'bg-blue-100 text-blue-900 border-blue-300 dark:bg-blue-950 dark:text-blue-300 dark:border-blue-800',
        },
        {
          id: 'reverse_shell' as PageId,
          label: isExe ? 'Persistence & Autostart' : 'Persistence & Remote Access',
          icon: TerminalSquare,
          requiresTarget: true,
          badge: isExe
            ? (persistenceCount > 0 ? persistenceCount : undefined)
            : (reverseShellDetected ? 'ALERT' : undefined),
          badgeColor: 'bg-rose-100 text-rose-900 border-rose-300 dark:bg-rose-950 dark:text-rose-300 dark:border-rose-800 animate-pulse',
        },
        { id: 'threat_intel' as PageId, label: 'Threat Intelligence', icon: Globe, requiresTarget: true },
        { id: 'osint_pivot' as PageId, label: 'OSINT & Pivots', icon: Share2, requiresTarget: false },
        { id: 'correlation_risk' as PageId, label: 'Correlation & Risk', icon: GitMerge, requiresTarget: true },
        { id: 'evidence_graph' as PageId, label: 'Evidence Graph', icon: Network, requiresTarget: true },
      ],
    },
    {
      group: 'TOOLS & REPORTING',
      items: [
        { id: 'report_viewer' as PageId, label: 'Report & Downloads', icon: FileText, requiresTarget: true },
        { id: 'tool_config' as PageId, label: 'Integration Manager', icon: Sliders },
      ],
    },
  ];

  const handleItemClick = (id: PageId, isDisabled?: boolean) => {
    if (isDisabled) return;
    onSelectPage(id);
    if (isMobile && onCloseMobile) {
      onCloseMobile();
    }
  };

  return (
    <aside
      className={`h-screen bg-sidebar border-r border-app flex flex-col select-none transition-all duration-300 z-30 flex-shrink-0 ${
        isMobile
          ? 'w-72 shadow-2xl'
          : collapsed
          ? 'w-[72px]'
          : 'w-64'
      }`}
    >
      {/* Mobile Header with Close Button */}
      {isMobile && (
        <div className="p-4 border-b border-app flex items-center justify-between">
          <span className="font-mono font-bold text-sm text-app-primary">FORENSICS MENU</span>
          <button
            onClick={onCloseMobile}
            className="p-1.5 rounded-md hover:bg-surface text-app-secondary hover:text-app-primary transition-colors cursor-pointer"
            aria-label="Close menu"
          >
            <X className="w-5 h-5" />
          </button>
        </div>
      )}

      {/* Nav List - Independent Vertical Scroll */}
      <div className="flex-1 py-4 px-2 space-y-5 overflow-y-auto overflow-x-hidden">
        {navItems.map((group, gIdx) => (
          <div key={gIdx} className="space-y-1">
            {!collapsed && (
              <h3 className="text-[11px] uppercase font-mono tracking-wider text-app-secondary dark:text-slate-300 font-bold px-3 mb-1.5 truncate">
                {group.group}
              </h3>
            )}
            {collapsed && gIdx > 0 && (
              <div className="border-t border-app my-2 mx-2" />
            )}

            {group.items.map((item) => {
              const Icon = item.icon;
              const isActive = currentPage === item.id;
              const isDisabled = item.requiresTarget && !hasActiveTarget;

              return (
                <button
                  key={item.id}
                  onClick={() => handleItemClick(item.id, isDisabled)}
                  disabled={isDisabled}
                  title={collapsed ? `${item.label}${item.badge ? ` (${item.badge})` : ''}` : undefined}
                  className={`w-full flex items-center ${
                    collapsed ? 'justify-center px-0 py-2.5' : 'justify-between px-3 py-2'
                  } rounded-lg font-mono text-xs transition-all relative group cursor-pointer ${
                    isActive
                      ? 'bg-cyan-50 text-cyan-700 border border-cyan-200 dark:bg-cyan-950/70 dark:text-cyan-300 dark:border-cyan-800 shadow-sm font-bold'
                      : isDisabled
                      ? 'text-app-muted opacity-40 cursor-not-allowed'
                      : 'text-app-primary dark:text-slate-100 hover:text-cyan-700 dark:hover:text-cyan-300 hover:bg-surface font-medium'
                  }`}
                >
                  <div className={`flex items-center gap-3 ${collapsed ? 'justify-center' : 'truncate'}`}>
                    <Icon
                      className={`w-4 h-4 shrink-0 transition-transform ${
                        isActive
                          ? 'text-cyan-600 dark:text-cyan-400 scale-110'
                          : 'text-app-secondary dark:text-slate-400 group-hover:text-app-primary'
                      }`}
                    />
                    {!collapsed && <span className="truncate text-xs">{item.label}</span>}
                  </div>

                  {/* Badge */}
                  {!collapsed && item.badge && (
                    <span
                      className={`text-[10px] px-1.5 py-0.5 rounded font-mono font-bold border ${item.badgeColor}`}
                    >
                      {item.badge}
                    </span>
                  )}

                  {/* Collapsed dot indicator when badge exists */}
                  {collapsed && item.badge && (
                    <span className="absolute top-1.5 right-2 w-2 h-2 rounded-full bg-cyan-500 animate-pulse" />
                  )}
                </button>
              );
            })}
          </div>
        ))}
      </div>

      {/* Forensic Station Footer */}
      <div className="p-3 border-t border-app bg-surface-subtle">
        {!collapsed ? (
          <div className="space-y-1">
            <div className="text-[11px] font-mono text-app-secondary flex items-center justify-between font-semibold">
              <span>SAFE FORENSIC LAB</span>
              <span className="text-emerald-600 dark:text-emerald-400 font-bold">AIR-GAP SAFE</span>
            </div>
            <p className="text-[11px] text-app-muted font-mono truncate">
              Passive Static Analysis Engine
            </p>
          </div>
        ) : (
          <div className="flex justify-center" title="Safe Forensic Lab: Air-Gap Safe">
            <div className="w-2.5 h-2.5 rounded-full bg-emerald-500" />
          </div>
        )}
      </div>
    </aside>
  );
};

