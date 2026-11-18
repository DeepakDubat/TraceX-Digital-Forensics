import React, { useState, useEffect, Suspense, lazy } from 'react';
import { Navbar } from './components/Navbar';
import { Sidebar, PageId } from './components/Sidebar';
import { DashboardPage } from './pages/DashboardPage';
import { NetworkPrivacyModal } from './components/NetworkPrivacyModal';
import { api } from './api';
import { DashboardStats, InvestigationDetail } from './types';

// Route-based code-splitting for performance optimization
const NewInvestigationPage = lazy(() => import('./pages/NewInvestigationPage').then(m => ({ default: m.NewInvestigationPage })));
const AnalysisProgressPage = lazy(() => import('./pages/AnalysisProgressPage').then(m => ({ default: m.AnalysisProgressPage })));
const StaticAnalysisPage = lazy(() => import('./pages/StaticAnalysisPage').then(m => ({ default: m.StaticAnalysisPage })));
const C2IntelligencePage = lazy(() => import('./pages/C2IntelligencePage').then(m => ({ default: m.C2IntelligencePage })));
const TokenSecretsPage = lazy(() => import('./pages/TokenSecretsPage').then(m => ({ default: m.TokenSecretsPage })));
const ReverseShellPage = lazy(() => import('./pages/ReverseShellPage').then(m => ({ default: m.ReverseShellPage })));
const ThreatIntelPage = lazy(() => import('./pages/ThreatIntelPage').then(m => ({ default: m.ThreatIntelPage })));
const IpDetailsPage = lazy(() => import('./pages/IpDetailsPage').then(m => ({ default: m.IpDetailsPage })));
const EvidenceGraphPage = lazy(() => import('./pages/EvidenceGraphPage').then(m => ({ default: m.EvidenceGraphPage })));
const HistoryPage = lazy(() => import('./pages/HistoryPage').then(m => ({ default: m.HistoryPage })));
const ToolConfigPage = lazy(() => import('./pages/ToolConfigPage').then(m => ({ default: m.ToolConfigPage })));
const ReportViewerPage = lazy(() => import('./pages/ReportViewerPage').then(m => ({ default: m.ReportViewerPage })));
const OSINTInvestigationPage = lazy(() => import('./pages/OSINTInvestigationPage').then(m => ({ default: m.OSINTInvestigationPage })));
const AuthorizedNetworkValidationPage = lazy(() => import('./pages/AuthorizedNetworkValidationPage').then(m => ({ default: m.AuthorizedNetworkValidationPage })));
const StaticWorkspacePage = lazy(() => import('./pages/StaticWorkspacePage').then(m => ({ default: m.StaticWorkspacePage })));
const CorrelationRiskPage = lazy(() => import('./pages/CorrelationRiskPage').then(m => ({ default: m.CorrelationRiskPage })));

const PageLoadingFallback: React.FC = () => (
  <div className="flex-1 h-full min-h-[400px] flex flex-col items-center justify-center p-8 text-center select-none">
    <div className="relative w-12 h-12 mb-4">
      <div className="absolute inset-0 rounded-full border-2 border-cyan-500/20 animate-ping" />
      <div className="w-12 h-12 rounded-full border-2 border-t-cyan-500 border-r-cyan-500 border-b-transparent border-l-transparent animate-spin" />
    </div>
    <div className="font-mono text-xs uppercase tracking-widest text-cyan-400 font-semibold mb-1">
      INITIALIZING FORENSIC MODULE
    </div>
    <div className="font-mono text-[11px] text-app-muted">
      Loading analytical components and telemetry views...
    </div>
  </div>
);

export const App: React.FC = () => {
  const [currentPage, setCurrentPage] = useState<PageId>('dashboard');
  const [currentInvestigationId, setCurrentInvestigationId] = useState<string | null>(null);
  const [currentDetail, setCurrentDetail] = useState<InvestigationDetail | null>(null);
  const [stats, setStats] = useState<DashboardStats | null>(null);
  const [statsLoading, setStatsLoading] = useState(true);

  //Authoritative global network privacy mode (LOCAL_ONLY | HYBRID)
  const [networkMode, setNetworkMode] = useState<'LOCAL_ONLY' | 'HYBRID'>('LOCAL_ONLY');
  const [isNetworkModalOpen, setIsNetworkModalOpen] = useState(false);

  // Load authoritative network privacy mode
  useEffect(() => {
    api.getNetworkMode()
      .then((res) => {
        if (res?.mode) {
          setNetworkMode(res.mode);
        }
      })
      .catch((err) => {
        console.warn('Failed to load initial network mode:', err);
      });
  }, []);

  const handleNetworkModeChanged = (newMode: 'LOCAL_ONLY' | 'HYBRID') => {
    setNetworkMode(newMode);
    window.dispatchEvent(new CustomEvent('tracex-network-mode-changed', { detail: { mode: newMode } }));
  };

  // Sidebar collapse state (desktop)
  const [sidebarCollapsed, setSidebarCollapsed] = useState<boolean>(() => {
    return localStorage.getItem('forensics_sidebar_collapsed') === 'true';
  });

  // Mobile sidebar drawer state
  const [mobileSidebarOpen, setMobileSidebarOpen] = useState(false);

  // Toggle desktop sidebar collapse
  const handleToggleSidebar = () => {
    // If on small screen, toggle mobile drawer
    if (window.innerWidth < 1024) {
      setMobileSidebarOpen(!mobileSidebarOpen);
    } else {
      setSidebarCollapsed((prev) => {
        const next = !prev;
        localStorage.setItem('forensics_sidebar_collapsed', String(next));
        return next;
      });
    }
  };

  // Close mobile drawer on Escape key
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape' && mobileSidebarOpen) {
        setMobileSidebarOpen(false);
      }
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [mobileSidebarOpen]);

  // Load stats
  const refreshStats = async () => {
    try {
      const data = await api.getDashboardStats();
      setStats(data);
    } catch (err) {
      console.error('Failed to load stats', err);
    } finally {
      setStatsLoading(false);
    }
  };

  useEffect(() => {
    refreshStats();
    const interval = setInterval(refreshStats, 8000);
    return () => clearInterval(interval);
  }, []);

  // When an investigation is selected, load its full details
  const selectInvestigation = async (id: string, targetPage: PageId = 'static_findings') => {
    setCurrentInvestigationId(id);
    try {
      const detail = await api.getInvestigationDetail(id);
      setCurrentDetail(detail);
      if (detail.record.status === 'analyzing') {
        setCurrentPage('progress');
      } else {
        setCurrentPage(targetPage);
      }
    } catch (err) {
      console.error(err);
      setCurrentPage('dashboard');
    }
  };

  // Investigation created callback
  const handleInvestigationCreated = (id: string) => {
    setCurrentInvestigationId(id);
    selectInvestigation(id, 'progress');
    refreshStats();
  };

  const handleAnalysisCompleted = async () => {
    if (currentInvestigationId) {
      try {
        const detail = await api.getInvestigationDetail(currentInvestigationId);
        setCurrentDetail(detail);
      } catch (err) {
        console.error(err);
      }
    }
    refreshStats();
  };

  // Calculate unique IP count for sidebar badge matching backend extractor
  const ipCount = React.useMemo(() => {
    if (!currentDetail) return 0;
    const ips = new Set<string>();
    const ipv4Regex = /\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b/g;

    currentDetail.network_iocs?.forEach(ioc => {
      if (ioc.ioc_type === 'ipv4' || ioc.ioc_type === 'ipv6') {
        ips.add(ioc.value.trim());
      } else if (ioc.value) {
        const matches = ioc.value.match(ipv4Regex);
        matches?.forEach(m => ips.add(m));
      }
    });

    currentDetail.c2_indicators?.forEach(c2 => {
      const val = c2.normalized_value || c2.value || '';
      if (c2.indicator_type === 'ip') {
        ips.add(val.trim());
      } else if (val) {
        const matches = val.match(ipv4Regex);
        matches?.forEach(m => ips.add(m));
      }
    });

    currentDetail.static_findings?.forEach(f => {
      const text = `${f.title || ''} ${f.description || ''} ${f.evidence_snippet || ''} ${f.technical_explanation || ''}`;
      const matches = text.match(ipv4Regex);
      matches?.forEach(m => {
        if (m !== '0.0.0.0' && m !== '255.255.255.255') ips.add(m);
      });
    });

    return ips.size;
  }, [currentDetail]);

  return (
    <div className="h-screen w-screen overflow-hidden flex flex-row bg-app text-app-primary font-sans selection:bg-cyan-500/20 selection:text-cyan-800 dark:selection:text-cyan-200">
      {/* Desktop Fixed Sidebar */}
      <div className="hidden lg:flex flex-shrink-0 z-30">
        <Sidebar
          currentPage={currentPage}
          onSelectPage={setCurrentPage}
          hasActiveTarget={Boolean(currentDetail)}
          reverseShellDetected={currentDetail?.record?.reverse_shell_detected}
          c2Count={currentDetail?.c2_indicators?.length || 0}
          ipCount={ipCount}
          secretCount={currentDetail?.secrets?.length || 0}
          fileType={currentDetail?.record?.file_type}
          persistenceCount={currentDetail?.persistence_findings?.length || 0}
          collapsed={sidebarCollapsed}
          onToggleCollapse={handleToggleSidebar}
        />
      </div>

      {/* Mobile Off-canvas Drawer */}
      {mobileSidebarOpen && (
        <div className="fixed inset-0 z-50 flex lg:hidden">
          {/* Backdrop */}
          <div
            className="fixed inset-0 bg-black/60 backdrop-blur-xs transition-opacity"
            onClick={() => setMobileSidebarOpen(false)}
            aria-hidden="true"
          />

          {/* Drawer content */}
          <div className="relative z-10 flex">
            <Sidebar
              currentPage={currentPage}
              onSelectPage={setCurrentPage}
              hasActiveTarget={Boolean(currentDetail)}
              reverseShellDetected={currentDetail?.record?.reverse_shell_detected}
              c2Count={currentDetail?.c2_indicators?.length || 0}
              ipCount={ipCount}
              secretCount={currentDetail?.secrets?.length || 0}
              fileType={currentDetail?.record?.file_type}
              persistenceCount={currentDetail?.persistence_findings?.length || 0}
              isMobile={true}
              onCloseMobile={() => setMobileSidebarOpen(false)}
            />
          </div>
        </div>
      )}

      {/* Main Application Area */}
      <div className="flex-1 h-screen flex flex-col overflow-hidden min-w-0">
        {/* Fixed Topbar Header */}
        <Navbar
          currentInvestigation={currentDetail?.record}
          activeJobsCount={stats?.active_running_tasks || 0}
          networkMode={networkMode}
          onOpenNetworkModal={() => setIsNetworkModalOpen(true)}
          onRefresh={refreshStats}
          onNavigateNew={() => setCurrentPage('new_investigation')}
          onToggleSidebar={handleToggleSidebar}
          sidebarCollapsed={sidebarCollapsed}
        />

        {/* Scrollable Page Content */}
        <main className="flex-1 overflow-y-auto overflow-x-hidden bg-app relative">
          <Suspense fallback={<PageLoadingFallback />}>
            {currentPage === 'dashboard' && (
              <DashboardPage
                stats={stats}
                loading={statsLoading}
                onSelectInvestigation={(id) => selectInvestigation(id, 'static_findings')}
                onNavigateNew={() => setCurrentPage('new_investigation')}
              />
            )}

            {currentPage === 'new_investigation' && (
              <NewInvestigationPage onInvestigationCreated={handleInvestigationCreated} />
            )}

            {currentPage === 'osint_pivot' && (
              <OSINTInvestigationPage
                currentDetail={currentDetail}
                onSelectInvestigation={(id) => selectInvestigation(id, 'osint_pivot')}
              />
            )}

            {currentPage === 'progress' && currentInvestigationId && (
              <AnalysisProgressPage
                investigationId={currentInvestigationId}
                onAnalysisCompleted={handleAnalysisCompleted}
                onViewReport={() => setCurrentPage('report_viewer')}
              />
            )}

            {currentPage === 'static_findings' && currentDetail && (
              <StaticAnalysisPage detail={currentDetail} />
            )}

            {currentPage === 'c2_intel' && currentDetail && (
              <C2IntelligencePage detail={currentDetail} />
            )}

            {currentPage === 'ip_details' && currentDetail && (
              <IpDetailsPage detail={currentDetail} networkMode={networkMode} />
            )}

            {currentPage === 'secrets' && currentDetail && (
              <TokenSecretsPage detail={currentDetail} />
            )}

            {currentPage === 'reverse_shell' && currentDetail && (
              <ReverseShellPage detail={currentDetail} />
            )}

            {currentPage === 'threat_intel' && currentDetail && (
              <ThreatIntelPage detail={currentDetail} />
            )}

            {currentPage === 'network_validation' && currentDetail && (
              <AuthorizedNetworkValidationPage detail={currentDetail} />
            )}

            {currentPage === 'static_workspace' && (
              <StaticWorkspacePage
                detail={currentDetail}
                onSelectInvestigation={(id) => selectInvestigation(id, 'static_workspace')}
                onNavigatePage={(p) => setCurrentPage(p as PageId)}
              />
            )}

            {currentPage === 'correlation_risk' && currentDetail && (
              <CorrelationRiskPage detail={currentDetail} />
            )}

            {currentPage === 'evidence_graph' && currentDetail && (
              <EvidenceGraphPage detail={currentDetail} />
            )}

            {currentPage === 'history' && (
              <HistoryPage onSelectInvestigation={(id) => selectInvestigation(id, 'static_findings')} />
            )}

            {currentPage === 'tool_config' && <ToolConfigPage />}

            {currentPage === 'report_viewer' && currentDetail && (
              <ReportViewerPage detail={currentDetail} />
            )}
          </Suspense>
        </main>
      </div>

      {/* Network Privacy & Connection Settings Modal */}
      <NetworkPrivacyModal
        isOpen={isNetworkModalOpen}
        currentMode={networkMode}
        onClose={() => setIsNetworkModalOpen(false)}
        onModeChanged={handleNetworkModeChanged}
      />
    </div>
  );
};

export default App;

