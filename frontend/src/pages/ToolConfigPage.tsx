import React, { useState, useEffect, useRef, useMemo } from 'react';
import {
  CheckCircle2,
  XCircle,
  AlertTriangle,
  Save,
  Lock,
  Cpu,
  RefreshCw,
  Info,
  ExternalLink,
  Eye,
  EyeOff,
  Server,
  Terminal,
  ShieldCheck,
  Globe,
  Activity,
  Key,
  Search,
  Trash2,
  ShieldAlert,
  Monitor,
  Layers,
  FolderOpen,
  Filter,
  Check,
  X,
  Wrench
} from 'lucide-react';
import { api } from '../api';
import { ToolExecution } from '../types';

interface LocalToolStatusItem {
  id: string;
  name: string;
  installed: boolean;
  version?: string;
  executable_path?: string;
  path_configured?: boolean;
  status?: string;
  test_status?: string;
  diagnostic_message?: string;
  details?: Record<string, any>;
}

export interface ProviderCatalogItem {
  id: string;
  name: string;
  category: 'threat_intel' | 'osint' | 'sandboxes' | 'local_tools' | 'network_analysis' | 'utilities' | string;
  description: string;
  requires_credentials: boolean;
  is_local_tool: boolean;
  credential_type: string;
  auth_type?: string;
  supports_oauth?: boolean;
  fields: Array<{
    key: string;
    label: string;
    type: string;
    placeholder?: string;
    help_text?: string;
  }>;
  register_url?: string;
  docs_url?: string;
  install_url?: string;
  rate_limits?: string;
  privacy_note?: string;
  is_configured: boolean;
  is_valid: boolean;
  status: string;
  status_badge: string;
  display_status?: string;
  last_tested_at?: string;
  last_error_code?: string;
  last_error_message?: string;
  account_identifier?: string;
  token_expires_at?: string;
  masked_values?: Record<string, string>;
  fingerprint?: string;
}

interface SummaryCounters {
  total: number;
  connected: number;
  credentials_saved: number;
  not_configured: number;
  authentication_failed: number;
  local_tools_available: number;
}

export const ToolConfigPage: React.FC = () => {
  const isMounted = useRef(true);

  // Diagnostic State
  const [tools, setTools] = useState<ToolExecution[]>([]);
  const [dbStatus, setDbStatus] = useState<any>(null);
  const [backendStatus, setBackendStatus] = useState<any>(null);

  // BYOK Credentials Catalog, Summary & Master Key State
  const [credentialsCatalog, setCredentialsCatalog] = useState<ProviderCatalogItem[]>([]);
  const [summaryCounters, setSummaryCounters] = useState<SummaryCounters | null>(null);
  const [localToolStatus, setLocalToolStatus] = useState<Record<string, LocalToolStatusItem>>({});
  const [masterKeyInfo, setMasterKeyInfo] = useState<{
    status: string;
    key_source: string;
    encryption_algorithm: string;
    zero_plaintext_guarantee: boolean;
  } | null>(null);

  // UI Filtering & Search
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedCategory, setSelectedCategory] = useState<string>('all');
  const [statusFilter, setStatusFilter] = useState<'all' | 'connected' | 'saved' | 'not_configured' | 'failed'>('all');

  // Input editing state per provider: provider_id -> { fieldKey: value }
  const [editedCreds, setEditedCreds] = useState<Record<string, Record<string, string>>>({});
  const [showSecrets, setShowSecrets] = useState<Record<string, boolean>>({});

  // Loading States
  const [initialProbing, setInitialProbing] = useState<boolean>(true);
  const [refreshingAll, setRefreshingAll] = useState<boolean>(false);
  const [savingProvider, setSavingProvider] = useState<string | null>(null);
  const [statusMessage, setStatusMessage] = useState<{ type: 'success' | 'error' | 'info'; text: string } | null>(null);

  // Testing states
  const [testingTools, setTestingTools] = useState<Record<string, boolean>>({});
  const [testResults, setTestResults] = useState<Record<string, {
    success: boolean;
    connected?: boolean;
    status: string;
    message: string;
    actionable_hint?: string;
    error_code?: string;
    details?: any;
    model_count?: number;
    test_timestamp?: string;
  }>>({});

  // Gemini Auth Mode Toggle (OAuth vs API Key)
  const [geminiAuthMode, setGeminiAuthMode] = useState<'oauth' | 'api_key'>('api_key');

  // OpenCode CLI Integration State
  const [openCodeStatus, setOpenCodeStatus] = useState<import('../types').OpenCodeStatus | null>(null);
  const [testingOpenCodeAnalysis, setTestingOpenCodeAnalysis] = useState(false);

  useEffect(() => {
    isMounted.current = true;
    fetchAllData();

    const handleModeChange = (e: any) => {
      const mode = e.detail?.mode;
      if (mode === 'HYBRID') {
        setTestResults((prev) => {
          const next = { ...prev };
          for (const [k, v] of Object.entries(next)) {
            if ((v as any).status?.toUpperCase().includes('LOCAL-ONLY') || (v as any).message?.toUpperCase().includes('LOCAL-ONLY')) {
              delete next[k];
            }
          }
          return next;
        });
      }
      fetchAllData();
    };

    window.addEventListener('tracex-network-mode-changed', handleModeChange);

    return () => {
      isMounted.current = false;
      window.removeEventListener('tracex-network-mode-changed', handleModeChange);
    };
  }, []);

  const refreshLocalToolStatus = async () => {
    try {
      const data = await api.getLocalToolsStatus();
      if (!isMounted.current) return;
      const map: Record<string, LocalToolStatusItem> = {};
      for (const item of data.tools || []) map[item.id] = item;
      setLocalToolStatus(map);
    } catch (e) {
      // Non-fatal: cards fall back to the catalog status.
    }
  };

  const fetchAllData = async () => {
    setRefreshingAll(true);

    const results = await Promise.allSettled([
      api.getTools(),
      api.getDatabaseHealth(),
      api.getBackendHealth(),
      api.getCredentialsCatalog(),
      api.getMasterKeyStatus(),
      api.getLocalToolsStatus(),
      api.getCredentialsSummary(),
      api.getOpenCodeStatus(),
    ]);

    if (!isMounted.current) return;

    // 1. Tools
    if (results[0].status === 'fulfilled') setTools(results[0].value);

    // 2. Database Health
    if (results[1].status === 'fulfilled') {
      setDbStatus(results[1].value);
    } else {
      setDbStatus({ success: false, status: 'UNREACHABLE', diagnostic_message: 'Database probe failed.' });
    }

    // 3. Backend Health
    if (results[2].status === 'fulfilled') {
      setBackendStatus(results[2].value);
    } else {
      setBackendStatus({ success: false, status: 'OFFLINE', diagnostic_message: 'Backend service offline.' });
    }

    // 4. Credentials Catalog
    if (results[3].status === 'fulfilled') {
      const catalog: ProviderCatalogItem[] = results[3].value;
      setCredentialsCatalog(catalog);

      const initialEdits: Record<string, Record<string, string>> = {};
      for (const item of catalog) {
        if (item.masked_values) {
          initialEdits[item.id] = { ...item.masked_values };
        }
        if (item.id === 'gemini' && item.auth_type === 'oauth2') {
          setGeminiAuthMode('oauth');
        }
      }
      setEditedCreds(initialEdits);
    }

    // 5. Master Key
    if (results[4].status === 'fulfilled') setMasterKeyInfo(results[4].value);

    // 6. Local Forensic Tool runtime status
    if (results[5].status === 'fulfilled') {
      const map: Record<string, LocalToolStatusItem> = {};
      for (const item of (results[5].value.tools || [])) map[item.id] = item;
      setLocalToolStatus(map);
    }

    // 7. Authoritative Backend Summary Counters
    if (results[6].status === 'fulfilled') {
      setSummaryCounters(results[6].value);
    }

    // 8. OpenCode CLI Status
    if (results[7]?.status === 'fulfilled') {
      setOpenCodeStatus(results[7].value);
    }

    setInitialProbing(false);
    setRefreshingAll(false);
  };

  // Re-synchronize catalog and summary after any mutation
  const syncStateAfterMutation = async (providerId?: string) => {
    try {
      const [cat, sum] = await Promise.all([
        api.getCredentialsCatalog(),
        api.getCredentialsSummary(),
      ]);
      if (isMounted.current) {
        setCredentialsCatalog(cat);
        setSummaryCounters(sum);
        if (providerId) {
          const updatedItem = cat.find((c: any) => c.id === providerId);
          if (updatedItem && updatedItem.masked_values) {
            setEditedCreds((prev) => ({
              ...prev,
              [providerId]: { ...updatedItem.masked_values },
            }));
          }
        }
      }
    } catch (e) {
      // Non-fatal
    }
  };

  // OAuth Connect Trigger (Google Gemini)
  const handleStartOAuth = async (providerId: string) => {
    setStatusMessage(null);
    try {
      const res = await api.startOAuthFlow(providerId);
      if (res && res.authorization_url) {
        api.openPortal(res.authorization_url);
      }
    } catch (err: any) {
      setStatusMessage({
        type: 'error',
        text: err.message || `Failed to initiate OAuth flow for ${providerId}.`
      });
    }
  };

  // OAuth Disconnect Trigger
  const handleDisconnectOAuth = async (providerId: string) => {
    try {
      await api.disconnectOAuth(providerId);
      setStatusMessage({ type: 'info', text: `Disconnected from ${providerId}.` });
      await syncStateAfterMutation(providerId);
    } catch (err: any) {
      setStatusMessage({ type: 'error', text: err.message || `Failed to disconnect ${providerId}.` });
    }
  };

  const handleToggleOpenCodeEnabled = async () => {
    if (!openCodeStatus) return;
    try {
      const newEnabled = !openCodeStatus.enabled;
      const res = await api.updateOpenCodeConfig({ enabled: newEnabled });
      if (res.status) setOpenCodeStatus(res.status);
      setStatusMessage({
        type: 'success',
        text: `OpenCode CLI AI assistance ${newEnabled ? 'enabled' : 'disabled'}.`
      });
    } catch (e: any) {
      setStatusMessage({ type: 'error', text: `Failed to toggle OpenCode: ${e.message}` });
    }
  };

  const handleTestOpenCodeAnalysis = async () => {
    setTestingOpenCodeAnalysis(true);
    try {
      const res = await api.testOpenCodeAnalysis(true);
      setStatusMessage({
        type: res.success ? 'success' : 'error',
        text: res.success
          ? `Synthetic analysis verified: ${res.observations_count} observations, ${res.recommendations_count} recommendations.`
          : (res.warnings_or_errors?.[0] || 'Synthetic test analysis failed.')
      });
    } catch (e: any) {
      setStatusMessage({ type: 'error', text: `Synthetic test analysis failed: ${e.message}` });
    } finally {
      setTestingOpenCodeAnalysis(false);
    }
  };

  // Direct Online Login / Connect Action
  const handleOnlineConnect = (provider: ProviderCatalogItem) => {
    if (provider.id === 'gemini' && geminiAuthMode === 'oauth') {
      handleStartOAuth('gemini');
      return;
    }
    const targetUrl = provider.register_url || provider.docs_url;
    if (targetUrl) {
      api.openPortal(targetUrl);
    }
  };

  // Save Provider Credentials (transitions state to CREDENTIAL SAVED)
  const handleSaveProviderCredentials = async (provider: ProviderCatalogItem) => {
    setSavingProvider(provider.id);
    setStatusMessage(null);

    try {
      const dataToSave = editedCreds[provider.id] || {};
      const res = await api.saveProviderCredential(provider.id, dataToSave, provider.credential_type);

      setStatusMessage({
        type: 'success',
        text: res.message || `Credentials for ${provider.name} encrypted and saved securely. Click 'Test Connection' to verify live connectivity.`,
      });

      // Clear previous local test outcome so status badge explicitly reflects CREDENTIAL SAVED
      setTestResults((prev) => {
        const copy = { ...prev };
        delete copy[provider.id];
        return copy;
      });

      await syncStateAfterMutation(provider.id);

      if (provider.is_local_tool) {
        await refreshLocalToolStatus();
      }
    } catch (err: any) {
      if (isMounted.current) {
        setStatusMessage({
          type: 'error',
          text: err.message || `Failed to save credentials for ${provider.name}.`,
        });
      }
    } finally {
      if (isMounted.current) setSavingProvider(null);
    }
  };

  // Delete Provider Credentials
  const handleDeleteProviderCredentials = async (provider: ProviderCatalogItem) => {
    if (!window.confirm(`Are you sure you want to permanently remove credentials for ${provider.name}?`)) {
      return;
    }

    try {
      await api.deleteProviderCredential(provider.id);
      setStatusMessage({
        type: 'info',
        text: `Credentials for ${provider.name} permanently purged from encrypted storage.`,
      });

      setEditedCreds((prev) => ({
        ...prev,
        [provider.id]: {},
      }));

      setTestResults((prev) => {
        const copy = { ...prev };
        delete copy[provider.id];
        return copy;
      });

      await syncStateAfterMutation(provider.id);
    } catch (err: any) {
      setStatusMessage({
        type: 'error',
        text: err.message || `Failed to purge credentials for ${provider.name}.`,
      });
    }
  };

  // Test Provider Credential
  const handleTestProvider = async (provider: ProviderCatalogItem) => {
    setTestingTools((prev) => ({ ...prev, [provider.id]: true }));

    try {
      // Strip masked placeholder asterisks so we don't send literal '****' to live APIs
      const inputValues = editedCreds[provider.id] || {};
      const cleanData: Record<string, any> = {};
      for (const [k, v] of Object.entries(inputValues)) {
        if (typeof v === 'string' && (v.includes('****') || v.includes('••••') || v.trim() === '')) {
          continue;
        }
        cleanData[k] = v;
      }

      const res = await api.testProviderCredential(
        provider.id,
        Object.keys(cleanData).length > 0 ? cleanData : undefined
      );

      if (isMounted.current) {
        setTestResults((prev) => ({
          ...prev,
          [provider.id]: {
            success: Boolean(res.connected || res.success),
            connected: Boolean(res.connected || res.success),
            status: res.status || (res.connected ? 'CONNECTED' : 'FAILED'),
            message: res.message || 'Connection test completed.',
            actionable_hint: (res as any).actionable_hint,
            error_code: (res as any).error_code,
            model_count: (res as any).model_count,
            details: res.details,
            test_timestamp: new Date().toLocaleTimeString(),
          },
        }));

        await syncStateAfterMutation(provider.id);

        if (provider.is_local_tool) {
          await refreshLocalToolStatus();
        }
      }
    } catch (err: any) {
      if (isMounted.current) {
        setTestResults((prev) => ({
          ...prev,
          [provider.id]: {
            success: false,
            connected: false,
            status: 'CONNECTION ERROR',
            message: err.message || 'Connection test failed. Network timeout or unreachable host.',
            test_timestamp: new Date().toLocaleTimeString(),
          },
        }));
      }
    } finally {
      if (isMounted.current) {
        setTestingTools((prev) => ({ ...prev, [provider.id]: false }));
      }
    }
  };

  // Handle Input Changes
  const handleInputChange = (providerId: string, fieldKey: string, value: string) => {
    setEditedCreds((prev) => ({
      ...prev,
      [providerId]: {
        ...(prev[providerId] || {}),
        [fieldKey]: value,
      },
    }));
  };

  // Open host-native file picker for a local tool path
  const handleBrowsePath = async (provider: ProviderCatalogItem, fieldKey: string) => {
    try {
      const isRulesField = provider.id === 'yara';
      const res = await api.browseFile(
        isRulesField ? 'Select YARA rules file' : `Select ${provider.name} executable`,
        undefined,
        isRulesField
          ? [['YARA rule files', '*.yar *.yara'], ['All files', '*.*']]
          : [['Executable / JAR files', '*.bat *.cmd *.exe *.jar'], ['All files', '*.*']]
      );
      if (res.success && res.path) {
        handleInputChange(provider.id, fieldKey, res.path.replace(/\//g, '\\'));
      } else if (res.error) {
        setStatusMessage({ type: 'error', text: res.error });
      }
    } catch (err: any) {
      setStatusMessage({
        type: 'error',
        text: err.message || 'Could not open the native file picker. You can type the path manually.',
      });
    }
  };

  // Toggle secret visibility
  const toggleSecretVisibility = (fieldId: string) => {
    setShowSecrets((prev) => ({
      ...prev,
      [fieldId]: !prev[fieldId],
    }));
  };

  // Categories definition (6 Canonical Forensic Groups)
  const categories = [
    { id: 'all', label: 'All Integrations', icon: Layers },
    { id: 'threat_intel', label: 'Threat Intelligence', icon: ShieldAlert },
    { id: 'osint', label: 'OSINT & IOC Enrichment', icon: Globe },
    { id: 'local_tools', label: 'Local Forensic Tools', icon: Terminal },
    { id: 'network_analysis', label: 'Passive Network Analysis', icon: Activity },
    { id: 'utilities', label: 'Utilities & Other Integrations', icon: Wrench },
  ];

  // Helper to determine active status across 10 authoritative statuses
  const getProviderStatus = (provider: ProviderCatalogItem) => {
    const currentTest = testResults[provider.id];
    if (currentTest) {
      if (currentTest.connected || currentTest.success) {
        return { badge: 'verified', label: currentTest.status || 'CONNECTED', status: 'CONNECTED' };
      }
      const isAuthErr =
        currentTest.error_code === '401' ||
        (currentTest.status || '').includes('401') ||
        (currentTest.message || '').toLowerCase().includes('auth') ||
        (currentTest.message || '').toLowerCase().includes('key') ||
        (currentTest.message || '').toLowerCase().includes('unauthorized');
      return {
        badge: isAuthErr ? 'auth_failed' : 'invalid',
        label: currentTest.status || (isAuthErr ? 'AUTHENTICATION FAILED (401)' : 'CONNECTION ERROR'),
        status: isAuthErr ? 'AUTHENTICATION_FAILED' : 'CONNECTION_ERROR'
      };
    }

    const canonical = provider.status || 'NOT_CONFIGURED';
    const badge = provider.status_badge || 'not_configured';
    const label = provider.display_status || canonical;
    return { badge, label, status: canonical };
  };

  // Reactive summary counters with backend fallback
  const activeStats = useMemo(() => {
    if (summaryCounters) {
      // If there are ephemeral in-flight test outcomes that succeeded, adjust connected
      let connDelta = 0;
      let saveDelta = 0;
      for (const [pid, res] of Object.entries(testResults)) {
        const item = credentialsCatalog.find((c) => c.id === pid);
        if (item && item.status === 'CREDENTIAL_SAVED' && res.success) {
          connDelta++;
          saveDelta++;
        }
      }
      return {
        total: summaryCounters.total || credentialsCatalog.length,
        connected: summaryCounters.connected + connDelta,
        credentials_saved: Math.max(0, summaryCounters.credentials_saved - saveDelta),
        not_configured: summaryCounters.not_configured,
        authentication_failed: summaryCounters.authentication_failed,
        local_tools_available: summaryCounters.local_tools_available,
      };
    }

    // Fallback: derive directly from catalog
    const total = credentialsCatalog.length;
    let connected = 0;
    let credentials_saved = 0;
    let not_configured = 0;
    let authentication_failed = 0;
    let local_tools_available = 0;

    for (const item of credentialsCatalog) {
      const st = getProviderStatus(item);
      if (st.status === 'CONNECTED') {
        connected++;
        if (item.is_local_tool) local_tools_available++;
      } else if (st.status === 'CREDENTIAL_SAVED') {
        credentials_saved++;
      } else if (st.status === 'NOT_CONFIGURED') {
        not_configured++;
      } else if (
        st.status === 'AUTHENTICATION_FAILED' ||
        st.status === 'TOKEN_EXPIRED' ||
        st.badge === 'auth_failed' ||
        st.badge === 'invalid'
      ) {
        authentication_failed++;
      }
    }

    return { total, connected, credentials_saved, not_configured, authentication_failed, local_tools_available };
  }, [summaryCounters, credentialsCatalog, testResults]);

  // Counts for categories
  const categoryCounts = useMemo(() => {
    const counts: Record<string, number> = { all: credentialsCatalog.length };
    for (const item of credentialsCatalog) {
      counts[item.category] = (counts[item.category] || 0) + 1;
    }
    return counts;
  }, [credentialsCatalog]);

  // Global matches across all categories for active search query
  const globalSearchMatchesCount = useMemo(() => {
    if (!searchQuery.trim()) return 0;
    const query = searchQuery.toLowerCase().trim();
    return credentialsCatalog.filter((item) => {
      const st = getProviderStatus(item);
      const matchName = (item.name || '').toLowerCase().includes(query);
      const matchDesc = (item.description || '').toLowerCase().includes(query);
      const matchId = (item.id || '').toLowerCase().includes(query);
      const matchProvider = ((item as any).provider || '').toLowerCase().includes(query);
      const matchAuth = (item.auth_type || '').toLowerCase().includes(query);
      const matchCategory = (item.category || '').toLowerCase().includes(query);
      const matchStatus = (st.label || '').toLowerCase().includes(query) || (st.status || '').toLowerCase().includes(query);
      return matchName || matchDesc || matchId || matchProvider || matchAuth || matchCategory || matchStatus;
    }).length;
  }, [credentialsCatalog, searchQuery, testResults]);

  // Filtered providers
  const filteredProviders = useMemo(() => {
    return credentialsCatalog.filter((item) => {
      // Category filter
      if (selectedCategory !== 'all') {
        if (item.category !== selectedCategory) return false;
      }

      // Status filter
      const st = getProviderStatus(item);
      if (statusFilter === 'connected' && st.status !== 'CONNECTED') return false;
      if (statusFilter === 'saved' && st.status !== 'CREDENTIAL_SAVED') return false;
      if (statusFilter === 'not_configured' && st.status !== 'NOT_CONFIGURED' && st.status !== 'NOT_INSTALLED') return false;
      if (statusFilter === 'failed' && st.status !== 'AUTHENTICATION_FAILED' && st.badge !== 'auth_failed' && st.badge !== 'invalid') return false;

      // Deep multi-field Search Query
      if (searchQuery.trim()) {
        const query = searchQuery.toLowerCase().trim();
        const matchName = (item.name || '').toLowerCase().includes(query);
        const matchDesc = (item.description || '').toLowerCase().includes(query);
        const matchId = (item.id || '').toLowerCase().includes(query);
        const matchProvider = ((item as any).provider || '').toLowerCase().includes(query);
        const matchAuth = (item.auth_type || '').toLowerCase().includes(query);
        const matchCategory = (item.category || '').toLowerCase().includes(query);
        const matchStatus = (st.label || '').toLowerCase().includes(query) || (st.status || '').toLowerCase().includes(query);

        if (!matchName && !matchDesc && !matchId && !matchProvider && !matchAuth && !matchCategory && !matchStatus) {
          return false;
        }
      }
      return true;
    });
  }, [credentialsCatalog, selectedCategory, statusFilter, searchQuery, testResults]);

  // Render Status Badge across the 10 authoritative statuses
  const renderStatusBadge = (statusLabel: string, badgeType: string, isChecking = false) => {
    if (isChecking) {
      return (
        <span className="text-[11px] font-bold px-2.5 py-1 rounded font-mono uppercase bg-blue-100 text-blue-800 border border-blue-300 dark:bg-blue-950/80 dark:text-blue-300 dark:border-blue-800 flex items-center gap-1.5 shadow-xs">
          <RefreshCw className="w-3 h-3 animate-spin text-blue-600 dark:text-blue-400" />
          <span>VERIFYING...</span>
        </span>
      );
    }

    const s = (statusLabel || '').toUpperCase();

    if (badgeType === 'verified' || s.includes('CONNECTED') || s.includes('INSTALLED') || s.includes('HEALTHY') || s.includes('ONLINE')) {
      return (
        <span className="text-[11px] font-bold px-2.5 py-1 rounded font-mono uppercase bg-emerald-100 text-emerald-800 border border-emerald-300 dark:bg-emerald-950/80 dark:text-emerald-300 dark:border-emerald-800 flex items-center gap-1.5 shadow-xs">
          <CheckCircle2 className="w-3.5 h-3.5 text-emerald-600 dark:text-emerald-400" />
          <span>{statusLabel}</span>
        </span>
      );
    }

    if (badgeType === 'local_only_blocked' || s.includes('BLOCKED BY LOCAL-ONLY') || s.includes('LOCAL-ONLY MODE')) {
      return (
        <span className="text-[11px] font-bold px-2.5 py-1 rounded font-mono uppercase bg-amber-100 text-amber-800 border border-amber-300 dark:bg-amber-950/80 dark:text-amber-300 dark:border-amber-800 flex items-center gap-1.5 shadow-xs">
          <Lock className="w-3.5 h-3.5 text-amber-600 dark:text-amber-400" />
          <span>BLOCKED BY LOCAL-ONLY MODE</span>
        </span>
      );
    }

    if (badgeType === 'configured' || s.includes('CREDENTIAL SAVED') || s.includes('PATH CONFIGURED')) {
      return (
        <span className="text-[11px] font-bold px-2.5 py-1 rounded font-mono uppercase bg-sky-100 text-sky-800 border border-sky-300 dark:bg-sky-950/80 dark:text-sky-300 dark:border-sky-800 flex items-center gap-1.5 shadow-xs">
          <ShieldCheck className="w-3.5 h-3.5 text-sky-600 dark:text-sky-400" />
          <span>CREDENTIAL SAVED</span>
        </span>
      );
    }

    if (s.includes('RATE LIMITED') || s.includes('EXPIRED') || s.includes('429')) {
      return (
        <span className="text-[11px] font-bold px-2.5 py-1 rounded font-mono uppercase bg-amber-100 text-amber-800 border border-amber-300 dark:bg-amber-950/80 dark:text-amber-300 dark:border-amber-800 flex items-center gap-1.5 shadow-xs">
          <AlertTriangle className="w-3.5 h-3.5 text-amber-600 dark:text-amber-400" />
          <span>{statusLabel}</span>
        </span>
      );
    }

    if (badgeType === 'not_configured' || s.includes('NOT CONFIGURED') || s.includes('NOT INSTALLED')) {
      return (
        <span className="text-[11px] font-bold px-2.5 py-1 rounded font-mono uppercase bg-slate-100 text-slate-700 border border-slate-300 dark:bg-slate-800 dark:text-slate-300 dark:border-slate-700 flex items-center gap-1.5 shadow-xs">
          <Info className="w-3.5 h-3.5 text-slate-500" />
          <span>{statusLabel}</span>
        </span>
      );
    }

    return (
      <span className="text-[11px] font-bold px-2.5 py-1 rounded font-mono uppercase bg-rose-100 text-rose-800 border border-rose-300 dark:bg-rose-950/80 dark:text-rose-300 dark:border-rose-800 flex items-center gap-1.5 shadow-xs">
        <XCircle className="w-3.5 h-3.5 text-rose-600 dark:text-rose-400" />
        <span>{statusLabel}</span>
      </span>
    );
  };

  return (
    <div className="p-4 sm:p-6 md:p-8 space-y-6 max-w-7xl mx-auto selection:bg-cyan-500/20">
      {/* Top Header & Station Status */}
      <div className="border-b border-app pb-5 flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-3 flex-wrap">
            <h1 className="text-xl md:text-2xl font-bold text-app-primary tracking-tight font-mono">
              Integration Manager &amp; Tool Hub
            </h1>
            <span className="text-xs bg-sky-100 dark:bg-sky-950 text-sky-800 dark:text-sky-300 border border-sky-300 dark:border-sky-800 px-2.5 py-1 rounded-md font-mono font-bold flex items-center gap-1.5">
              <ShieldCheck className="w-3.5 h-3.5 text-sky-600 dark:text-sky-400" />
              <span>STATION: LOCAL WORKSTATION</span>
            </span>
          </div>
          <p className="text-xs sm:text-sm text-app-secondary mt-1">
            Configure external threat intelligence feeds, AI engines, and local forensic binaries with AES-128 DPAPI protection.
          </p>
        </div>

        {/* Global Action Bar */}
        <div className="flex items-center gap-3 flex-wrap">
          <div className="flex items-center gap-2 bg-slate-100 dark:bg-slate-800/80 px-3 py-1.5 rounded-lg border border-slate-300 dark:border-slate-700 text-xs font-mono">
            <Monitor className="w-3.5 h-3.5 text-indigo-500" />
            <span className="text-app-secondary">DPAPI Master Key:</span>
            <span className="font-bold text-emerald-600 dark:text-emerald-400 uppercase">ACTIVE</span>
          </div>

          <button
            onClick={fetchAllData}
            disabled={refreshingAll}
            className="inline-flex items-center gap-2 px-3.5 py-2 text-xs font-medium rounded-lg border border-app bg-app-card text-app-primary hover:bg-app-hover shadow-xs transition-colors cursor-pointer"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${refreshingAll ? 'animate-spin text-cyan-500' : ''}`} />
            <span>{refreshingAll ? 'Probing...' : 'Refresh All'}</span>
          </button>
        </div>
      </div>

      {/* Top Statistics Banner (6 Real-Data Authoritative Counters) */}
      <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-3 sm:gap-4">
        {/* 1. TOTAL INTEGRATIONS */}
        <div
          className="bg-app-card border border-app rounded-xl p-3.5 flex flex-col justify-between shadow-xs hover:border-slate-400 transition-colors"
          title="Total forensic integrations and engines catalogued in TraceX"
        >
          <div className="flex items-center justify-between text-app-secondary text-xs font-mono">
            <span>TOTAL</span>
            <Layers className="w-4 h-4 text-slate-400" />
          </div>
          <div className="text-2xl font-bold font-mono text-app-primary mt-2">
            {activeStats.total}
          </div>
          <div className="text-[10px] text-app-muted mt-0.5">Catalogued tools</div>
        </div>

        {/* 2. CONNECTED */}
        <div
          className="bg-app-card border border-emerald-300/40 dark:border-emerald-800/40 rounded-xl p-3.5 flex flex-col justify-between shadow-xs hover:border-emerald-500 transition-colors"
          title="Verified live APIs and installed local forensic tools ready for analysis"
        >
          <div className="flex items-center justify-between text-emerald-700 dark:text-emerald-300 text-xs font-mono font-semibold">
            <span>CONNECTED</span>
            <CheckCircle2 className="w-4 h-4 text-emerald-500" />
          </div>
          <div className="text-2xl font-bold font-mono text-emerald-600 dark:text-emerald-400 mt-2">
            {activeStats.connected}
          </div>
          <div className="text-[10px] text-emerald-600/70 dark:text-emerald-400/70 mt-0.5">Live API &amp; binary verified</div>
        </div>

        {/* 3. CREDENTIALS SAVED / UNVERIFIED */}
        <div
          className="bg-app-card border border-sky-300/40 dark:border-sky-800/40 rounded-xl p-3.5 flex flex-col justify-between shadow-xs hover:border-sky-500 transition-colors"
          title="Credentials securely encrypted and saved in DPAPI storage, awaiting test verification"
        >
          <div className="flex items-center justify-between text-sky-700 dark:text-sky-300 text-xs font-mono font-semibold">
            <span>SAVED / UNVERIFIED</span>
            <ShieldCheck className="w-4 h-4 text-sky-500" />
          </div>
          <div className="text-2xl font-bold font-mono text-sky-600 dark:text-sky-400 mt-2">
            {activeStats.credentials_saved}
          </div>
          <div className="text-[10px] text-sky-600/70 dark:text-sky-400/70 mt-0.5">Pending test verification</div>
        </div>

        {/* 4. NOT CONFIGURED */}
        <div
          className="bg-app-card border border-app rounded-xl p-3.5 flex flex-col justify-between shadow-xs hover:border-slate-400 transition-colors"
          title="Remote feeds and AI integrations with no API key or token configured"
        >
          <div className="flex items-center justify-between text-app-secondary text-xs font-mono">
            <span>NOT CONFIGURED</span>
            <Info className="w-4 h-4 text-slate-400" />
          </div>
          <div className="text-2xl font-bold font-mono text-slate-600 dark:text-slate-300 mt-2">
            {activeStats.not_configured}
          </div>
          <div className="text-[10px] text-app-muted mt-0.5">Awaiting user setup</div>
        </div>

        {/* 5. AUTHENTICATION FAILED */}
        <div
          className="bg-app-card border border-rose-300/40 dark:border-rose-800/40 rounded-xl p-3.5 flex flex-col justify-between shadow-xs hover:border-rose-500 transition-colors"
          title="Integrations where connection test returned 401 Unauthorized, 403 Forbidden, or expired token"
        >
          <div className="flex items-center justify-between text-rose-700 dark:text-rose-300 text-xs font-mono font-semibold">
            <span>AUTH FAILED</span>
            <XCircle className="w-4 h-4 text-rose-500" />
          </div>
          <div className="text-2xl font-bold font-mono text-rose-600 dark:text-rose-400 mt-2">
            {activeStats.authentication_failed}
          </div>
          <div className="text-[10px] text-rose-600/70 dark:text-rose-400/70 mt-0.5">Invalid key or expired token</div>
        </div>

        {/* 6. LOCAL TOOLS AVAILABLE */}
        <div
          className="bg-app-card border border-teal-300/40 dark:border-teal-800/40 rounded-xl p-3.5 flex flex-col justify-between shadow-xs hover:border-teal-500 transition-colors"
          title="Air-gapped static parsers, decompilers, and local engines verified on this machine"
        >
          <div className="flex items-center justify-between text-teal-700 dark:text-teal-300 text-xs font-mono font-semibold">
            <span>LOCAL ENGINES</span>
            <Terminal className="w-4 h-4 text-teal-500" />
          </div>
          <div className="text-2xl font-bold font-mono text-teal-600 dark:text-teal-400 mt-2">
            {activeStats.local_tools_available}
          </div>
          <div className="text-[10px] text-teal-600/70 dark:text-teal-400/70 mt-0.5">Air-gapped static parsers</div>
        </div>
      </div>

      {/* Security Architecture Guarantee Banner */}
      <div className="bg-gradient-to-r from-slate-900 via-slate-850 to-indigo-950 text-white rounded-xl p-4 sm:p-5 border border-indigo-800/60 shadow-md">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
          <div className="flex items-start gap-3">
            <div className="p-2.5 bg-indigo-600/30 rounded-lg border border-indigo-500/40 mt-0.5">
              <Lock className="w-5 h-5 text-indigo-400" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <span className="font-bold text-sm text-indigo-100">Zero Cloud Leakage &amp; Windows DPAPI Master Key Wrapping</span>
                <span className="text-[10px] bg-emerald-500/20 text-emerald-300 border border-emerald-500/40 px-2 py-0.5 rounded font-mono font-bold">
                  AES-128-CBC / Fernet
                </span>
              </div>
              <p className="text-xs text-indigo-200/80 mt-1 max-w-3xl">
                All external API keys, tokens, and binary paths are encrypted at rest with the workstation platform master key and bound to your Windows user security context. Sensitive keys are decrypted strictly in ephemeral memory at request dispatch.
              </p>
            </div>
          </div>

          {masterKeyInfo && (
            <div className="bg-slate-950/70 p-2.5 rounded-lg border border-indigo-900 text-right text-xs font-mono space-y-0.5 shrink-0">
              <div className="text-indigo-300 text-[10px]">MASTER KEY SOURCE:</div>
              <div className="text-emerald-400 font-bold uppercase">{masterKeyInfo.key_source}</div>
            </div>
          )}
        </div>
      </div>

      {/* Real-time Status Alert Banner */}
      {statusMessage && (
        <div
          className={`p-3.5 rounded-lg border text-xs sm:text-sm flex items-center justify-between shadow-xs ${
            statusMessage.type === 'success'
              ? 'bg-emerald-50 text-emerald-900 border-emerald-300 dark:bg-emerald-950/50 dark:text-emerald-200 dark:border-emerald-800'
              : statusMessage.type === 'error'
              ? 'bg-rose-50 text-rose-900 border-rose-300 dark:bg-rose-950/50 dark:text-rose-200 dark:border-rose-800'
              : 'bg-blue-50 text-blue-900 border-blue-300 dark:bg-blue-950/50 dark:text-blue-200 dark:border-blue-800'
          }`}
        >
          <span>{statusMessage.text}</span>
          <button onClick={() => setStatusMessage(null)} className="font-bold text-xs hover:opacity-75 cursor-pointer ml-3">
            ✕
          </button>
        </div>
      )}

      {/* Main Content Layout: Compact Category Sidebar + Cards Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-4 gap-6 items-start">
        {/* Left Column: Category Selector & Filter Panel */}
        <div className="lg:col-span-1 space-y-4">
          <div className="bg-app-card border border-app rounded-xl p-4 shadow-xs space-y-4">
            {/* Search Input */}
            <div className="space-y-1.5">
              <label className="text-[11px] font-bold text-app-secondary uppercase font-mono tracking-wider">
                Search Tools
              </label>
              <div className="relative">
                <Search className="w-4 h-4 text-slate-400 absolute left-3 top-2.5 pointer-events-none" />
                <input
                  type="text"
                  value={searchQuery}
                  onChange={(e) => setSearchQuery(e.target.value)}
                  placeholder="Filter by name, ID, provider..."
                  className="w-full pl-9 pr-8 py-1.5 text-xs bg-slate-50 dark:bg-slate-900 border border-app rounded-md text-app-primary placeholder:text-slate-400 focus:outline-none focus:ring-2 focus:ring-cyan-500 font-mono"
                />
                {searchQuery && (
                  <button
                    type="button"
                    onClick={() => setSearchQuery('')}
                    className="absolute right-2 top-2 text-slate-400 hover:text-slate-600 dark:hover:text-slate-200 cursor-pointer p-0.5 rounded"
                    title="Clear search"
                  >
                    <X className="w-3.5 h-3.5" />
                  </button>
                )}
              </div>
            </div>

            {/* Status Filter */}
            <div className="space-y-1.5">
              <label className="text-[11px] font-bold text-app-secondary uppercase font-mono tracking-wider flex items-center gap-1.5">
                <Filter className="w-3.5 h-3.5 text-slate-400" />
                <span>Status Filter</span>
              </label>
              <select
                value={statusFilter}
                onChange={(e) => setStatusFilter(e.target.value as any)}
                aria-label="Filter integrations by status"
                className="w-full text-xs font-mono bg-slate-50 dark:bg-slate-900 border border-app rounded-md px-2.5 py-1.5 text-app-primary focus:outline-none focus:ring-2 focus:ring-cyan-500 cursor-pointer"
              >
                <option value="all">All Statuses ({credentialsCatalog.length})</option>
                <option value="connected">Connected / Installed ({activeStats.connected})</option>
                <option value="saved">Credential Saved ({activeStats.credentials_saved})</option>
                <option value="not_configured">Not Configured ({activeStats.not_configured})</option>
                <option value="failed">Authentication Failed ({activeStats.authentication_failed})</option>
              </select>
            </div>

            {/* Categories Vertical Navigation */}
            <div className="space-y-1 pt-2 border-t border-app">
              <label className="text-[11px] font-bold text-app-secondary uppercase font-mono tracking-wider block mb-2">
                Categories
              </label>
              <nav className="space-y-1">
                {categories.map((cat) => {
                  const Icon = cat.icon;
                  const count = categoryCounts[cat.id] || 0;
                  const isActive = selectedCategory === cat.id;

                  return (
                    <button
                      key={cat.id}
                      onClick={() => setSelectedCategory(cat.id)}
                      className={`w-full flex items-center justify-between px-3 py-2 rounded-lg text-xs font-medium transition-colors cursor-pointer ${
                        isActive
                          ? 'bg-cyan-50 text-cyan-700 dark:bg-cyan-950/60 dark:text-cyan-300 font-bold border border-cyan-200 dark:border-cyan-800/60'
                          : 'text-app-secondary hover:text-app-primary hover:bg-slate-100 dark:hover:bg-slate-800/60'
                      }`}
                    >
                      <div className="flex items-center gap-2.5 truncate">
                        <Icon className={`w-4 h-4 shrink-0 ${isActive ? 'text-cyan-600 dark:text-cyan-400' : 'text-slate-400'}`} />
                        <span className="truncate">{cat.label}</span>
                      </div>
                      <span
                        className={`text-[10px] px-2 py-0.5 rounded-full font-mono font-bold shrink-0 ${
                          isActive
                            ? 'bg-cyan-600 text-white dark:bg-cyan-500 dark:text-slate-900'
                            : 'bg-slate-200 dark:bg-slate-800 text-slate-700 dark:text-slate-300'
                        }`}
                      >
                        {count}
                      </span>
                    </button>
                  );
                })}
              </nav>
            </div>
          </div>
        </div>

        {/* Right Column: Integration Cards Grid */}
        <div className="lg:col-span-3 space-y-4">
          {/* Cross-Category Search Banner */}
          {searchQuery.trim() && selectedCategory !== 'all' && globalSearchMatchesCount > filteredProviders.length && (
            <div className="bg-cyan-50 dark:bg-cyan-950/40 border border-cyan-300 dark:border-cyan-800 rounded-xl p-3 flex flex-col sm:flex-row items-start sm:items-center justify-between gap-2 text-xs font-mono text-cyan-900 dark:text-cyan-200">
              <span>
                Found <strong>{filteredProviders.length}</strong> match{filteredProviders.length === 1 ? '' : 'es'} in current category, and <strong>{globalSearchMatchesCount}</strong> total across all categories.
              </span>
              <button
                type="button"
                onClick={() => setSelectedCategory('all')}
                className="px-2.5 py-1 rounded-md bg-cyan-600 hover:bg-cyan-700 text-white font-bold shrink-0 text-xs shadow-xs cursor-pointer"
              >
                Show All {globalSearchMatchesCount} Matches
              </button>
            </div>
          )}

          {/* Active Filter Header */}
          <div className="flex items-center justify-between text-xs font-mono text-app-secondary px-1">
            <span>
              Showing <strong>{filteredProviders.length}</strong> of <strong>{credentialsCatalog.length}</strong> integrations
            </span>
            {(searchQuery || statusFilter !== 'all' || selectedCategory !== 'all') && (
              <button
                onClick={() => {
                  setSearchQuery('');
                  setStatusFilter('all');
                  setSelectedCategory('all');
                }}
                className="text-cyan-600 hover:text-cyan-700 dark:text-cyan-400 underline cursor-pointer"
              >
                Reset Filters
              </button>
            )}
          </div>

          {/* Cards Grid or Empty State */}
          {filteredProviders.length === 0 ? (
            <div className="bg-app-card border border-app rounded-xl p-8 text-center space-y-3">
              <Search className="w-8 h-8 text-slate-400 mx-auto" />
              <div className="text-sm font-bold text-app-primary">No integration tools found</div>
              <p className="text-xs text-app-secondary max-w-md mx-auto">
                No tools matched your search <strong>"{searchQuery}"</strong>
                {selectedCategory !== 'all' ? ` in category "${categories.find((c: any) => c.id === selectedCategory)?.label || selectedCategory}"` : ''}
                {statusFilter !== 'all' ? ` with status "${statusFilter}"` : ''}.
              </p>
              <div className="flex flex-wrap items-center justify-center gap-3 pt-2">
                {selectedCategory !== 'all' && globalSearchMatchesCount > 0 && (
                  <button
                    type="button"
                    onClick={() => setSelectedCategory('all')}
                    className="px-3 py-1.5 rounded-lg bg-cyan-600 hover:bg-cyan-700 text-white text-xs font-mono font-medium shadow-sm cursor-pointer"
                  >
                    Search Across All Categories ({globalSearchMatchesCount} matches)
                  </button>
                )}
                <button
                  type="button"
                  onClick={() => {
                    setSearchQuery('');
                    setStatusFilter('all');
                    setSelectedCategory('all');
                  }}
                  className="px-3 py-1.5 rounded-lg border border-app bg-surface hover:bg-slate-200 dark:hover:bg-slate-800 text-app-primary text-xs font-mono font-medium cursor-pointer"
                >
                  Reset All Filters
                </button>
              </div>
            </div>
          ) : (
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              {filteredProviders.map((provider) => {
              const currentTest = testResults[provider.id];
              const isTesting = testingTools[provider.id] || false;
              const isSaving = savingProvider === provider.id;
              const st = getProviderStatus(provider);
              const isGemini = provider.id === 'gemini';
              const isOAuthConnected = provider.auth_type === 'oauth2' && provider.is_configured;
              const isLocalTool = provider.is_local_tool;
              const lt = localToolStatus[provider.id];

              return (
                <div
                  key={provider.id}
                  className="bg-app-card border border-app rounded-xl p-5 flex flex-col justify-between space-y-4 hover:border-cyan-500/50 transition-all shadow-xs hover:shadow-md"
                >
                  <div className="space-y-3.5">
                    {/* Header with Title and Live Status Badge */}
                    <div className="flex items-start justify-between gap-3">
                      <div>
                        <div className="flex items-center gap-2 flex-wrap">
                          <h3 className="font-bold text-sm sm:text-base text-app-primary font-mono">{provider.name}</h3>
                          <span className="text-[10px] font-mono uppercase bg-slate-100 text-slate-700 dark:bg-slate-800 dark:text-slate-300 border border-slate-300 dark:border-slate-700 px-1.5 py-0.5 rounded">
                            {provider.category.replace('_', ' ')}
                          </span>
                          {provider.supports_oauth && (
                            <span className="text-[10px] font-mono font-bold bg-violet-100 text-violet-800 dark:bg-violet-950 dark:text-violet-300 border border-violet-300 dark:border-violet-800 px-1.5 py-0.5 rounded">
                              OAuth 2.0 PKCE
                            </span>
                          )}
                        </div>
                        <p className="text-xs text-app-secondary mt-1 line-clamp-2 leading-relaxed">{provider.description}</p>
                      </div>

                      <div className="flex flex-col items-end gap-1 shrink-0">
                        {renderStatusBadge(st.label, st.badge, isTesting)}
                        {provider.fingerprint && (
                          <span className="text-[10px] font-mono text-slate-400" title="Key SHA-256 Fingerprint">
                            FP: {provider.fingerprint}
                          </span>
                        )}
                      </div>
                    </div>

                    {/* Local Forensic Tool Runtime Detection */}
                    {isLocalTool && (
                      <div className="rounded-lg border border-app bg-slate-50 dark:bg-slate-900/60 p-3 space-y-1.5 text-[11px] font-mono">
                        <div className="flex items-center justify-between gap-2">
                          <span className="text-app-secondary">Installation</span>
                          <span className={`font-bold ${lt?.installed ? 'text-emerald-600 dark:text-emerald-400' : 'text-slate-500'}`}>
                            {lt ? (lt.installed ? 'INSTALLED' : 'NOT INSTALLED') : (st.status === 'CONNECTED' ? 'INSTALLED' : 'CHECKING...')}
                          </span>
                        </div>
                        <div className="flex items-start justify-between gap-2">
                          <span className="text-app-secondary shrink-0">Detected version</span>
                          <span className="text-app-primary text-right break-all">{lt?.version || 'Bundled/Built-in'}</span>
                        </div>
                        <div className="flex items-start justify-between gap-2">
                          <span className="text-app-secondary shrink-0">Executable path</span>
                          <span className="text-app-primary text-right break-all" title={lt?.executable_path || ''}>
                            {lt?.executable_path || 'System PATH / Python runtime'}
                          </span>
                        </div>
                        {lt?.diagnostic_message && (
                          <p className="text-[10px] text-slate-400 leading-tight pt-1 border-t border-app">{lt.diagnostic_message}</p>
                        )}
                        {provider.credential_type === 'builtin' && (
                          <p className="text-[10px] text-teal-600 dark:text-teal-400 leading-tight">
                            Bundled Python module — no external executable path required.
                          </p>
                        )}
                      </div>
                    )}

                    {/* Individual Tool Login / Connect Action */}
                    {!isLocalTool && (
                      <div className="pt-1">
                        <button
                          type="button"
                          onClick={() => handleOnlineConnect(provider)}
                          className="w-full py-2 px-3 rounded-lg bg-gradient-to-r from-cyan-600 to-indigo-600 hover:from-cyan-500 hover:to-indigo-500 text-white font-mono text-xs font-semibold flex items-center justify-center gap-2 shadow-xs transition-colors cursor-pointer"
                        >
                          <ExternalLink className="w-3.5 h-3.5" />
                          <span>
                            {isGemini && geminiAuthMode === 'oauth'
                              ? 'Login / Connect Account (Google OAuth)'
                              : `Login / Connect (${provider.name} Portal)`}
                          </span>
                        </button>
                        <p className="text-[10px] text-slate-400 text-center mt-1">
                          Opens official authentication portal in your default browser.
                        </p>
                      </div>
                    )}

                    {/* Gemini Specific OAuth / API Key Mode Toggle */}
                    {isGemini && (
                      <div className="flex items-center gap-1.5 p-1 bg-slate-100 dark:bg-slate-900 rounded-lg text-xs font-mono font-medium">
                        <button
                          type="button"
                          onClick={() => setGeminiAuthMode('oauth')}
                          className={`flex-1 py-1 rounded text-center transition-colors cursor-pointer ${
                            geminiAuthMode === 'oauth'
                              ? 'bg-white dark:bg-slate-800 text-cyan-600 dark:text-cyan-400 shadow-xs font-bold'
                              : 'text-slate-500 hover:text-slate-900 dark:hover:text-slate-200'
                          }`}
                        >
                          Google OAuth (PKCE)
                        </button>
                        <button
                          type="button"
                          onClick={() => setGeminiAuthMode('api_key')}
                          className={`flex-1 py-1 rounded text-center transition-colors cursor-pointer ${
                            geminiAuthMode === 'api_key'
                              ? 'bg-white dark:bg-slate-800 text-cyan-600 dark:text-cyan-400 shadow-xs font-bold'
                              : 'text-slate-500 hover:text-slate-900 dark:hover:text-slate-200'
                          }`}
                        >
                          API Key (Encrypted BYOK)
                        </button>
                      </div>
                    )}

                    {/* OAuth Connected Account Badge */}
                    {isOAuthConnected && provider.account_identifier && (
                      <div className="bg-violet-50 dark:bg-violet-950/40 p-2.5 rounded-lg border border-violet-200 dark:border-violet-800/60 flex items-center justify-between text-xs font-mono">
                        <span className="text-violet-800 dark:text-violet-300">
                          Account: <strong>{provider.account_identifier}</strong>
                        </span>
                        <button
                          onClick={() => handleDisconnectOAuth(provider.id)}
                          className="text-xs text-rose-600 hover:text-rose-700 dark:text-rose-400 font-sans font-semibold underline cursor-pointer"
                        >
                          Disconnect
                        </button>
                      </div>
                    )}

                    {/* OpenCode Execution Mode & Toggle Box */}
                    {provider.id === 'opencode' && (
                      <div className="p-3 bg-indigo-950/30 border border-indigo-900/60 rounded-lg space-y-2 text-xs">
                        <div className="flex items-center justify-between">
                          <span className="font-bold text-indigo-200 flex items-center gap-1.5">
                            <Cpu className="w-4 h-4 text-indigo-400" />
                            AI-Assisted Investigation Toggle:
                          </span>
                          <label className="relative inline-flex items-center cursor-pointer">
                            <input
                              type="checkbox"
                              checked={openCodeStatus?.enabled || false}
                              onChange={handleToggleOpenCodeEnabled}
                              className="sr-only peer"
                            />
                            <div className="w-9 h-5 bg-slate-700 peer-focus:outline-none rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-slate-300 after:border after:rounded-full after:h-4 after:w-4 after:transition-all peer-checked:bg-indigo-600"></div>
                            <span className="ml-2 font-mono text-[11px] font-bold text-indigo-200">
                              {openCodeStatus?.enabled ? 'ENABLED' : 'DISABLED'}
                            </span>
                          </label>
                        </div>
                        <div className="text-[11px] text-slate-300 space-y-1 font-mono pt-1 border-t border-indigo-950">
                          <div>
                            Mode: <span className="text-cyan-400 font-bold">{openCodeStatus?.network_mode || 'LOCAL_ONLY'}</span> ({openCodeStatus?.status_label})
                          </div>
                          <div className="text-[10px] text-slate-400">
                            {openCodeStatus?.status_description}
                          </div>
                        </div>
                      </div>
                    )}

                    {/* Input Fields for API Keys, URLs, or Local Binary Paths */}
                    {(!isGemini || geminiAuthMode === 'api_key') && provider.fields && provider.fields.length > 0 && (
                      <div className="space-y-2.5 pt-1">
                        {provider.fields.map((f) => {
                          const fieldId = `${provider.id}_${f.key}`;
                          const isPassword = f.type === 'password';
                          const isVisible = showSecrets[fieldId] || false;
                          const val = (editedCreds[provider.id] && editedCreds[provider.id][f.key]) || '';

                          return (
                            <div key={f.key} className="space-y-1">
                              <div className="flex items-center justify-between">
                                <label className="text-[11px] font-semibold text-app-secondary uppercase tracking-wider block font-mono">
                                  {f.label}
                                </label>
                                {isLocalTool && (
                                  <span className="text-[10px] text-teal-600 dark:text-teal-400 font-mono">Local Path</span>
                                )}
                              </div>
                              <div className="flex items-center gap-2">
                                <div className="relative flex-1">
                                  <input
                                    type={isPassword && !isVisible ? 'password' : 'text'}
                                    value={val}
                                    onChange={(e) => handleInputChange(provider.id, f.key, e.target.value)}
                                    placeholder={f.placeholder}
                                    className="w-full text-xs font-mono bg-slate-50 dark:bg-slate-900 border border-app rounded-md px-3 py-1.5 text-app-primary placeholder:text-slate-400 focus:outline-none focus:ring-2 focus:ring-cyan-500 transition-colors"
                                  />
                                  {isPassword && (
                                    <button
                                      type="button"
                                      onClick={() => toggleSecretVisibility(fieldId)}
                                      className="absolute right-2.5 top-2 text-slate-400 hover:text-slate-600 dark:hover:text-slate-200 cursor-pointer"
                                      title={isVisible ? "Hide secret" : "Reveal secret"}
                                    >
                                      {isVisible ? <EyeOff className="w-3.5 h-3.5" /> : <Eye className="w-3.5 h-3.5" />}
                                    </button>
                                  )}
                                </div>
                                {isLocalTool && !isPassword && (
                                  <button
                                    type="button"
                                    onClick={() => handleBrowsePath(provider, f.key)}
                                    className="px-2.5 py-1.5 text-xs font-mono font-medium rounded-md border border-app bg-app-card text-app-primary hover:bg-app-hover flex items-center gap-1.5 transition-colors cursor-pointer shrink-0"
                                    title="Browse for a local file"
                                  >
                                    <FolderOpen className="w-3.5 h-3.5" />
                                    <span>Browse</span>
                                  </button>
                                )}
                              </div>
                              {f.help_text && <p className="text-[10px] text-slate-400">{f.help_text}</p>}
                            </div>
                          );
                        })}
                      </div>
                    )}

                    {/* Live Diagnostic Feedback Box */}
                    {currentTest && (
                      <div
                        className={`p-3 rounded-lg border text-xs space-y-1.5 font-mono ${
                          currentTest.success
                            ? 'bg-emerald-50 dark:bg-emerald-950/40 border-emerald-300 dark:border-emerald-800 text-emerald-900 dark:text-emerald-200'
                            : 'bg-rose-50 dark:bg-rose-950/40 border-rose-300 dark:border-rose-800 text-rose-900 dark:text-rose-200'
                        }`}
                      >
                        <div className="font-bold flex items-center gap-1.5">
                          {currentTest.success ? (
                            <CheckCircle2 className="w-3.5 h-3.5 text-emerald-600 dark:text-emerald-400 shrink-0" />
                          ) : (
                            <XCircle className="w-3.5 h-3.5 text-rose-600 dark:text-rose-400 shrink-0" />
                          )}
                          <span>{currentTest.status}</span>
                          {currentTest.test_timestamp && (
                            <span className="text-[10px] opacity-75 font-normal ml-auto">{currentTest.test_timestamp}</span>
                          )}
                        </div>
                        <p className="text-[11px] leading-relaxed break-words">{currentTest.message}</p>
                        {currentTest.actionable_hint && (
                          <div className="text-[10px] text-amber-700 dark:text-amber-300 font-sans pt-1 border-t border-amber-300/30">
                            <strong>Troubleshooting Advice:</strong> {currentTest.actionable_hint}
                          </div>
                        )}
                      </div>
                    )}

                    {/* Rate Limits & Privacy Notes */}
                    {(provider.rate_limits || provider.privacy_note) && (
                      <div className="text-[11px] text-app-secondary space-y-0.5 pt-2 border-t border-app">
                        {provider.rate_limits && <div><strong className="font-mono text-app-primary">Quota:</strong> {provider.rate_limits}</div>}
                        {provider.privacy_note && <div className="text-[10px] text-slate-400 leading-tight">{provider.privacy_note}</div>}
                      </div>
                    )}
                  </div>

                  {/* Bottom Action Footer */}
                  <div className="flex items-center justify-between gap-2 pt-3 border-t border-app">
                    <div className="flex items-center gap-3 flex-wrap">
                      {isLocalTool ? (
                        <>
                          {provider.register_url && (
                            <button
                              type="button"
                              onClick={() => api.openPortal(provider.register_url!)}
                              className="text-xs text-cyan-600 hover:text-cyan-700 dark:text-cyan-400 flex items-center gap-1 font-mono cursor-pointer"
                              title="Open official download page"
                            >
                              <span>Download</span>
                              <ExternalLink className="w-3 h-3" />
                            </button>
                          )}
                          {provider.docs_url && (
                            <button
                              type="button"
                              onClick={() => api.openPortal(provider.docs_url!)}
                              className="text-xs text-slate-500 hover:text-slate-700 dark:text-slate-400 flex items-center gap-1 font-mono cursor-pointer"
                              title="Open official documentation"
                            >
                              <span>Docs</span>
                              <ExternalLink className="w-3 h-3" />
                            </button>
                          )}
                        </>
                      ) : (
                        <>
                          {provider.register_url && (
                            <button
                              type="button"
                              onClick={() => api.openPortal(provider.register_url!)}
                              className="text-xs text-cyan-600 hover:text-cyan-700 dark:text-cyan-400 flex items-center gap-1 font-mono cursor-pointer"
                            >
                              <span>Get API Key</span>
                              <ExternalLink className="w-3 h-3" />
                            </button>
                          )}
                          {provider.docs_url && (
                            <button
                              type="button"
                              onClick={() => api.openPortal(provider.docs_url!)}
                              className="text-xs text-slate-500 hover:text-slate-700 dark:text-slate-400 flex items-center gap-1 font-mono cursor-pointer"
                            >
                              <span>Docs</span>
                              <ExternalLink className="w-3 h-3" />
                            </button>
                          )}
                        </>
                      )}
                    </div>

                    <div className="flex items-center gap-2">
                      {provider.is_configured && (
                        <button
                          type="button"
                          onClick={() => handleDeleteProviderCredentials(provider)}
                          title="Purge encrypted credentials"
                          className="p-1.5 text-slate-400 hover:text-rose-600 dark:hover:text-rose-400 rounded-md transition-colors cursor-pointer"
                        >
                          <Trash2 className="w-4 h-4" />
                        </button>
                      )}

                      <button
                        type="button"
                        onClick={() => handleTestProvider(provider)}
                        disabled={isTesting}
                        className="px-2.5 py-1.5 text-xs font-mono font-medium rounded-md border border-app bg-app-card text-app-primary hover:bg-app-hover flex items-center gap-1.5 disabled:opacity-50 transition-colors cursor-pointer"
                      >
                        <RefreshCw className={`w-3 h-3 ${isTesting ? 'animate-spin text-cyan-500' : ''}`} />
                        <span>{isTesting ? 'Testing...' : (isLocalTool ? 'Test Tool' : 'Test Connection')}</span>
                      </button>

                      {provider.id === 'opencode' && (
                        <button
                          type="button"
                          onClick={handleTestOpenCodeAnalysis}
                          disabled={testingOpenCodeAnalysis}
                          className="px-2.5 py-1.5 text-xs font-mono font-medium rounded-md border border-indigo-600/50 bg-indigo-950/40 text-indigo-200 hover:bg-indigo-900/50 flex items-center gap-1.5 disabled:opacity-50 transition-colors cursor-pointer"
                          title="Run synthetic static forensic test"
                        >
                          <Cpu className={`w-3 h-3 ${testingOpenCodeAnalysis ? 'animate-spin text-indigo-400' : ''}`} />
                          <span>{testingOpenCodeAnalysis ? 'Testing...' : 'Test Analysis'}</span>
                        </button>
                      )}

                      {(!isGemini || geminiAuthMode === 'api_key') && (
                        <button
                          type="button"
                          onClick={() => handleSaveProviderCredentials(provider)}
                          disabled={isSaving}
                          className="px-3 py-1.5 text-xs font-mono font-semibold rounded-md bg-cyan-600 text-white hover:bg-cyan-700 flex items-center gap-1.5 disabled:opacity-50 shadow-xs transition-colors cursor-pointer"
                        >
                          <Save className="w-3.5 h-3.5" />
                          <span>{isSaving ? 'Saving...' : 'Save'}</span>
                        </button>
                      )}
                    </div>
                  </div>
                </div>
              );
            })}
          </div>
          )}
        </div>
      </div>
    </div>
  );
};
