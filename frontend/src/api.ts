import {
  DashboardStats,
  InvestigationRecord,
  InvestigationDetail,
  ToolExecution,
  SandboxEnvironmentInfo,
  SandboxCapabilityMatrix,
  DynamicObservation,
  DynamicArtifact,
  ProcessTreeNode,
  DynamicReport,
  DynamicDashboardMetrics,
  SavedReportResult,
  SavedReportItem,
  IPDetailRecord,
  InvestigationIPsSummary
} from './types';

export function getApiBase(): string {
  if (typeof window !== 'undefined') {
    if ((window as any).__API_BASE__) {
      return (window as any).__API_BASE__;
    }
    const pathname = window.location.pathname;
    const proxyMatch = pathname.match(/^(\/(?:https?:\/\/[^/]+|\/proxy\/\d+))/i);
    if (proxyMatch) {
      return `${proxyMatch[1]}/api`;
    }
  }
  return '/api';
}

function getCsrfToken(): string | null {
  if (typeof document === 'undefined') return null;
  const match = document.cookie.match(new RegExp('(^| )workbench_csrf=([^;]+)'));
  return match ? decodeURIComponent(match[2]) : null;
}

export function getBridgeToken(): string | null {
  if (typeof window !== 'undefined') {
    if ((window as any).__TRACEX_BRIDGE_TOKEN__) {
      return (window as any).__TRACEX_BRIDGE_TOKEN__;
    }
    const meta = document.querySelector('meta[name="tracex-bridge-token"]');
    if (meta) {
      return meta.getAttribute('content');
    }
    return 'tracex-workstation-desktop-token';
  }
  return null;
}

// Global fetch interceptor ensuring TraceX desktop bridge token & session cookies are attached
if (typeof window !== 'undefined' && !(window as any).__TRACEX_FETCH_HOOKED__) {
  (window as any).__TRACEX_FETCH_HOOKED__ = true;
  const rawFetch = window.fetch.bind(window);
  window.fetch = async function (input: RequestInfo | URL, init?: RequestInit): Promise<Response> {
    const headers = new Headers(init?.headers || {});
    const csrfToken = getCsrfToken();
    if (csrfToken && !headers.has('x-csrf-token') && init?.method && ['POST', 'PUT', 'DELETE', 'PATCH'].includes(init.method.toUpperCase())) {
      headers.set('x-csrf-token', csrfToken);
    }
    const bridgeToken = getBridgeToken();
    if (bridgeToken && !headers.has('x-tracex-bridge-token')) {
      headers.set('x-tracex-bridge-token', bridgeToken);
    }
    return rawFetch(input, {
      credentials: init?.credentials || 'include',
      ...init,
      headers,
    });
  };
}

export async function fetchWithTimeout(
  input: RequestInfo | URL,
  init?: RequestInit,
  timeoutMs: number = 8000
): Promise<Response> {
  const controller = new AbortController();
  const timeoutId = setTimeout(() => {
    controller.abort(new Error(`Network request timed out after ${timeoutMs}ms`));
  }, timeoutMs);

  if (init?.signal) {
    const parentSignal = init.signal;
    if (parentSignal.aborted) {
      controller.abort(parentSignal.reason);
    } else {
      parentSignal.addEventListener('abort', () => controller.abort(parentSignal.reason), { once: true });
    }
  }

  const csrfToken = getCsrfToken();
  const bridgeToken = getBridgeToken();
  const headers = new Headers(init?.headers || {});
  if (csrfToken && !headers.has('x-csrf-token') && init?.method && ['POST', 'PUT', 'DELETE', 'PATCH'].includes(init.method.toUpperCase())) {
    headers.set('x-csrf-token', csrfToken);
  }
  if (bridgeToken && !headers.has('x-tracex-bridge-token')) {
    headers.set('x-tracex-bridge-token', bridgeToken);
  }

  try {
    const res = await fetch(input, {
      credentials: init?.credentials || 'include',
      ...init,
      headers,
      signal: controller.signal,
    });
    return res;
  } finally {
    clearTimeout(timeoutId);
  }
}

export const API_BASE = getApiBase();

export const api = {
  // Dashboard & Stats
  async getDashboardStats(): Promise<DashboardStats> {
    const res = await fetch(`${API_BASE}/dashboard/stats`);
    if (!res.ok) throw new Error('Failed to fetch dashboard statistics.');
    return res.json();
  },

  // Upload File (APK or EXE)
  async uploadFile(formData: FormData): Promise<{
    status: string;
    investigation_id: string;
    filename: string;
    file_type: string;
    sha256: string;
    size_bytes: number;
  }> {
    const res = await fetch(`${API_BASE}/investigations/upload`, {
      method: 'POST',
      body: formData,
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({ detail: res.statusText || 'Upload error' }));
      const errorObj = new Error(err.detail || 'Upload failed.');
      (errorObj as any).status = res.status;
      throw errorObj;
    }
    return res.json();
  },

  async uploadApk(formData: FormData): Promise<{
    status: string;
    investigation_id: string;
    filename: string;
    sha256: string;
  }> {
    return this.uploadFile(formData);
  },

  // List investigations
  async listInvestigations(search?: string): Promise<InvestigationRecord[]> {
    const url = search
      ? `${API_BASE}/investigations?search=${encodeURIComponent(search)}`
      : `${API_BASE}/investigations`;
    const res = await fetch(url);
    if (!res.ok) throw new Error('Failed to fetch investigations list.');
    return res.json();
  },

  // Get investigation detail
  async getInvestigationDetail(id: string): Promise<InvestigationDetail> {
    const res = await fetch(`${API_BASE}/investigations/${id}`);
    if (!res.ok) throw new Error(`Failed to load investigation ${id}.`);
    return res.json();
  },

  // Get status
  async getInvestigationStatus(id: string): Promise<{
    id: string;
    status: string;
    progress: number;
    current_stage: string;
    stage_index?: number;
    last_heartbeat?: string;
    error_message?: string;
    total_findings?: number;
    severity?: string;
  }> {
    const res = await fetch(`${API_BASE}/investigations/${id}/status`);
    if (!res.ok) throw new Error('Failed to fetch investigation status.');
    return res.json();
  },

  // Cancel running investigation
  async cancelInvestigation(id: string): Promise<{ status: string; message: string }> {
    const res = await fetch(`${API_BASE}/investigations/${id}/cancel`, {
      method: 'POST',
    });
    if (!res.ok) throw new Error('Failed to cancel investigation.');
    return res.json();
  },

  // Delete investigation
  async deleteInvestigation(id: string): Promise<void> {
    const res = await fetch(`${API_BASE}/investigations/${id}`, {
      method: 'DELETE',
    });
    if (!res.ok) throw new Error('Failed to delete investigation.');
  },

  // Unredact secret (Authorized action)
  async unredactSecret(investigationId: string, secretId: string): Promise<{
    id: string;
    raw_value: string;
    token_category: string;
  }> {
    const res = await fetch(`${API_BASE}/investigations/${investigationId}/secrets/unredact?secret_id=${encodeURIComponent(secretId)}`);
    if (!res.ok) throw new Error('Failed to unredact secret.');
    return res.json();
  },

  // Compare
  async compareInvestigations(id1: string, id2: string): Promise<any> {
    const res = await fetch(`${API_BASE}/investigations/compare?id1=${encodeURIComponent(id1)}&id2=${encodeURIComponent(id2)}`);
    if (!res.ok) throw new Error('Failed to compare investigations.');
    return res.json();
  },

  // Report URLs
  getTxtReportUrl(id: string, unredact = false): string {
    return `${API_BASE}/investigations/${id}/report/txt?unredact=${unredact}`;
  },

  getHtmlReportUrl(id: string, unredact = false): string {
    return `${API_BASE}/investigations/${id}/report/html?unredact=${unredact}`;
  },

  getPdfReportUrl(id: string, unredact = false): string {
    return `${API_BASE}/investigations/${id}/report/pdf?unredact=${unredact}`;
  },

  getCsvIocUrl(id: string): string {
    return `${API_BASE}/investigations/${id}/report/csv`;
  },

  getJsonExportUrl(id: string): string {
    return `${API_BASE}/investigations/${id}/report/json`;
  },

  getOSINTIndicatorsCsvUrl(id: string): string {
    return `${API_BASE}/investigations/${id}/report/osint/indicators.csv`;
  },

  getOSINTObservationsCsvUrl(id: string): string {
    return `${API_BASE}/investigations/${id}/report/osint/observations.csv`;
  },

  getSecretExposuresCsvUrl(id: string): string {
    return `${API_BASE}/investigations/${id}/report/osint/secrets.csv`;
  },

  getBundleZipUrl(id: string): string {
    return `${API_BASE}/investigations/${id}/report/bundle`;
  },

  async downloadReportFile(url: string, defaultFilename: string): Promise<void> {
    const res = await fetch(url);
    if (!res.ok) {
      const errText = await res.text().catch(() => 'Download request failed.');
      let msg = 'Failed to download report.';
      try {
        const json = JSON.parse(errText);
        msg = json.detail || msg;
      } catch {
        msg = errText || msg;
      }
      throw new Error(msg);
    }
    const blob = await res.blob();
    const disposition = res.headers.get('content-disposition');
    let filename = defaultFilename;
    if (disposition && disposition.includes('filename=')) {
      const match = disposition.match(/filename=["']?([^"';]+)["']?/);
      if (match && match[1]) {
        filename = match[1].trim();
      }
    }
    const blobUrl = window.URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = blobUrl;
    link.download = filename;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    setTimeout(() => window.URL.revokeObjectURL(blobUrl), 1000);
  },

  async previewReport(id: string): Promise<string> {
    const res = await fetch(`${API_BASE}/investigations/${id}/report/preview`);
    if (!res.ok) throw new Error('Failed to fetch report preview.');
    return res.text();
  },

  async saveReportToDocuments(
    investigationId: string,
    format: string,
    unredact: boolean = false,
    overwrite: boolean = false,
    customFilename?: string
  ): Promise<SavedReportResult> {
    const res = await fetch(`${API_BASE}/investigations/${investigationId}/report/save`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        format,
        unredact,
        overwrite,
        custom_filename: customFilename || null
      })
    });
    if (!res.ok) {
      const errText = await res.text().catch(() => 'Failed to save report.');
      let msg = 'Failed to save report to documents.';
      try {
        const json = JSON.parse(errText);
        msg = json.detail || msg;
      } catch {
        msg = errText || msg;
      }
      throw new Error(msg);
    }
    return res.json();
  },

  async getSavedReports(investigationId: string): Promise<SavedReportItem[]> {
    const res = await fetch(`${API_BASE}/investigations/${investigationId}/report/saved-files`);
    if (!res.ok) throw new Error('Failed to fetch saved reports list.');
    return res.json();
  },

  async openReportFile(filepath: string): Promise<void> {
    const res = await fetch(`${API_BASE}/reports/open-file`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ filepath })
    });
    if (!res.ok) {
      const json = await res.json().catch(() => ({ detail: 'Failed to open report.' }));
      throw new Error(json.detail || 'Failed to open report.');
    }
  },

  async showReportInFolder(filepath: string): Promise<void> {
    const res = await fetch(`${API_BASE}/reports/show-in-folder`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ filepath })
    });
    if (!res.ok) {
      const json = await res.json().catch(() => ({ detail: 'Failed to show report in folder.' }));
      throw new Error(json.detail || 'Failed to show report in folder.');
    }
  },

  async verifyReportPath(filepath: string): Promise<{ status: string; exists: boolean; filepath: string; filename: string; file_size: number }> {
    const res = await fetch(`${API_BASE}/reports/verify-path`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ filepath })
    });
    if (!res.ok) {
      const json = await res.json().catch(() => ({ detail: 'Report file path verification failed.' }));
      throw new Error(json.detail || 'Report file path verification failed.');
    }
    return res.json();
  },

  // IP Details & Comprehensive Intelligence Lookups
  async getInvestigationIpDetails(id: string, refresh: boolean = false): Promise<InvestigationIPsSummary> {
    const res = await fetch(`${API_BASE}/investigations/${id}/ip-details?refresh=${refresh}`);
    if (!res.ok) {
      const errText = await res.text().catch(() => 'Failed to load IP details.');
      let msg = 'Failed to load IP details.';
      try {
        const json = JSON.parse(errText);
        msg = json.detail || msg;
      } catch {
        msg = errText || msg;
      }
      throw new Error(msg);
    }
    return res.json();
  },

  async getSingleIpDetails(id: string, ip: string, refresh: boolean = false): Promise<IPDetailRecord> {
    const res = await fetch(`${API_BASE}/investigations/${id}/ip-details/${encodeURIComponent(ip)}?refresh=${refresh}`);
    if (!res.ok) throw new Error(`Failed to load details for IP ${ip}`);
    return res.json();
  },

  async exportSingleIpReport(
    id: string,
    ip: string,
    format: string = 'pdf',
    overwrite: boolean = true
  ): Promise<SavedReportResult> {
    const res = await fetch(`${API_BASE}/investigations/${id}/ip-details/${encodeURIComponent(ip)}/export`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ format, overwrite })
    });
    if (!res.ok) {
      const json = await res.json().catch(() => ({ detail: 'Failed to export IP report.' }));
      throw new Error(json.detail || 'Failed to export IP report.');
    }
    return res.json();
  },

  async exportAllIpsReport(
    id: string,
    format: string = 'pdf',
    overwrite: boolean = true
  ): Promise<SavedReportResult> {
    const res = await fetch(`${API_BASE}/investigations/${id}/ip-details/export-all`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ format, overwrite })
    });
    if (!res.ok) {
      const json = await res.json().catch(() => ({ detail: 'Failed to export all-IP report.' }));
      throw new Error(json.detail || 'Failed to export all-IP report.');
    }
    return res.json();
  },

  async getSavedReportsForIp(id: string, ip: string): Promise<SavedReportItem[]> {
    const res = await fetch(`${API_BASE}/investigations/${id}/ip-details/${encodeURIComponent(ip)}/saved-files`);
    if (!res.ok) return [];
    return res.json();
  },

  // Tools & Settings
  async getTools(): Promise<ToolExecution[]> {
    const res = await fetchWithTimeout(`${getApiBase()}/tools`, {}, 8000);
    if (!res.ok) throw new Error('Failed to fetch tools status.');
    return res.json();
  },

  async getSettings(): Promise<any> {
    const res = await fetchWithTimeout(`${getApiBase()}/settings`, {}, 6000);
    if (!res.ok) throw new Error('Failed to fetch settings.');
    return res.json();
  },

  async getDatabaseHealth(): Promise<{
    success: boolean;
    tool_name: string;
    installed: boolean;
    status: string;
    version?: string;
    test_status: string;
    test_timestamp: string;
    diagnostic_message: string;
    details?: Record<string, any>;
  }> {
    const res = await fetchWithTimeout(`${getApiBase()}/tools/database`, {}, 5000);
    if (!res.ok) throw new Error('Failed to query database health.');
    return res.json();
  },

  async getBackendHealth(): Promise<{
    success: boolean;
    tool_name: string;
    installed: boolean;
    status: string;
    version?: string;
    test_status: string;
    test_timestamp: string;
    diagnostic_message: string;
    details?: Record<string, any>;
  }> {
    const res = await fetchWithTimeout(`${getApiBase()}/tools/backend`, {}, 5000);
    if (!res.ok) throw new Error('Failed to query backend health.');
    return res.json();
  },

  async updateSettings(settingsData: any): Promise<void> {
    const res = await fetchWithTimeout(`${getApiBase()}/settings`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(settingsData),
    }, 8000);
    if (!res.ok) throw new Error('Failed to update settings.');
  },

  // Bring Your Own Key (BYOK) Credential Management
  async getCredentialsSummary(): Promise<{
    total: number;
    connected: number;
    credentials_saved: number;
    not_configured: number;
    authentication_failed: number;
    local_tools_available: number;
  }> {
    const res = await fetchWithTimeout(`${getApiBase()}/credentials/summary`, {}, 8000);
    if (!res.ok) throw new Error('Failed to fetch credentials summary.');
    return res.json();
  },

  async getCredentialsCatalog(): Promise<any[]> {
    const res = await fetchWithTimeout(`${getApiBase()}/credentials/providers`, {}, 8000);
    if (!res.ok) throw new Error('Failed to fetch credentials catalog.');
    return res.json();
  },

  async getMasterKeyStatus(): Promise<{
    status: string;
    key_source: string;
    encryption_algorithm: string;
    zero_plaintext_guarantee: boolean;
  }> {
    const res = await fetchWithTimeout(`${getApiBase()}/credentials/master-key/status`, {}, 5000);
    if (!res.ok) throw new Error('Failed to fetch master key status.');
    return res.json();
  },

  async saveProviderCredential(providerId: string, data: Record<string, any>, credentialType?: string): Promise<any> {
    const res = await fetchWithTimeout(`${getApiBase()}/credentials/${encodeURIComponent(providerId)}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ data, credential_type: credentialType }),
    }, 8000);
    if (!res.ok) {
      const err = await res.json().catch(() => ({ detail: 'Save failed' }));
      throw new Error(err.detail || 'Failed to save credential.');
    }
    return res.json();
  },

  async deleteProviderCredential(providerId: string): Promise<any> {
    const res = await fetchWithTimeout(`${getApiBase()}/credentials/${encodeURIComponent(providerId)}`, {
      method: 'DELETE',
    }, 8000);
    if (!res.ok) throw new Error('Failed to delete credential.');
    return res.json();
  },

  async testProviderCredential(providerId: string, data?: Record<string, any>): Promise<{
    success: boolean;
    connected: boolean;
    status: string;
    message: string;
    details?: Record<string, any>;
    test_timestamp?: string;
  }> {
    const res = await fetchWithTimeout(`${getApiBase()}/credentials/${encodeURIComponent(providerId)}/test`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ data }),
    }, 12000);
    return res.json();
  },

  async openPortal(url: string): Promise<any> {
    try {
      const res = await fetchWithTimeout(`${getApiBase()}/credentials/open-portal`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url }),
      }, 5000);
      if (res.ok) return res.json();
    } catch (e) {
      // Fallback in case backend call fails
    }
    window.open(url, '_blank');
    return { success: true };
  },

  async getLocalToolsStatus(): Promise<{ tools: any[]; timestamp_utc?: string }> {
    const res = await fetchWithTimeout(`${getApiBase()}/credentials/local-tools/status`, {}, 30000);
    if (!res.ok) throw new Error('Failed to fetch local tool status.');
    return res.json();
  },

  async browseFile(title?: string, initialDir?: string, filetypes?: string[][]): Promise<{ success: boolean; path: string; error?: string }> {
    const res = await fetchWithTimeout(`${getApiBase()}/settings/browse-file`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ title, initial_dir: initialDir, filetypes }),
    }, 120000);
    if (!res.ok) throw new Error('Failed to open the file picker.');
    return res.json();
  },

  // User Authentication & Sessions
  async getSetupStatus(): Promise<{ setup_required: boolean; deployment_mode: string }> {
    const res = await fetchWithTimeout(`${getApiBase()}/auth/setup-status`, {}, 5000);
    if (!res.ok) return { setup_required: false, deployment_mode: 'workstation' };
    return res.json();
  },

  async initialSetup(data: { username?: string; password: string; email?: string }): Promise<any> {
    const res = await fetchWithTimeout(`${getApiBase()}/auth/initial-setup`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(data),
    }, 10000);
    if (!res.ok) {
      const err = await res.json().catch(() => ({ detail: 'Initial setup failed.' }));
      throw new Error(err.detail || 'Initial setup failed.');
    }
    return res.json();
  },

  async login(username: string, password: string, remember_me?: boolean): Promise<any> {
    const res = await fetchWithTimeout(`${getApiBase()}/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username, password, remember_me }),
    }, 8000);
    if (!res.ok) {
      const err = await res.json().catch(() => ({ detail: 'Authentication failed.' }));
      throw new Error(err.detail || 'Authentication failed.');
    }
    return res.json();
  },

  async logout(): Promise<any> {
    const res = await fetchWithTimeout(`${getApiBase()}/auth/logout`, {
      method: 'POST',
    }, 5000);
    return res.json();
  },

  async getCurrentUser(): Promise<{ authenticated: boolean; user: any }> {
    const res = await fetchWithTimeout(`${getApiBase()}/auth/me`, {}, 5000);
    if (!res.ok) return { authenticated: false, user: null };
    return res.json();
  },

  async updateProfile(email?: string, currentPassword?: string, newPassword?: string): Promise<any> {
    const res = await fetchWithTimeout(`${getApiBase()}/auth/profile`, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, current_password: currentPassword, new_password: newPassword }),
    }, 8000);
    if (!res.ok) {
      const err = await res.json().catch(() => ({ detail: 'Profile update failed.' }));
      throw new Error(err.detail || 'Profile update failed.');
    }
    return res.json();
  },

  // OAuth 2.0 PKCE Flows
  async startOAuthFlow(providerId: string, redirectUri?: string): Promise<{
    authorization_url: string;
    state: string;
    expires_in: number;
    provider: string;
  }> {
    const params = new URLSearchParams();
    if (redirectUri) params.append('redirect_uri', redirectUri);
    const query = params.toString() ? `?${params.toString()}` : '';
    const res = await fetchWithTimeout(`${getApiBase()}/oauth/${encodeURIComponent(providerId)}/authorize${query}`, {}, 8000);
    if (!res.ok) {
      const err = await res.json().catch(() => ({ detail: 'Failed to initiate OAuth flow.' }));
      throw new Error(err.detail || 'Failed to initiate OAuth flow.');
    }
    return res.json();
  },

  async disconnectOAuth(providerId: string): Promise<any> {
    const res = await fetchWithTimeout(`${getApiBase()}/oauth/${encodeURIComponent(providerId)}/disconnect`, {
      method: 'POST',
    }, 8000);
    if (!res.ok) throw new Error('Failed to disconnect OAuth provider.');
    return res.json();
  },

  async testTool(toolName: string, customPath?: string): Promise<{
    success: boolean;
    status: string;
    message: string;
    details?: Record<string, any>;
    version?: string;
    test_status?: string;
    test_timestamp?: string;
  }> {
    const res = await fetchWithTimeout(`${getApiBase()}/settings/test-tool`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ tool_name: toolName, custom_path: customPath }),
    }, 12000);
    return res.json();
  },

  async testMobSF(url?: string, apiKey?: string): Promise<{
    success: boolean;
    status: string;
    message: string;
    details?: Record<string, any>;
    version?: string;
    test_status?: string;
    test_timestamp?: string;
  }> {
    const res = await fetchWithTimeout(`${getApiBase()}/settings/test-mobsf`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url, api_key: apiKey }),
    }, 8000);
    return res.json();
  },

  async testOTX(apiKey?: string): Promise<{
    status: 'Connected' | 'Invalid credentials' | 'Rate limited' | 'Provider unavailable' | 'Network error' | 'Not configured';
    connected: boolean;
    message: string;
  }> {
    const res = await fetchWithTimeout(`${getApiBase()}/settings/test-otx`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ api_key: apiKey }),
    }, 10000);
    if (!res.ok) throw new Error('Failed to test AlienVault OTX connection.');
    return res.json();
  },

  // ========================================================
  // UNIVERSAL DIGITAL FORENSICS API
  // ========================================================

  async uploadUniversalEvidence(formData: FormData): Promise<{
    status: string;
    investigation_id: string;
    case_reference?: string;
    total_staged_files: number;
    evidence_items: Array<{
      id: string;
      filename: string;
      detected_format: string;
      size_bytes: number;
      sha256: string;
      format_mismatch: boolean;
    }>;
  }> {
    const res = await fetch(`${API_BASE}/universal/investigations/upload`, {
      method: 'POST',
      body: formData,
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({ detail: res.statusText || 'Universal evidence intake failed.' }));
      const errorObj = new Error(err.detail || 'Universal evidence intake failed.');
      (errorObj as any).status = res.status;
      throw errorObj;
    }
    return res.json();
  },

  async getUniversalInvestigationDetail(investigationId: string): Promise<import('./types').UniversalInvestigationDetail> {
    const res = await fetch(`${API_BASE}/universal/investigations/${investigationId}/detail`);
    if (!res.ok) throw new Error('Failed to load universal investigation details.');
    return res.json();
  },

  async getEvidenceItems(investigationId: string): Promise<import('./types').EvidenceItem[]> {
    const res = await fetch(`${API_BASE}/universal/investigations/${investigationId}/evidence`);
    if (!res.ok) throw new Error('Failed to load evidence items.');
    return res.json();
  },

  async getArtifacts(investigationId: string, evidenceId?: string): Promise<import('./types').ExtractedArtifact[]> {
    const url = evidenceId 
      ? `${API_BASE}/universal/investigations/${investigationId}/artifacts?evidence_id=${encodeURIComponent(evidenceId)}`
      : `${API_BASE}/universal/investigations/${investigationId}/artifacts`;
    const res = await fetch(url);
    if (!res.ok) throw new Error('Failed to load artifacts.');
    return res.json();
  },

  async getRelationships(investigationId: string): Promise<import('./types').EvidenceRelationship[]> {
    const res = await fetch(`${API_BASE}/universal/investigations/${investigationId}/relationships`);
    if (!res.ok) throw new Error('Failed to load evidence correlations.');
    return res.json();
  },

  async getTimeline(investigationId: string): Promise<import('./types').TimelineEvent[]> {
    const res = await fetch(`${API_BASE}/universal/investigations/${investigationId}/timeline`);
    if (!res.ok) throw new Error('Failed to load forensic timeline.');
    return res.json();
  },

  async getChainOfCustody(investigationId: string): Promise<{
    investigation_id: string;
    integrity_audit: { status: string; valid: boolean; event_count: number; inconsistencies: any[] };
    events: import('./types').ChainOfCustodyEvent[];
  }> {
    const res = await fetch(`${API_BASE}/universal/investigations/${investigationId}/chain-of-custody`);
    if (!res.ok) throw new Error('Failed to load chain of custody ledger.');
    return res.json();
  },

  async getFindingsRegister(investigationId: string, evidenceId?: string): Promise<import('./types').FindingRecord[]> {
    const url = evidenceId
      ? `${API_BASE}/universal/investigations/${investigationId}/findings-register?evidence_id=${encodeURIComponent(evidenceId)}`
      : `${API_BASE}/universal/investigations/${investigationId}/findings-register`;
    const res = await fetch(url);
    if (!res.ok) throw new Error('Failed to load findings register.');
    return res.json();
  },

  async verifyFinding(
    investigationId: string,
    findingId: string,
    verificationState: string,
    analystNotes?: string
  ): Promise<any> {
    const formData = new FormData();
    formData.append('verification_state', verificationState);
    if (analystNotes) formData.append('analyst_notes', analystNotes);

    const res = await fetch(`${API_BASE}/universal/investigations/${investigationId}/findings/${findingId}/verify`, {
      method: 'PATCH',
      body: formData
    });
    if (!res.ok) throw new Error('Failed to update finding verification state.');
    return res.json();
  },

  async searchCrossCase(
    queryType: 'hash' | 'indicator',
    value: string,
    currentId?: string
  ): Promise<any[]> {
    const url = `${API_BASE}/universal/search/cross-case?query_type=${queryType}&value=${encodeURIComponent(value)}${currentId ? `&current_investigation_id=${currentId}` : ''}`;
    const res = await fetch(url);
    if (!res.ok) throw new Error('Failed to search cross-case indicators.');
    return res.json();
  },

  getMasterReportTxtUrl(investigationId: string): string {
    return `${API_BASE}/universal/investigations/${investigationId}/report/master/txt`;
  },

  getMasterReportHtmlUrl(investigationId: string): string {
    return `${API_BASE}/universal/investigations/${investigationId}/report/master/html`;
  },

  getReproducibilityBundleUrl(investigationId: string): string {
    return `${API_BASE}/universal/investigations/${investigationId}/report/bundle`;
  },

  // ==========================================
  // OSINT & RECURSIVE PIVOT API METHODS
  // ==========================================

  async getOSINTIndicators(investigationId: string, autoCollect: boolean = true): Promise<import('./types').OSINTIndicator[]> {
    const res = await fetch(`${API_BASE}/osint/investigations/${investigationId}/indicators?auto_collect=${autoCollect}`);
    if (!res.ok) throw new Error('Failed to load OSINT indicators.');
    return res.json();
  },

  async collectOSINT(investigationId: string): Promise<any> {
    const res = await fetch(`${API_BASE}/osint/investigations/${investigationId}/collect`, { method: 'POST' });
    if (!res.ok) throw new Error('Failed to collect OSINT indicators.');
    return res.json();
  },

  async getOSINTObservations(investigationId: string, indicatorId?: string): Promise<import('./types').OSINTObservation[]> {
    const url = indicatorId
      ? `${API_BASE}/osint/investigations/${investigationId}/observations?indicator_id=${encodeURIComponent(indicatorId)}`
      : `${API_BASE}/osint/investigations/${investigationId}/observations`;
    const res = await fetch(url);
    if (!res.ok) throw new Error('Failed to load OSINT observations.');
    return res.json();
  },

  async enrichOSINT(investigationId: string, indicatorIds?: string[], forceRefresh: boolean = false): Promise<import('./types').OSINTObservation[]> {
    const res = await fetch(`${API_BASE}/osint/investigations/${investigationId}/enrich`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ indicator_ids: indicatorIds, force_refresh: forceRefresh })
    });
    if (!res.ok) throw new Error('Failed to enrich indicators.');
    return res.json();
  },

  async runRecursivePivot(
    investigationId: string,
    maxDepth: number = 3,
    budgetLimit: number = 50,
    seedIndicatorIds?: string[]
  ): Promise<import('./types').RecursivePivotJob> {
    const res = await fetch(`${API_BASE}/osint/investigations/${investigationId}/pivot`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        max_depth: maxDepth,
        budget_limit: budgetLimit,
        seed_indicator_ids: seedIndicatorIds
      })
    });
    if (!res.ok) throw new Error('Failed to run recursive pivot.');
    return res.json();
  },

  async getOSINTGraph(investigationId: string): Promise<{
    investigation_id: string;
    nodes: import('./types').OSINTGraphNode[];
    edges: import('./types').OSINTGraphEdge[];
    total_nodes: number;
    total_edges: number;
  }> {
    const res = await fetch(`${API_BASE}/osint/investigations/${investigationId}/graph`);
    if (!res.ok) throw new Error('Failed to load OSINT graph.');
    return res.json();
  },

  async getSecretExposures(investigationId: string): Promise<import('./types').SecretExposureFinding[]> {
    const res = await fetch(`${API_BASE}/osint/investigations/${investigationId}/secrets`);
    if (!res.ok) throw new Error('Failed to load secret exposures.');
    return res.json();
  },

  // ==========================================
  // AUTHORIZED NETWORK VALIDATION API METHODS
  // ==========================================

  async createNetworkScope(payload: {
    investigation_id: string;
    case_id?: string;
    authorized_targets: string[];
    allowed_test_types: string[];
    allowed_ports: number[];
    authorization_note: string;
    operator_name: string;
    operator_confirmed: boolean;
    request_budget: number;
    duration_hours: number;
  }): Promise<import('./types').AuthorizedNetworkScope> {
    const res = await fetch(`${API_BASE}/network-validation/scopes`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({ detail: 'Failed to create authorized scope.' }));
      throw new Error(err.detail || 'Failed to create authorized scope.');
    }
    return res.json();
  },

  async getNetworkScopes(investigationId: string): Promise<import('./types').AuthorizedNetworkScope[]> {
    const res = await fetch(`${API_BASE}/network-validation/scopes/${investigationId}`);
    if (!res.ok) throw new Error('Failed to load authorization scopes.');
    return res.json();
  },

  async revokeNetworkScope(scopeId: string): Promise<any> {
    const res = await fetch(`${API_BASE}/network-validation/scopes/${scopeId}/revoke`, { method: 'POST' });
    if (!res.ok) throw new Error('Failed to revoke scope.');
    return res.json();
  },

  async executeNetworkValidation(payload: {
    scope_id: string;
    investigation_id: string;
    target: string;
    test_type: string;
    port?: number;
  }): Promise<import('./types').ActiveValidationResult> {
    const res = await fetch(`${API_BASE}/network-validation/execute`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({ detail: 'Network validation failed.' }));
      throw new Error(err.detail || 'Network validation failed.');
    }
    return res.json();
  },

  async getValidationResults(investigationId: string): Promise<import('./types').ActiveValidationResult[]> {
    const res = await fetch(`${API_BASE}/network-validation/results/${investigationId}`);
    if (!res.ok) throw new Error('Failed to load validation results.');
    return res.json();
  },

  async updateKillSwitch(active: boolean, reason?: string): Promise<{ kill_switch_active: boolean; message: string }> {
    const res = await fetch(`${API_BASE}/network-validation/kill-switch`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ active, reason })
    });
    if (!res.ok) throw new Error('Failed to update kill switch state.');
    return res.json();
  },

  async getKillSwitchStatus(): Promise<{ kill_switch_active: boolean; local_only_mode: boolean }> {
    const res = await fetch(`${API_BASE}/network-validation/kill-switch/status`);
    if (!res.ok) throw new Error('Failed to load kill switch status.');
    return res.json();
  },

  // ==========================================
  // NETWORK PRIVACY MODE (AUTHORITATIVE SYSTEM)
  // ==========================================

  async getNetworkMode(): Promise<{
    mode: 'LOCAL_ONLY' | 'HYBRID';
    local_only_mode: boolean;
    description: string;
    features: string[];
  }> {
    const res = await fetchWithTimeout(`${getApiBase()}/system/network-mode`, {}, 5000);
    if (!res.ok) throw new Error('Failed to load network privacy mode.');
    return res.json();
  },

  async setNetworkMode(mode: 'LOCAL_ONLY' | 'HYBRID'): Promise<{
    success: boolean;
    mode: 'LOCAL_ONLY' | 'HYBRID';
    local_only_mode: boolean;
    message: string;
    description: string;
    features: string[];
  }> {
    const res = await fetchWithTimeout(`${getApiBase()}/system/network-mode`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ mode }),
    }, 6000);
    if (!res.ok) throw new Error('Failed to update network privacy mode.');
    return res.json();
  },

  // ==========================================
  // DYNAMIC SANDBOX & TELEMETRY API METHODS
  // ==========================================

  async getSandboxTools(): Promise<import('./types').SandboxToolStatus[]> {
    const res = await fetch(`${API_BASE}/sandbox/tools`);
    if (!res.ok) throw new Error('Failed to load sandbox tools status.');
    return res.json();
  },

  async getSandboxRuns(investigationId: string): Promise<import('./types').DynamicSandboxRun[]> {
    const res = await fetch(`${API_BASE}/sandbox/runs/${investigationId}`);
    if (!res.ok) throw new Error('Failed to load sandbox runs.');
    return res.json();
  },

  async getRunTelemetry(runId: string): Promise<import('./types').DynamicTelemetryEvent[]> {
    const res = await fetch(`${API_BASE}/sandbox/runs/${runId}/telemetry`);
    if (!res.ok) throw new Error('Failed to load telemetry events.');
    return res.json();
  },

  async getRunFlows(runId: string): Promise<import('./types').NetworkFlowRecord[]> {
    const res = await fetch(`${API_BASE}/sandbox/runs/${runId}/flows`);
    if (!res.ok) throw new Error('Failed to load network flows.');
    return res.json();
  },

  async importSandboxTelemetry(payload: {
    investigation_id: string;
    evidence_id: string;
    target_binary: string;
    sandbox_environment?: string;
    is_simulated_network?: boolean;
    telemetry_json?: Record<string, any>;
  }): Promise<import('./types').DynamicSandboxRun> {
    const res = await fetch(`${API_BASE}/sandbox/import-telemetry`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    });
    if (!res.ok) throw new Error('Failed to import telemetry.');
    return res.json();
  },

  async uploadSandboxPcap(formData: FormData): Promise<import('./types').DynamicSandboxRun> {
    const res = await fetch(`${API_BASE}/sandbox/upload-pcap`, {
      method: 'POST',
      body: formData
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({ detail: 'Failed to upload and analyze PCAP.' }));
      throw new Error(err.detail || 'Failed to upload and analyze PCAP.');
    }
    return res.json();
  },

  // ==========================================
  // STATIC-DYNAMIC CORRELATION & RISK ENGINE
  // ==========================================

  async triggerCorrelation(investigationId: string): Promise<import('./types').StaticDynamicCorrelation[]> {
    const res = await fetch(`${API_BASE}/sandbox/correlate/${investigationId}`, { method: 'POST' });
    if (!res.ok) throw new Error('Failed to correlate findings.');
    return res.json();
  },

  async getCorrelations(investigationId: string): Promise<import('./types').StaticDynamicCorrelation[]> {
    const res = await fetch(`${API_BASE}/sandbox/correlations/${investigationId}`);
    if (!res.ok) throw new Error('Failed to load correlations.');
    return res.json();
  },

  async triggerRiskAssessment(investigationId: string): Promise<import('./types').EvidenceRiskAssessment> {
    const res = await fetch(`${API_BASE}/sandbox/assess-risk/${investigationId}`, { method: 'POST' });
    if (!res.ok) throw new Error('Failed to assess dimensional risk.');
    return res.json();
  },

  async getRiskAssessment(investigationId: string): Promise<import('./types').EvidenceRiskAssessment | null> {
    const res = await fetch(`${API_BASE}/sandbox/risk-assessment/${investigationId}`);
    if (!res.ok) throw new Error('Failed to load risk assessment.');
    return res.json();
  },

  // ==========================================
  // OSINT PROVIDER MANAGEMENT API METHODS
  // ==========================================

  async getOSINTProviders(): Promise<import('./types').OSINTProviderMetadata[]> {
    const res = await fetchWithTimeout(`${getApiBase()}/settings/osint-providers`, {}, 6000);
    if (!res.ok) throw new Error('Failed to load OSINT providers.');
    return res.json();
  },

  async testOSINTProvider(providerId: string, payload: { api_key?: string; endpoint?: string }): Promise<any> {
    const res = await fetchWithTimeout(`${getApiBase()}/settings/test-provider/${providerId}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    }, 10000);
    return res.json();
  },

  // ==========================================
  // DYNAMIC MALWARE ANALYSIS LAB API METHODS
  // ==========================================

  async getDynamicCapabilities(): Promise<SandboxCapabilityMatrix> {
    const res = await fetchWithTimeout(`${getApiBase()}/dynamic/capabilities`);
    if (!res.ok) throw new Error('Failed to load dynamic sandbox capabilities.');
    return res.json();
  },

  async getDynamicEnvironments(): Promise<SandboxEnvironmentInfo[]> {
    const res = await fetchWithTimeout(`${getApiBase()}/dynamic/environments`);
    if (!res.ok) throw new Error('Failed to load sandbox environments.');
    return res.json();
  },

  async getDynamicDashboard(): Promise<DynamicDashboardMetrics> {
    const res = await fetchWithTimeout(`${getApiBase()}/dynamic/dashboard`);
    if (!res.ok) throw new Error('Failed to load dynamic analysis dashboard metrics.');
    return res.json();
  },

  async testDynamicEnvironment(envId: string): Promise<{ success: boolean; message: string; details: any }> {
    const res = await fetchWithTimeout(`${getApiBase()}/dynamic/environments/${envId}/test`, {
      method: 'POST'
    }, 15000);
    if (!res.ok) throw new Error('Failed to test sandbox environment.');
    return res.json();
  },

  async createDynamicAnalysis(data: {
    investigation_id: string;
    sample_type: 'APK' | 'PE' | 'GENERIC';
    sample_path: string;
    sample_name: string;
    environment_id: string;
    network_mode?: string;
    timeout_seconds?: number;
    analysis_options?: Record<string, any>;
  }): Promise<any> {
    const res = await fetchWithTimeout(`${getApiBase()}/dynamic/analyses`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(data)
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.detail || 'Failed to initialize dynamic analysis.');
    }
    return res.json();
  },

  async listDynamicAnalyses(investigationId?: string): Promise<any[]> {
    const query = investigationId ? `?investigation_id=${encodeURIComponent(investigationId)}` : '';
    const res = await fetchWithTimeout(`${getApiBase()}/dynamic/analyses${query}`);
    if (!res.ok) throw new Error('Failed to list dynamic analyses.');
    return res.json();
  },

  async getDynamicAnalysis(runId: string): Promise<any> {
    const res = await fetchWithTimeout(`${getApiBase()}/dynamic/analyses/${runId}`);
    if (!res.ok) throw new Error('Failed to load dynamic analysis details.');
    return res.json();
  },

  async startDynamicAnalysis(runId: string): Promise<any> {
    const res = await fetchWithTimeout(`${getApiBase()}/dynamic/analyses/${runId}/start`, {
      method: 'POST'
    }, 30000);
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.detail || 'Failed to start dynamic analysis.');
    }
    return res.json();
  },

  async finalizeDynamicAnalysis(runId: string, resultData?: any): Promise<any> {
    const res = await fetchWithTimeout(`${getApiBase()}/dynamic/analyses/${runId}/finalize`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(resultData || {})
    }, 30000);
    if (!res.ok) throw new Error('Failed to finalize dynamic analysis.');
    return res.json();
  },

  async cancelDynamicAnalysis(runId: string): Promise<any> {
    const res = await fetchWithTimeout(`${getApiBase()}/dynamic/analyses/${runId}/cancel`, {
      method: 'POST'
    });
    if (!res.ok) throw new Error('Failed to cancel dynamic analysis.');
    return res.json();
  },

  async getDynamicProcessTree(runId: string): Promise<ProcessTreeNode[]> {
    const res = await fetchWithTimeout(`${getApiBase()}/dynamic/analyses/${runId}/process-tree`);
    if (!res.ok) throw new Error('Failed to load dynamic process tree.');
    return res.json();
  },

  async getDynamicNetworkFlows(runId: string): Promise<any[]> {
    const res = await fetchWithTimeout(`${getApiBase()}/dynamic/analyses/${runId}/network`);
    if (!res.ok) throw new Error('Failed to load dynamic network flows.');
    return res.json();
  },

  async getDynamicObservations(runId: string, category?: string): Promise<DynamicObservation[]> {
    const query = category ? `?category=${encodeURIComponent(category)}` : '';
    const res = await fetchWithTimeout(`${getApiBase()}/dynamic/analyses/${runId}/observations${query}`);
    if (!res.ok) throw new Error('Failed to load dynamic observations.');
    return res.json();
  },

  async getDynamicArtifacts(runId: string): Promise<DynamicArtifact[]> {
    const res = await fetchWithTimeout(`${getApiBase()}/dynamic/analyses/${runId}/artifacts`);
    if (!res.ok) throw new Error('Failed to load dynamic artifacts.');
    return res.json();
  },

  async getDynamicReport(runId: string): Promise<DynamicReport> {
    const res = await fetchWithTimeout(`${getApiBase()}/dynamic/analyses/${runId}/report`);
    if (!res.ok) throw new Error('Failed to load dynamic analysis report.');
    return res.json();
  },

  async getVMEnvironment(): Promise<any> {
    const res = await fetchWithTimeout(`${getApiBase()}/dynamic/vm-environment`);
    if (!res.ok) throw new Error('Failed to load VM environment and hypervisor status.');
    return res.json();
  },

  async testNestedVirtualization(): Promise<any> {
    const res = await fetchWithTimeout(`${getApiBase()}/dynamic/vm-environment/test-nested`, {
      method: 'POST'
    });
    if (!res.ok) throw new Error('Failed to test nested virtualization.');
    return res.json();
  },

  // ==========================================
  // OpenCode AI Forensic Engine API
  // ==========================================
  async getOpenCodeStatus(): Promise<import('./types').OpenCodeStatus> {
    const res = await fetchWithTimeout(`${getApiBase()}/opencode/status`);
    if (!res.ok) throw new Error('Failed to fetch OpenCode status.');
    return res.json();
  },

  async testOpenCodeInstallation(): Promise<any> {
    const res = await fetchWithTimeout(`${getApiBase()}/opencode/test-installation`, {
      method: 'POST'
    });
    if (!res.ok) throw new Error('Failed to test OpenCode installation.');
    return res.json();
  },

  async testOpenCodeAnalysis(consentApproved: boolean = false): Promise<any> {
    const res = await fetchWithTimeout(`${getApiBase()}/opencode/test-analysis`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ consent_approved: consentApproved })
    });
    if (!res.ok) throw new Error('Failed to run OpenCode test analysis.');
    return res.json();
  },

  async updateOpenCodeConfig(config: { enabled?: boolean; model?: string; timeout_seconds?: number }): Promise<any> {
    const res = await fetchWithTimeout(`${getApiBase()}/opencode/config`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(config)
    });
    if (!res.ok) throw new Error('Failed to update OpenCode configuration.');
    return res.json();
  },

  async triggerAIAnalysis(investigationId: string, consentApproved: boolean = false, model?: string): Promise<any> {
    const res = await fetchWithTimeout(`${getApiBase()}/investigations/${investigationId}/ai-analyze`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ consent_approved: consentApproved, model })
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({ detail: 'AI analysis failed.' }));
      throw new Error(err.detail || 'AI analysis failed.');
    }
    return res.json();
  },

  async reviewAIObservation(investigationId: string, obsId: string, status: string, reviewNotes?: string): Promise<any> {
    const res = await fetchWithTimeout(`${getApiBase()}/investigations/${investigationId}/ai-observations/${obsId}/review`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ status, review_notes: reviewNotes })
    });
    if (!res.ok) throw new Error('Failed to update observation status.');
    return res.json();
  }
};


