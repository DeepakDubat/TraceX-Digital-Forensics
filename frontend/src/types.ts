export interface InvestigationRecord {
  id: string;
  filename: string;
  original_size: number;
  md5: string;
  sha1: string;
  sha256: string;
  case_reference?: string;
  investigator_name?: string;
  description?: string;
  analyst_notes?: string;
  local_only_mode: boolean;
  status: 'pending' | 'analyzing' | 'completed' | 'failed' | 'cancelled';
  progress: number;
  current_stage: string;
  created_at: string;
  started_at?: string;
  completed_at?: string;
  error_message?: string;
  total_findings: number;
  severity: 'Informational' | 'Low' | 'Medium' | 'High' | 'Critical';
  confidence: string;
  package_name?: string;
  app_name?: string;
  c2_count: number;
  secret_count: number;
  reverse_shell_detected: boolean;
  file_type: 'apk' | 'exe' | 'multi' | 'generic';
  ai_assisted_analysis?: boolean;
}

export interface PermissionInfo {
  name: string;
  protection_level?: string;
  description?: string;
  is_dangerous: boolean;
  is_custom: boolean;
}

export interface ComponentInfo {
  name: string;
  component_type: 'activity' | 'service' | 'receiver' | 'provider';
  exported: boolean;
  permission?: string;
}

export interface CertificateInfo {
  subject: Record<string, string>;
  issuer: Record<string, string>;
  serial_number?: string;
  valid_from?: string;
  valid_to?: string;
  sha1_fingerprint?: string;
  sha256_fingerprint?: string;
  md5_fingerprint?: string;
  signature_algorithm?: string;
  is_self_signed: boolean;
  v1_signed: boolean;
  v2_signed: boolean;
  v3_signed: boolean;
}

export interface ApkMetadata {
  app_name?: string;
  package_name?: string;
  version_name?: string;
  version_code?: string;
  min_sdk_version?: string;
  target_sdk_version?: string;
  launcher_activity?: string;
  permissions: PermissionInfo[];
  activities: ComponentInfo[];
  services: ComponentInfo[];
  receivers: ComponentInfo[];
  providers: ComponentInfo[];
  certificates: CertificateInfo[];
  dex_files: Array<{ name: string; size: number; compressed_size: number }>;
  native_libraries: string[];
  embedded_archives: string[];
  embedded_executables: string[];
  uses_cleartext_traffic?: boolean;
  is_debuggable: boolean;
  allow_backup: boolean;
}

export interface StaticFinding {
  id: string;
  finding_id?: string;
  category: string;
  severity: 'Informational' | 'Low' | 'Medium' | 'High' | 'Critical' | string;
  confidence: 'Low' | 'Medium' | 'High' | 'Confirmed' | string;
  classification?: 'CONFIRMED FACT' | 'SUSPICIOUS INDICATOR' | 'HEURISTIC DETECTION' | 'NOT VERIFIED' | 'NOT APPLICABLE' | string;
  title: string;
  description: string;
  source_file?: string;
  file_path?: string;
  code_reference?: string;
  offset_or_reference?: string;
  evidence_snippet?: string;
  supporting_evidence?: string;
  detection_method?: string;
  evidence_source?: string;
  reason_for_detection?: string;
  technical_explanation?: string;
  explanation?: string;
  potential_impact?: string;
  remediation?: string;
  remediation_advice?: string;
  false_positive_considerations?: string;
}

export interface C2Indicator {
  id: string;
  indicator_type: 'domain' | 'ip' | 'url' | 'websocket' | 'dga' | 'dynamic_dns' | 'doh' | 'decoded_c2';
  value: string;
  normalized_value: string;
  source_file: string;
  code_reference?: string;
  port?: number;
  protocol?: string;
  encoding_steps?: string;
  classification: 'potential_c2' | 'suspicious_destination' | 'embedded_unclassified' | 'third_party' | 'private_ip' | 'benign' | 'reported_malicious' | 'unverified';
  why_suspicious: string;
  confidence: 'Low' | 'Medium' | 'High' | 'Confirmed';
  threat_intel_status: string;
  recommended_validation: string;
}

export interface SecretFinding {
  id: string;
  token_category: string;
  redacted_value: string;
  raw_value?: string;
  source_location: string;
  code_reference?: string;
  rule_matched: string;
  in_network_path: boolean;
  related_indicator?: string;
  confidence: string;
  verification_status: string;
  context_snippet?: string;
}

export interface ReverseShellFinding {
  id: string;
  pattern_type: string;
  title: string;
  severity: 'Medium' | 'High' | 'Critical';
  confidence: string;
  code_references: string[];
  execution_chain: string[];
  evidence_snippet?: string;
  explanation: string;
  limitations: string;
}

export interface NetworkIOC {
  id: string;
  ioc_type: 'ipv4' | 'ipv6' | 'domain' | 'url';
  value: string;
  source_file: string;
  related_domain?: string;
  related_urls: string[];
  ports: number[];
  is_private: boolean;
  asn?: string;
  country?: string;
  owner?: string;
  classification: string;
  confidence: string;
  threat_intel_summary?: string;
}

export interface ThreatIntelResult {
  id: string;
  provider: string;
  indicator: string;
  indicator_type: string;
  query_time: string;
  status: 'clean' | 'suspicious' | 'malicious' | 'not_found' | 'error' | 'rate_limited' | 'skipped';
  detections: number;
  total_engines: number;
  details: Record<string, any>;
  error_message?: string;
}

export interface ToolExecution {
  tool_name: string;
  installed: boolean;
  path_configured?: boolean;
  executable_path?: string;
  status: string;
  version?: string;
  duration_seconds?: number;
  exit_code?: number;
  output_path?: string;
  errors_warnings?: string;
  findings_count?: number;
  limitations?: string;
  connection_status?: string;
  test_status?: 'passed' | 'failed' | 'not_run' | 'error';
  test_timestamp?: string;
  diagnostic_message?: string;
  details?: Record<string, any>;
}

export interface FinalAssessment {
  overall_severity: 'Informational' | 'Low' | 'Medium' | 'High' | 'Critical';
  overall_confidence: 'Low' | 'Medium' | 'High';
  risk_score: number;
  executive_summary: string;
  strongest_evidence: string[];
  potential_malicious_functionality: string[];
  unanswered_questions: string[];
  limitations: string[];
  recommended_actions: string[];
  dynamic_analysis_conducted: boolean;
  external_intelligence_used: boolean;
}

export interface PeSection {
  name: string;
  virtual_address: string;
  virtual_size: number;
  raw_data_offset: number;
  raw_data_size: number;
  entropy: number;
  characteristics: string;
  readable: boolean;
  writable: boolean;
  executable: boolean;
  suspicious_indicators: string[];
  out_of_bounds: boolean;
}

export interface ImportedFunction {
  name: string;
  ordinal?: number;
  category: string;
  severity: string;
  confidence: string;
  why_relevant: string;
}

export interface ImportedDll {
  dll_name: string;
  functions: ImportedFunction[];
}

export interface PePersistenceFinding {
  id: string;
  mechanism: string;
  indicator_type: string;
  title: string;
  severity: string;
  confidence: string;
  source_evidence: string;
  details: string;
  limitations: string;
}

export interface PeMetadata {
  file_type: string;
  machine: string;
  magic: string;
  compilation_timestamp?: string;
  compilation_timestamp_raw?: number;
  timestamp_assessment: string;
  entry_point_rva: string;
  image_base: string;
  size_of_image: number;
  size_of_headers: number;
  checksum: string;
  subsystem: string;
  dll_characteristics: string[];
  file_characteristics: string[];
  number_of_sections: number;
  number_of_data_directories: number;
  version_info: Record<string, string>;
  sections: PeSection[];
  imports: ImportedDll[];
  exports: string[];
  is_signed: boolean;
  signature_info: Record<string, any>;
  packer_detected: boolean;
  packer_indicators: string[];
}

export interface GraphNode {
  id: string;
  label: string;
  type: 'apk' | 'exe' | 'package' | 'section' | 'c2' | 'secret' | 'reverse_shell' | 'persistence';
  severity?: string;
  details?: string;
}

export interface GraphLink {
  source: string;
  target: string;
  relationship: string;
}

export interface InvestigationDetail {
  record: InvestigationRecord;
  metadata?: ApkMetadata;
  pe_metadata?: PeMetadata;
  static_findings: StaticFinding[];
  c2_indicators: C2Indicator[];
  secrets: SecretFinding[];
  reverse_shell_findings: ReverseShellFinding[];
  persistence_findings: PePersistenceFinding[];
  network_iocs: NetworkIOC[];
  threat_intel: ThreatIntelResult[];
  tool_executions: ToolExecution[];
  assessment?: FinalAssessment;
  graph_data?: {
    nodes: GraphNode[];
    links: GraphLink[];
  };
  ai_observations?: AIObservation[];
  ai_recommendations?: AIRecommendation[];
  ai_notes?: AIAssistedNotes;
}

export interface AIObservation {
  id: string;
  investigation_id: string;
  evidence_id?: string;
  title: string;
  explanation: string;
  related_evidence_refs: string[];
  confidence: string;
  reasoning_summary: string;
  suggested_verification_steps: string[];
  status: 'UNVERIFIED' | 'ACCEPTED' | 'REJECTED';
  reviewer?: string;
  reviewed_at?: string;
  review_notes?: string;
  created_at: string;
}

export interface AIRecommendation {
  id: string;
  investigation_id: string;
  title: string;
  category: string;
  description: string;
  suggested_command_or_action?: string;
  priority: 'High' | 'Medium' | 'Low';
}

export interface AIAssistedNotes {
  investigation_id: string;
  execution_status: string;
  model_provider?: string;
  analysis_timestamp?: string;
  disclaimer: string;
  warnings_or_errors: string[];
  consent_approved: boolean;
}

export interface OpenCodeStatus {
  installed: boolean;
  version?: string;
  path?: string;
  enabled: boolean;
  model: string;
  is_local_model: boolean;
  auth_providers: { provider: string; status: string }[];
  network_mode: string;
  status_label: string;
  status_description: string;
  timeout_seconds: number;
}

export interface DashboardStats {
  total_investigations: number;
  apk_files_analyzed: number;
  exe_files_analyzed?: number;
  files_with_suspicious_indicators: number;
  high_confidence_malware_findings: number;
  potential_c2_configurations: number;
  detected_reverse_shell_indicators: number;
  detected_persistence_indicators?: number;
  active_running_tasks: number;
  detected_secrets_count: number;
  workspace_disk_mb: number;
  recent_investigations: InvestigationRecord[];
}

// ========================================================
// UNIVERSAL DIGITAL FORENSICS INTERFACES
// ========================================================

export interface EvidenceItem {
  id: string;
  investigation_id: string;
  parent_evidence_id?: string;
  filename: string;
  relative_path?: string;
  file_size: number;
  mime_type?: string;
  detected_format: string;
  extension?: string;
  format_mismatch: boolean;
  md5?: string;
  sha1?: string;
  sha256: string;
  sha512?: string;
  working_copy_sha256?: string;
  integrity_status: string;
  source_info?: string;
  examiner_notes?: string;
  acquired_at: string;
  filesystem_created_at?: string;
  filesystem_modified_at?: string;
  processing_state: string;
  entropy: number;
  triage_summary: Record<string, any>;
  metadata: Record<string, any>;
  created_at: string;
}

export interface ExtractedArtifact {
  id: string;
  investigation_id: string;
  evidence_id: string;
  parent_artifact_id?: string;
  artifact_type: string;
  source_format: string;
  source_location?: string;
  value: string;
  structured_data: Record<string, any>;
  sha256?: string;
  extractor_name: string;
  extracted_at: string;
  confidence: string;
  parser_warnings?: string;
}

export interface EvidenceRelationship {
  id: string;
  investigation_id: string;
  source_evidence_id: string;
  target_evidence_id: string;
  relationship_type: string;
  supporting_artifact_ids: string[];
  matching_method: string;
  strength: string;
  limitations?: string;
  created_at: string;
}

export interface TimelineEvent {
  id: string;
  investigation_id: string;
  evidence_id?: string;
  original_timestamp: string;
  original_timezone?: string;
  normalized_utc: string;
  timestamp_source: string;
  transformation_applied?: string;
  reliability: string;
  event_type: string;
  description: string;
  associated_finding_id?: string;
  related_evidence_ids: string[];
}

export interface ChainOfCustodyEvent {
  id: string;
  investigation_id: string;
  evidence_id?: string;
  event_type: string;
  timestamp_utc: string;
  examiner: string;
  original_hash?: string;
  working_copy_hash?: string;
  verification_result: string;
  details: Record<string, any>;
  prev_event_hash?: string;
  event_hash: string;
}

export interface FindingRecord {
  id: string;
  case_id?: string;
  investigation_id: string;
  evidence_id?: string;
  artifact_ids: string[];
  title: string;
  description: string;
  observation: string;
  interpretation: string;
  severity: 'Informational' | 'Low' | 'Medium' | 'High' | 'Critical';
  confidence: 'Low' | 'Medium' | 'High' | 'Confirmed';
  analysis_method: string;
  source_location?: string;
  analyzer_name: string;
  analyzer_version?: string;
  rule_version?: string;
  timestamp_utc: string;
  alternative_explanation?: string;
  limitations?: string;
  verification_state: 'pending_review' | 'verified' | 'rejected' | 'needs_more_evidence';
  analyst_notes?: string;
}

export interface DetectionCoverageItem {
  evidence_id: string;
  filename: string;
  detected_format: string;
  stages: Record<string, string>;
  findings_count: number;
  limitations: string[];
}

export interface ContradictionItem {
  id: string;
  title: string;
  category: string;
  evidence_ids: string[];
  details: string;
  observed_conflicts: Array<Record<string, any>>;
}

export interface OSINTIndicator {
  id: string;
  investigation_id: string;
  evidence_id?: string;
  artifact_id?: string;
  source_filename?: string;
  source_location?: string;
  indicator_type: string;
  value: string;
  normalized_value: string;
  provenance_type: string;
  extractor_or_provider: string;
  confidence: string;
  pivot_depth: number;
  parent_indicator_id?: string;
  first_seen_utc: string;
  last_updated_utc: string;
  limitations?: string;
  is_sensitive_secret: boolean;
  masked_value?: string;
}

export interface OSINTObservation {
  id: string;
  investigation_id: string;
  indicator_id: string;
  provider: string;
  indicator_type: string;
  indicator_value: string;
  query_timestamp_utc: string;
  provider_timestamp_utc?: string;
  status: string;
  normalized_data: Record<string, any>;
  permalink?: string;
  data_freshness: string;
  cache_expires_utc?: string;
  error_message?: string;
  limitations?: string;
}

export interface SecretExposureFinding {
  id: string;
  investigation_id: string;
  evidence_id: string;
  artifact_id: string;
  secret_type: string;
  masked_token: string;
  source_filename: string;
  source_location: string;
  independently_found_public_identities: string[];
  safety_attestation: string;
  risk_level: string;
  observation: string;
  interpretation: string;
}

export interface RecursivePivotJob {
  id: string;
  investigation_id: string;
  status: string;
  max_depth: number;
  current_depth: number;
  total_indicators_evaluated: number;
  total_new_indicators_discovered: number;
  total_provider_queries: number;
  budget_limit_queries: number;
  started_at_utc?: string;
  completed_at_utc?: string;
  errors: string[];
}

export interface OSINTGraphNode {
  id: string;
  node_type: string;
  label: string;
  entity_value: string;
  provenance: string;
  severity: string;
  data?: Record<string, any>;
}

export interface OSINTGraphEdge {
  id: string;
  source: string;
  target: string;
  relationship_type: string;
  provider_or_tool: string;
  confidence: string;
  permalink?: string;
  limitations?: string;
}

export interface UniversalInvestigationDetail extends InvestigationDetail {
  evidence_items: EvidenceItem[];
  extracted_artifacts: ExtractedArtifact[];
  evidence_relationships: EvidenceRelationship[];
  timeline_events: TimelineEvent[];
  chain_of_custody: ChainOfCustodyEvent[];
  findings_register: FindingRecord[];
  coverage_matrix: DetectionCoverageItem[];
  contradictions: ContradictionItem[];
  osint_indicators?: OSINTIndicator[];
  osint_observations?: OSINTObservation[];
  secret_exposure_findings?: SecretExposureFinding[];
  pivot_jobs?: RecursivePivotJob[];
  osint_graph_nodes?: OSINTGraphNode[];
  osint_graph_edges?: OSINTGraphEdge[];
  authorized_scopes?: AuthorizedNetworkScope[];
  active_validation_results?: ActiveValidationResult[];
  dynamic_sandbox_runs?: DynamicSandboxRun[];
  dynamic_telemetry_events?: DynamicTelemetryEvent[];
  network_flows?: NetworkFlowRecord[];
  dropped_artifacts?: DroppedArtifactRecord[];
  static_dynamic_correlations?: StaticDynamicCorrelation[];
  evidence_risk_assessment?: EvidenceRiskAssessment;
}

// ========================================================
// ADVANCED OSINT, NETWORK VALIDATION & DYNAMIC FORENSICS
// ========================================================

export interface AuthorizedNetworkScope {
  id: string;
  investigation_id: string;
  case_id?: string;
  authorized_targets: string[];
  allowed_test_types: string[];
  allowed_ports: number[];
  authorization_note: string;
  operator_name: string;
  operator_confirmed: boolean;
  request_budget: number;
  requests_used: number;
  created_at_utc: string;
  expires_at_utc: string;
  is_revoked: boolean;
}

export interface ActiveValidationResult {
  id: string;
  scope_id: string;
  investigation_id: string;
  target: string;
  test_type: string;
  status: string; // SUCCESS, SCOPE_REJECTED, PRIVATE_IP_BLOCKED, TIMEOUT, FAILED, CANCELLED
  resolved_ips: string[];
  port?: number;
  timing_ms: number;
  tls_cert_info?: Record<string, any>;
  http_status?: number;
  http_headers?: Record<string, string>;
  diagnostic_message?: string;
  timestamp_utc: string;
  operator_confirmation_ref?: string;
}

export interface SandboxToolStatus {
  tool_name: string;
  status: 'INSTALLED' | 'NOT_CONFIGURED' | 'UNAVAILABLE';
  version?: string;
  details?: Record<string, any>;
}

export interface DynamicSandboxRun {
  id: string;
  investigation_id: string;
  evidence_id: string;
  target_binary: string;
  sandbox_environment: string;
  status: 'PENDING' | 'RUNNING' | 'COMPLETED' | 'FAILED' | 'PARTIAL' | 'CANCELLED';
  is_simulated_network: boolean;
  simulated_services: string[];
  duration_seconds: number;
  started_at_utc: string;
  completed_at_utc?: string;
  process_count: number;
  file_event_count: number;
  registry_event_count: number;
  network_flow_count: number;
  dropped_artifacts_count: number;
  pcap_filename?: string;
  pcap_sha256?: string;
  sandbox_logs: string[];
  limitations?: string;
}

export interface DynamicTelemetryEvent {
  id: string;
  run_id: string;
  investigation_id: string;
  event_category: string;
  timestamp_utc: string;
  process_id?: number;
  process_name?: string;
  parent_process_id?: number;
  parent_process_name?: string;
  command_line?: string;
  target_path?: string;
  operation?: string;
  details: Record<string, any>;
  is_simulated: boolean;
  related_indicator_id?: string;
}

export interface NetworkFlowRecord {
  id: string;
  run_id: string;
  investigation_id: string;
  timestamp_utc: string;
  src_ip: string;
  src_port: number;
  dst_ip: string;
  dst_port: number;
  protocol: string;
  direction: string;
  dns_hostname?: string;
  tls_sni?: string;
  cert_fingerprint?: string;
  http_method?: string;
  http_status?: number;
  packet_count: number;
  byte_count: number;
  pcap_file?: string;
  packet_reference?: string;
  is_simulated: boolean;
  related_indicator_ids: string[];
}

export interface DroppedArtifactRecord {
  id: string;
  run_id: string;
  investigation_id: string;
  filename: string;
  file_path?: string;
  size_bytes: number;
  sha256: string;
  file_type?: string;
  dropped_by_process?: string;
  timestamp_utc: string;
}

export interface StaticDynamicCorrelation {
  id: string;
  investigation_id: string;
  static_finding_id: string;
  dynamic_event_id: string;
  source_evidence_id?: string;
  indicator_value: string;
  correlation_method: string;
  confidence: string;
  supporting_event_summary: string;
  packet_reference?: string;
  is_simulated_event: boolean;
  alternative_explanation: string;
  limitations: string;
  created_at_utc: string;
}

export interface EvidenceRiskAssessment {
  id: string;
  investigation_id: string;
  static_capability_score: number;
  observed_execution_score: number;
  observed_network_score: number;
  successful_protocol_interaction_score: number;
  confirmed_data_transfer_score: number;
  threat_intel_reputation_score: number;
  overall_risk_score: number;
  severity: 'Informational' | 'Low' | 'Medium' | 'High' | 'Critical';
  confidence: 'Unverified' | 'Low' | 'Medium' | 'High' | 'Confirmed';
  score_inputs: string[];
  weighting_method: string;
  corroboration_sources: string[];
  contradictory_evidence: string[];
  missing_evidence: string[];
  known_limitations: string[];
  assessed_at_utc: string;
}

export interface OSINTProviderMetadata {
  id: string;
  name: string;
  supported_indicator_types: string[];
  requires_credentials: boolean;
  is_configured: boolean;
  is_commercial_or_restricted: boolean;
  privacy_implications: string;
  rate_limit_policy: string;
  endpoint: string;
  known_limitations: string;
}

export interface SandboxEnvironmentInfo {
  id: string;
  name: string;
  platform?: 'windows' | 'android' | 'multi';
  os_family?: 'windows' | 'android' | 'multi' | string;
  provider_type: string;
  status: string;
  verification_status?: string;
  vm_name?: string;
  endpoint?: string;
  os_version?: string;
  version?: string;
  snapshot_name?: string;
  network_modes?: string[];
  capabilities?: string[];
  missing_prerequisites?: string[];
  setup_instructions?: string;
  created_at_utc?: string;
  last_health_check_utc?: string;
  details?: any;
  config?: any;
}

export interface SandboxCapabilityMatrix {
  host_os: string;
  host_edition: string;
  virtualization_enabled: boolean;
  hyperv_hypervisor_present: boolean;
  windows_sandbox_installed: boolean;
  android_sdk_path?: string;
  adb_path?: string;
  avd_count: number;
  avd_names: string[];
  mobfs_running: boolean;
  fakenet_present: boolean;
  inetsim_reachable: boolean;
  environments: SandboxEnvironmentInfo[];
  timestamp_utc: string;
}

export interface DynamicObservation {
  id: string;
  run_id: string;
  investigation_id: string;
  category: 'PROCESS' | 'FILE' | 'REGISTRY' | 'NETWORK' | 'API' | 'SECURITY';
  event_type: string;
  timestamp_utc: string;
  source: string;
  process_name?: string;
  process_id?: number;
  target_path?: string;
  details: Record<string, any>;
  mitre_technique?: string;
  severity: 'INFORMATIONAL' | 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  confidence: 'CONFIRMED' | 'HIGH' | 'MEDIUM' | 'LOW';
  status: 'VERIFIED' | 'MOCKED' | 'RUNTIME_OBSERVED' | 'STATIC_INDICATOR';
}

export interface DynamicArtifact {
  id: string;
  run_id: string;
  investigation_id: string;
  filename: string;
  artifact_type: 'dropped_file' | 'memory_dump' | 'pcap' | 'screenshot' | 'logcat' | 'procmon_csv' | 'report';
  sha256: string;
  size_bytes: number;
  extracted_path: string;
  details: Record<string, any>;
  created_at_utc: string;
}

export interface ProcessTreeNode {
  pid: number;
  ppid?: number;
  name: string;
  path?: string;
  cmdline?: string;
  integrity_level?: string;
  started_at_utc?: string;
  terminated_at_utc?: string;
  is_suspicious: boolean;
  mitre_tactics: string[];
  children: ProcessTreeNode[];
}

export interface DynamicReport {
  id: string;
  run_id: string;
  investigation_id: string;
  summary: string;
  risk_score: number;
  risk_level: string;
  total_processes: number;
  total_network_connections: number;
  total_files_dropped: number;
  total_registry_changes: number;
  mitre_tactics_observed: string[];
  mitre_techniques_observed: string[];
  correlations: any[];
  limitations: string[];
  markdown_content: string;
  json_data: Record<string, any>;
  generated_at_utc: string;
}

export interface DynamicDashboardMetrics {
  total_analyses: number;
  running_analyses: number;
  completed_analyses: number;
  failed_analyses: number;
  available_environments: number;
  active_threats_observed: number;
  average_risk_score: number;
  top_techniques: Array<{ technique: string; count: number }>;
  recent_runs: any[];
}

export interface SavedReportResult {
  status: string;
  request_id: string;
  investigation_id: string;
  format: string;
  filename: string;
  filepath: string;
  directory: string;
  file_size: number;
  file_size_formatted: string;
  created_at: string;
  error?: string;
}

export interface SavedReportItem {
  filename: string;
  filepath: string;
  directory: string;
  file_size: number;
  file_size_formatted: string;
  format: string;
  modified_at: string;
}

// ==============================================================================
// IP DETAILS & COMPREHENSIVE IP INTELLIGENCE REPORT INTERFACES
// ==============================================================================

export interface IPEvidenceReference {
  source_file: string;
  class_name?: string;
  method_name?: string;
  evidence_location?: string;
  associated_url?: string;
  associated_domain?: string;
  finding_id?: string;
  extraction_timestamp: string;
  context_snippet?: string;
}

export interface SourceReference {
  provider: string;
  query_timestamp: string;
  source_url?: string;
  lookup_status: string;
  confidence: string;
}

export interface IPNetworkInfo {
  net_range?: string;
  cidr?: string;
  net_name?: string;
  net_handle?: string;
  parent_handle?: string;
  net_type?: string;
  origin_as?: string;
  rir?: string;
  registration_status?: string;
  reg_date?: string;
  updated_date?: string;
  resource_link?: string;
  referral_server?: string;
  comment?: string;
}

export interface IPOrganizationInfo {
  organization?: string;
  org_id?: string;
  address?: string;
  city?: string;
  state_prov?: string;
  postal_code?: string;
  country?: string;
  official_website?: string;
  tech_contact_name?: string;
  tech_contact_email?: string;
  tech_contact_phone?: string;
  abuse_contact_name?: string;
  abuse_contact_email?: string;
  abuse_contact_phone?: string;
  admin_contact_name?: string;
}

export interface IPGeolocationInfo {
  country?: string;
  country_code?: string;
  region?: string;
  state?: string;
  city?: string;
  postal_code?: string;
  latitude?: number;
  longitude?: number;
  timezone?: string;
  continent?: string;
  confidence: string;
  data_source?: string;
  disclaimer: string;
}

export interface IPRoutingASNInfo {
  asn?: string;
  asn_name?: string;
  as_organization?: string;
  origin_as?: string;
  network_prefix?: string;
  cidr?: string;
  network_owner?: string;
  isp?: string;
  internet_transit_provider?: string;
  upstream_provider?: string;
  peering_info?: string;
  bgp_routing_info?: string;
  rir?: string;
}

export interface IPHostingServerInfo {
  hosting_provider?: string;
  cloud_provider?: string;
  datacenter?: string;
  vps_provider?: string;
  cdn_provider?: string;
  server_classification: string;
  classification_confidence: string;
  evidence_basis?: string;
}

export interface IPDomainDnsInfo {
  reverse_dns?: string;
  hostname?: string;
  associated_domains: string[];
  associated_urls: string[];
  a_records: string[];
  aaaa_records: string[];
  cname_records: string[];
  mx_records: string[];
  ns_records: string[];
  txt_records: string[];
  dns_provider?: string;
  resolution_timestamp?: string;
}

export interface IPThreatReputationInfo {
  threat_status: string;
  malicious_count: number;
  suspicious_count: number;
  total_security_engines: number;
  abuse_confidence_score?: number;
  threat_categories: string[];
  known_malware_associations: string[];
  known_botnet_associations: string[];
  scanner_activity?: string;
  suspicious_network_behaviour?: string;
  known_c2_associations: boolean;
  blacklist_status: string;
  last_reported_date?: string;
  first_seen_date?: string;
  last_seen_date?: string;
  provider_results: Record<string, any>;
}

export interface IPClassificationInfo {
  is_private: boolean;
  is_loopback: boolean;
  is_link_local: boolean;
  is_reserved: boolean;
  is_multicast: boolean;
  is_carrier_grade_nat: boolean;
  is_cloud: boolean;
  is_cdn: boolean;
  is_vpn: boolean;
  is_proxy: boolean;
  is_tor_exit_node: boolean;
  is_public_dns: boolean;
  classification_label: string;
  classification_confidence: string;
}

export interface IPDetailRecord {
  id: string;
  investigation_id: string;
  ip_address: string;
  ip_version: string;
  canonical_ip: string;
  classification: IPClassificationInfo;
  network_info: IPNetworkInfo;
  organization_info: IPOrganizationInfo;
  geolocation_info: IPGeolocationInfo;
  routing_asn_info: IPRoutingASNInfo;
  hosting_server_info: IPHostingServerInfo;
  domain_dns_info: IPDomainDnsInfo;
  threat_info: IPThreatReputationInfo;
  evidence_references: IPEvidenceReference[];
  source_references: SourceReference[];
  lookup_status: string;
  lookup_timestamp: string;
  created_at_utc: string;
}

export interface InvestigationIPsSummary {
  investigation_id: string;
  total_unique_ips: number;
  ipv4_count: number;
  ipv6_count: number;
  public_ip_count: number;
  private_ip_count: number;
  cloud_ip_count: number;
  malicious_ip_count: number;
  suspicious_ip_count: number;
  clean_ip_count: number;
  unknown_ip_count: number;
  network_mode: string;
  extraction_timestamp_utc: string;
  ips: IPDetailRecord[];
}








