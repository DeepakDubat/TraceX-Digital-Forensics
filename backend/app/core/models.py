from datetime import datetime
from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field, model_validator

class InvestigationBase(BaseModel):
    case_reference: Optional[str] = None
    investigator_name: Optional[str] = None
    description: Optional[str] = None
    analyst_notes: Optional[str] = None
    local_only_mode: bool = False
    ai_assisted_analysis: bool = False
    file_type: str = "apk" # apk, exe

class InvestigationCreate(InvestigationBase):
    pass

class InvestigationRecord(InvestigationBase):
    id: str
    filename: str
    original_size: int
    md5: str
    sha1: str
    sha256: str
    status: str = "pending" # pending, analyzing, completed, failed, cancelled
    progress: int = 0
    current_stage: str = "Initialized"
    created_at: datetime = Field(default_factory=datetime.utcnow)
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    error_message: Optional[str] = None
    file_type: str = "apk" # apk, exe
    
    # Summary counters
    total_findings: int = 0
    severity: str = "Informational" # Informational, Low, Medium, High, Critical
    confidence: str = "Unverified"
    package_name: Optional[str] = None
    app_name: Optional[str] = None
    c2_count: int = 0
    secret_count: int = 0
    reverse_shell_detected: bool = False

class PermissionInfo(BaseModel):
    name: str
    protection_level: Optional[str] = "normal"
    description: Optional[str] = None
    is_dangerous: bool = False
    is_custom: bool = False

class ComponentInfo(BaseModel):
    name: str
    component_type: str # activity, service, receiver, provider
    exported: bool = False
    permission: Optional[str] = None
    intent_filters: List[Dict[str, Any]] = []

class CertificateInfo(BaseModel):
    subject: Dict[str, str] = {}
    issuer: Dict[str, str] = {}
    serial_number: Optional[str] = None
    valid_from: Optional[str] = None
    valid_to: Optional[str] = None
    sha1_fingerprint: Optional[str] = None
    sha256_fingerprint: Optional[str] = None
    md5_fingerprint: Optional[str] = None
    signature_algorithm: Optional[str] = None
    is_self_signed: bool = False
    v1_signed: bool = False
    v2_signed: bool = False
    v3_signed: bool = False

class ApkMetadata(BaseModel):
    app_name: Optional[str] = None
    package_name: Optional[str] = None
    version_name: Optional[str] = None
    version_code: Optional[str] = None
    min_sdk_version: Optional[str] = None
    target_sdk_version: Optional[str] = None
    max_sdk_version: Optional[str] = None
    launcher_activity: Optional[str] = None
    permissions: List[PermissionInfo] = []
    activities: List[ComponentInfo] = []
    services: List[ComponentInfo] = []
    receivers: List[ComponentInfo] = []
    providers: List[ComponentInfo] = []
    certificates: List[CertificateInfo] = []
    dex_files: List[Dict[str, Any]] = []
    native_libraries: List[str] = []
    embedded_archives: List[str] = []
    embedded_executables: List[str] = []
    uses_cleartext_traffic: Optional[bool] = None
    is_debuggable: bool = False
    allow_backup: bool = True
    network_security_config: Optional[str] = None
    icon_base64: Optional[str] = None

class StaticFinding(BaseModel):
    id: str
    finding_id: Optional[str] = None
    category: str # manifest, dex_bytecode, crypto, dynamic_loading, reflection, network, persistence
    severity: str # Informational, Low, Medium, High, Critical
    confidence: str # Low, Medium, High, Confirmed
    classification: str = "HEURISTIC DETECTION" # CONFIRMED FACT, SUSPICIOUS INDICATOR, HEURISTIC DETECTION, NOT VERIFIED, NOT APPLICABLE
    title: str
    description: str
    source_file: Optional[str] = None
    file_path: Optional[str] = None
    code_reference: Optional[str] = None
    offset_or_reference: Optional[str] = None
    evidence_snippet: Optional[str] = None
    supporting_evidence: Optional[str] = None
    detection_method: Optional[str] = "Static Analysis"
    evidence_source: Optional[str] = None
    reason_for_detection: Optional[str] = None
    technical_explanation: Optional[str] = None
    explanation: Optional[str] = None
    potential_impact: Optional[str] = None
    remediation: Optional[str] = None
    remediation_advice: Optional[str] = None
    false_positive_considerations: Optional[str] = None

    @model_validator(mode="before")
    @classmethod
    def sync_finding_fields(cls, data: Any) -> Any:
        if isinstance(data, dict):
            fid = data.get("finding_id") or data.get("id") or "FINDING-000"
            data["id"] = fid
            data["finding_id"] = fid
            
            sf = data.get("file_path") or data.get("source_file") or "evidence_file"
            data["source_file"] = sf
            data["file_path"] = sf
            data.setdefault("evidence_source", sf)

            cr = data.get("offset_or_reference") or data.get("code_reference") or ""
            data["code_reference"] = cr
            data["offset_or_reference"] = cr

            es = data.get("supporting_evidence") or data.get("evidence_snippet") or ""
            data["evidence_snippet"] = es
            data["supporting_evidence"] = es

            exp = data.get("technical_explanation") or data.get("explanation") or data.get("description") or ""
            data["explanation"] = exp
            data["technical_explanation"] = exp
            data.setdefault("reason_for_detection", data.get("description") or exp)

            rem = data.get("remediation") or data.get("remediation_advice") or "Follow standard forensic triage and code review procedures."
            data["remediation"] = rem
            data["remediation_advice"] = rem

            if "classification" not in data or not data["classification"]:
                conf = str(data.get("confidence", "")).lower()
                sev = str(data.get("severity", "")).lower()
                cat = str(data.get("category", "")).lower()
                if conf in ("confirmed", "high") and cat in ("manifest", "signature", "headers"):
                    data["classification"] = "CONFIRMED FACT"
                elif sev in ("high", "critical"):
                    data["classification"] = "SUSPICIOUS INDICATOR"
                elif sev == "informational":
                    data["classification"] = "CONFIRMED FACT"
                else:
                    data["classification"] = "HEURISTIC DETECTION"

            data.setdefault("potential_impact", f"Potential {data.get('severity', 'Medium')} risk associated with {data.get('category', 'code')} configuration.")
            data.setdefault("false_positive_considerations", "Review context to ensure component is not part of standard operating system framework or legitimate third-party SDK.")
        return data

class C2Indicator(BaseModel):
    id: str
    indicator_type: str # domain, ip, url, websocket, dga, dynamic_dns, doh
    value: str
    normalized_value: str
    source_file: str
    code_reference: Optional[str] = None
    port: Optional[int] = None
    protocol: Optional[str] = None
    encoding_steps: Optional[str] = None
    classification: str # potential_c2, suspicious_destination, embedded_unclassified, third_party, private_ip, benign, reported_malicious, unverified
    why_suspicious: str
    confidence: str # Low, Medium, High, Confirmed
    threat_intel_status: str = "Unchecked"
    recommended_validation: str

class SecretFinding(BaseModel):
    id: str
    token_category: str # api_key, auth_token, bearer, jwt, telegram_bot, oauth, cloud_credential, private_key, password_hash, encryption_key, custom_token
    redacted_value: str
    raw_value: Optional[str] = None # Retained securely for authorized detail view
    source_location: str
    code_reference: Optional[str] = None
    rule_matched: str
    in_network_path: bool = False
    related_indicator: Optional[str] = None
    confidence: str # Low, Medium, High
    verification_status: str = "Pattern Matched (Offline Heuristic)"
    context_snippet: Optional[str] = None

class ReverseShellFinding(BaseModel):
    id: str
    pattern_type: str # process_builder, runtime_exec, socket_command_chain, shell_binary, io_stream_redirect, native_exec, busybox
    title: str
    severity: str # Medium, High, Critical
    confidence: str # Inconclusive, Suspicious API, Possible Remote Command Execution, Probable Reverse-Shell, Confirmed Chain
    code_references: List[str] = []
    execution_chain: List[str] = []
    evidence_snippet: Optional[str] = None
    explanation: str
    limitations: str = "Static analysis identifies presence of code paths; live runtime execution is not conducted to prevent active C2 interaction."

class NetworkIOC(BaseModel):
    id: str
    ioc_type: str # ipv4, ipv6, domain, url
    value: str
    source_file: str
    related_domain: Optional[str] = None
    related_urls: List[str] = []
    ports: List[int] = []
    is_private: bool = False
    asn: Optional[str] = None
    country: Optional[str] = None
    owner: Optional[str] = None
    classification: str = "Embedded String"
    confidence: str = "Medium"
    threat_intel_summary: Optional[str] = None

class ThreatIntelResult(BaseModel):
    id: str
    provider: str # VirusTotal, AbuseIPDB, AlienVault OTX, URLhaus, MalwareBazaar
    indicator: str
    indicator_type: str # hash, domain, ip, url
    query_time: datetime = Field(default_factory=datetime.utcnow)
    status: str # clean, suspicious, malicious, not_found, error, rate_limited, skipped
    detections: int = 0
    total_engines: int = 0
    details: Dict[str, Any] = {}
    error_message: Optional[str] = None

class ToolExecution(BaseModel):
    tool_name: str
    installed: bool = False
    path_configured: bool = False
    executable_path: Optional[str] = None
    status: str = "pending" # pending, running, completed, failed, skipped, or structured status
    version: Optional[str] = None
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    duration_seconds: float = 0.0
    exit_code: Optional[int] = None
    output_path: Optional[str] = None
    errors_warnings: Optional[str] = None
    findings_count: int = 0
    limitations: Optional[str] = None
    connection_status: Optional[str] = None
    test_status: str = "not_run" # passed, failed, not_run, error
    test_timestamp: Optional[str] = None
    diagnostic_message: Optional[str] = None
    category: str = "Static Analysis"
    supported_inputs: List[str] = []
    dependencies: List[str] = []
    operational_status: Optional[str] = None
    details: Dict[str, Any] = {}

class FinalAssessment(BaseModel):
    overall_severity: str = "Informational"
    overall_confidence: str = "Medium"
    risk_score: int = 0
    executive_summary: str = ""
    strongest_evidence: List[str] = []
    potential_malicious_functionality: List[str] = []
    unanswered_questions: List[str] = []
    limitations: List[str] = []
    recommended_actions: List[str] = []
    dynamic_analysis_conducted: bool = False
    external_intelligence_used: bool = False

class PeSection(BaseModel):
    name: str
    virtual_address: str
    virtual_size: int
    raw_data_offset: int
    raw_data_size: int
    entropy: float
    characteristics: str
    readable: bool = True
    writable: bool = False
    executable: bool = False
    suspicious_indicators: List[str] = []
    out_of_bounds: bool = False

class ImportedFunction(BaseModel):
    name: str
    ordinal: Optional[int] = None
    category: str = "System"
    severity: str = "Informational"
    confidence: str = "Medium"
    why_relevant: str = ""

class ImportedDll(BaseModel):
    dll_name: str
    functions: List[ImportedFunction] = []

class PePersistenceFinding(BaseModel):
    id: str
    mechanism: str # Registry Run Key, Startup Folder, Windows Service, Scheduled Task, Process Injection, PowerShell Execution, WMI, DLL Loading
    indicator_type: str # String Indicator, API Capability, Correlated Pattern
    title: str
    severity: str # Low, Medium, High, Critical
    confidence: str # Low, Medium, High, Confirmed
    source_evidence: str
    details: str
    limitations: str = "Static analysis identifies presence of persistence indicators; execution is not performed."

class PeMetadata(BaseModel):
    file_type: str = "exe"
    machine: str = "Unknown"
    magic: str = "PE32"
    compilation_timestamp: Optional[str] = None
    compilation_timestamp_raw: Optional[int] = None
    timestamp_assessment: str = "Normal"
    entry_point_rva: str = "0x0"
    image_base: str = "0x0"
    size_of_image: int = 0
    size_of_headers: int = 0
    checksum: str = "0x0"
    subsystem: str = "Unknown"
    dll_characteristics: List[str] = []
    file_characteristics: List[str] = []
    number_of_sections: int = 0
    number_of_data_directories: int = 0
    version_info: Dict[str, str] = {}
    sections: List[PeSection] = []
    imports: List[ImportedDll] = []
    exports: List[str] = []
    is_signed: bool = False
    signature_info: Dict[str, Any] = {}
    packer_detected: bool = False
    packer_indicators: List[str] = []

# ========================================================
# OPENCODE AI-ASSISTED FORENSIC ENGINE MODELS
# ========================================================

class AIObservation(BaseModel):
    id: str # e.g. AIOBS-001
    investigation_id: str
    evidence_id: Optional[str] = None
    title: str
    explanation: str
    related_evidence_refs: List[str] = []
    confidence: str = "Unverified" # Unverified, Low, Medium, High
    reasoning_summary: str
    suggested_verification_steps: List[str] = []
    status: str = "UNVERIFIED" # UNVERIFIED, ACCEPTED, REJECTED
    reviewer: Optional[str] = None
    reviewed_at: Optional[datetime] = None
    review_notes: Optional[str] = None
    created_at: datetime = Field(default_factory=datetime.utcnow)

class AIRecommendation(BaseModel):
    id: str # e.g. AIREC-001
    investigation_id: str
    title: str
    category: str # Verification, Network Analysis, Code Review, YARA Rule
    description: str
    suggested_command_or_action: Optional[str] = None
    priority: str = "Medium" # High, Medium, Low

class AIAssistedNotes(BaseModel):
    investigation_id: str
    execution_status: str # COMPLETED, SKIPPED, DISABLED, FAILED, UNAVAILABLE
    model_provider: Optional[str] = None
    analysis_timestamp: Optional[datetime] = None
    disclaimer: str = "AI-assisted technical explanation. Every factual conclusion must be independently verified against raw decompiled bytecode and deterministic analyzer evidence."
    warnings_or_errors: List[str] = []
    consent_approved: bool = False

class AIObservationReviewRequest(BaseModel):
    status: str # ACCEPTED, REJECTED, UNVERIFIED
    review_notes: Optional[str] = None

class InvestigationDetail(BaseModel):
    record: InvestigationRecord
    metadata: Optional[Any] = None # ApkMetadata or PeMetadata
    pe_metadata: Optional[PeMetadata] = None
    static_findings: List[StaticFinding] = []
    c2_indicators: List[C2Indicator] = []
    secrets: List[SecretFinding] = []
    reverse_shell_findings: List[ReverseShellFinding] = []
    persistence_findings: List[PePersistenceFinding] = []
    network_iocs: List[NetworkIOC] = []
    threat_intel: List[ThreatIntelResult] = []
    tool_executions: List[ToolExecution] = []
    assessment: Optional[FinalAssessment] = None
    graph_data: Optional[Dict[str, Any]] = None
    ai_observations: List[AIObservation] = []
    ai_recommendations: List[AIRecommendation] = []
    ai_notes: Optional[AIAssistedNotes] = None

class SystemStatus(BaseModel):
    tools: List[ToolExecution] = []
    apis: Dict[str, Dict[str, Any]] = {}
    local_only_mode: bool = False
    active_jobs: int = 0
    workspace_disk_usage_mb: float = 0.0

# ========================================================
# UNIVERSAL DIGITAL FORENSICS MODELS
# ========================================================

class EvidenceItem(BaseModel):
    id: str
    investigation_id: str
    parent_evidence_id: Optional[str] = None
    filename: str
    relative_path: Optional[str] = None
    file_size: int
    mime_type: Optional[str] = None
    detected_format: str
    extension: Optional[str] = None
    format_mismatch: bool = False
    md5: Optional[str] = None
    sha1: Optional[str] = None
    sha256: str
    sha512: Optional[str] = None
    working_copy_sha256: Optional[str] = None
    integrity_status: str = "VERIFIED" # VERIFIED, MISMATCH, NOT_VERIFIED
    source_info: Optional[str] = None
    examiner_notes: Optional[str] = None
    acquired_at: datetime = Field(default_factory=datetime.utcnow)
    filesystem_created_at: Optional[str] = None
    filesystem_modified_at: Optional[str] = None
    processing_state: str = "NOT_RUN" # FULL, PARTIAL, METADATA_ONLY, GENERIC_TRIAGE_ONLY, UNSUPPORTED, FAILED, SKIPPED_BY_POLICY, NOT_RUN
    entropy: float = 0.0
    triage_summary: Dict[str, Any] = {}
    metadata: Dict[str, Any] = {}
    created_at: datetime = Field(default_factory=datetime.utcnow)

class ExtractedArtifact(BaseModel):
    id: str
    investigation_id: str
    evidence_id: str
    parent_artifact_id: Optional[str] = None
    artifact_type: str # url, ip, domain, email, file_attachment, image_ocr, pdf_action, office_macro, api_call, etc.
    source_format: str
    source_location: Optional[str] = None
    value: str
    structured_data: Dict[str, Any] = {}
    sha256: Optional[str] = None
    extractor_name: str
    extracted_at: datetime = Field(default_factory=datetime.utcnow)
    confidence: str = "Medium"
    parser_warnings: Optional[str] = None

class EvidenceRelationship(BaseModel):
    id: str
    investigation_id: str
    source_evidence_id: str
    target_evidence_id: str
    relationship_type: str # EXACT_HASH_MATCH, SHARED_C2_DOMAIN, SHARED_IP, SHARED_URL, SHARED_EMAIL, PARENT_CHILD_ARCHIVE, EMAIL_ATTACHMENT, PERCEPTUAL_IMAGE_SIMILARITY, SHARED_CERTIFICATE, SHARED_SECRET
    supporting_artifact_ids: List[str] = []
    matching_method: str
    strength: str = "Exact" # Exact, High, Medium, Heuristic
    limitations: Optional[str] = None
    created_at: datetime = Field(default_factory=datetime.utcnow)

class TimelineEvent(BaseModel):
    id: str
    investigation_id: str
    evidence_id: Optional[str] = None
    original_timestamp: str
    original_timezone: Optional[str] = None
    normalized_utc: str
    timestamp_source: str
    transformation_applied: Optional[str] = None
    reliability: str = "High" # High, Medium, Low
    event_type: str
    description: str
    associated_finding_id: Optional[str] = None
    related_evidence_ids: List[str] = []

class ChainOfCustodyEvent(BaseModel):
    id: str
    investigation_id: str
    evidence_id: Optional[str] = None
    event_type: str # EVIDENCE_RECEIVED, HASH_VERIFIED, WORKING_COPY_CREATED, ANALYSIS_STARTED, ANALYSIS_COMPLETED, INTEGRITY_CHECK_FAILED, REPORT_GENERATED, ANALYST_NOTE_ADDED, EVIDENCE_EXPORTED
    timestamp_utc: str
    examiner: str
    original_hash: Optional[str] = None
    working_copy_hash: Optional[str] = None
    verification_result: str = "PASSED" # PASSED, FAILED, INITIAL
    details: Dict[str, Any] = {}
    prev_event_hash: Optional[str] = None
    event_hash: str

class FindingRecord(BaseModel):
    id: str
    case_id: Optional[str] = None
    investigation_id: str
    evidence_id: Optional[str] = None
    artifact_ids: List[str] = []
    title: str
    description: str
    observation: str
    interpretation: str
    severity: str = "Medium" # Informational, Low, Medium, High, Critical
    confidence: str = "Medium" # Low, Medium, High, Confirmed
    analysis_method: str
    source_location: Optional[str] = None
    analyzer_name: str
    analyzer_version: Optional[str] = None
    rule_version: Optional[str] = None
    timestamp_utc: str = Field(default_factory=lambda: datetime.utcnow().isoformat())
    alternative_explanation: Optional[str] = None
    limitations: Optional[str] = None
    verification_state: str = "pending_review" # pending_review, verified, rejected, needs_more_evidence
    analyst_notes: Optional[str] = None
    source_evidence: Optional[str] = None
    source_file: Optional[str] = None
    frame_number: Optional[int] = None
    packet_number: Optional[int] = None
    timestamp: Optional[str] = None
    engine: Optional[str] = None
    rule_id: Optional[str] = None
    original_hash: Optional[str] = None

class DetectionCoverageItem(BaseModel):
    evidence_id: str
    filename: str
    detected_format: str
    stages: Dict[str, str] = {} # e.g. "Format Identification": "COMPLETED", "OCR": "UNAVAILABLE"
    findings_count: int = 0
    limitations: List[str] = []

class ContradictionItem(BaseModel):
    id: str
    title: str
    category: str # Timestamp Inconsistency, Format Mismatch, Unsupported Claim
    evidence_ids: List[str] = []
    details: str
    observed_conflicts: List[Dict[str, Any]] = []

# ========================================================
# OSINT & RECURSIVE PIVOT MODELS
# ========================================================

class OSINTIndicator(BaseModel):
    id: str
    investigation_id: str
    evidence_id: Optional[str] = None
    artifact_id: Optional[str] = None
    source_filename: Optional[str] = None
    source_location: Optional[str] = None
    indicator_type: str # ipv4, ipv6, domain, hostname, url, hash, email, certificate_fingerprint, telegram_bot_token, telegram_username
    value: str
    normalized_value: str
    provenance_type: str = "DIRECT_EVIDENCE" # DIRECT_EVIDENCE, PIVOT_DERIVED, HISTORICAL_RECORD, INFERRED
    extractor_or_provider: str
    confidence: str = "High" # Confirmed, High, Medium, Low, Unverified
    pivot_depth: int = 0
    parent_indicator_id: Optional[str] = None
    first_seen_utc: str = Field(default_factory=lambda: datetime.utcnow().isoformat())
    last_updated_utc: str = Field(default_factory=lambda: datetime.utcnow().isoformat())
    limitations: Optional[str] = None
    is_sensitive_secret: bool = False
    masked_value: Optional[str] = None

class OSINTObservation(BaseModel):
    id: str
    investigation_id: str
    indicator_id: str
    provider: str # VirusTotal, AbuseIPDB, AlienVault OTX, URLhaus, MalwareBazaar, urlscan.io, DNS, ReverseDNS, RDAP, NetworkInfo, CertTransparency
    indicator_type: str
    indicator_value: str
    query_timestamp_utc: str = Field(default_factory=lambda: datetime.utcnow().isoformat())
    provider_timestamp_utc: Optional[str] = None
    status: str # SUCCESS, NO_DATA, NOT_FOUND, RATE_LIMITED, UNAUTHORIZED, FORBIDDEN, TIMEOUT, NETWORK_ERROR, UNAVAILABLE, SKIPPED_BY_PRIVACY_POLICY, SKIPPED_LOCAL_ONLY, INVALID_INDICATOR, PARTIAL
    normalized_data: Dict[str, Any] = {}
    permalink: Optional[str] = None
    data_freshness: str = "Live" # Live, Cached, Historical
    cache_expires_utc: Optional[str] = None
    error_message: Optional[str] = None
    limitations: Optional[str] = None

class SecretExposureFinding(BaseModel):
    id: str
    investigation_id: str
    evidence_id: str
    artifact_id: str
    secret_type: str # telegram_bot_token, aws_access_key, api_key, private_key
    masked_token: str
    source_filename: str
    source_location: str
    independently_found_public_identities: List[str] = [] # e.g. ["@DarkC2Bot", "https://t.me/DarkC2Bot"]
    safety_attestation: str = "Token was strictly isolated and masked. Never transmitted to third-party endpoints or Telegram servers."
    risk_level: str = "High"
    observation: str
    interpretation: str

class OSINTGraphNode(BaseModel):
    id: str
    node_type: str # evidence_file, domain, ip, url, certificate, asn, organization, file_hash, telegram_username, secret_exposure
    label: str
    entity_value: str
    provenance: str # Direct Evidence, OSINT Provider, Derived Pivot
    severity: str = "Informational"
    data: Dict[str, Any] = {}

class OSINTGraphEdge(BaseModel):
    id: str
    source: str
    target: str
    relationship_type: str # EXTRACTED_FROM, RESOLVES_TO, REVERSE_RESOLVES_TO, REGISTERED_WITH, ASSIGNED_TO_NETWORK, HOSTED_BY, GEOLOCATED_APPROXIMATELY_TO, CERTIFICATE_LISTS_HOSTNAME, OBSERVED_BY_PROVIDER, RELATED_BY_PROVIDER, HASH_MATCH, URL_HOSTED_ON, PARENT_INDICATOR, POSSIBLE_RELATIONSHIP, CORROBORATES, CONTRADICTS
    provider_or_tool: str
    confidence: str = "High"
    permalink: Optional[str] = None
    limitations: Optional[str] = None

class RecursivePivotJob(BaseModel):
    id: str
    investigation_id: str
    status: str = "pending" # pending, running, completed, stopped_budget, stopped_depth, failed
    max_depth: int = 3
    current_depth: int = 0
    total_indicators_evaluated: int = 0
    total_new_indicators_discovered: int = 0
    total_provider_queries: int = 0
    budget_limit_queries: int = 50
    started_at_utc: Optional[str] = None
    completed_at_utc: Optional[str] = None
    errors: List[str] = []

# ========================================================
# AUTHORIZED NETWORK VALIDATION MODELS
# ========================================================

class AuthorizedNetworkScope(BaseModel):
    id: str
    investigation_id: str
    case_id: Optional[str] = None
    authorized_targets: List[str] = [] # approved domains and public IPs
    allowed_test_types: List[str] = [] # DNS, TCP_CONNECT, TLS_INSPECT, HTTPS_HEAD, LIMITED_GET
    allowed_ports: List[int] = [80, 443]
    authorization_note: str
    operator_name: str
    operator_confirmed: bool = False
    request_budget: int = 20
    requests_used: int = 0
    created_at_utc: str = Field(default_factory=lambda: datetime.utcnow().isoformat())
    expires_at_utc: str
    is_revoked: bool = False

class ActiveValidationResult(BaseModel):
    id: str
    scope_id: str
    investigation_id: str
    target: str
    test_type: str
    status: str # SUCCESS, SCOPE_REJECTED, PRIVATE_IP_BLOCKED, TIMEOUT, FAILED, CANCELLED
    resolved_ips: List[str] = []
    port: Optional[int] = None
    timing_ms: float = 0.0
    tls_cert_info: Optional[Dict[str, Any]] = None
    http_status: Optional[int] = None
    http_headers: Optional[Dict[str, str]] = None
    diagnostic_message: Optional[str] = None
    timestamp_utc: str = Field(default_factory=lambda: datetime.utcnow().isoformat())
    operator_confirmation_ref: Optional[str] = None

# ========================================================
# DYNAMIC SANDBOX & NETWORK TELEMETRY MODELS
# ========================================================

class SandboxToolStatus(BaseModel):
    tool_name: str # CAPE Sandbox, FakeNet-NG, INetSim, Wireshark/tshark, Zeek, Suricata
    status: str # INSTALLED, NOT_CONFIGURED, UNAVAILABLE
    version: Optional[str] = None
    details: Dict[str, Any] = {}

class SandboxEnvironmentInfo(BaseModel):
    id: str
    name: str
    provider_type: str # "hyperv", "windows_sandbox", "cape", "android_emulator", "genymotion", "mobsf_dynamic"
    os_family: str # "windows", "android"
    is_available: bool = False
    status: str = "NOT_CONFIGURED" # "INSTALLED_AND_READY", "CONFIGURED_OFFLINE", "NOT_CONFIGURED", "UNSUPPORTED_PLATFORM"
    version: Optional[str] = None
    details: Dict[str, Any] = {}
    config: Dict[str, Any] = {}
    last_checked_at: str = Field(default_factory=lambda: datetime.utcnow().isoformat())

class SandboxCapabilityMatrix(BaseModel):
    os_name: str
    os_version: str
    cpu_virtualization_enabled: bool = False
    hyperv_supported: bool = False
    hyperv_active: bool = False
    windows_sandbox_installed: bool = False
    android_sdk_installed: bool = False
    adb_installed: bool = False
    available_avds: List[str] = []
    active_emulators: List[str] = []
    mobsf_dynamic_configured: bool = False
    cape_configured: bool = False
    fakenet_installed: bool = False
    inetsim_installed: bool = False
    overall_windows_readiness: str = "NOT_CONFIGURED"
    overall_android_readiness: str = "NOT_CONFIGURED"
    checked_at_utc: str = Field(default_factory=lambda: datetime.utcnow().isoformat())

class DynamicSandboxRun(BaseModel):
    id: str
    investigation_id: str
    evidence_id: str
    target_binary: str
    sandbox_environment: str # e.g. "Isolated VM", "Simulated Network (FakeNet-NG)", "Imported Sandbox Run"
    status: str = "PENDING" # PENDING, INITIALIZING, PROVISIONING, RUNNING, MONITORING, COLLECTING, TEARDOWN, RESTORING, COMPLETED, FAILED, CANCELLED
    is_simulated_network: bool = True
    simulated_services: List[str] = ["DNS", "HTTP", "HTTPS"]
    duration_seconds: float = 0.0
    started_at_utc: str = Field(default_factory=lambda: datetime.utcnow().isoformat())
    completed_at_utc: Optional[str] = None
    process_count: int = 0
    file_event_count: int = 0
    registry_event_count: int = 0
    network_flow_count: int = 0
    dropped_artifacts_count: int = 0
    pcap_filename: Optional[str] = None
    pcap_sha256: Optional[str] = None
    sandbox_logs: List[str] = []
    limitations: Optional[str] = "No malware executed on host. Telemetry captured via isolated guest or simulated network."
    # Dynamic Lab v2.0 Extensions
    user_id: Optional[str] = None
    target_sha256: Optional[str] = None
    target_type: str = "generic" # "apk", "exe", "generic"
    provider: Optional[str] = None
    environment_id: Optional[str] = None
    network_policy: str = "DISABLED" # "DISABLED", "ISOLATED_SIMULATION", "LIVE_INTERNET"
    timeout_seconds: int = 120
    risk_score: float = 0.0
    risk_level: str = "Informational" # "Informational", "Low", "Medium", "High", "Critical"
    report_id: Optional[str] = None

class DynamicTelemetryEvent(BaseModel):
    id: str
    run_id: str
    investigation_id: str
    event_category: str # PROCESS, FILE, REGISTRY, MODULE, API, NETWORK_FLOW, DNS_QUERY, TLS_HANDSHAKE, HTTP_REQUEST, DROPPED_FILE
    timestamp_utc: str
    process_id: Optional[int] = None
    process_name: Optional[str] = None
    parent_process_id: Optional[int] = None
    parent_process_name: Optional[str] = None
    command_line: Optional[str] = None
    target_path: Optional[str] = None
    operation: Optional[str] = None # e.g. "CreateKey", "SetValue", "WriteFile", "Connect", "Query"
    details: Dict[str, Any] = {}
    is_simulated: bool = True
    related_indicator_id: Optional[str] = None

class NetworkFlowRecord(BaseModel):
    id: str
    run_id: str
    investigation_id: str
    timestamp_utc: str
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    protocol: str # TCP, UDP, ICMP, DNS, TLS, HTTP
    direction: str = "OUTBOUND" # OUTBOUND, INBOUND, LOCAL
    dns_hostname: Optional[str] = None
    tls_sni: Optional[str] = None
    cert_fingerprint: Optional[str] = None
    http_method: Optional[str] = None
    http_status: Optional[int] = None
    packet_count: int = 1
    byte_count: int = 0
    pcap_file: Optional[str] = None
    packet_reference: Optional[str] = None # e.g. "Packet #14"
    is_simulated: bool = True
    related_indicator_ids: List[str] = []

class DroppedArtifactRecord(BaseModel):
    id: str
    run_id: str
    investigation_id: str
    filename: str
    file_path: Optional[str] = None
    size_bytes: int = 0
    sha256: str
    file_type: Optional[str] = None
    dropped_by_process: Optional[str] = None
    timestamp_utc: str = Field(default_factory=lambda: datetime.utcnow().isoformat())

class DynamicObservation(BaseModel):
    id: str
    run_id: str
    investigation_id: str
    evidence_id: Optional[str] = None
    observation_type: str # "PROCESS", "NETWORK", "FILESYSTEM", "REGISTRY", "API", "BEHAVIOR"
    severity: str = "INFORMATIONAL" # "INFORMATIONAL", "LOW", "MEDIUM", "HIGH", "CRITICAL"
    title: str
    description: str
    details: Dict[str, Any] = {}
    mitre_technique: Optional[str] = None
    timestamp_utc: str = Field(default_factory=lambda: datetime.utcnow().isoformat())

class DynamicArtifact(BaseModel):
    id: str
    run_id: str
    investigation_id: str
    artifact_type: str # "PCAP", "DROPPED_FILE", "SCREENSHOT", "LOG", "MEMORY_DUMP", "REPORT"
    filename: str
    file_path: Optional[str] = None
    size_bytes: int = 0
    sha256: str
    description: Optional[str] = None
    created_at_utc: str = Field(default_factory=lambda: datetime.utcnow().isoformat())

class DynamicReport(BaseModel):
    id: str
    run_id: str
    investigation_id: str
    report_type: str = "DYNAMIC" # "DYNAMIC", "COMBINED"
    title: str
    summary_markdown: str
    full_report: Dict[str, Any] = {}
    risk_score: float = 0.0
    risk_severity: str = "Informational"
    generated_by: Optional[str] = None
    generated_at_utc: str = Field(default_factory=lambda: datetime.utcnow().isoformat())

class ProcessTreeNode(BaseModel):
    pid: int
    name: str
    parent_pid: Optional[int] = None
    parent_name: Optional[str] = None
    command_line: Optional[str] = None
    timestamp_utc: str
    is_suspicious: bool = False
    children: List['ProcessTreeNode'] = []

# ========================================================
# STATIC-VERSUS-DYNAMIC CORRELATION & RISK MODELS
# ========================================================

class StaticDynamicCorrelation(BaseModel):
    id: str
    investigation_id: str
    static_finding_id: str
    dynamic_event_id: str
    source_evidence_id: Optional[str] = None
    indicator_value: str
    correlation_method: str # DOMAIN_MATCH_IN_DNS, IMPORT_MATCH_IN_PROCESS, URL_MATCH_IN_HTTP, HASH_MATCH_IN_DROPPED_FILE, TLS_SNI_MATCH
    confidence: str = "Medium" # Confirmed, High, Medium, Low
    supporting_event_summary: str
    packet_reference: Optional[str] = None
    is_simulated_event: bool = True
    alternative_explanation: str
    limitations: str
    created_at_utc: str = Field(default_factory=lambda: datetime.utcnow().isoformat())

class EvidenceRiskAssessment(BaseModel):
    id: str
    investigation_id: str
    static_capability_score: float = 0.0 # 0.0 to 10.0
    observed_execution_score: float = 0.0
    observed_network_score: float = 0.0
    successful_protocol_interaction_score: float = 0.0
    confirmed_data_transfer_score: float = 0.0
    threat_intel_reputation_score: float = 0.0
    overall_risk_score: float = 0.0
    severity: str = "Informational" # Informational, Low, Medium, High, Critical
    confidence: str = "Unverified" # Unverified, Low, Medium, High, Confirmed
    score_inputs: List[str] = []
    weighting_method: str = "Evidence-Corroborated Dimensional Scoring"
    corroboration_sources: List[str] = []
    contradictory_evidence: List[str] = []
    missing_evidence: List[str] = []
    known_limitations: List[str] = []
    assessed_at_utc: str = Field(default_factory=lambda: datetime.utcnow().isoformat())

class UniversalInvestigationDetail(BaseModel):
    record: InvestigationRecord
    evidence_items: List[EvidenceItem] = []
    extracted_artifacts: List[ExtractedArtifact] = []
    evidence_relationships: List[EvidenceRelationship] = []
    timeline_events: List[TimelineEvent] = []
    chain_of_custody: List[ChainOfCustodyEvent] = []
    findings_register: List[FindingRecord] = []
    coverage_matrix: List[DetectionCoverageItem] = []
    contradictions: List[ContradictionItem] = []
    graph_data: Optional[Dict[str, Any]] = None
    # OSINT & Recursive Pivot additions
    osint_indicators: List[OSINTIndicator] = []
    osint_observations: List[OSINTObservation] = []
    secret_exposure_findings: List[SecretExposureFinding] = []
    pivot_jobs: List[RecursivePivotJob] = []
    osint_graph_nodes: List[OSINTGraphNode] = []
    osint_graph_edges: List[OSINTGraphEdge] = []
    # Advanced Dynamic & Network additions
    authorized_scopes: List[AuthorizedNetworkScope] = []
    active_validation_results: List[ActiveValidationResult] = []
    dynamic_sandbox_runs: List[DynamicSandboxRun] = []
    dynamic_telemetry_events: List[DynamicTelemetryEvent] = []
    dynamic_observations: List[DynamicObservation] = []
    dynamic_artifacts: List[DynamicArtifact] = []
    dynamic_reports: List[DynamicReport] = []
    network_flows: List[NetworkFlowRecord] = []
    dropped_artifacts: List[DroppedArtifactRecord] = []
    static_dynamic_correlations: List[StaticDynamicCorrelation] = []
    evidence_risk_assessment: Optional[EvidenceRiskAssessment] = None
    # Preserved legacy fields for full backwards-compatibility
    metadata: Optional[Any] = None
    pe_metadata: Optional[PeMetadata] = None
    static_findings: List[StaticFinding] = []
    c2_indicators: List[C2Indicator] = []
    secrets: List[SecretFinding] = []
    reverse_shell_findings: List[ReverseShellFinding] = []
    persistence_findings: List[PePersistenceFinding] = []
    network_iocs: List[NetworkIOC] = []
    threat_intel: List[ThreatIntelResult] = []
    tool_executions: List[ToolExecution] = []
    assessment: Optional[FinalAssessment] = None
    ai_observations: List[AIObservation] = []
    ai_recommendations: List[AIRecommendation] = []
    ai_notes: Optional[AIAssistedNotes] = None


