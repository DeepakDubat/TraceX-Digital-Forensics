import sqlite3
from pathlib import Path
from backend.app.config import settings

def get_db_connection() -> sqlite3.Connection:
    """Return a configured SQLite connection with row factory and foreign keys."""
    settings.DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(settings.DB_PATH), timeout=30.0)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA busy_timeout=30000;")
    conn.execute("PRAGMA foreign_keys=ON;")
    return conn

def init_db():
    """Initialize database tables and indices for APK Forensics & Threat Intel Workbench."""
    settings.DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(settings.DB_PATH), timeout=30.0)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA busy_timeout=30000;")
    cursor = conn.cursor()
    
    cursor.executescript("""
    CREATE TABLE IF NOT EXISTS investigations (
        id TEXT PRIMARY KEY,
        filename TEXT NOT NULL,
        original_size INTEGER NOT NULL,
        md5 TEXT NOT NULL,
        sha1 TEXT NOT NULL,
        sha256 TEXT NOT NULL,
        case_reference TEXT,
        investigator_name TEXT,
        description TEXT,
        analyst_notes TEXT,
        local_only_mode INTEGER DEFAULT 0,
        status TEXT NOT NULL,
        progress INTEGER DEFAULT 0,
        current_stage TEXT,
        created_at TEXT NOT NULL,
        started_at TEXT,
        completed_at TEXT,
        error_message TEXT,
        total_findings INTEGER DEFAULT 0,
        severity TEXT DEFAULT 'Informational',
        confidence TEXT DEFAULT 'Unverified',
        package_name TEXT,
        app_name TEXT,
        c2_count INTEGER DEFAULT 0,
        secret_count INTEGER DEFAULT 0,
        reverse_shell_detected INTEGER DEFAULT 0,
        file_type TEXT DEFAULT 'apk'
    );

    CREATE INDEX IF NOT EXISTS idx_inv_sha256 ON investigations(sha256);
    CREATE INDEX IF NOT EXISTS idx_inv_package ON investigations(package_name);
    CREATE INDEX IF NOT EXISTS idx_inv_created ON investigations(created_at);

    CREATE TABLE IF NOT EXISTS metadata (
        investigation_id TEXT PRIMARY KEY,
        data_json TEXT NOT NULL,
        FOREIGN KEY (investigation_id) REFERENCES investigations(id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS static_findings (
        id TEXT PRIMARY KEY,
        investigation_id TEXT NOT NULL,
        category TEXT NOT NULL,
        severity TEXT NOT NULL,
        confidence TEXT NOT NULL,
        title TEXT NOT NULL,
        description TEXT NOT NULL,
        source_file TEXT,
        code_reference TEXT,
        evidence_snippet TEXT,
        explanation TEXT,
        remediation_advice TEXT,
        FOREIGN KEY (investigation_id) REFERENCES investigations(id) ON DELETE CASCADE
    );

    CREATE INDEX IF NOT EXISTS idx_findings_inv ON static_findings(investigation_id);

    CREATE TABLE IF NOT EXISTS c2_indicators (
        id TEXT PRIMARY KEY,
        investigation_id TEXT NOT NULL,
        indicator_type TEXT NOT NULL,
        value TEXT NOT NULL,
        normalized_value TEXT NOT NULL,
        source_file TEXT NOT NULL,
        code_reference TEXT,
        port INTEGER,
        protocol TEXT,
        encoding_steps TEXT,
        classification TEXT NOT NULL,
        why_suspicious TEXT NOT NULL,
        confidence TEXT NOT NULL,
        threat_intel_status TEXT DEFAULT 'Unchecked',
        recommended_validation TEXT NOT NULL,
        FOREIGN KEY (investigation_id) REFERENCES investigations(id) ON DELETE CASCADE
    );

    CREATE INDEX IF NOT EXISTS idx_c2_inv ON c2_indicators(investigation_id);

    CREATE TABLE IF NOT EXISTS secret_findings (
        id TEXT PRIMARY KEY,
        investigation_id TEXT NOT NULL,
        token_category TEXT NOT NULL,
        redacted_value TEXT NOT NULL,
        raw_value TEXT,
        source_location TEXT NOT NULL,
        code_reference TEXT,
        rule_matched TEXT NOT NULL,
        in_network_path INTEGER DEFAULT 0,
        related_indicator TEXT,
        confidence TEXT NOT NULL,
        verification_status TEXT NOT NULL,
        context_snippet TEXT,
        FOREIGN KEY (investigation_id) REFERENCES investigations(id) ON DELETE CASCADE
    );

    CREATE INDEX IF NOT EXISTS idx_secrets_inv ON secret_findings(investigation_id);

    CREATE TABLE IF NOT EXISTS reverse_shell_findings (
        id TEXT PRIMARY KEY,
        investigation_id TEXT NOT NULL,
        pattern_type TEXT NOT NULL,
        title TEXT NOT NULL,
        severity TEXT NOT NULL,
        confidence TEXT NOT NULL,
        code_references_json TEXT,
        execution_chain_json TEXT,
        evidence_snippet TEXT,
        explanation TEXT NOT NULL,
        limitations TEXT NOT NULL,
        FOREIGN KEY (investigation_id) REFERENCES investigations(id) ON DELETE CASCADE
    );

    CREATE INDEX IF NOT EXISTS idx_revshell_inv ON reverse_shell_findings(investigation_id);

    CREATE TABLE IF NOT EXISTS network_iocs (
        id TEXT PRIMARY KEY,
        investigation_id TEXT NOT NULL,
        ioc_type TEXT NOT NULL,
        value TEXT NOT NULL,
        source_file TEXT NOT NULL,
        related_domain TEXT,
        related_urls_json TEXT,
        ports_json TEXT,
        is_private INTEGER DEFAULT 0,
        asn TEXT,
        country TEXT,
        owner TEXT,
        classification TEXT,
        confidence TEXT,
        threat_intel_summary TEXT,
        FOREIGN KEY (investigation_id) REFERENCES investigations(id) ON DELETE CASCADE
    );

    CREATE INDEX IF NOT EXISTS idx_iocs_inv ON network_iocs(investigation_id);

    CREATE TABLE IF NOT EXISTS threat_intel_results (
        id TEXT PRIMARY KEY,
        investigation_id TEXT NOT NULL,
        provider TEXT NOT NULL,
        indicator TEXT NOT NULL,
        indicator_type TEXT NOT NULL,
        query_time TEXT NOT NULL,
        status TEXT NOT NULL,
        detections INTEGER DEFAULT 0,
        total_engines INTEGER DEFAULT 0,
        details_json TEXT,
        error_message TEXT,
        FOREIGN KEY (investigation_id) REFERENCES investigations(id) ON DELETE CASCADE
    );

    CREATE INDEX IF NOT EXISTS idx_ti_inv ON threat_intel_results(investigation_id);

    CREATE TABLE IF NOT EXISTS tool_executions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        investigation_id TEXT NOT NULL,
        tool_name TEXT NOT NULL,
        installed INTEGER DEFAULT 0,
        status TEXT NOT NULL,
        version TEXT,
        start_time TEXT,
        end_time TEXT,
        duration_seconds REAL DEFAULT 0.0,
        exit_code INTEGER,
        output_path TEXT,
        errors_warnings TEXT,
        findings_count INTEGER DEFAULT 0,
        limitations TEXT,
        FOREIGN KEY (investigation_id) REFERENCES investigations(id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS final_assessments (
        investigation_id TEXT PRIMARY KEY,
        overall_severity TEXT NOT NULL,
        overall_confidence TEXT NOT NULL,
        risk_score INTEGER NOT NULL,
        executive_summary TEXT NOT NULL,
        strongest_evidence_json TEXT,
        potential_malicious_functionality_json TEXT,
        unanswered_questions_json TEXT,
        limitations_json TEXT,
        recommended_actions_json TEXT,
        dynamic_analysis_conducted INTEGER DEFAULT 0,
        external_intelligence_used INTEGER DEFAULT 0,
        FOREIGN KEY (investigation_id) REFERENCES investigations(id) ON DELETE CASCADE
    );

        CREATE TABLE IF NOT EXISTS pe_persistence_findings (
        id TEXT PRIMARY KEY,
        investigation_id TEXT NOT NULL,
        mechanism TEXT NOT NULL,
        indicator_type TEXT NOT NULL,
        title TEXT NOT NULL,
        severity TEXT NOT NULL,
        confidence TEXT NOT NULL,
        source_evidence TEXT,
        details TEXT,
        limitations TEXT,
        FOREIGN KEY (investigation_id) REFERENCES investigations(id) ON DELETE CASCADE
    );

    CREATE INDEX IF NOT EXISTS idx_pe_persist_inv ON pe_persistence_findings(investigation_id);

    CREATE TABLE IF NOT EXISTS app_settings (
        setting_key TEXT PRIMARY KEY,
        setting_value TEXT NOT NULL,
        updated_at TEXT NOT NULL
    );

    -- ========================================================
    -- UNIVERSAL DIGITAL FORENSICS SCHEMA ADDITIONS
    -- ========================================================

    CREATE TABLE IF NOT EXISTS evidence_items (
        id TEXT PRIMARY KEY,
        investigation_id TEXT NOT NULL,
        parent_evidence_id TEXT,
        filename TEXT NOT NULL,
        relative_path TEXT,
        file_size INTEGER NOT NULL,
        mime_type TEXT,
        detected_format TEXT NOT NULL,
        extension TEXT,
        format_mismatch INTEGER DEFAULT 0,
        md5 TEXT,
        sha1 TEXT,
        sha256 TEXT NOT NULL,
        sha512 TEXT,
        working_copy_sha256 TEXT,
        integrity_status TEXT DEFAULT 'VERIFIED',
        source_info TEXT,
        examiner_notes TEXT,
        acquired_at TEXT NOT NULL,
        filesystem_created_at TEXT,
        filesystem_modified_at TEXT,
        processing_state TEXT DEFAULT 'NOT_RUN',
        entropy REAL DEFAULT 0.0,
        triage_summary_json TEXT,
        metadata_json TEXT,
        created_at TEXT NOT NULL,
        FOREIGN KEY (investigation_id) REFERENCES investigations(id) ON DELETE CASCADE,
        FOREIGN KEY (parent_evidence_id) REFERENCES evidence_items(id) ON DELETE SET NULL
    );

    CREATE INDEX IF NOT EXISTS idx_evd_inv ON evidence_items(investigation_id);
    CREATE INDEX IF NOT EXISTS idx_evd_sha256 ON evidence_items(sha256);
    CREATE INDEX IF NOT EXISTS idx_evd_parent ON evidence_items(parent_evidence_id);

    CREATE TABLE IF NOT EXISTS extracted_artifacts (
        id TEXT PRIMARY KEY,
        investigation_id TEXT NOT NULL,
        evidence_id TEXT NOT NULL,
        parent_artifact_id TEXT,
        artifact_type TEXT NOT NULL,
        source_format TEXT NOT NULL,
        source_location TEXT,
        value TEXT NOT NULL,
        structured_data_json TEXT,
        sha256 TEXT,
        extractor_name TEXT NOT NULL,
        extracted_at TEXT NOT NULL,
        confidence TEXT DEFAULT 'Medium',
        parser_warnings TEXT,
        FOREIGN KEY (investigation_id) REFERENCES investigations(id) ON DELETE CASCADE,
        FOREIGN KEY (evidence_id) REFERENCES evidence_items(id) ON DELETE CASCADE
    );

    CREATE INDEX IF NOT EXISTS idx_art_inv ON extracted_artifacts(investigation_id);
    CREATE INDEX IF NOT EXISTS idx_art_evd ON extracted_artifacts(evidence_id);
    CREATE INDEX IF NOT EXISTS idx_art_type ON extracted_artifacts(artifact_type);
    CREATE INDEX IF NOT EXISTS idx_art_inv_type ON extracted_artifacts(investigation_id, artifact_type);

    CREATE TABLE IF NOT EXISTS evidence_relationships (
        id TEXT PRIMARY KEY,
        investigation_id TEXT NOT NULL,
        source_evidence_id TEXT NOT NULL,
        target_evidence_id TEXT NOT NULL,
        relationship_type TEXT NOT NULL,
        supporting_artifact_ids_json TEXT,
        matching_method TEXT NOT NULL,
        strength TEXT NOT NULL,
        limitations TEXT,
        created_at TEXT NOT NULL,
        FOREIGN KEY (investigation_id) REFERENCES investigations(id) ON DELETE CASCADE,
        FOREIGN KEY (source_evidence_id) REFERENCES evidence_items(id) ON DELETE CASCADE,
        FOREIGN KEY (target_evidence_id) REFERENCES evidence_items(id) ON DELETE CASCADE
    );

    CREATE INDEX IF NOT EXISTS idx_rel_inv ON evidence_relationships(investigation_id);

    CREATE TABLE IF NOT EXISTS timeline_events (
        id TEXT PRIMARY KEY,
        investigation_id TEXT NOT NULL,
        evidence_id TEXT,
        original_timestamp TEXT NOT NULL,
        original_timezone TEXT,
        normalized_utc TEXT NOT NULL,
        timestamp_source TEXT NOT NULL,
        transformation_applied TEXT,
        reliability TEXT NOT NULL,
        event_type TEXT NOT NULL,
        description TEXT NOT NULL,
        associated_finding_id TEXT,
        related_evidence_ids_json TEXT,
        created_at TEXT NOT NULL,
        FOREIGN KEY (investigation_id) REFERENCES investigations(id) ON DELETE CASCADE,
        FOREIGN KEY (evidence_id) REFERENCES evidence_items(id) ON DELETE CASCADE
    );

    CREATE INDEX IF NOT EXISTS idx_tml_inv ON timeline_events(investigation_id);
    CREATE INDEX IF NOT EXISTS idx_tml_utc ON timeline_events(normalized_utc);
    CREATE INDEX IF NOT EXISTS idx_tml_inv_utc ON timeline_events(investigation_id, normalized_utc);

    CREATE TABLE IF NOT EXISTS chain_of_custody (
        id TEXT PRIMARY KEY,
        investigation_id TEXT NOT NULL,
        evidence_id TEXT,
        event_type TEXT NOT NULL,
        timestamp_utc TEXT NOT NULL,
        examiner TEXT NOT NULL,
        original_hash TEXT,
        working_copy_hash TEXT,
        verification_result TEXT DEFAULT 'PASSED',
        details_json TEXT,
        prev_event_hash TEXT,
        event_hash TEXT NOT NULL,
        FOREIGN KEY (investigation_id) REFERENCES investigations(id) ON DELETE CASCADE,
        FOREIGN KEY (evidence_id) REFERENCES evidence_items(id) ON DELETE CASCADE
    );

    CREATE INDEX IF NOT EXISTS idx_coc_inv ON chain_of_custody(investigation_id);

    CREATE TABLE IF NOT EXISTS findings_register (
        id TEXT PRIMARY KEY,
        investigation_id TEXT NOT NULL,
        evidence_id TEXT,
        artifact_ids_json TEXT,
        title TEXT NOT NULL,
        description TEXT NOT NULL,
        observation TEXT NOT NULL,
        interpretation TEXT NOT NULL,
        severity TEXT NOT NULL,
        confidence TEXT NOT NULL,
        analysis_method TEXT NOT NULL,
        source_location TEXT,
        analyzer_name TEXT NOT NULL,
        analyzer_version TEXT,
        rule_version TEXT,
        timestamp_utc TEXT NOT NULL,
        alternative_explanation TEXT,
        limitations TEXT,
        verification_state TEXT DEFAULT 'pending_review',
        analyst_notes TEXT,
        source_evidence TEXT,
        source_file TEXT,
        frame_number INTEGER,
        packet_number INTEGER,
        timestamp TEXT,
        engine TEXT,
        rule_id TEXT,
        original_hash TEXT,
        FOREIGN KEY (investigation_id) REFERENCES investigations(id) ON DELETE CASCADE,
        FOREIGN KEY (evidence_id) REFERENCES evidence_items(id) ON DELETE CASCADE
    );

    CREATE INDEX IF NOT EXISTS idx_fnd_inv ON findings_register(investigation_id);
    CREATE INDEX IF NOT EXISTS idx_fnd_sev ON findings_register(severity);
    CREATE INDEX IF NOT EXISTS idx_fnd_ver ON findings_register(verification_state);

    CREATE TABLE IF NOT EXISTS analysis_runs (
        id TEXT PRIMARY KEY,
        investigation_id TEXT NOT NULL,
        started_at TEXT NOT NULL,
        completed_at TEXT,
        status TEXT NOT NULL,
        total_files INTEGER DEFAULT 0,
        analyzed_files INTEGER DEFAULT 0,
        failed_files INTEGER DEFAULT 0,
        skipped_files INTEGER DEFAULT 0,
        coverage_matrix_json TEXT,
        execution_logs TEXT,
        FOREIGN KEY (investigation_id) REFERENCES investigations(id) ON DELETE CASCADE
    );

    CREATE INDEX IF NOT EXISTS idx_runs_inv ON analysis_runs(investigation_id);

    CREATE TABLE IF NOT EXISTS osint_indicators (
        id TEXT PRIMARY KEY,
        investigation_id TEXT NOT NULL,
        evidence_id TEXT,
        artifact_id TEXT,
        source_filename TEXT,
        source_location TEXT,
        indicator_type TEXT NOT NULL,
        value TEXT NOT NULL,
        normalized_value TEXT NOT NULL,
        provenance_type TEXT DEFAULT 'DIRECT_EVIDENCE',
        extractor_or_provider TEXT NOT NULL,
        confidence TEXT DEFAULT 'High',
        pivot_depth INTEGER DEFAULT 0,
        parent_indicator_id TEXT,
        first_seen_utc TEXT NOT NULL,
        last_updated_utc TEXT NOT NULL,
        limitations TEXT,
        is_sensitive_secret INTEGER DEFAULT 0,
        masked_value TEXT,
        FOREIGN KEY (investigation_id) REFERENCES investigations(id) ON DELETE CASCADE
    );

    CREATE INDEX IF NOT EXISTS idx_osint_ind_inv ON osint_indicators(investigation_id);
    CREATE INDEX IF NOT EXISTS idx_osint_ind_val ON osint_indicators(normalized_value);
    CREATE INDEX IF NOT EXISTS idx_osint_ind_type ON osint_indicators(indicator_type);

    CREATE TABLE IF NOT EXISTS osint_observations (
        id TEXT PRIMARY KEY,
        investigation_id TEXT NOT NULL,
        indicator_id TEXT NOT NULL,
        provider TEXT NOT NULL,
        indicator_type TEXT NOT NULL,
        indicator_value TEXT NOT NULL,
        query_timestamp_utc TEXT NOT NULL,
        provider_timestamp_utc TEXT,
        status TEXT NOT NULL,
        normalized_data_json TEXT,
        permalink TEXT,
        data_freshness TEXT DEFAULT 'Live',
        cache_expires_utc TEXT,
        error_message TEXT,
        limitations TEXT,
        FOREIGN KEY (investigation_id) REFERENCES investigations(id) ON DELETE CASCADE,
        FOREIGN KEY (indicator_id) REFERENCES osint_indicators(id) ON DELETE CASCADE
    );

    CREATE INDEX IF NOT EXISTS idx_osint_obs_inv ON osint_observations(investigation_id);
    CREATE INDEX IF NOT EXISTS idx_osint_obs_ind ON osint_observations(indicator_id);
    CREATE INDEX IF NOT EXISTS idx_osint_obs_prov ON osint_observations(provider);

    CREATE TABLE IF NOT EXISTS osint_pivot_jobs (
        id TEXT PRIMARY KEY,
        investigation_id TEXT NOT NULL,
        status TEXT NOT NULL,
        max_depth INTEGER DEFAULT 3,
        current_depth INTEGER DEFAULT 0,
        total_indicators_evaluated INTEGER DEFAULT 0,
        total_new_indicators_discovered INTEGER DEFAULT 0,
        total_provider_queries INTEGER DEFAULT 0,
        budget_limit_queries INTEGER DEFAULT 50,
        started_at_utc TEXT,
        completed_at_utc TEXT,
        errors_json TEXT,
        FOREIGN KEY (investigation_id) REFERENCES investigations(id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS osint_cache (
        cache_key TEXT PRIMARY KEY,
        provider TEXT NOT NULL,
        indicator_type TEXT NOT NULL,
        indicator_value TEXT NOT NULL,
        response_json TEXT NOT NULL,
        status TEXT NOT NULL,
        created_at_utc TEXT NOT NULL,
        expires_at_utc TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS secret_exposure_findings (
        id TEXT PRIMARY KEY,
        investigation_id TEXT NOT NULL,
        evidence_id TEXT NOT NULL,
        artifact_id TEXT NOT NULL,
        secret_type TEXT NOT NULL,
        masked_token TEXT NOT NULL,
        source_filename TEXT NOT NULL,
        source_location TEXT NOT NULL,
        independently_found_public_identities_json TEXT,
        safety_attestation TEXT NOT NULL,
        risk_level TEXT DEFAULT 'High',
        observation TEXT NOT NULL,
        interpretation TEXT NOT NULL,
        FOREIGN KEY (investigation_id) REFERENCES investigations(id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS authorized_network_scopes (
        id TEXT PRIMARY KEY,
        investigation_id TEXT NOT NULL,
        case_id TEXT,
        authorized_targets_json TEXT NOT NULL,
        allowed_test_types_json TEXT NOT NULL,
        allowed_ports_json TEXT NOT NULL,
        authorization_note TEXT NOT NULL,
        operator_name TEXT NOT NULL,
        operator_confirmed INTEGER NOT NULL DEFAULT 0,
        request_budget INTEGER DEFAULT 20,
        requests_used INTEGER DEFAULT 0,
        created_at_utc TEXT NOT NULL,
        expires_at_utc TEXT NOT NULL,
        is_revoked INTEGER DEFAULT 0,
        FOREIGN KEY (investigation_id) REFERENCES investigations(id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS active_validation_results (
        id TEXT PRIMARY KEY,
        scope_id TEXT NOT NULL,
        investigation_id TEXT NOT NULL,
        target TEXT NOT NULL,
        test_type TEXT NOT NULL,
        status TEXT NOT NULL,
        resolved_ips_json TEXT,
        port INTEGER,
        timing_ms REAL DEFAULT 0.0,
        tls_cert_info_json TEXT,
        http_status INTEGER,
        http_headers_json TEXT,
        diagnostic_message TEXT,
        timestamp_utc TEXT NOT NULL,
        operator_confirmation_ref TEXT,
        FOREIGN KEY (scope_id) REFERENCES authorized_network_scopes(id) ON DELETE CASCADE,
        FOREIGN KEY (investigation_id) REFERENCES investigations(id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS dynamic_sandbox_runs (
        id TEXT PRIMARY KEY,
        investigation_id TEXT NOT NULL,
        evidence_id TEXT NOT NULL,
        target_binary TEXT NOT NULL,
        sandbox_environment TEXT NOT NULL,
        status TEXT NOT NULL,
        is_simulated_network INTEGER DEFAULT 1,
        simulated_services_json TEXT,
        duration_seconds REAL DEFAULT 0.0,
        started_at_utc TEXT NOT NULL,
        completed_at_utc TEXT,
        process_count INTEGER DEFAULT 0,
        file_event_count INTEGER DEFAULT 0,
        registry_event_count INTEGER DEFAULT 0,
        network_flow_count INTEGER DEFAULT 0,
        dropped_artifacts_count INTEGER DEFAULT 0,
        pcap_filename TEXT,
        pcap_sha256 TEXT,
        sandbox_logs_json TEXT,
        limitations TEXT,
        FOREIGN KEY (investigation_id) REFERENCES investigations(id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS dynamic_telemetry_events (
        id TEXT PRIMARY KEY,
        run_id TEXT NOT NULL,
        investigation_id TEXT NOT NULL,
        event_category TEXT NOT NULL,
        timestamp_utc TEXT NOT NULL,
        process_id INTEGER,
        process_name TEXT,
        parent_process_id INTEGER,
        parent_process_name TEXT,
        command_line TEXT,
        target_path TEXT,
        operation TEXT,
        details_json TEXT,
        is_simulated INTEGER DEFAULT 1,
        related_indicator_id TEXT,
        FOREIGN KEY (run_id) REFERENCES dynamic_sandbox_runs(id) ON DELETE CASCADE,
        FOREIGN KEY (investigation_id) REFERENCES investigations(id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS network_flow_records (
        id TEXT PRIMARY KEY,
        run_id TEXT NOT NULL,
        investigation_id TEXT NOT NULL,
        timestamp_utc TEXT NOT NULL,
        src_ip TEXT NOT NULL,
        src_port INTEGER NOT NULL,
        dst_ip TEXT NOT NULL,
        dst_port INTEGER NOT NULL,
        protocol TEXT NOT NULL,
        direction TEXT NOT NULL,
        dns_hostname TEXT,
        tls_sni TEXT,
        cert_fingerprint TEXT,
        http_method TEXT,
        http_status INTEGER,
        packet_count INTEGER DEFAULT 1,
        byte_count INTEGER DEFAULT 0,
        pcap_file TEXT,
        packet_reference TEXT,
        is_simulated INTEGER DEFAULT 1,
        related_indicator_ids_json TEXT,
        FOREIGN KEY (run_id) REFERENCES dynamic_sandbox_runs(id) ON DELETE CASCADE,
        FOREIGN KEY (investigation_id) REFERENCES investigations(id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS dropped_artifact_records (
        id TEXT PRIMARY KEY,
        run_id TEXT NOT NULL,
        investigation_id TEXT NOT NULL,
        filename TEXT NOT NULL,
        file_path TEXT,
        size_bytes INTEGER DEFAULT 0,
        sha256 TEXT NOT NULL,
        file_type TEXT,
        dropped_by_process TEXT,
        timestamp_utc TEXT NOT NULL,
        FOREIGN KEY (run_id) REFERENCES dynamic_sandbox_runs(id) ON DELETE CASCADE,
        FOREIGN KEY (investigation_id) REFERENCES investigations(id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS static_dynamic_correlations (
        id TEXT PRIMARY KEY,
        investigation_id TEXT NOT NULL,
        static_finding_id TEXT NOT NULL,
        dynamic_event_id TEXT NOT NULL,
        source_evidence_id TEXT,
        indicator_value TEXT NOT NULL,
        correlation_method TEXT NOT NULL,
        confidence TEXT NOT NULL,
        supporting_event_summary TEXT NOT NULL,
        packet_reference TEXT,
        is_simulated_event INTEGER DEFAULT 1,
        alternative_explanation TEXT,
        limitations TEXT,
        created_at_utc TEXT NOT NULL,
        FOREIGN KEY (investigation_id) REFERENCES investigations(id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS evidence_risk_assessments (
        id TEXT PRIMARY KEY,
        investigation_id TEXT NOT NULL,
        static_capability_score REAL DEFAULT 0.0,
        observed_execution_score REAL DEFAULT 0.0,
        observed_network_score REAL DEFAULT 0.0,
        successful_protocol_interaction_score REAL DEFAULT 0.0,
        confirmed_data_transfer_score REAL DEFAULT 0.0,
        threat_intel_reputation_score REAL DEFAULT 0.0,
        overall_risk_score REAL DEFAULT 0.0,
        severity TEXT NOT NULL,
        confidence TEXT NOT NULL,
        score_inputs_json TEXT,
        weighting_method TEXT NOT NULL,
        corroboration_sources_json TEXT,
        contradictory_evidence_json TEXT,
        missing_evidence_json TEXT,
        known_limitations_json TEXT,
        assessed_at_utc TEXT NOT NULL,
        FOREIGN KEY (investigation_id) REFERENCES investigations(id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS provider_credentials (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        provider_name TEXT UNIQUE NOT NULL,
        credential_type TEXT NOT NULL,
        encrypted_data TEXT NOT NULL,
        key_fingerprint TEXT NOT NULL,
        is_valid INTEGER DEFAULT 1,
        last_tested_at TEXT,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL
    );

    CREATE INDEX IF NOT EXISTS idx_provider_name ON provider_credentials(provider_name);

    -- =========================================================================
    -- UNIVERSAL APPLICATION USERS & SESSIONS
    -- =========================================================================
    CREATE TABLE IF NOT EXISTS users (
        id TEXT PRIMARY KEY,
        username TEXT UNIQUE NOT NULL,
        email TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        salt BLOB NOT NULL,
        role TEXT NOT NULL DEFAULT 'investigator',
        is_active INTEGER NOT NULL DEFAULT 1,
        failed_login_attempts INTEGER NOT NULL DEFAULT 0,
        locked_until TEXT,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL
    );

    CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);
    CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);

    CREATE TABLE IF NOT EXISTS user_sessions (
        id TEXT PRIMARY KEY,
        user_id TEXT NOT NULL,
        session_token_masked TEXT,
        user_agent TEXT,
        ip_address TEXT,
        expires_at TEXT NOT NULL,
        created_at TEXT NOT NULL,
        last_activity_at TEXT NOT NULL,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    );

    CREATE INDEX IF NOT EXISTS idx_sessions_user ON user_sessions(user_id);
    CREATE INDEX IF NOT EXISTS idx_sessions_expires ON user_sessions(expires_at);

    CREATE TABLE IF NOT EXISTS user_password_resets (
        id TEXT PRIMARY KEY,
        user_id TEXT NOT NULL,
        token_hash TEXT NOT NULL,
        expires_at TEXT NOT NULL,
        used INTEGER DEFAULT 0,
        created_at TEXT NOT NULL,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS user_provider_credentials (
        id TEXT PRIMARY KEY,
        user_id TEXT NOT NULL,
        provider_name TEXT NOT NULL,
        auth_type TEXT NOT NULL DEFAULT 'api_key',
        encrypted_data TEXT NOT NULL,
        key_fingerprint TEXT NOT NULL,
        is_valid INTEGER DEFAULT 1,
        last_tested_at TEXT,
        last_error_code TEXT,
        last_error_message TEXT,
        token_expires_at TEXT,
        refresh_token_encrypted TEXT,
        scope TEXT,
        account_identifier TEXT,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL,
        UNIQUE(user_id, provider_name),
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    );

    CREATE INDEX IF NOT EXISTS idx_user_prov_creds ON user_provider_credentials(user_id, provider_name);

    -- =========================================================================
    -- DYNAMIC LAB: ENVIRONMENTS, OBSERVATIONS, ARTIFACTS & REPORTS
    -- =========================================================================
    CREATE TABLE IF NOT EXISTS sandbox_environments (
        id TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        provider_type TEXT NOT NULL,
        os_family TEXT NOT NULL,
        is_available INTEGER DEFAULT 0,
        status TEXT NOT NULL,
        version TEXT,
        details_json TEXT,
        config_json TEXT,
        last_checked_at TEXT NOT NULL
    );

    CREATE INDEX IF NOT EXISTS idx_sandbox_env_type ON sandbox_environments(provider_type);
    CREATE INDEX IF NOT EXISTS idx_sandbox_env_os ON sandbox_environments(os_family);

    CREATE TABLE IF NOT EXISTS dynamic_observations (
        id TEXT PRIMARY KEY,
        run_id TEXT NOT NULL,
        investigation_id TEXT NOT NULL,
        evidence_id TEXT,
        observation_type TEXT NOT NULL,
        severity TEXT NOT NULL,
        title TEXT NOT NULL,
        description TEXT NOT NULL,
        details_json TEXT,
        mitre_technique TEXT,
        timestamp_utc TEXT NOT NULL,
        FOREIGN KEY (run_id) REFERENCES dynamic_sandbox_runs(id) ON DELETE CASCADE,
        FOREIGN KEY (investigation_id) REFERENCES investigations(id) ON DELETE CASCADE
    );

    CREATE INDEX IF NOT EXISTS idx_dyn_obs_run ON dynamic_observations(run_id);
    CREATE INDEX IF NOT EXISTS idx_dyn_obs_inv ON dynamic_observations(investigation_id);
    CREATE INDEX IF NOT EXISTS idx_dyn_obs_type ON dynamic_observations(observation_type);

    CREATE TABLE IF NOT EXISTS dynamic_artifacts (
        id TEXT PRIMARY KEY,
        run_id TEXT NOT NULL,
        investigation_id TEXT NOT NULL,
        artifact_type TEXT NOT NULL,
        filename TEXT NOT NULL,
        file_path TEXT,
        size_bytes INTEGER DEFAULT 0,
        sha256 TEXT NOT NULL,
        description TEXT,
        created_at_utc TEXT NOT NULL,
        FOREIGN KEY (run_id) REFERENCES dynamic_sandbox_runs(id) ON DELETE CASCADE,
        FOREIGN KEY (investigation_id) REFERENCES investigations(id) ON DELETE CASCADE
    );

    CREATE INDEX IF NOT EXISTS idx_dyn_art_run ON dynamic_artifacts(run_id);
    CREATE INDEX IF NOT EXISTS idx_dyn_art_inv ON dynamic_artifacts(investigation_id);
    CREATE INDEX IF NOT EXISTS idx_dyn_art_sha ON dynamic_artifacts(sha256);

    CREATE TABLE IF NOT EXISTS dynamic_reports (
        id TEXT PRIMARY KEY,
        run_id TEXT NOT NULL,
        investigation_id TEXT NOT NULL,
        report_type TEXT NOT NULL,
        title TEXT NOT NULL,
        summary_markdown TEXT,
        full_report_json TEXT,
        risk_score REAL DEFAULT 0.0,
        risk_severity TEXT DEFAULT 'Informational',
        generated_by TEXT,
        generated_at_utc TEXT NOT NULL,
        FOREIGN KEY (run_id) REFERENCES dynamic_sandbox_runs(id) ON DELETE CASCADE,
        FOREIGN KEY (investigation_id) REFERENCES investigations(id) ON DELETE CASCADE
    );

    CREATE INDEX IF NOT EXISTS idx_dyn_rep_run ON dynamic_reports(run_id);
    CREATE INDEX IF NOT EXISTS idx_dyn_rep_inv ON dynamic_reports(investigation_id);

    -- OpenCode AI-Assisted Forensic Engine Tables (Separated from Deterministic Findings)
    CREATE TABLE IF NOT EXISTS ai_observations (
        id TEXT PRIMARY KEY,
        investigation_id TEXT NOT NULL,
        evidence_id TEXT,
        title TEXT NOT NULL,
        explanation TEXT NOT NULL,
        related_evidence_refs TEXT NOT NULL,
        confidence TEXT DEFAULT 'Unverified',
        reasoning_summary TEXT NOT NULL,
        suggested_verification_steps TEXT NOT NULL,
        status TEXT DEFAULT 'UNVERIFIED',
        reviewer TEXT,
        reviewed_at TEXT,
        review_notes TEXT,
        created_at TEXT NOT NULL,
        FOREIGN KEY (investigation_id) REFERENCES investigations(id) ON DELETE CASCADE
    );

    CREATE INDEX IF NOT EXISTS idx_ai_obs_inv ON ai_observations(investigation_id);

    CREATE TABLE IF NOT EXISTS ai_recommendations (
        id TEXT PRIMARY KEY,
        investigation_id TEXT NOT NULL,
        title TEXT NOT NULL,
        category TEXT NOT NULL,
        description TEXT NOT NULL,
        suggested_command_or_action TEXT,
        priority TEXT DEFAULT 'Medium',
        FOREIGN KEY (investigation_id) REFERENCES investigations(id) ON DELETE CASCADE
    );

    CREATE INDEX IF NOT EXISTS idx_ai_rec_inv ON ai_recommendations(investigation_id);

    CREATE TABLE IF NOT EXISTS ai_investigation_notes (
        investigation_id TEXT PRIMARY KEY,
        execution_status TEXT NOT NULL,
        model_provider TEXT,
        analysis_timestamp TEXT,
        disclaimer TEXT NOT NULL,
        warnings_or_errors TEXT,
        consent_approved INTEGER DEFAULT 0,
        FOREIGN KEY (investigation_id) REFERENCES investigations(id) ON DELETE CASCADE
    );
    """)
    
    # Safe migrations on existing investigations table
    cursor.execute("PRAGMA table_info(investigations);")
    columns = [row["name"] for row in cursor.fetchall()]
    if "file_type" not in columns:
        cursor.execute("ALTER TABLE investigations ADD COLUMN file_type TEXT DEFAULT 'apk';")
    if "is_multi_evidence" not in columns:
        cursor.execute("ALTER TABLE investigations ADD COLUMN is_multi_evidence INTEGER DEFAULT 0;")
    if "evidence_count" not in columns:
        cursor.execute("ALTER TABLE investigations ADD COLUMN evidence_count INTEGER DEFAULT 1;")
    if "ai_assisted_analysis" not in columns:
        cursor.execute("ALTER TABLE investigations ADD COLUMN ai_assisted_analysis INTEGER DEFAULT 0;")

    # Safe migrations on dynamic_sandbox_runs table
    cursor.execute("PRAGMA table_info(dynamic_sandbox_runs);")
    dsr_cols = [row["name"] for row in cursor.fetchall()]
    if "user_id" not in dsr_cols:
        cursor.execute("ALTER TABLE dynamic_sandbox_runs ADD COLUMN user_id TEXT;")
    if "target_sha256" not in dsr_cols:
        cursor.execute("ALTER TABLE dynamic_sandbox_runs ADD COLUMN target_sha256 TEXT;")
    if "target_type" not in dsr_cols:
        cursor.execute("ALTER TABLE dynamic_sandbox_runs ADD COLUMN target_type TEXT DEFAULT 'generic';")
    if "provider" not in dsr_cols:
        cursor.execute("ALTER TABLE dynamic_sandbox_runs ADD COLUMN provider TEXT;")
    if "environment_id" not in dsr_cols:
        cursor.execute("ALTER TABLE dynamic_sandbox_runs ADD COLUMN environment_id TEXT;")
    if "network_policy" not in dsr_cols:
        cursor.execute("ALTER TABLE dynamic_sandbox_runs ADD COLUMN network_policy TEXT DEFAULT 'DISABLED';")
    if "timeout_seconds" not in dsr_cols:
        cursor.execute("ALTER TABLE dynamic_sandbox_runs ADD COLUMN timeout_seconds INTEGER DEFAULT 120;")
    if "risk_score" not in dsr_cols:
        cursor.execute("ALTER TABLE dynamic_sandbox_runs ADD COLUMN risk_score REAL DEFAULT 0.0;")
    if "risk_level" not in dsr_cols:
        cursor.execute("ALTER TABLE dynamic_sandbox_runs ADD COLUMN risk_level TEXT DEFAULT 'Informational';")
    if "report_id" not in dsr_cols:
        cursor.execute("ALTER TABLE dynamic_sandbox_runs ADD COLUMN report_id TEXT;")

    # Additive migration for evidence-backed tool findings (safe on production databases)
    cursor.execute("PRAGMA table_info(findings_register);")
    finding_cols = [row["name"] for row in cursor.fetchall()]
    finding_migrations = {
        "source_evidence": "TEXT",
        "source_file": "TEXT",
        "frame_number": "INTEGER",
        "packet_number": "INTEGER",
        "timestamp": "TEXT",
        "engine": "TEXT",
        "rule_id": "TEXT",
        "original_hash": "TEXT",
    }
    for column, column_type in finding_migrations.items():
        if column not in finding_cols:
            cursor.execute(f"ALTER TABLE findings_register ADD COLUMN {column} {column_type};")

    conn.commit()
    conn.close()
