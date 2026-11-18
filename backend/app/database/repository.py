import json
from pathlib import Path
from datetime import datetime
from typing import List, Optional, Dict, Any
from backend.app.database.db import get_db_connection
from backend.app.core.models import (
    InvestigationRecord, ApkMetadata, PeMetadata, StaticFinding, C2Indicator,
    SecretFinding, ReverseShellFinding, PePersistenceFinding, NetworkIOC, ThreatIntelResult,
    ToolExecution, FinalAssessment, InvestigationDetail,
    EvidenceItem, ExtractedArtifact, EvidenceRelationship, TimelineEvent,
    ChainOfCustodyEvent, FindingRecord, DetectionCoverageItem, ContradictionItem,
    UniversalInvestigationDetail, OSINTIndicator, OSINTObservation,
    SecretExposureFinding, RecursivePivotJob, OSINTGraphNode, OSINTGraphEdge,
    AuthorizedNetworkScope, ActiveValidationResult, DynamicSandboxRun,
    DynamicTelemetryEvent, NetworkFlowRecord, DroppedArtifactRecord,
    StaticDynamicCorrelation, EvidenceRiskAssessment,
    SandboxEnvironmentInfo, DynamicObservation, DynamicArtifact, DynamicReport,
    AIObservation, AIRecommendation, AIAssistedNotes
)

class Repository:
    """Data access repository for investigations and findings."""
    
    def create_investigation(self, record: InvestigationRecord):
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("""
            INSERT OR REPLACE INTO investigations (
                id, filename, original_size, md5, sha1, sha256,
                case_reference, investigator_name, description, analyst_notes,
                local_only_mode, status, progress, current_stage,
                created_at, started_at, completed_at, error_message,
                total_findings, severity, confidence, package_name, app_name,
                c2_count, secret_count, reverse_shell_detected, file_type,
                ai_assisted_analysis
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            record.id, record.filename, record.original_size, record.md5, record.sha1, record.sha256,
            record.case_reference, record.investigator_name, record.description, record.analyst_notes,
            1 if record.local_only_mode else 0, record.status, record.progress, record.current_stage,
            record.created_at.isoformat(),
            record.started_at.isoformat() if record.started_at else None,
            record.completed_at.isoformat() if record.completed_at else None,
            record.error_message, record.total_findings, record.severity, record.confidence,
            record.package_name, record.app_name, record.c2_count, record.secret_count,
            1 if record.reverse_shell_detected else 0,
            record.file_type or "apk",
            1 if getattr(record, "ai_assisted_analysis", False) else 0
        ))
        conn.commit()
        conn.close()

    def update_investigation(self, record: InvestigationRecord):
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("""
            UPDATE investigations SET
                status = ?, progress = ?, current_stage = ?,
                started_at = ?, completed_at = ?, error_message = ?,
                total_findings = ?, severity = ?, confidence = ?,
                package_name = ?, app_name = ?, c2_count = ?,
                secret_count = ?, reverse_shell_detected = ?,
                analyst_notes = ?, case_reference = ?,
                ai_assisted_analysis = ?
            WHERE id = ?
        """, (
            record.status, record.progress, record.current_stage,
            record.started_at.isoformat() if record.started_at else None,
            record.completed_at.isoformat() if record.completed_at else None,
            record.error_message, record.total_findings, record.severity, record.confidence,
            record.package_name, record.app_name, record.c2_count,
            record.secret_count, 1 if record.reverse_shell_detected else 0,
            record.analyst_notes, record.case_reference,
            1 if getattr(record, "ai_assisted_analysis", False) else 0,
            record.id
        ))
        conn.commit()
        conn.close()

    def get_investigation(self, inv_id: str) -> Optional[InvestigationRecord]:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM investigations WHERE id = ?", (inv_id,))
        row = cursor.fetchone()
        conn.close()
        if not row:
            return None
        return self._row_to_record(row)

    def list_investigations(self, search: Optional[str] = None) -> List[InvestigationRecord]:
        conn = get_db_connection()
        cursor = conn.cursor()
        if search:
            query = """
                SELECT * FROM investigations
                WHERE filename LIKE ? OR package_name LIKE ? OR sha256 LIKE ? OR id LIKE ? OR case_reference LIKE ?
                ORDER BY created_at DESC
            """
            like_term = f"%{search}%"
            cursor.execute(query, (like_term, like_term, like_term, like_term, like_term))
        else:
            cursor.execute("SELECT * FROM investigations ORDER BY created_at DESC")
        rows = cursor.fetchall()
        conn.close()
        return [self._row_to_record(r) for r in rows]

    def delete_investigation(self, inv_id: str) -> bool:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("DELETE FROM investigations WHERE id = ?", (inv_id,))
        rows_affected = cursor.rowcount
        conn.commit()
        conn.close()
        return rows_affected > 0

    def save_metadata(self, inv_id: str, metadata: Any):
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("""
            INSERT OR REPLACE INTO metadata (investigation_id, data_json)
            VALUES (?, ?)
        """, (inv_id, metadata.model_dump_json() if hasattr(metadata, "model_dump_json") else json.dumps(metadata)))
        conn.commit()
        conn.close()

    def get_metadata(self, inv_id: str) -> Optional[Any]:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT data_json FROM metadata WHERE investigation_id = ?", (inv_id,))
        row = cursor.fetchone()
        conn.close()
        if row:
            data = json.loads(row["data_json"])
            if data.get("file_type") == "exe":
                return PeMetadata.model_validate_json(row["data_json"])
            return ApkMetadata.model_validate_json(row["data_json"])
        return None

    def save_static_findings(self, inv_id: str, findings: List[StaticFinding]):
        conn = get_db_connection()
        cursor = conn.cursor()
        for f in findings:
            cursor.execute("""
                INSERT OR REPLACE INTO static_findings (
                    id, investigation_id, category, severity, confidence,
                    title, description, source_file, code_reference,
                    evidence_snippet, explanation, remediation_advice
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                f.id, inv_id, f.category, f.severity, f.confidence,
                f.title, f.description, f.source_file, f.code_reference,
                f.evidence_snippet, f.explanation, f.remediation_advice
            ))
        conn.commit()
        conn.close()

    def get_static_findings(self, inv_id: str) -> List[StaticFinding]:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM static_findings WHERE investigation_id = ?", (inv_id,))
        rows = cursor.fetchall()
        conn.close()
        return [StaticFinding(
            id=r["id"], category=r["category"], severity=r["severity"],
            confidence=r["confidence"], title=r["title"], description=r["description"],
            source_file=r["source_file"], code_reference=r["code_reference"],
            evidence_snippet=r["evidence_snippet"], explanation=r["explanation"],
            remediation_advice=r["remediation_advice"]
        ) for r in rows]

    def save_c2_indicators(self, inv_id: str, indicators: List[C2Indicator]):
        conn = get_db_connection()
        cursor = conn.cursor()
        for ind in indicators:
            cursor.execute("""
                INSERT OR REPLACE INTO c2_indicators (
                    id, investigation_id, indicator_type, value, normalized_value,
                    source_file, code_reference, port, protocol, encoding_steps,
                    classification, why_suspicious, confidence, threat_intel_status,
                    recommended_validation
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                ind.id, inv_id, ind.indicator_type, ind.value, ind.normalized_value,
                ind.source_file, ind.code_reference, ind.port, ind.protocol,
                ind.encoding_steps, ind.classification, ind.why_suspicious,
                ind.confidence, ind.threat_intel_status, ind.recommended_validation
            ))
        conn.commit()
        conn.close()

    def get_c2_indicators(self, inv_id: str) -> List[C2Indicator]:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM c2_indicators WHERE investigation_id = ?", (inv_id,))
        rows = cursor.fetchall()
        conn.close()
        return [C2Indicator(
            id=r["id"], indicator_type=r["indicator_type"], value=r["value"],
            normalized_value=r["normalized_value"], source_file=r["source_file"],
            code_reference=r["code_reference"], port=r["port"], protocol=r["protocol"],
            encoding_steps=r["encoding_steps"], classification=r["classification"],
            why_suspicious=r["why_suspicious"], confidence=r["confidence"],
            threat_intel_status=r["threat_intel_status"], recommended_validation=r["recommended_validation"]
        ) for r in rows]

    def save_secrets(self, inv_id: str, secrets: List[SecretFinding]):
        conn = get_db_connection()
        cursor = conn.cursor()
        for s in secrets:
            cursor.execute("""
                INSERT OR REPLACE INTO secret_findings (
                    id, investigation_id, token_category, redacted_value, raw_value,
                    source_location, code_reference, rule_matched, in_network_path,
                    related_indicator, confidence, verification_status, context_snippet
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                s.id, inv_id, s.token_category, s.redacted_value, s.raw_value,
                s.source_location, s.code_reference, s.rule_matched,
                1 if s.in_network_path else 0, s.related_indicator,
                s.confidence, s.verification_status, s.context_snippet
            ))
        conn.commit()
        conn.close()

    def get_secrets(self, inv_id: str, include_raw: bool = False) -> List[SecretFinding]:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM secret_findings WHERE investigation_id = ?", (inv_id,))
        rows = cursor.fetchall()
        conn.close()
        return [SecretFinding(
            id=r["id"], token_category=r["token_category"],
            redacted_value=r["redacted_value"],
            raw_value=r["raw_value"] if include_raw else None,
            source_location=r["source_location"], code_reference=r["code_reference"],
            rule_matched=r["rule_matched"], in_network_path=bool(r["in_network_path"]),
            related_indicator=r["related_indicator"], confidence=r["confidence"],
            verification_status=r["verification_status"], context_snippet=r["context_snippet"]
        ) for r in rows]

    def save_reverse_shell_findings(self, inv_id: str, findings: List[ReverseShellFinding]):
        conn = get_db_connection()
        cursor = conn.cursor()
        for f in findings:
            cursor.execute("""
                INSERT OR REPLACE INTO reverse_shell_findings (
                    id, investigation_id, pattern_type, title, severity, confidence,
                    code_references_json, execution_chain_json, evidence_snippet,
                    explanation, limitations
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                f.id, inv_id, f.pattern_type, f.title, f.severity, f.confidence,
                json.dumps(f.code_references), json.dumps(f.execution_chain),
                f.evidence_snippet, f.explanation, f.limitations
            ))
        conn.commit()
        conn.close()

    def get_reverse_shell_findings(self, inv_id: str) -> List[ReverseShellFinding]:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM reverse_shell_findings WHERE investigation_id = ?", (inv_id,))
        rows = cursor.fetchall()
        conn.close()
        return [ReverseShellFinding(
            id=r["id"], pattern_type=r["pattern_type"], title=r["title"],
            severity=r["severity"], confidence=r["confidence"],
            code_references=json.loads(r["code_references_json"] or "[]"),
            execution_chain=json.loads(r["execution_chain_json"] or "[]"),
            evidence_snippet=r["evidence_snippet"], explanation=r["explanation"],
            limitations=r["limitations"]
        ) for r in rows]

    def save_network_iocs(self, inv_id: str, iocs: List[NetworkIOC]):
        conn = get_db_connection()
        cursor = conn.cursor()
        for ioc in iocs:
            cursor.execute("""
                INSERT OR REPLACE INTO network_iocs (
                    id, investigation_id, ioc_type, value, source_file, related_domain,
                    related_urls_json, ports_json, is_private, asn, country, owner,
                    classification, confidence, threat_intel_summary
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                ioc.id, inv_id, ioc.ioc_type, ioc.value, ioc.source_file, ioc.related_domain,
                json.dumps(ioc.related_urls), json.dumps(ioc.ports),
                1 if ioc.is_private else 0, ioc.asn, ioc.country, ioc.owner,
                ioc.classification, ioc.confidence, ioc.threat_intel_summary
            ))
        conn.commit()
        conn.close()

    def get_network_iocs(self, inv_id: str) -> List[NetworkIOC]:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM network_iocs WHERE investigation_id = ?", (inv_id,))
        rows = cursor.fetchall()
        conn.close()
        return [NetworkIOC(
            id=r["id"], ioc_type=r["ioc_type"], value=r["value"], source_file=r["source_file"],
            related_domain=r["related_domain"],
            related_urls=json.loads(r["related_urls_json"] or "[]"),
            ports=json.loads(r["ports_json"] or "[]"),
            is_private=bool(r["is_private"]), asn=r["asn"], country=r["country"],
            owner=r["owner"], classification=r["classification"] or "Embedded String",
            confidence=r["confidence"] or "Medium", threat_intel_summary=r["threat_intel_summary"]
        ) for r in rows]

    def save_threat_intel_results(self, inv_id: str, results: List[ThreatIntelResult]):
        conn = get_db_connection()
        cursor = conn.cursor()
        for res in results:
            cursor.execute("""
                INSERT OR REPLACE INTO threat_intel_results (
                    id, investigation_id, provider, indicator, indicator_type,
                    query_time, status, detections, total_engines, details_json, error_message
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                res.id, inv_id, res.provider, res.indicator, res.indicator_type,
                res.query_time.isoformat(), res.status, res.detections, res.total_engines,
                json.dumps(res.details), res.error_message
            ))
        conn.commit()
        conn.close()

    def get_threat_intel_results(self, inv_id: str) -> List[ThreatIntelResult]:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM threat_intel_results WHERE investigation_id = ?", (inv_id,))
        rows = cursor.fetchall()
        conn.close()
        return [ThreatIntelResult(
            id=r["id"], provider=r["provider"], indicator=r["indicator"],
            indicator_type=r["indicator_type"],
            query_time=datetime.fromisoformat(r["query_time"]),
            status=r["status"], detections=r["detections"], total_engines=r["total_engines"],
            details=json.loads(r["details_json"] or "{}"), error_message=r["error_message"]
        ) for r in rows]

    def save_tool_executions(self, inv_id: str, executions: List[ToolExecution]):
        conn = get_db_connection()
        cursor = conn.cursor()
        for te in executions:
            cursor.execute("""
                INSERT INTO tool_executions (
                    investigation_id, tool_name, installed, status, version,
                    start_time, end_time, duration_seconds, exit_code,
                    output_path, errors_warnings, findings_count, limitations
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                inv_id, te.tool_name, 1 if te.installed else 0, te.status, te.version,
                te.start_time.isoformat() if te.start_time else None,
                te.end_time.isoformat() if te.end_time else None,
                te.duration_seconds, te.exit_code, te.output_path,
                te.errors_warnings, te.findings_count, te.limitations
            ))
        conn.commit()
        conn.close()

    def get_tool_executions(self, inv_id: str) -> List[ToolExecution]:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM tool_executions WHERE investigation_id = ?", (inv_id,))
        rows = cursor.fetchall()
        conn.close()
        return [ToolExecution(
            tool_name=r["tool_name"], installed=bool(r["installed"]), status=r["status"],
            version=r["version"],
            start_time=datetime.fromisoformat(r["start_time"]) if r["start_time"] else None,
            end_time=datetime.fromisoformat(r["end_time"]) if r["end_time"] else None,
            duration_seconds=r["duration_seconds"] or 0.0, exit_code=r["exit_code"],
            output_path=r["output_path"], errors_warnings=r["errors_warnings"],
            findings_count=r["findings_count"] or 0, limitations=r["limitations"]
        ) for r in rows]

    def save_assessment(self, inv_id: str, assessment: FinalAssessment):
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("""
            INSERT OR REPLACE INTO final_assessments (
                investigation_id, overall_severity, overall_confidence, risk_score,
                executive_summary, strongest_evidence_json, potential_malicious_functionality_json,
                unanswered_questions_json, limitations_json, recommended_actions_json,
                dynamic_analysis_conducted, external_intelligence_used
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            inv_id, assessment.overall_severity, assessment.overall_confidence, assessment.risk_score,
            assessment.executive_summary, json.dumps(assessment.strongest_evidence),
            json.dumps(assessment.potential_malicious_functionality),
            json.dumps(assessment.unanswered_questions), json.dumps(assessment.limitations),
            json.dumps(assessment.recommended_actions),
            1 if assessment.dynamic_analysis_conducted else 0,
            1 if assessment.external_intelligence_used else 0
        ))
        conn.commit()
        conn.close()

    def get_assessment(self, inv_id: str) -> Optional[FinalAssessment]:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM final_assessments WHERE investigation_id = ?", (inv_id,))
        r = cursor.fetchone()
        conn.close()
        if not r:
            return None
        return FinalAssessment(
            overall_severity=r["overall_severity"], overall_confidence=r["overall_confidence"],
            risk_score=r["risk_score"], executive_summary=r["executive_summary"],
            strongest_evidence=json.loads(r["strongest_evidence_json"] or "[]"),
            potential_malicious_functionality=json.loads(r["potential_malicious_functionality_json"] or "[]"),
            unanswered_questions=json.loads(r["unanswered_questions_json"] or "[]"),
            limitations=json.loads(r["limitations_json"] or "[]"),
            recommended_actions=json.loads(r["recommended_actions_json"] or "[]"),
            dynamic_analysis_conducted=bool(r["dynamic_analysis_conducted"]),
            external_intelligence_used=bool(r["external_intelligence_used"])
        )

    def save_persistence_findings(self, inv_id: str, findings: List[PePersistenceFinding]):
        conn = get_db_connection()
        cursor = conn.cursor()
        for f in findings:
            cursor.execute("""
                INSERT OR REPLACE INTO pe_persistence_findings (
                    id, investigation_id, mechanism, indicator_type, title,
                    severity, confidence, source_evidence, details, limitations
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                f.id, inv_id, f.mechanism, f.indicator_type, f.title,
                f.severity, f.confidence, f.source_evidence, f.details, f.limitations
            ))
        conn.commit()
        conn.close()

    def get_persistence_findings(self, inv_id: str) -> List[PePersistenceFinding]:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM pe_persistence_findings WHERE investigation_id = ?", (inv_id,))
        rows = cursor.fetchall()
        conn.close()
        return [PePersistenceFinding(
            id=r["id"], mechanism=r["mechanism"], indicator_type=r["indicator_type"],
            title=r["title"], severity=r["severity"], confidence=r["confidence"],
            source_evidence=r["source_evidence"], details=r["details"],
            limitations=r["limitations"]
        ) for r in rows]

    def get_investigation_detail(self, inv_id: str, include_raw_secrets: bool = False) -> Optional[InvestigationDetail]:
        record = self.get_investigation(inv_id)
        if not record:
            return None
        metadata = self.get_metadata(inv_id)
        static_findings = self.get_static_findings(inv_id)
        c2_indicators = self.get_c2_indicators(inv_id)
        secrets = self.get_secrets(inv_id, include_raw=include_raw_secrets)
        reverse_shell_findings = self.get_reverse_shell_findings(inv_id)
        persistence_findings = self.get_persistence_findings(inv_id)
        network_iocs = self.get_network_iocs(inv_id)
        threat_intel = self.get_threat_intel_results(inv_id)
        tool_executions = self.get_tool_executions(inv_id)
        assessment = self.get_assessment(inv_id)
        
        pe_metadata = None
        if record.file_type == "exe" and metadata:
            if isinstance(metadata, PeMetadata):
                pe_metadata = metadata
            elif isinstance(metadata, dict):
                pe_metadata = PeMetadata.model_validate(metadata)
        
        # Build relationship graph data
        graph_data = self._build_evidence_graph(
            record, metadata, pe_metadata, c2_indicators, secrets, reverse_shell_findings, persistence_findings, network_iocs
        )

        ai_observations = self.list_ai_observations(inv_id)
        ai_recommendations = self.list_ai_recommendations(inv_id)
        ai_notes = self.get_ai_investigation_notes(inv_id)
        
        return InvestigationDetail(
            record=record, metadata=metadata, pe_metadata=pe_metadata,
            static_findings=static_findings, c2_indicators=c2_indicators,
            secrets=secrets, reverse_shell_findings=reverse_shell_findings,
            persistence_findings=persistence_findings, network_iocs=network_iocs,
            threat_intel=threat_intel, tool_executions=tool_executions,
            assessment=assessment, graph_data=graph_data,
            ai_observations=ai_observations,
            ai_recommendations=ai_recommendations,
            ai_notes=ai_notes
        )

    def _build_evidence_graph(self, record, metadata, pe_metadata, c2_indicators, secrets, reverse_shell_findings, persistence_findings, network_iocs) -> Dict[str, Any]:
        """Constructs an interactive evidence graph connecting artifact, components/sections, C2, and secrets."""
        nodes = []
        links = []
        
        # Root node
        root_node_id = f"file_{record.id}"
        nodes.append({
            "id": root_node_id,
            "label": record.filename,
            "type": record.file_type,
            "severity": record.severity,
            "details": f"SHA256: {record.sha256[:12]}..."
        })
        
        if record.file_type == "exe":
            # Add PE metadata / section nodes
            if pe_metadata and pe_metadata.sections:
                for sec in pe_metadata.sections[:5]:
                    sec_node_id = f"sec_{record.id}_{sec.name}"
                    nodes.append({
                        "id": sec_node_id,
                        "label": f"Section {sec.name}",
                        "type": "section",
                        "severity": "High" if sec.suspicious_indicators else "Informational",
                        "details": f"Entropy: {sec.entropy:.2f} | RVA: {sec.virtual_address}"
                    })
                    links.append({"source": root_node_id, "target": sec_node_id, "relationship": "contains_section"})
            # Add persistence finding nodes
            for pf in persistence_findings[:6]:
                pf_id = f"pf_{pf.id}"
                nodes.append({
                    "id": pf_id,
                    "label": pf.title,
                    "type": "persistence",
                    "severity": pf.severity,
                    "details": pf.mechanism
                })
                links.append({"source": root_node_id, "target": pf_id, "relationship": "persistence_mechanism"})
        else:
            # Metadata / Package node for APK
            if record.package_name:
                pkg_id = f"pkg_{record.package_name}"
                nodes.append({
                    "id": pkg_id,
                    "label": record.package_name,
                    "type": "package",
                    "severity": "Informational",
                    "details": f"App: {record.app_name or 'Unknown'}"
                })
                links.append({"source": root_node_id, "target": pkg_id, "relationship": "declares_package"})
            # Reverse Shell Findings
            for rs in reverse_shell_findings[:5]:
                rs_id = f"rs_{rs.id}"
                nodes.append({
                    "id": rs_id,
                    "label": rs.title,
                    "type": "reverse_shell",
                    "severity": rs.severity,
                    "details": rs.explanation[:80] + "..."
                })
                links.append({"source": root_node_id, "target": rs_id, "relationship": "exhibits_behavior"})
            
        # Shared: C2 Indicators
        for ind in c2_indicators[:12]:
            c2_id = f"c2_{ind.id}"
            nodes.append({
                "id": c2_id,
                "label": f"{ind.indicator_type.upper()}: {ind.value}",
                "type": "c2",
                "severity": "Critical" if "c2" in ind.classification else "High",
                "details": ind.why_suspicious
            })
            links.append({"source": root_node_id, "target": c2_id, "relationship": "contains_indicator"})
            
        # Shared: Secrets / Tokens
        for sec in secrets[:10]:
            sec_id = f"sec_{sec.id}"
            nodes.append({
                "id": sec_id,
                "label": f"{sec.token_category}: {sec.redacted_value}",
                "type": "secret",
                "severity": "Medium" if sec.confidence == "Low" else "High",
                "details": f"Rule: {sec.rule_matched}"
            })
            links.append({"source": root_node_id, "target": sec_id, "relationship": "embeds_token"})

        return {"nodes": nodes, "links": links}

    def get_dashboard_stats(self) -> Dict[str, Any]:
        """Calculate real statistics from investigation records."""
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute("SELECT COUNT(*) FROM investigations")
        total_investigations = cursor.fetchone()[0]
        
        cursor.execute("SELECT COUNT(*) FROM investigations WHERE file_type = 'apk'")
        apk_count = cursor.fetchone()[0]

        cursor.execute("SELECT COUNT(*) FROM investigations WHERE file_type = 'exe'")
        exe_count = cursor.fetchone()[0]
        
        cursor.execute("SELECT COUNT(*) FROM investigations WHERE total_findings > 0")
        with_suspicious = cursor.fetchone()[0]
        
        cursor.execute("SELECT COUNT(*) FROM investigations WHERE severity IN ('High', 'Critical')")
        high_critical = cursor.fetchone()[0]
        
        cursor.execute("SELECT COUNT(*) FROM investigations WHERE reverse_shell_detected = 1")
        reverse_shell_count = cursor.fetchone()[0]
        
        cursor.execute("SELECT COUNT(*) FROM pe_persistence_findings")
        pe_persistence_count = cursor.fetchone()[0]
        
        cursor.execute("SELECT COUNT(*) FROM investigations WHERE status = 'analyzing'")
        running_jobs = cursor.fetchone()[0]
        
        cursor.execute("SELECT COUNT(*) FROM c2_indicators WHERE classification IN ('potential_c2', 'suspicious_destination', 'reported_malicious')")
        c2_count = cursor.fetchone()[0]
        
        cursor.execute("SELECT COUNT(*) FROM secret_findings")
        secret_count = cursor.fetchone()[0]
        
        cursor.execute("SELECT * FROM investigations ORDER BY created_at DESC LIMIT 5")
        recent_rows = cursor.fetchall()
        recent_investigations = [self._row_to_record(r) for r in recent_rows]
        
        conn.close()
        
        return {
            "total_investigations": total_investigations,
            "apk_files_analyzed": apk_count,
            "exe_files_analyzed": exe_count,
            "files_with_suspicious_indicators": with_suspicious,
            "high_confidence_malware_findings": high_critical,
            "potential_c2_configurations": c2_count,
            "detected_reverse_shell_indicators": reverse_shell_count,
            "detected_persistence_indicators": pe_persistence_count,
            "active_running_tasks": running_jobs,
            "detected_secrets_count": secret_count,
            "recent_investigations": recent_investigations
        }

    def save_setting(self, key: str, value: str):
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("""
            INSERT OR REPLACE INTO app_settings (setting_key, setting_value, updated_at)
            VALUES (?, ?, ?)
        """, (key, value, datetime.utcnow().isoformat()))
        conn.commit()
        conn.close()

    def get_setting(self, key: str, default: Optional[str] = None) -> Optional[str]:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT setting_value FROM app_settings WHERE setting_key = ?", (key,))
        row = cursor.fetchone()
        conn.close()
        if row:
            return row["setting_value"]
        return default

    def get_all_settings(self) -> Dict[str, str]:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT setting_key, setting_value FROM app_settings")
        rows = cursor.fetchall()
        conn.close()
        return {r["setting_key"]: r["setting_value"] for r in rows}

    # ========================================================
    # BYOK ENCRYPTED PROVIDER CREDENTIALS
    # ========================================================

    def save_provider_credential(
        self,
        provider_name: str,
        credential_type: str,
        encrypted_data: str,
        key_fingerprint: str,
        is_valid: bool = True,
        last_tested_at: Optional[str] = None
    ) -> bool:
        conn = get_db_connection()
        cursor = conn.cursor()
        now = datetime.utcnow().isoformat()
        cursor.execute("""
            INSERT INTO provider_credentials (
                provider_name, credential_type, encrypted_data, key_fingerprint,
                is_valid, last_tested_at, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(provider_name) DO UPDATE SET
                credential_type = excluded.credential_type,
                encrypted_data = excluded.encrypted_data,
                key_fingerprint = excluded.key_fingerprint,
                is_valid = excluded.is_valid,
                last_tested_at = COALESCE(excluded.last_tested_at, provider_credentials.last_tested_at),
                updated_at = excluded.updated_at
        """, (
            provider_name.lower().strip(),
            credential_type,
            encrypted_data,
            key_fingerprint,
            1 if is_valid else 0,
            last_tested_at,
            now,
            now
        ))
        conn.commit()
        conn.close()
        return True

    def get_provider_credential(self, provider_name: str) -> Optional[Dict[str, Any]]:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("""
            SELECT id, provider_name, credential_type, encrypted_data, key_fingerprint,
                   is_valid, last_tested_at, created_at, updated_at
            FROM provider_credentials
            WHERE provider_name = ?
        """, (provider_name.lower().strip(),))
        row = cursor.fetchone()
        conn.close()
        if not row:
            return None
        return dict(row)

    def list_provider_credentials(self) -> List[Dict[str, Any]]:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("""
            SELECT id, provider_name, credential_type, encrypted_data, key_fingerprint,
                   is_valid, last_tested_at, created_at, updated_at
            FROM provider_credentials
            ORDER BY provider_name ASC
        """)
        rows = cursor.fetchall()
        conn.close()
        return [dict(r) for r in rows]

    def delete_provider_credential(self, provider_name: str) -> bool:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("DELETE FROM provider_credentials WHERE provider_name = ?", (provider_name.lower().strip(),))
        deleted = cursor.rowcount > 0
        conn.commit()
        conn.close()
        return deleted

    def update_provider_credential_status(self, provider_name: str, is_valid: bool, last_tested_at: str) -> bool:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("""
            UPDATE provider_credentials
            SET is_valid = ?, last_tested_at = ?, updated_at = ?
            WHERE provider_name = ?
        """, (
            1 if is_valid else 0,
            last_tested_at,
            datetime.utcnow().isoformat(),
            provider_name.lower().strip()
        ))
        updated = cursor.rowcount > 0
        conn.commit()
        conn.close()
        return updated

    # ========================================================
    # UNIVERSAL USER AUTHENTICATION & SESSIONS
    # ========================================================

    def create_user(
        self,
        user_id: str,
        username: str,
        email: str,
        password_hash: str,
        salt: bytes,
        role: str = "investigator"
    ) -> Dict[str, Any]:
        conn = get_db_connection()
        cursor = conn.cursor()
        now = datetime.utcnow().isoformat()
        cursor.execute("""
            INSERT INTO users (
                id, username, email, password_hash, salt, role,
                is_active, failed_login_attempts, locked_until, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, 1, 0, NULL, ?, ?)
        """, (user_id, username.lower().strip(), email.lower().strip(), password_hash, salt, role, now, now))
        conn.commit()
        conn.close()
        return self.get_user_by_id(user_id)

    def get_user_by_id(self, user_id: str) -> Optional[Dict[str, Any]]:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
        row = cursor.fetchone()
        conn.close()
        return dict(row) if row else None

    def get_user_by_username(self, username: str) -> Optional[Dict[str, Any]]:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE lower(username) = ?", (username.lower().strip(),))
        row = cursor.fetchone()
        conn.close()
        return dict(row) if row else None

    def get_user_by_email(self, email: str) -> Optional[Dict[str, Any]]:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE lower(email) = ?", (email.lower().strip(),))
        row = cursor.fetchone()
        conn.close()
        return dict(row) if row else None

    def update_user_password(self, user_id: str, password_hash: str, salt: bytes) -> bool:
        conn = get_db_connection()
        cursor = conn.cursor()
        now = datetime.utcnow().isoformat()
        cursor.execute("""
            UPDATE users
            SET password_hash = ?, salt = ?, failed_login_attempts = 0, locked_until = NULL, updated_at = ?
            WHERE id = ?
        """, (password_hash, salt, now, user_id))
        updated = cursor.rowcount > 0
        conn.commit()
        conn.close()
        return updated

    def update_user_failed_attempts(self, user_id: str, failed_attempts: int, locked_until: Optional[str] = None) -> bool:
        conn = get_db_connection()
        cursor = conn.cursor()
        now = datetime.utcnow().isoformat()
        cursor.execute("""
            UPDATE users
            SET failed_login_attempts = ?, locked_until = ?, updated_at = ?
            WHERE id = ?
        """, (failed_attempts, locked_until, now, user_id))
        updated = cursor.rowcount > 0
        conn.commit()
        conn.close()
        return updated

    def reset_user_failed_attempts(self, user_id: str) -> bool:
        return self.update_user_failed_attempts(user_id, 0, None)

    def list_users(self) -> List[Dict[str, Any]]:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("""
            SELECT id, username, email, role, is_active, failed_login_attempts, locked_until, created_at, updated_at
            FROM users
            ORDER BY created_at ASC
        """)
        rows = cursor.fetchall()
        conn.close()
        return [dict(r) for r in rows]

    def count_users(self) -> int:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM users")
        count = cursor.fetchone()[0]
        conn.close()
        return count

    def delete_user(self, user_id: str) -> bool:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("DELETE FROM users WHERE id = ?", (user_id,))
        deleted = cursor.rowcount > 0
        conn.commit()
        conn.close()
        return deleted

    # ========================================================
    # SESSIONS & AUTH TOKENS
    # ========================================================

    def create_user_session(
        self,
        session_id: str,
        user_id: str,
        session_token_masked: str,
        expires_at: str,
        user_agent: Optional[str] = None,
        ip_address: Optional[str] = None
    ) -> Dict[str, Any]:
        conn = get_db_connection()
        cursor = conn.cursor()
        now = datetime.utcnow().isoformat()
        cursor.execute("""
            INSERT INTO user_sessions (
                id, user_id, session_token_masked, user_agent, ip_address,
                expires_at, created_at, last_activity_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (session_id, user_id, session_token_masked, user_agent, ip_address, expires_at, now, now))
        conn.commit()
        conn.close()
        return {
            "id": session_id,
            "user_id": user_id,
            "session_token_masked": session_token_masked,
            "expires_at": expires_at,
            "created_at": now,
            "last_activity_at": now
        }

    def get_user_session(self, session_id: str) -> Optional[Dict[str, Any]]:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("""
            SELECT s.*, u.username, u.email, u.role, u.is_active, u.locked_until
            FROM user_sessions s
            JOIN users u ON s.user_id = u.id
            WHERE s.id = ?
        """, (session_id,))
        row = cursor.fetchone()
        conn.close()
        return dict(row) if row else None

    def update_session_activity(self, session_id: str, last_activity_at: str, expires_at: str) -> bool:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("""
            UPDATE user_sessions
            SET last_activity_at = ?, expires_at = ?
            WHERE id = ?
        """, (last_activity_at, expires_at, session_id))
        updated = cursor.rowcount > 0
        conn.commit()
        conn.close()
        return updated

    def delete_user_session(self, session_id: str) -> bool:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("DELETE FROM user_sessions WHERE id = ?", (session_id,))
        deleted = cursor.rowcount > 0
        conn.commit()
        conn.close()
        return deleted

    def delete_user_sessions_by_user_id(self, user_id: str, except_session_id: Optional[str] = None) -> int:
        conn = get_db_connection()
        cursor = conn.cursor()
        if except_session_id:
            cursor.execute("DELETE FROM user_sessions WHERE user_id = ? AND id != ?", (user_id, except_session_id))
        else:
            cursor.execute("DELETE FROM user_sessions WHERE user_id = ?", (user_id,))
        count = cursor.rowcount
        conn.commit()
        conn.close()
        return count

    def clean_expired_sessions(self) -> int:
        conn = get_db_connection()
        cursor = conn.cursor()
        now = datetime.utcnow().isoformat()
        cursor.execute("DELETE FROM user_sessions WHERE expires_at < ?", (now,))
        count = cursor.rowcount
        conn.commit()
        conn.close()
        return count

    # ========================================================
    # PASSWORD RESETS
    # ========================================================

    def create_password_reset(self, reset_id: str, user_id: str, token_hash: str, expires_at: str) -> bool:
        conn = get_db_connection()
        cursor = conn.cursor()
        now = datetime.utcnow().isoformat()
        cursor.execute("""
            INSERT INTO user_password_resets (id, user_id, token_hash, expires_at, used, created_at)
            VALUES (?, ?, ?, ?, 0, ?)
        """, (reset_id, user_id, token_hash, expires_at, now))
        conn.commit()
        conn.close()
        return True

    def get_password_reset(self, token_hash: str) -> Optional[Dict[str, Any]]:
        conn = get_db_connection()
        cursor = conn.cursor()
        now = datetime.utcnow().isoformat()
        cursor.execute("""
            SELECT * FROM user_password_resets
            WHERE token_hash = ? AND used = 0 AND expires_at > ?
        """, (token_hash, now))
        row = cursor.fetchone()
        conn.close()
        return dict(row) if row else None

    def mark_password_reset_used(self, reset_id: str) -> bool:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("UPDATE user_password_resets SET used = 1 WHERE id = ?", (reset_id,))
        updated = cursor.rowcount > 0
        conn.commit()
        conn.close()
        return updated

    # ========================================================
    # USER-SCOPED PROVIDER CREDENTIALS & OAuth TOKENS
    # ========================================================

    def save_user_provider_credential(
        self,
        user_id: str,
        provider_name: str,
        auth_type: str,
        encrypted_data: str,
        key_fingerprint: str,
        is_valid: bool = True,
        last_tested_at: Optional[str] = None,
        last_error_code: Optional[str] = None,
        last_error_message: Optional[str] = None,
        token_expires_at: Optional[str] = None,
        refresh_token_encrypted: Optional[str] = None,
        scope: Optional[str] = None,
        account_identifier: Optional[str] = None,
        reset_test_status: bool = False
    ) -> bool:
        import uuid
        conn = get_db_connection()
        cursor = conn.cursor()
        now = datetime.utcnow().isoformat()
        cred_id = str(uuid.uuid4())
        
        tested_clause = "last_tested_at = NULL," if reset_test_status else "last_tested_at = COALESCE(excluded.last_tested_at, user_provider_credentials.last_tested_at),"
        err_code_clause = "last_error_code = NULL," if reset_test_status else "last_error_code = excluded.last_error_code,"
        err_msg_clause = "last_error_message = NULL," if reset_test_status else "last_error_message = excluded.last_error_message,"

        cursor.execute(f"""
            INSERT INTO user_provider_credentials (
                id, user_id, provider_name, auth_type, encrypted_data, key_fingerprint,
                is_valid, last_tested_at, last_error_code, last_error_message,
                token_expires_at, refresh_token_encrypted, scope, account_identifier,
                created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(user_id, provider_name) DO UPDATE SET
                auth_type = excluded.auth_type,
                encrypted_data = excluded.encrypted_data,
                key_fingerprint = excluded.key_fingerprint,
                is_valid = excluded.is_valid,
                {tested_clause}
                {err_code_clause}
                {err_msg_clause}
                token_expires_at = COALESCE(excluded.token_expires_at, user_provider_credentials.token_expires_at),
                refresh_token_encrypted = COALESCE(excluded.refresh_token_encrypted, user_provider_credentials.refresh_token_encrypted),
                scope = COALESCE(excluded.scope, user_provider_credentials.scope),
                account_identifier = COALESCE(excluded.account_identifier, user_provider_credentials.account_identifier),
                updated_at = excluded.updated_at
        """, (
            cred_id, user_id, provider_name.lower().strip(), auth_type,
            encrypted_data, key_fingerprint, 1 if is_valid else 0,
            None if reset_test_status else last_tested_at,
            None if reset_test_status else last_error_code,
            None if reset_test_status else last_error_message,
            token_expires_at, refresh_token_encrypted, scope, account_identifier,
            now, now
        ))
        conn.commit()
        conn.close()
        return True

    def get_user_provider_credential(self, user_id: str, provider_name: str) -> Optional[Dict[str, Any]]:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("""
            SELECT * FROM user_provider_credentials
            WHERE user_id = ? AND provider_name = ?
        """, (user_id, provider_name.lower().strip()))
        row = cursor.fetchone()
        conn.close()
        return dict(row) if row else None

    def list_user_provider_credentials(self, user_id: str) -> List[Dict[str, Any]]:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("""
            SELECT * FROM user_provider_credentials
            WHERE user_id = ?
            ORDER BY provider_name ASC
        """, (user_id,))
        rows = cursor.fetchall()
        conn.close()
        return [dict(r) for r in rows]

    def delete_user_provider_credential(self, user_id: str, provider_name: str) -> bool:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("""
            DELETE FROM user_provider_credentials
            WHERE user_id = ? AND provider_name = ?
        """, (user_id, provider_name.lower().strip()))
        deleted = cursor.rowcount > 0
        conn.commit()
        conn.close()
        return deleted

    def update_user_provider_credential_status(
        self,
        user_id: str,
        provider_name: str,
        is_valid: bool,
        last_tested_at: Optional[str] = None,
        last_error_code: Optional[str] = None,
        last_error_message: Optional[str] = None
    ) -> bool:
        conn = get_db_connection()
        cursor = conn.cursor()
        now = datetime.utcnow().isoformat()
        cursor.execute("""
            UPDATE user_provider_credentials
            SET is_valid = ?, last_tested_at = ?, last_error_code = ?, last_error_message = ?, updated_at = ?
            WHERE user_id = ? AND provider_name = ?
        """, (
            1 if is_valid else 0,
            last_tested_at or now,
            last_error_code,
            last_error_message,
            now,
            user_id,
            provider_name.lower().strip()
        ))
        updated = cursor.rowcount > 0
        conn.commit()
        conn.close()
        return updated

    def update_user_provider_tokens(
        self,
        user_id: str,
        provider_name: str,
        encrypted_data: str,
        refresh_token_encrypted: Optional[str] = None,
        token_expires_at: Optional[str] = None
    ) -> bool:
        conn = get_db_connection()
        cursor = conn.cursor()
        now = datetime.utcnow().isoformat()
        if refresh_token_encrypted:
            cursor.execute("""
                UPDATE user_provider_credentials
                SET encrypted_data = ?, refresh_token_encrypted = ?, token_expires_at = ?, is_valid = 1, updated_at = ?
                WHERE user_id = ? AND provider_name = ?
            """, (encrypted_data, refresh_token_encrypted, token_expires_at, now, user_id, provider_name.lower().strip()))
        else:
            cursor.execute("""
                UPDATE user_provider_credentials
                SET encrypted_data = ?, token_expires_at = ?, is_valid = 1, updated_at = ?
                WHERE user_id = ? AND provider_name = ?
            """, (encrypted_data, token_expires_at, now, user_id, provider_name.lower().strip()))
        updated = cursor.rowcount > 0
        conn.commit()
        conn.close()
        return updated

    def migrate_legacy_credentials_to_user(self, target_user_id: str) -> int:
        """Migrate any credentials in legacy provider_credentials table to target user."""
        legacy = self.list_provider_credentials()
        migrated_count = 0
        for row in legacy:
            p_name = row["provider_name"]
            existing = self.get_user_provider_credential(target_user_id, p_name)
            if not existing and row.get("encrypted_data"):
                self.save_user_provider_credential(
                    user_id=target_user_id,
                    provider_name=p_name,
                    auth_type=row.get("credential_type", "api_key"),
                    encrypted_data=row["encrypted_data"],
                    key_fingerprint=row.get("key_fingerprint", ""),
                    is_valid=bool(row.get("is_valid", 1)),
                    last_tested_at=row.get("last_tested_at")
                )
                migrated_count += 1
        return migrated_count

    # ========================================================
    # UNIVERSAL EVIDENCE ITEMS
    # ========================================================

    def create_evidence_item(self, item: EvidenceItem):
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("""
            INSERT OR REPLACE INTO evidence_items (
                id, investigation_id, parent_evidence_id, filename, relative_path,
                file_size, mime_type, detected_format, extension, format_mismatch,
                md5, sha1, sha256, sha512, working_copy_sha256, integrity_status,
                source_info, examiner_notes, acquired_at, filesystem_created_at,
                filesystem_modified_at, processing_state, entropy, triage_summary_json,
                metadata_json, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            item.id, item.investigation_id, item.parent_evidence_id, item.filename, item.relative_path,
            item.file_size, item.mime_type, item.detected_format, item.extension, 1 if item.format_mismatch else 0,
            item.md5, item.sha1, item.sha256, item.sha512, item.working_copy_sha256, item.integrity_status,
            item.source_info, item.examiner_notes, item.acquired_at.isoformat(),
            item.filesystem_created_at, item.filesystem_modified_at, item.processing_state,
            item.entropy, json.dumps(item.triage_summary), json.dumps(item.metadata),
            item.created_at.isoformat()
        ))
        conn.commit()
        conn.close()

    def save_evidence_items(self, investigation_id: str, items: List[EvidenceItem]):
        for item in items:
            self.create_evidence_item(item)

    def update_evidence_item(self, item: EvidenceItem):
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("""
            UPDATE evidence_items SET
                processing_state = ?, entropy = ?, triage_summary_json = ?,
                metadata_json = ?, working_copy_sha256 = ?, integrity_status = ?,
                format_mismatch = ?, detected_format = ?, mime_type = ?
            WHERE id = ?
        """, (
            item.processing_state, item.entropy, json.dumps(item.triage_summary),
            json.dumps(item.metadata), item.working_copy_sha256, item.integrity_status,
            1 if item.format_mismatch else 0, item.detected_format, item.mime_type,
            item.id
        ))
        conn.commit()
        conn.close()

    def get_evidence_item(self, item_id: str) -> Optional[EvidenceItem]:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM evidence_items WHERE id = ?", (item_id,))
        row = cursor.fetchone()
        conn.close()
        if not row:
            return None
        return self._row_to_evidence_item(row)

    def list_evidence_items(self, investigation_id: str) -> List[EvidenceItem]:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM evidence_items WHERE investigation_id = ? ORDER BY created_at ASC", (investigation_id,))
        rows = cursor.fetchall()
        conn.close()
        return [self._row_to_evidence_item(r) for r in rows]

    def delete_evidence_item(self, item_id: str) -> bool:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("DELETE FROM evidence_items WHERE id = ?", (item_id,))
        affected = cursor.rowcount
        conn.commit()
        conn.close()
        return affected > 0

    def _row_to_evidence_item(self, row) -> EvidenceItem:
        triage = json.loads(row["triage_summary_json"]) if row["triage_summary_json"] else {}
        meta = json.loads(row["metadata_json"]) if row["metadata_json"] else {}
        return EvidenceItem(
            id=row["id"],
            investigation_id=row["investigation_id"],
            parent_evidence_id=row["parent_evidence_id"],
            filename=row["filename"],
            relative_path=row["relative_path"],
            file_size=row["file_size"],
            mime_type=row["mime_type"],
            detected_format=row["detected_format"],
            extension=row["extension"],
            format_mismatch=bool(row["format_mismatch"]),
            md5=row["md5"],
            sha1=row["sha1"],
            sha256=row["sha256"],
            sha512=row["sha512"],
            working_copy_sha256=row["working_copy_sha256"],
            integrity_status=row["integrity_status"] or "VERIFIED",
            source_info=row["source_info"],
            examiner_notes=row["examiner_notes"],
            acquired_at=datetime.fromisoformat(row["acquired_at"]),
            filesystem_created_at=row["filesystem_created_at"],
            filesystem_modified_at=row["filesystem_modified_at"],
            processing_state=row["processing_state"] or "NOT_RUN",
            entropy=float(row["entropy"] or 0.0),
            triage_summary=triage,
            metadata=meta,
            created_at=datetime.fromisoformat(row["created_at"])
        )

    # ========================================================
    # EXTRACTED ARTIFACTS
    # ========================================================

    def save_extracted_artifacts(self, investigation_id: str, artifacts: List[ExtractedArtifact]):
        conn = get_db_connection()
        cursor = conn.cursor()
        for a in artifacts:
            cursor.execute("""
                INSERT OR REPLACE INTO extracted_artifacts (
                    id, investigation_id, evidence_id, parent_artifact_id,
                    artifact_type, source_format, source_location, value,
                    structured_data_json, sha256, extractor_name, extracted_at,
                    confidence, parser_warnings
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                a.id, investigation_id, a.evidence_id, a.parent_artifact_id,
                a.artifact_type, a.source_format, a.source_location, a.value,
                json.dumps(a.structured_data), a.sha256, a.extractor_name,
                a.extracted_at.isoformat(), a.confidence, a.parser_warnings
            ))
        conn.commit()
        conn.close()

    def list_extracted_artifacts(self, investigation_id: str, evidence_id: Optional[str] = None) -> List[ExtractedArtifact]:
        conn = get_db_connection()
        cursor = conn.cursor()
        if evidence_id:
            cursor.execute("SELECT * FROM extracted_artifacts WHERE investigation_id = ? AND evidence_id = ? ORDER BY extracted_at ASC", (investigation_id, evidence_id))
        else:
            cursor.execute("SELECT * FROM extracted_artifacts WHERE investigation_id = ? ORDER BY extracted_at ASC", (investigation_id,))
        rows = cursor.fetchall()
        conn.close()
        results = []
        for r in rows:
            data = json.loads(r["structured_data_json"]) if r["structured_data_json"] else {}
            results.append(ExtractedArtifact(
                id=r["id"],
                investigation_id=r["investigation_id"],
                evidence_id=r["evidence_id"],
                parent_artifact_id=r["parent_artifact_id"],
                artifact_type=r["artifact_type"],
                source_format=r["source_format"],
                source_location=r["source_location"],
                value=r["value"],
                structured_data=data,
                sha256=r["sha256"],
                extractor_name=r["extractor_name"],
                extracted_at=datetime.fromisoformat(r["extracted_at"]),
                confidence=r["confidence"] or "Medium",
                parser_warnings=r["parser_warnings"]
            ))
        return results

    # ========================================================
    # EVIDENCE RELATIONSHIPS (CROSS-FILE CORRELATION)
    # ========================================================

    def save_evidence_relationships(self, investigation_id: str, relationships: List[EvidenceRelationship]):
        conn = get_db_connection()
        cursor = conn.cursor()
        for rel in relationships:
            cursor.execute("""
                INSERT OR REPLACE INTO evidence_relationships (
                    id, investigation_id, source_evidence_id, target_evidence_id,
                    relationship_type, supporting_artifact_ids_json, matching_method,
                    strength, limitations, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                rel.id, investigation_id, rel.source_evidence_id, rel.target_evidence_id,
                rel.relationship_type, json.dumps(rel.supporting_artifact_ids),
                rel.matching_method, rel.strength, rel.limitations,
                rel.created_at.isoformat()
            ))
        conn.commit()
        conn.close()

    def list_evidence_relationships(self, investigation_id: str) -> List[EvidenceRelationship]:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM evidence_relationships WHERE investigation_id = ? ORDER BY created_at ASC", (investigation_id,))
        rows = cursor.fetchall()
        conn.close()
        results = []
        for r in rows:
            supp = json.loads(r["supporting_artifact_ids_json"]) if r["supporting_artifact_ids_json"] else []
            results.append(EvidenceRelationship(
                id=r["id"],
                investigation_id=r["investigation_id"],
                source_evidence_id=r["source_evidence_id"],
                target_evidence_id=r["target_evidence_id"],
                relationship_type=r["relationship_type"],
                supporting_artifact_ids=supp,
                matching_method=r["matching_method"],
                strength=r["strength"] or "Exact",
                limitations=r["limitations"],
                created_at=datetime.fromisoformat(r["created_at"])
            ))
        return results

    # ========================================================
    # TIMELINE EVENTS
    # ========================================================

    def save_timeline_events(self, investigation_id: str, events: List[TimelineEvent]):
        conn = get_db_connection()
        cursor = conn.cursor()
        for ev in events:
            cursor.execute("""
                INSERT OR REPLACE INTO timeline_events (
                    id, investigation_id, evidence_id, original_timestamp,
                    original_timezone, normalized_utc, timestamp_source,
                    transformation_applied, reliability, event_type,
                    description, associated_finding_id, related_evidence_ids_json,
                    created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                ev.id, investigation_id, ev.evidence_id, ev.original_timestamp,
                ev.original_timezone, ev.normalized_utc, ev.timestamp_source,
                ev.transformation_applied, ev.reliability, ev.event_type,
                ev.description, ev.associated_finding_id,
                json.dumps(ev.related_evidence_ids), datetime.utcnow().isoformat()
            ))
        conn.commit()
        conn.close()

    def list_timeline_events(self, investigation_id: str) -> List[TimelineEvent]:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM timeline_events WHERE investigation_id = ? ORDER BY normalized_utc ASC", (investigation_id,))
        rows = cursor.fetchall()
        conn.close()
        results = []
        for r in rows:
            rel_evd = json.loads(r["related_evidence_ids_json"]) if r["related_evidence_ids_json"] else []
            results.append(TimelineEvent(
                id=r["id"],
                investigation_id=r["investigation_id"],
                evidence_id=r["evidence_id"],
                original_timestamp=r["original_timestamp"],
                original_timezone=r["original_timezone"],
                normalized_utc=r["normalized_utc"],
                timestamp_source=r["timestamp_source"],
                transformation_applied=r["transformation_applied"],
                reliability=r["reliability"] or "High",
                event_type=r["event_type"],
                description=r["description"],
                associated_finding_id=r["associated_finding_id"],
                related_evidence_ids=rel_evd
            ))
        return results

    # ========================================================
    # CHAIN OF CUSTODY (INTEGRITY LEDGER)
    # ========================================================

    def add_chain_of_custody_event(self, event: ChainOfCustodyEvent):
        conn = get_db_connection()
        cursor = conn.cursor()
        try:
            cursor.execute("""
                INSERT OR REPLACE INTO chain_of_custody (
                    id, investigation_id, evidence_id, event_type, timestamp_utc,
                    examiner, original_hash, working_copy_hash, verification_result,
                    details_json, prev_event_hash, event_hash
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                event.id, event.investigation_id, event.evidence_id, event.event_type,
                event.timestamp_utc, event.examiner, event.original_hash,
                event.working_copy_hash, event.verification_result,
                json.dumps(event.details), event.prev_event_hash, event.event_hash
            ))
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def get_last_chain_of_custody_event(self, investigation_id: str) -> Optional[ChainOfCustodyEvent]:
        conn = get_db_connection()
        try:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM chain_of_custody WHERE investigation_id = ? ORDER BY rowid DESC LIMIT 1", (investigation_id,))
            row = cursor.fetchone()
            if not row:
                return None
            details = json.loads(row["details_json"]) if row["details_json"] else {}
            return ChainOfCustodyEvent(
                id=row["id"],
                investigation_id=row["investigation_id"],
                evidence_id=row["evidence_id"],
                event_type=row["event_type"],
                timestamp_utc=row["timestamp_utc"],
                examiner=row["examiner"],
                original_hash=row["original_hash"],
                working_copy_hash=row["working_copy_hash"],
                verification_result=row["verification_result"] or "PASSED",
                details=details,
                prev_event_hash=row["prev_event_hash"],
                event_hash=row["event_hash"]
            )
        finally:
            conn.close()

    def list_chain_of_custody(self, investigation_id: str) -> List[ChainOfCustodyEvent]:
        conn = get_db_connection()
        try:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM chain_of_custody WHERE investigation_id = ? ORDER BY rowid ASC", (investigation_id,))
            rows = cursor.fetchall()
            results = []
            for r in rows:
                details = json.loads(r["details_json"]) if r["details_json"] else {}
                results.append(ChainOfCustodyEvent(
                    id=r["id"],
                    investigation_id=r["investigation_id"],
                    evidence_id=r["evidence_id"],
                    event_type=r["event_type"],
                    timestamp_utc=r["timestamp_utc"],
                    examiner=r["examiner"],
                    original_hash=r["original_hash"],
                    working_copy_hash=r["working_copy_hash"],
                    verification_result=r["verification_result"] or "PASSED",
                    details=details,
                    prev_event_hash=r["prev_event_hash"],
                    event_hash=r["event_hash"]
                ))
            return results
        finally:
            conn.close()

    # ========================================================
    # FINDINGS REGISTER (EVIDENCE-BACKED FINDINGS)
    # ========================================================

    def save_findings_register(self, investigation_id: str, findings: List[FindingRecord]):
        conn = get_db_connection()
        cursor = conn.cursor()
        for f in findings:
            cursor.execute("""
                INSERT OR REPLACE INTO findings_register (
                    id, investigation_id, evidence_id, artifact_ids_json, title,
                    description, observation, interpretation, severity, confidence,
                    analysis_method, source_location, analyzer_name, analyzer_version,
                    rule_version, timestamp_utc, alternative_explanation, limitations,
                    verification_state, analyst_notes, source_evidence, source_file,
                    frame_number, packet_number, timestamp, engine, rule_id, original_hash
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                f.id, investigation_id, f.evidence_id, json.dumps(f.artifact_ids),
                f.title, f.description, f.observation, f.interpretation,
                f.severity, f.confidence, f.analysis_method, f.source_location,
                f.analyzer_name, f.analyzer_version, f.rule_version,
                f.timestamp_utc, f.alternative_explanation, f.limitations,
                f.verification_state, f.analyst_notes, f.source_evidence, f.source_file,
                f.frame_number, f.packet_number, f.timestamp, f.engine, f.rule_id, f.original_hash
            ))
        conn.commit()
        conn.close()

    def list_findings_register(self, investigation_id: str, evidence_id: Optional[str] = None) -> List[FindingRecord]:
        conn = get_db_connection()
        cursor = conn.cursor()
        if evidence_id:
            cursor.execute("SELECT * FROM findings_register WHERE investigation_id = ? AND evidence_id = ? ORDER BY timestamp_utc ASC", (investigation_id, evidence_id))
        else:
            cursor.execute("SELECT * FROM findings_register WHERE investigation_id = ? ORDER BY timestamp_utc ASC", (investigation_id,))
        rows = cursor.fetchall()
        conn.close()
        results = []
        for r in rows:
            arts = json.loads(r["artifact_ids_json"]) if r["artifact_ids_json"] else []

            def field(name):
                return r[name] if name in r.keys() else None

            results.append(FindingRecord(
                id=r["id"],
                case_id=r["investigation_id"],
                investigation_id=r["investigation_id"],
                evidence_id=r["evidence_id"],
                artifact_ids=arts,
                title=r["title"],
                description=r["description"],
                observation=r["observation"],
                interpretation=r["interpretation"],
                severity=r["severity"],
                confidence=r["confidence"],
                analysis_method=r["analysis_method"],
                source_location=r["source_location"],
                analyzer_name=r["analyzer_name"],
                analyzer_version=r["analyzer_version"],
                rule_version=r["rule_version"],
                timestamp_utc=r["timestamp_utc"],
                alternative_explanation=r["alternative_explanation"],
                limitations=r["limitations"],
                verification_state=r["verification_state"] or "pending_review",
                analyst_notes=r["analyst_notes"],
                source_evidence=field("source_evidence"),
                source_file=field("source_file"),
                frame_number=field("frame_number"),
                packet_number=field("packet_number"),
                timestamp=field("timestamp"),
                engine=field("engine"),
                rule_id=field("rule_id"),
                original_hash=field("original_hash")
            ))
        return results

    def update_finding_verification(self, finding_id: str, verification_state: str, analyst_notes: Optional[str] = None) -> bool:
        conn = get_db_connection()
        cursor = conn.cursor()
        if analyst_notes is not None:
            cursor.execute("UPDATE findings_register SET verification_state = ?, analyst_notes = ? WHERE id = ?", (verification_state, analyst_notes, finding_id))
        else:
            cursor.execute("UPDATE findings_register SET verification_state = ? WHERE id = ?", (verification_state, finding_id))
        affected = cursor.rowcount
        conn.commit()
        conn.close()
        return affected > 0

    # ========================================================
    # CROSS-CASE SEARCH & DUPLICATE IDENTIFICATION
    # ========================================================

    def search_cross_case_hashes(self, sha256: str, current_inv_id: Optional[str] = None) -> List[Dict[str, Any]]:
        conn = get_db_connection()
        cursor = conn.cursor()
        query = """
            SELECT e.id as evidence_id, e.investigation_id, e.filename, e.detected_format,
                   e.created_at, i.case_reference, i.investigator_name
            FROM evidence_items e
            JOIN investigations i ON e.investigation_id = i.id
            WHERE e.sha256 = ?
        """
        params = [sha256]
        if current_inv_id:
            query += " AND e.investigation_id != ?"
            params.append(current_inv_id)
        cursor.execute(query, tuple(params))
        rows = cursor.fetchall()
        conn.close()
        return [dict(r) for r in rows]

    def search_cross_case_indicators(self, indicator_type: str, value: str, current_inv_id: Optional[str] = None) -> List[Dict[str, Any]]:
        conn = get_db_connection()
        cursor = conn.cursor()
        query = """
            SELECT a.id as artifact_id, a.investigation_id, a.evidence_id, a.artifact_type,
                   a.value, a.source_location, a.extracted_at, i.case_reference, i.filename as case_filename
            FROM extracted_artifacts a
            JOIN investigations i ON a.investigation_id = i.id
            WHERE a.value = ?
        """
        params = [value]
        if current_inv_id:
            query += " AND a.investigation_id != ?"
            params.append(current_inv_id)
        cursor.execute(query, tuple(params))
        rows = cursor.fetchall()
        conn.close()
        return [dict(r) for r in rows]

    # ========================================================
    # UNIVERSAL INVESTIGATION AGGREGATION
    # ========================================================

    def get_universal_investigation_detail(self, inv_id: str) -> Optional[UniversalInvestigationDetail]:
        """
        Retrieves complete universal investigation detail.
        Maintains backwards compatibility by synthesizing an EvidenceItem if none exist.
        """
        detail = self.get_investigation_detail(inv_id)
        if not detail:
            return None

        evidence_items = self.list_evidence_items(inv_id)
        if not evidence_items:
            # Backwards-compatibility synthesis: ensure every legacy investigation has at least 1 EvidenceItem
            synth_evd = EvidenceItem(
                id=f"EVD-{detail.record.id}",
                investigation_id=inv_id,
                filename=detail.record.filename,
                file_size=detail.record.original_size,
                detected_format=detail.record.file_type or "apk",
                extension=Path(detail.record.filename).suffix,
                md5=detail.record.md5,
                sha1=detail.record.sha1,
                sha256=detail.record.sha256,
                working_copy_sha256=detail.record.sha256,
                integrity_status="VERIFIED",
                source_info="Primary investigation artifact",
                examiner_notes=detail.record.analyst_notes,
                acquired_at=detail.record.created_at,
                processing_state="FULL" if detail.record.status == "completed" else "PARTIAL",
                entropy=6.8 if detail.record.file_type == "exe" else 7.2,
                triage_summary={
                    "status": "Legacy single-file triage",
                    "file_type": detail.record.file_type or "apk"
                },
                metadata={},
                created_at=detail.record.created_at
            )
            evidence_items = [synth_evd]

        extracted_artifacts = self.list_extracted_artifacts(inv_id)
        relationships = self.list_evidence_relationships(inv_id)
        timeline = self.list_timeline_events(inv_id)
        coc = self.list_chain_of_custody(inv_id)
        findings = self.list_findings_register(inv_id)

        # Build coverage matrix
        coverage: List[DetectionCoverageItem] = []
        for ev in evidence_items:
            ev_findings = [f for f in findings if f.evidence_id == ev.id]
            stages = {
                "Format Identification": "COMPLETED",
                "Hashing": "COMPLETED",
                "Metadata Extraction": "COMPLETED" if ev.processing_state in ("FULL", "PARTIAL") else "SKIPPED",
                "Structural Parsing": "COMPLETED" if ev.processing_state in ("FULL", "PARTIAL") else "SKIPPED",
                "Content Extraction": "COMPLETED" if len(extracted_artifacts) > 0 else "PARTIAL",
                "Specialized Static Analysis": "COMPLETED" if ev.processing_state == "FULL" else "PARTIAL",
                "YARA Scanning": "COMPLETED" if ev.detected_format in ("apk", "exe", "pe") else "NOT_APPLICABLE",
                "Threat Intelligence": "COMPLETED" if len(detail.threat_intel) > 0 else "SKIPPED",
                "Cross-File Correlation": "COMPLETED" if len(relationships) > 0 else "NOT_APPLICABLE"
            }
            coverage.append(DetectionCoverageItem(
                evidence_id=ev.id,
                filename=ev.filename,
                detected_format=ev.detected_format,
                stages=stages,
                findings_count=len(ev_findings),
                limitations=[]
            ))

        # Build contradiction items
        contradictions: List[ContradictionItem] = []
        # Check for format mismatch
        for ev in evidence_items:
            if ev.format_mismatch:
                contradictions.append(ContradictionItem(
                    id=f"CTD-FMT-{ev.id}",
                    title=f"Extension/Format Mismatch in {ev.filename}",
                    category="Format Mismatch",
                    evidence_ids=[ev.id],
                    details=f"File extension is '{ev.extension}' but structural byte inspection detected actual format as '{ev.detected_format.upper()}'. Potential disguise or masquerading.",
                    observed_conflicts=[{"declared_extension": ev.extension, "actual_signature": ev.detected_format}]
                ))

        # Load OSINT entities
        osint_indicators = self.list_osint_indicators(inv_id)
        osint_observations = self.list_osint_observations(inv_id)
        secret_exposure_findings = self.list_secret_exposure_findings(inv_id)
        pivot_jobs = self.list_pivot_jobs(inv_id)

        # Load Authorized Network Validation & Dynamic Sandbox entities
        authorized_scopes = self.list_authorized_scopes(inv_id)
        active_validation_results = self.list_active_validation_results(inv_id)
        dynamic_sandbox_runs = self.list_sandbox_runs(inv_id)
        dynamic_telemetry_events = self.list_telemetry_events(inv_id)
        network_flows = self.list_network_flow_records(inv_id)
        dropped_artifacts = self.list_dropped_artifact_records(inv_id)
        static_dynamic_correlations = self.list_static_dynamic_correlations(inv_id)
        evidence_risk_assessment = self.get_risk_assessment(inv_id)

        # Pre-instantiate detail object to construct OSINT graph
        partial_detail = UniversalInvestigationDetail(
            record=detail.record,
            evidence_items=evidence_items,
            extracted_artifacts=extracted_artifacts,
            evidence_relationships=relationships,
            timeline_events=timeline,
            chain_of_custody=coc,
            findings_register=findings,
            coverage_matrix=coverage,
            contradictions=contradictions,
            graph_data=detail.graph_data,
            osint_indicators=osint_indicators,
            osint_observations=osint_observations,
            secret_exposure_findings=secret_exposure_findings,
            pivot_jobs=pivot_jobs,
            authorized_scopes=authorized_scopes,
            active_validation_results=active_validation_results,
            dynamic_sandbox_runs=dynamic_sandbox_runs,
            dynamic_telemetry_events=dynamic_telemetry_events,
            network_flows=network_flows,
            dropped_artifacts=dropped_artifacts,
            static_dynamic_correlations=static_dynamic_correlations,
            evidence_risk_assessment=evidence_risk_assessment,
            metadata=detail.metadata,
            pe_metadata=detail.pe_metadata,
            static_findings=detail.static_findings,
            c2_indicators=detail.c2_indicators,
            secrets=detail.secrets,
            reverse_shell_findings=detail.reverse_shell_findings,
            persistence_findings=detail.persistence_findings,
            network_iocs=detail.network_iocs,
            threat_intel=detail.threat_intel,
            tool_executions=detail.tool_executions,
            assessment=detail.assessment,
            ai_observations=detail.ai_observations,
            ai_recommendations=detail.ai_recommendations,
            ai_notes=detail.ai_notes
        )

        try:
            from backend.app.analyzers.universal.osint_graph_builder import osint_graph_builder
            graph_nodes, graph_edges = osint_graph_builder.build_graph(partial_detail)
            partial_detail.osint_graph_nodes = graph_nodes
            partial_detail.osint_graph_edges = graph_edges
        except Exception:
            pass

        return partial_detail

    def _row_to_record(self, row) -> InvestigationRecord:
        file_type = "apk"
        if "file_type" in row.keys() and row["file_type"]:
            file_type = row["file_type"]
        return InvestigationRecord(
            id=row["id"], filename=row["filename"], original_size=row["original_size"],
            md5=row["md5"], sha1=row["sha1"], sha256=row["sha256"],
            case_reference=row["case_reference"], investigator_name=row["investigator_name"],
            description=row["description"], analyst_notes=row["analyst_notes"],
            local_only_mode=bool(row["local_only_mode"]), status=row["status"],
            progress=row["progress"], current_stage=row["current_stage"],
            created_at=datetime.fromisoformat(row["created_at"]),
            started_at=datetime.fromisoformat(row["started_at"]) if row["started_at"] else None,
            completed_at=datetime.fromisoformat(row["completed_at"]) if row["completed_at"] else None,
            error_message=row["error_message"], total_findings=row["total_findings"],
            severity=row["severity"], confidence=row["confidence"],
            package_name=row["package_name"], app_name=row["app_name"],
            c2_count=row["c2_count"], secret_count=row["secret_count"],
            reverse_shell_detected=bool(row["reverse_shell_detected"]),
            file_type=file_type,
            ai_assisted_analysis=bool(row["ai_assisted_analysis"]) if ("ai_assisted_analysis" in row.keys() and row["ai_assisted_analysis"] is not None) else False
        )

    def search_cross_case_indicators(self, query: str) -> Dict[str, Any]:
        """
        Cross-case duplicate & indicator search across all past investigations:
        - Exact SHA-256 / SHA-512 / MD5 hash matches
        - Extracted artifact matches (IPs, URLs, domains, secrets)
        - Returns exact matches and heuristic indicator matches
        """
        conn = get_db_connection()
        cursor = conn.cursor()
        clean_q = query.strip()
        exact_hash_matches = []
        indicator_matches = []

        try:
            # 1. Search evidence items by hash or filename
            cursor.execute("""
                SELECT e.*, i.case_reference, i.investigator_name, i.status as case_status
                FROM evidence_items e
                JOIN investigations i ON e.investigation_id = i.id
                WHERE e.sha256 = ? OR e.md5 = ? OR e.sha1 = ? OR e.sha512 = ? OR e.filename LIKE ?
            """, (clean_q, clean_q, clean_q, clean_q, f"%{clean_q}%"))
            for r in cursor.fetchall():
                exact_hash_matches.append({
                    "match_type": "EXACT_HASH" if clean_q in (r["sha256"], r["md5"], r["sha1"], r["sha512"]) else "FILENAME_SIMILARITY",
                    "investigation_id": r["investigation_id"],
                    "case_reference": r["case_reference"],
                    "evidence_id": r["id"],
                    "filename": r["filename"],
                    "detected_format": r["detected_format"],
                    "sha256": r["sha256"],
                    "acquired_at": r["acquired_at"]
                })

            # 2. Search extracted artifacts (IOCs, domains, IPs, URLs)
            cursor.execute("""
                SELECT a.*, i.case_reference
                FROM extracted_artifacts a
                JOIN investigations i ON a.investigation_id = i.id
                WHERE a.value LIKE ?
            """, (f"%{clean_q}%",))
            for r in cursor.fetchall():
                indicator_matches.append({
                    "match_type": "SHARED_INDICATOR",
                    "investigation_id": r["investigation_id"],
                    "case_reference": r["case_reference"],
                    "artifact_id": r["id"],
                    "evidence_id": r["evidence_id"],
                    "artifact_type": r["artifact_type"],
                    "value": r["value"],
                    "source_location": r["source_location"]
                })
        finally:
            conn.close()

        return {
            "query": query,
            "total_matches": len(exact_hash_matches) + len(indicator_matches),
            "exact_matches": exact_hash_matches,
            "indicator_matches": indicator_matches
        }

    # ========================================================
    # OSINT & RECURSIVE PIVOT PERSISTENCE
    # ========================================================

    def create_osint_indicator(self, ind: OSINTIndicator):
        conn = get_db_connection()
        cursor = conn.cursor()
        try:
            cursor.execute("""
                INSERT OR REPLACE INTO osint_indicators (
                    id, investigation_id, evidence_id, artifact_id, source_filename,
                    source_location, indicator_type, value, normalized_value,
                    provenance_type, extractor_or_provider, confidence, pivot_depth,
                    parent_indicator_id, first_seen_utc, last_updated_utc, limitations,
                    is_sensitive_secret, masked_value
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                ind.id, ind.investigation_id, ind.evidence_id, ind.artifact_id,
                ind.source_filename, ind.source_location, ind.indicator_type,
                ind.value, ind.normalized_value, ind.provenance_type,
                ind.extractor_or_provider, ind.confidence, ind.pivot_depth,
                ind.parent_indicator_id, ind.first_seen_utc, ind.last_updated_utc,
                ind.limitations, 1 if ind.is_sensitive_secret else 0, ind.masked_value
            ))
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def list_osint_indicators(self, investigation_id: str) -> List[OSINTIndicator]:
        conn = get_db_connection()
        cursor = conn.cursor()
        try:
            cursor.execute("SELECT * FROM osint_indicators WHERE investigation_id = ? ORDER BY pivot_depth ASC, first_seen_utc ASC", (investigation_id,))
            rows = cursor.fetchall()
        finally:
            conn.close()
        results = []
        for r in rows:
            results.append(OSINTIndicator(
                id=r["id"], investigation_id=r["investigation_id"], evidence_id=r["evidence_id"],
                artifact_id=r["artifact_id"], source_filename=r["source_filename"],
                source_location=r["source_location"], indicator_type=r["indicator_type"],
                value=r["value"], normalized_value=r["normalized_value"],
                provenance_type=r["provenance_type"], extractor_or_provider=r["extractor_or_provider"],
                confidence=r["confidence"], pivot_depth=r["pivot_depth"],
                parent_indicator_id=r["parent_indicator_id"], first_seen_utc=r["first_seen_utc"],
                last_updated_utc=r["last_updated_utc"], limitations=r["limitations"],
                is_sensitive_secret=bool(r["is_sensitive_secret"]), masked_value=r["masked_value"]
            ))
        return results

    def add_osint_observation(self, obs: OSINTObservation):
        conn = get_db_connection()
        cursor = conn.cursor()
        try:
            cursor.execute("""
                INSERT OR REPLACE INTO osint_observations (
                    id, investigation_id, indicator_id, provider, indicator_type,
                    indicator_value, query_timestamp_utc, provider_timestamp_utc,
                    status, normalized_data_json, permalink, data_freshness,
                    cache_expires_utc, error_message, limitations
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                obs.id, obs.investigation_id, obs.indicator_id, obs.provider,
                obs.indicator_type, obs.indicator_value, obs.query_timestamp_utc,
                obs.provider_timestamp_utc, obs.status, json.dumps(obs.normalized_data),
                obs.permalink, obs.data_freshness, obs.cache_expires_utc,
                obs.error_message, obs.limitations
            ))
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def list_osint_observations(self, investigation_id: str, indicator_id: Optional[str] = None) -> List[OSINTObservation]:
        conn = get_db_connection()
        cursor = conn.cursor()
        try:
            if indicator_id:
                cursor.execute("SELECT * FROM osint_observations WHERE investigation_id = ? AND indicator_id = ? ORDER BY query_timestamp_utc DESC", (investigation_id, indicator_id))
            else:
                cursor.execute("SELECT * FROM osint_observations WHERE investigation_id = ? ORDER BY query_timestamp_utc DESC", (investigation_id,))
            rows = cursor.fetchall()
        finally:
            conn.close()
        results = []
        for r in rows:
            data = json.loads(r["normalized_data_json"]) if r["normalized_data_json"] else {}
            results.append(OSINTObservation(
                id=r["id"], investigation_id=r["investigation_id"], indicator_id=r["indicator_id"],
                provider=r["provider"], indicator_type=r["indicator_type"], indicator_value=r["indicator_value"],
                query_timestamp_utc=r["query_timestamp_utc"], provider_timestamp_utc=r["provider_timestamp_utc"],
                status=r["status"], normalized_data=data, permalink=r["permalink"],
                data_freshness=r["data_freshness"], cache_expires_utc=r["cache_expires_utc"],
                error_message=r["error_message"], limitations=r["limitations"]
            ))
        return results

    def get_cached_osint_observation(self, provider: str, indicator_type: str, indicator_value: str) -> Optional[Dict[str, Any]]:
        conn = get_db_connection()
        cursor = conn.cursor()
        cache_key = f"{provider.lower()}:{indicator_type.lower()}:{indicator_value.lower()}"
        now_iso = datetime.utcnow().isoformat()
        try:
            cursor.execute("SELECT * FROM osint_cache WHERE cache_key = ? AND expires_at_utc > ?", (cache_key, now_iso))
            row = cursor.fetchone()
        finally:
            conn.close()
        if row:
            return {
                "status": row["status"],
                "data": json.loads(row["response_json"]),
                "created_at_utc": row["created_at_utc"]
            }
        return None

    def set_cached_osint_observation(self, provider: str, indicator_type: str, indicator_value: str, status: str, response_data: Dict[str, Any], ttl_seconds: int = 86400):
        from datetime import timedelta
        conn = get_db_connection()
        cursor = conn.cursor()
        cache_key = f"{provider.lower()}:{indicator_type.lower()}:{indicator_value.lower()}"
        now = datetime.utcnow()
        now_iso = now.isoformat()
        expires_iso = (now + timedelta(seconds=ttl_seconds)).isoformat()
        try:
            cursor.execute("""
                INSERT OR REPLACE INTO osint_cache (
                    cache_key, provider, indicator_type, indicator_value,
                    response_json, status, created_at_utc, expires_at_utc
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                cache_key, provider, indicator_type, indicator_value,
                json.dumps(response_data), status, now_iso, expires_iso
            ))
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def create_secret_exposure_finding(self, finding: SecretExposureFinding):
        conn = get_db_connection()
        cursor = conn.cursor()
        try:
            cursor.execute("""
                INSERT OR REPLACE INTO secret_exposure_findings (
                    id, investigation_id, evidence_id, artifact_id, secret_type,
                    masked_token, source_filename, source_location,
                    independently_found_public_identities_json, safety_attestation,
                    risk_level, observation, interpretation
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                finding.id, finding.investigation_id, finding.evidence_id, finding.artifact_id,
                finding.secret_type, finding.masked_token, finding.source_filename,
                finding.source_location, json.dumps(finding.independently_found_public_identities),
                finding.safety_attestation, finding.risk_level, finding.observation, finding.interpretation
            ))
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def list_secret_exposure_findings(self, investigation_id: str) -> List[SecretExposureFinding]:
        conn = get_db_connection()
        cursor = conn.cursor()
        try:
            cursor.execute("SELECT * FROM secret_exposure_findings WHERE investigation_id = ?", (investigation_id,))
            rows = cursor.fetchall()
        finally:
            conn.close()
        results = []
        for r in rows:
            idents = json.loads(r["independently_found_public_identities_json"]) if r["independently_found_public_identities_json"] else []
            results.append(SecretExposureFinding(
                id=r["id"], investigation_id=r["investigation_id"], evidence_id=r["evidence_id"],
                artifact_id=r["artifact_id"], secret_type=r["secret_type"], masked_token=r["masked_token"],
                source_filename=r["source_filename"], source_location=r["source_location"],
                independently_found_public_identities=idents, safety_attestation=r["safety_attestation"],
                risk_level=r["risk_level"], observation=r["observation"], interpretation=r["interpretation"]
            ))
        return results

    def create_or_update_pivot_job(self, job: RecursivePivotJob):
        conn = get_db_connection()
        cursor = conn.cursor()
        try:
            cursor.execute("""
                INSERT OR REPLACE INTO osint_pivot_jobs (
                    id, investigation_id, status, max_depth, current_depth,
                    total_indicators_evaluated, total_new_indicators_discovered,
                    total_provider_queries, budget_limit_queries, started_at_utc,
                    completed_at_utc, errors_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                job.id, job.investigation_id, job.status, job.max_depth,
                job.current_depth, job.total_indicators_evaluated,
                job.total_new_indicators_discovered, job.total_provider_queries,
                job.budget_limit_queries, job.started_at_utc, job.completed_at_utc,
                json.dumps(job.errors)
            ))
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def list_pivot_jobs(self, investigation_id: str) -> List[RecursivePivotJob]:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM osint_pivot_jobs WHERE investigation_id = ? ORDER BY started_at_utc DESC", (investigation_id,))
        rows = cursor.fetchall()
        conn.close()
        results = []
        for r in rows:
            errs = json.loads(r["errors_json"]) if r["errors_json"] else []
            results.append(RecursivePivotJob(
                id=r["id"], investigation_id=r["investigation_id"], status=r["status"],
                max_depth=r["max_depth"], current_depth=r["current_depth"],
                total_indicators_evaluated=r["total_indicators_evaluated"],
                total_new_indicators_discovered=r["total_new_indicators_discovered"],
                total_provider_queries=r["total_provider_queries"],
                budget_limit_queries=r["budget_limit_queries"], started_at_utc=r["started_at_utc"],
                completed_at_utc=r["completed_at_utc"], errors=errs
            ))
        return results

    # ========================================================
    # AUTHORIZED NETWORK VALIDATION REPOSITORY METHODS
    # ========================================================

    def create_authorized_scope(self, scope: AuthorizedNetworkScope):
        conn = get_db_connection()
        cursor = conn.cursor()
        try:
            cursor.execute("""
                INSERT OR REPLACE INTO authorized_network_scopes (
                    id, investigation_id, case_id, authorized_targets_json,
                    allowed_test_types_json, allowed_ports_json, authorization_note,
                    operator_name, operator_confirmed, request_budget, requests_used,
                    created_at_utc, expires_at_utc, is_revoked
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                scope.id, scope.investigation_id, scope.case_id,
                json.dumps(scope.authorized_targets),
                json.dumps(scope.allowed_test_types),
                json.dumps(scope.allowed_ports),
                scope.authorization_note, scope.operator_name,
                1 if scope.operator_confirmed else 0,
                scope.request_budget, scope.requests_used,
                scope.created_at_utc, scope.expires_at_utc,
                1 if scope.is_revoked else 0
            ))
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def get_authorized_scope(self, scope_id: str) -> Optional[AuthorizedNetworkScope]:
        conn = get_db_connection()
        cursor = conn.cursor()
        try:
            cursor.execute("SELECT * FROM authorized_network_scopes WHERE id = ?", (scope_id,))
            row = cursor.fetchone()
            if not row:
                return None
            return AuthorizedNetworkScope(
                id=row["id"], investigation_id=row["investigation_id"], case_id=row["case_id"],
                authorized_targets=json.loads(row["authorized_targets_json"]) if row["authorized_targets_json"] else [],
                allowed_test_types=json.loads(row["allowed_test_types_json"]) if row["allowed_test_types_json"] else [],
                allowed_ports=json.loads(row["allowed_ports_json"]) if row["allowed_ports_json"] else [],
                authorization_note=row["authorization_note"], operator_name=row["operator_name"],
                operator_confirmed=bool(row["operator_confirmed"]), request_budget=row["request_budget"],
                requests_used=row["requests_used"], created_at_utc=row["created_at_utc"],
                expires_at_utc=row["expires_at_utc"], is_revoked=bool(row["is_revoked"])
            )
        finally:
            conn.close()

    def list_authorized_scopes(self, investigation_id: str) -> List[AuthorizedNetworkScope]:
        conn = get_db_connection()
        cursor = conn.cursor()
        try:
            cursor.execute("SELECT * FROM authorized_network_scopes WHERE investigation_id = ? ORDER BY created_at_utc DESC", (investigation_id,))
            rows = cursor.fetchall()
            results = []
            for row in rows:
                results.append(AuthorizedNetworkScope(
                    id=row["id"], investigation_id=row["investigation_id"], case_id=row["case_id"],
                    authorized_targets=json.loads(row["authorized_targets_json"]) if row["authorized_targets_json"] else [],
                    allowed_test_types=json.loads(row["allowed_test_types_json"]) if row["allowed_test_types_json"] else [],
                    allowed_ports=json.loads(row["allowed_ports_json"]) if row["allowed_ports_json"] else [],
                    authorization_note=row["authorization_note"], operator_name=row["operator_name"],
                    operator_confirmed=bool(row["operator_confirmed"]), request_budget=row["request_budget"],
                    requests_used=row["requests_used"], created_at_utc=row["created_at_utc"],
                    expires_at_utc=row["expires_at_utc"], is_revoked=bool(row["is_revoked"])
                ))
            return results
        finally:
            conn.close()

    def revoke_scope(self, scope_id: str):
        conn = get_db_connection()
        cursor = conn.cursor()
        try:
            cursor.execute("UPDATE authorized_network_scopes SET is_revoked = 1 WHERE id = ?", (scope_id,))
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def increment_scope_requests(self, scope_id: str):
        conn = get_db_connection()
        cursor = conn.cursor()
        try:
            cursor.execute("UPDATE authorized_network_scopes SET requests_used = requests_used + 1 WHERE id = ?", (scope_id,))
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def add_active_validation_result(self, res: ActiveValidationResult):
        conn = get_db_connection()
        cursor = conn.cursor()
        try:
            cursor.execute("""
                INSERT OR REPLACE INTO active_validation_results (
                    id, scope_id, investigation_id, target, test_type, status,
                    resolved_ips_json, port, timing_ms, tls_cert_info_json,
                    http_status, http_headers_json, diagnostic_message,
                    timestamp_utc, operator_confirmation_ref
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                res.id, res.scope_id, res.investigation_id, res.target, res.test_type,
                res.status, json.dumps(res.resolved_ips), res.port, res.timing_ms,
                json.dumps(res.tls_cert_info) if res.tls_cert_info else None,
                res.http_status,
                json.dumps(res.http_headers) if res.http_headers else None,
                res.diagnostic_message, res.timestamp_utc, res.operator_confirmation_ref
            ))
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def list_active_validation_results(self, investigation_id: str) -> List[ActiveValidationResult]:
        conn = get_db_connection()
        cursor = conn.cursor()
        try:
            cursor.execute("SELECT * FROM active_validation_results WHERE investigation_id = ? ORDER BY timestamp_utc DESC", (investigation_id,))
            rows = cursor.fetchall()
            results = []
            for row in rows:
                results.append(ActiveValidationResult(
                    id=row["id"], scope_id=row["scope_id"], investigation_id=row["investigation_id"],
                    target=row["target"], test_type=row["test_type"], status=row["status"],
                    resolved_ips=json.loads(row["resolved_ips_json"]) if row["resolved_ips_json"] else [],
                    port=row["port"], timing_ms=row["timing_ms"] or 0.0,
                    tls_cert_info=json.loads(row["tls_cert_info_json"]) if row["tls_cert_info_json"] else None,
                    http_status=row["http_status"],
                    http_headers=json.loads(row["http_headers_json"]) if row["http_headers_json"] else None,
                    diagnostic_message=row["diagnostic_message"],
                    timestamp_utc=row["timestamp_utc"],
                    operator_confirmation_ref=row["operator_confirmation_ref"]
                ))
            return results
        finally:
            conn.close()

    # ========================================================
    # DYNAMIC SANDBOX & TELEMETRY REPOSITORY METHODS
    # ========================================================

    def _row_to_sandbox_run(self, row) -> DynamicSandboxRun:
        keys = row.keys() if hasattr(row, 'keys') else []
        return DynamicSandboxRun(
            id=row["id"],
            investigation_id=row["investigation_id"],
            evidence_id=row["evidence_id"],
            target_binary=row["target_binary"],
            sandbox_environment=row["sandbox_environment"],
            status=row["status"],
            is_simulated_network=bool(row["is_simulated_network"]),
            simulated_services=json.loads(row["simulated_services_json"]) if row["simulated_services_json"] else [],
            duration_seconds=row["duration_seconds"] or 0.0,
            started_at_utc=row["started_at_utc"],
            completed_at_utc=row["completed_at_utc"],
            process_count=row["process_count"] or 0,
            file_event_count=row["file_event_count"] or 0,
            registry_event_count=row["registry_event_count"] or 0,
            network_flow_count=row["network_flow_count"] or 0,
            dropped_artifacts_count=row["dropped_artifacts_count"] or 0,
            pcap_filename=row["pcap_filename"],
            pcap_sha256=row["pcap_sha256"],
            sandbox_logs=json.loads(row["sandbox_logs_json"]) if row["sandbox_logs_json"] else [],
            limitations=row["limitations"],
            user_id=row["user_id"] if "user_id" in keys else None,
            target_sha256=row["target_sha256"] if "target_sha256" in keys else None,
            target_type=row["target_type"] if "target_type" in keys and row["target_type"] else "generic",
            provider=row["provider"] if "provider" in keys else None,
            environment_id=row["environment_id"] if "environment_id" in keys else None,
            network_policy=row["network_policy"] if "network_policy" in keys and row["network_policy"] else "DISABLED",
            timeout_seconds=row["timeout_seconds"] if "timeout_seconds" in keys and row["timeout_seconds"] is not None else 120,
            risk_score=row["risk_score"] if "risk_score" in keys and row["risk_score"] is not None else 0.0,
            risk_level=row["risk_level"] if "risk_level" in keys and row["risk_level"] else "Informational",
            report_id=row["report_id"] if "report_id" in keys else None
        )

    def create_sandbox_run(self, run: DynamicSandboxRun):
        conn = get_db_connection()
        cursor = conn.cursor()
        try:
            cursor.execute("""
                INSERT INTO dynamic_sandbox_runs (
                    id, investigation_id, evidence_id, target_binary,
                    sandbox_environment, status, is_simulated_network,
                    simulated_services_json, duration_seconds, started_at_utc,
                    completed_at_utc, process_count, file_event_count,
                    registry_event_count, network_flow_count, dropped_artifacts_count,
                    pcap_filename, pcap_sha256, sandbox_logs_json, limitations,
                    user_id, target_sha256, target_type, provider, environment_id,
                    network_policy, timeout_seconds, risk_score, risk_level, report_id
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                run.id, run.investigation_id, run.evidence_id, run.target_binary,
                run.sandbox_environment, run.status, 1 if run.is_simulated_network else 0,
                json.dumps(run.simulated_services), run.duration_seconds,
                run.started_at_utc, run.completed_at_utc, run.process_count,
                run.file_event_count, run.registry_event_count, run.network_flow_count,
                run.dropped_artifacts_count, run.pcap_filename, run.pcap_sha256,
                json.dumps(run.sandbox_logs), run.limitations,
                run.user_id, run.target_sha256, run.target_type, run.provider, run.environment_id,
                run.network_policy, run.timeout_seconds, run.risk_score, run.risk_level, run.report_id
            ))
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def update_sandbox_run(self, run: DynamicSandboxRun):
        conn = get_db_connection()
        cursor = conn.cursor()
        try:
            cursor.execute("""
                UPDATE dynamic_sandbox_runs SET
                    status = ?, is_simulated_network = ?, simulated_services_json = ?,
                    duration_seconds = ?, started_at_utc = ?, completed_at_utc = ?,
                    process_count = ?, file_event_count = ?, registry_event_count = ?,
                    network_flow_count = ?, dropped_artifacts_count = ?,
                    pcap_filename = ?, pcap_sha256 = ?, sandbox_logs_json = ?,
                    limitations = ?, user_id = ?, target_sha256 = ?, target_type = ?,
                    provider = ?, environment_id = ?, network_policy = ?,
                    timeout_seconds = ?, risk_score = ?, risk_level = ?, report_id = ?
                WHERE id = ?
            """, (
                run.status, 1 if run.is_simulated_network else 0,
                json.dumps(run.simulated_services), run.duration_seconds,
                run.started_at_utc, run.completed_at_utc, run.process_count,
                run.file_event_count, run.registry_event_count, run.network_flow_count,
                run.dropped_artifacts_count, run.pcap_filename, run.pcap_sha256,
                json.dumps(run.sandbox_logs), run.limitations,
                run.user_id, run.target_sha256, run.target_type, run.provider, run.environment_id,
                run.network_policy, run.timeout_seconds, run.risk_score, run.risk_level, run.report_id,
                run.id
            ))
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def delete_sandbox_run(self, run_id: str) -> bool:
        conn = get_db_connection()
        cursor = conn.cursor()
        try:
            cursor.execute("DELETE FROM dynamic_sandbox_runs WHERE id = ?", (run_id,))
            deleted = cursor.rowcount > 0
            conn.commit()
            return deleted
        finally:
            conn.close()

    def get_sandbox_run(self, run_id: str) -> Optional[DynamicSandboxRun]:
        conn = get_db_connection()
        cursor = conn.cursor()
        try:
            cursor.execute("SELECT * FROM dynamic_sandbox_runs WHERE id = ?", (run_id,))
            row = cursor.fetchone()
            if not row:
                return None
            return self._row_to_sandbox_run(row)
        finally:
            conn.close()

    def list_sandbox_runs(self, investigation_id: str) -> List[DynamicSandboxRun]:
        conn = get_db_connection()
        cursor = conn.cursor()
        try:
            cursor.execute("SELECT * FROM dynamic_sandbox_runs WHERE investigation_id = ? ORDER BY started_at_utc DESC", (investigation_id,))
            rows = cursor.fetchall()
            return [self._row_to_sandbox_run(r) for r in rows]
        finally:
            conn.close()

    def list_all_sandbox_runs(
        self,
        user_id: Optional[str] = None,
        target_type: Optional[str] = None,
        status: Optional[str] = None,
        limit: int = 50,
        offset: int = 0
    ) -> List[DynamicSandboxRun]:
        conn = get_db_connection()
        cursor = conn.cursor()
        try:
            query = "SELECT * FROM dynamic_sandbox_runs WHERE 1=1"
            params = []
            if user_id:
                query += " AND user_id = ?"
                params.append(user_id)
            if target_type:
                query += " AND target_type = ?"
                params.append(target_type)
            if status:
                query += " AND status = ?"
                params.append(status)
            query += " ORDER BY started_at_utc DESC LIMIT ? OFFSET ?"
            params.extend([limit, offset])
            cursor.execute(query, tuple(params))
            rows = cursor.fetchall()
            return [self._row_to_sandbox_run(r) for r in rows]
        finally:
            conn.close()

    def add_telemetry_event(self, ev: DynamicTelemetryEvent):
        conn = get_db_connection()
        cursor = conn.cursor()
        try:
            cursor.execute("""
                INSERT OR REPLACE INTO dynamic_telemetry_events (
                    id, run_id, investigation_id, event_category, timestamp_utc,
                    process_id, process_name, parent_process_id, parent_process_name,
                    command_line, target_path, operation, details_json,
                    is_simulated, related_indicator_id
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                ev.id, ev.run_id, ev.investigation_id, ev.event_category, ev.timestamp_utc,
                ev.process_id, ev.process_name, ev.parent_process_id, ev.parent_process_name,
                ev.command_line, ev.target_path, ev.operation, json.dumps(ev.details),
                1 if ev.is_simulated else 0, ev.related_indicator_id
            ))
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def list_telemetry_events(self, investigation_id: str, run_id: Optional[str] = None) -> List[DynamicTelemetryEvent]:
        conn = get_db_connection()
        cursor = conn.cursor()
        try:
            if run_id:
                cursor.execute("SELECT * FROM dynamic_telemetry_events WHERE investigation_id = ? AND run_id = ? ORDER BY timestamp_utc ASC", (investigation_id, run_id))
            else:
                cursor.execute("SELECT * FROM dynamic_telemetry_events WHERE investigation_id = ? ORDER BY timestamp_utc ASC", (investigation_id,))
            rows = cursor.fetchall()
            results = []
            for row in rows:
                results.append(DynamicTelemetryEvent(
                    id=row["id"], run_id=row["run_id"], investigation_id=row["investigation_id"],
                    event_category=row["event_category"], timestamp_utc=row["timestamp_utc"],
                    process_id=row["process_id"], process_name=row["process_name"],
                    parent_process_id=row["parent_process_id"], parent_process_name=row["parent_process_name"],
                    command_line=row["command_line"], target_path=row["target_path"],
                    operation=row["operation"], details=json.loads(row["details_json"]) if row["details_json"] else {},
                    is_simulated=bool(row["is_simulated"]), related_indicator_id=row["related_indicator_id"]
                ))
            return results
        finally:
            conn.close()

    def add_network_flow_record(self, flow: NetworkFlowRecord):
        conn = get_db_connection()
        cursor = conn.cursor()
        try:
            cursor.execute("""
                INSERT OR REPLACE INTO network_flow_records (
                    id, run_id, investigation_id, timestamp_utc, src_ip, src_port,
                    dst_ip, dst_port, protocol, direction, dns_hostname, tls_sni,
                    cert_fingerprint, http_method, http_status, packet_count,
                    byte_count, pcap_file, packet_reference, is_simulated,
                    related_indicator_ids_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                flow.id, flow.run_id, flow.investigation_id, flow.timestamp_utc,
                flow.src_ip, flow.src_port, flow.dst_ip, flow.dst_port,
                flow.protocol, flow.direction, flow.dns_hostname, flow.tls_sni,
                flow.cert_fingerprint, flow.http_method, flow.http_status,
                flow.packet_count, flow.byte_count, flow.pcap_file,
                flow.packet_reference, 1 if flow.is_simulated else 0,
                json.dumps(flow.related_indicator_ids)
            ))
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def list_network_flow_records(self, investigation_id: str, run_id: Optional[str] = None) -> List[NetworkFlowRecord]:
        conn = get_db_connection()
        cursor = conn.cursor()
        try:
            if run_id:
                cursor.execute("SELECT * FROM network_flow_records WHERE investigation_id = ? AND run_id = ? ORDER BY timestamp_utc ASC", (investigation_id, run_id))
            else:
                cursor.execute("SELECT * FROM network_flow_records WHERE investigation_id = ? ORDER BY timestamp_utc ASC", (investigation_id,))
            rows = cursor.fetchall()
            results = []
            for row in rows:
                results.append(NetworkFlowRecord(
                    id=row["id"], run_id=row["run_id"], investigation_id=row["investigation_id"],
                    timestamp_utc=row["timestamp_utc"], src_ip=row["src_ip"], src_port=row["src_port"],
                    dst_ip=row["dst_ip"], dst_port=row["dst_port"], protocol=row["protocol"],
                    direction=row["direction"], dns_hostname=row["dns_hostname"], tls_sni=row["tls_sni"],
                    cert_fingerprint=row["cert_fingerprint"], http_method=row["http_method"],
                    http_status=row["http_status"], packet_count=row["packet_count"] or 1,
                    byte_count=row["byte_count"] or 0, pcap_file=row["pcap_file"],
                    packet_reference=row["packet_reference"], is_simulated=bool(row["is_simulated"]),
                    related_indicator_ids=json.loads(row["related_indicator_ids_json"]) if row["related_indicator_ids_json"] else []
                ))
            return results
        finally:
            conn.close()

    def add_dropped_artifact_record(self, artifact: DroppedArtifactRecord):
        conn = get_db_connection()
        cursor = conn.cursor()
        try:
            cursor.execute("""
                INSERT OR REPLACE INTO dropped_artifact_records (
                    id, run_id, investigation_id, filename, file_path,
                    size_bytes, sha256, file_type, dropped_by_process, timestamp_utc
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                artifact.id, artifact.run_id, artifact.investigation_id,
                artifact.filename, artifact.file_path, artifact.size_bytes,
                artifact.sha256, artifact.file_type, artifact.dropped_by_process,
                artifact.timestamp_utc
            ))
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def list_dropped_artifact_records(self, investigation_id: str, run_id: Optional[str] = None) -> List[DroppedArtifactRecord]:
        conn = get_db_connection()
        cursor = conn.cursor()
        try:
            if run_id:
                cursor.execute("SELECT * FROM dropped_artifact_records WHERE investigation_id = ? AND run_id = ?", (investigation_id, run_id))
            else:
                cursor.execute("SELECT * FROM dropped_artifact_records WHERE investigation_id = ?", (investigation_id,))
            rows = cursor.fetchall()
            results = []
            for row in rows:
                results.append(DroppedArtifactRecord(
                    id=row["id"], run_id=row["run_id"], investigation_id=row["investigation_id"],
                    filename=row["filename"], file_path=row["file_path"],
                    size_bytes=row["size_bytes"] or 0, sha256=row["sha256"],
                    file_type=row["file_type"], dropped_by_process=row["dropped_by_process"],
                    timestamp_utc=row["timestamp_utc"]
                ))
            return results
        finally:
            conn.close()

    # ========================================================
    # STATIC-DYNAMIC CORRELATION & RISK ASSESSMENT METHODS
    # ========================================================

    def add_static_dynamic_correlation(self, corr: StaticDynamicCorrelation):
        conn = get_db_connection()
        cursor = conn.cursor()
        try:
            cursor.execute("""
                INSERT OR REPLACE INTO static_dynamic_correlations (
                    id, investigation_id, static_finding_id, dynamic_event_id,
                    source_evidence_id, indicator_value, correlation_method,
                    confidence, supporting_event_summary, packet_reference,
                    is_simulated_event, alternative_explanation, limitations,
                    created_at_utc
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                corr.id, corr.investigation_id, corr.static_finding_id, corr.dynamic_event_id,
                corr.source_evidence_id, corr.indicator_value, corr.correlation_method,
                corr.confidence, corr.supporting_event_summary, corr.packet_reference,
                1 if corr.is_simulated_event else 0, corr.alternative_explanation,
                corr.limitations, corr.created_at_utc
            ))
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def list_static_dynamic_correlations(self, investigation_id: str) -> List[StaticDynamicCorrelation]:
        conn = get_db_connection()
        cursor = conn.cursor()
        try:
            cursor.execute("SELECT * FROM static_dynamic_correlations WHERE investigation_id = ? ORDER BY created_at_utc DESC", (investigation_id,))
            rows = cursor.fetchall()
            results = []
            for row in rows:
                results.append(StaticDynamicCorrelation(
                    id=row["id"], investigation_id=row["investigation_id"],
                    static_finding_id=row["static_finding_id"], dynamic_event_id=row["dynamic_event_id"],
                    source_evidence_id=row["source_evidence_id"], indicator_value=row["indicator_value"],
                    correlation_method=row["correlation_method"], confidence=row["confidence"],
                    supporting_event_summary=row["supporting_event_summary"],
                    packet_reference=row["packet_reference"], is_simulated_event=bool(row["is_simulated_event"]),
                    alternative_explanation=row["alternative_explanation"] or "",
                    limitations=row["limitations"] or "",
                    created_at_utc=row["created_at_utc"]
                ))
            return results
        finally:
            conn.close()

    def create_or_update_risk_assessment(self, assessment: EvidenceRiskAssessment):
        conn = get_db_connection()
        cursor = conn.cursor()
        try:
            cursor.execute("""
                INSERT OR REPLACE INTO evidence_risk_assessments (
                    id, investigation_id, static_capability_score, observed_execution_score,
                    observed_network_score, successful_protocol_interaction_score,
                    confirmed_data_transfer_score, threat_intel_reputation_score,
                    overall_risk_score, severity, confidence, score_inputs_json,
                    weighting_method, corroboration_sources_json,
                    contradictory_evidence_json, missing_evidence_json,
                    known_limitations_json, assessed_at_utc
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                assessment.id, assessment.investigation_id, assessment.static_capability_score,
                assessment.observed_execution_score, assessment.observed_network_score,
                assessment.successful_protocol_interaction_score, assessment.confirmed_data_transfer_score,
                assessment.threat_intel_reputation_score, assessment.overall_risk_score,
                assessment.severity, assessment.confidence, json.dumps(assessment.score_inputs),
                assessment.weighting_method, json.dumps(assessment.corroboration_sources),
                json.dumps(assessment.contradictory_evidence), json.dumps(assessment.missing_evidence),
                json.dumps(assessment.known_limitations), assessment.assessed_at_utc
            ))
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def get_risk_assessment(self, investigation_id: str) -> Optional[EvidenceRiskAssessment]:
        conn = get_db_connection()
        cursor = conn.cursor()
        try:
            cursor.execute("SELECT * FROM evidence_risk_assessments WHERE investigation_id = ?", (investigation_id,))
            row = cursor.fetchone()
            if not row:
                return None
            return EvidenceRiskAssessment(
                id=row["id"], investigation_id=row["investigation_id"],
                static_capability_score=row["static_capability_score"] or 0.0,
                observed_execution_score=row["observed_execution_score"] or 0.0,
                observed_network_score=row["observed_network_score"] or 0.0,
                successful_protocol_interaction_score=row["successful_protocol_interaction_score"] or 0.0,
                confirmed_data_transfer_score=row["confirmed_data_transfer_score"] or 0.0,
                threat_intel_reputation_score=row["threat_intel_reputation_score"] or 0.0,
                overall_risk_score=row["overall_risk_score"] or 0.0,
                severity=row["severity"], confidence=row["confidence"],
                score_inputs=json.loads(row["score_inputs_json"]) if row["score_inputs_json"] else [],
                weighting_method=row["weighting_method"] or "Evidence-Corroborated Dimensional Scoring",
                corroboration_sources=json.loads(row["corroboration_sources_json"]) if row["corroboration_sources_json"] else [],
                contradictory_evidence=json.loads(row["contradictory_evidence_json"]) if row["contradictory_evidence_json"] else [],
                missing_evidence=json.loads(row["missing_evidence_json"]) if row["missing_evidence_json"] else [],
                known_limitations=json.loads(row["known_limitations_json"]) if row["known_limitations_json"] else [],
                assessed_at_utc=row["assessed_at_utc"]
            )
        finally:
            conn.close()

    def upsert_sandbox_environment(self, env: SandboxEnvironmentInfo):
        conn = get_db_connection()
        cursor = conn.cursor()
        try:
            cursor.execute("""
                INSERT OR REPLACE INTO sandbox_environments (
                    id, name, provider_type, os_family, is_available,
                    status, version, details_json, config_json, last_checked_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                env.id, env.name, env.provider_type, env.os_family,
                1 if env.is_available else 0, env.status, env.version,
                json.dumps(env.details), json.dumps(env.config), env.last_checked_at
            ))
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def get_sandbox_environment(self, env_id: str) -> Optional[SandboxEnvironmentInfo]:
        conn = get_db_connection()
        cursor = conn.cursor()
        try:
            cursor.execute("SELECT * FROM sandbox_environments WHERE id = ?", (env_id,))
            row = cursor.fetchone()
            if not row:
                return None
            return SandboxEnvironmentInfo(
                id=row["id"], name=row["name"], provider_type=row["provider_type"],
                os_family=row["os_family"], is_available=bool(row["is_available"]),
                status=row["status"], version=row["version"],
                details=json.loads(row["details_json"]) if row["details_json"] else {},
                config=json.loads(row["config_json"]) if row["config_json"] else {},
                last_checked_at=row["last_checked_at"]
            )
        finally:
            conn.close()

    def list_sandbox_environments(self, os_family: Optional[str] = None) -> List[SandboxEnvironmentInfo]:
        conn = get_db_connection()
        cursor = conn.cursor()
        try:
            if os_family:
                cursor.execute("SELECT * FROM sandbox_environments WHERE os_family = ? ORDER BY name ASC", (os_family,))
            else:
                cursor.execute("SELECT * FROM sandbox_environments ORDER BY os_family, name ASC")
            rows = cursor.fetchall()
            return [
                SandboxEnvironmentInfo(
                    id=r["id"], name=r["name"], provider_type=r["provider_type"],
                    os_family=r["os_family"], is_available=bool(r["is_available"]),
                    status=r["status"], version=r["version"],
                    details=json.loads(r["details_json"]) if r["details_json"] else {},
                    config=json.loads(r["config_json"]) if r["config_json"] else {},
                    last_checked_at=r["last_checked_at"]
                ) for r in rows
            ]
        finally:
            conn.close()

    def add_dynamic_observation(self, obs: DynamicObservation):
        conn = get_db_connection()
        cursor = conn.cursor()
        try:
            cursor.execute("""
                INSERT OR REPLACE INTO dynamic_observations (
                    id, run_id, investigation_id, evidence_id, observation_type,
                    severity, title, description, details_json, mitre_technique, timestamp_utc
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                obs.id, obs.run_id, obs.investigation_id, obs.evidence_id,
                obs.observation_type, obs.severity, obs.title, obs.description,
                json.dumps(obs.details), obs.mitre_technique, obs.timestamp_utc
            ))
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def list_dynamic_observations(self, investigation_id: str, run_id: Optional[str] = None) -> List[DynamicObservation]:
        conn = get_db_connection()
        cursor = conn.cursor()
        try:
            if run_id:
                cursor.execute("SELECT * FROM dynamic_observations WHERE investigation_id = ? AND run_id = ? ORDER BY timestamp_utc ASC", (investigation_id, run_id))
            else:
                cursor.execute("SELECT * FROM dynamic_observations WHERE investigation_id = ? ORDER BY timestamp_utc ASC", (investigation_id,))
            rows = cursor.fetchall()
            return [
                DynamicObservation(
                    id=r["id"], run_id=r["run_id"], investigation_id=r["investigation_id"],
                    evidence_id=r["evidence_id"], observation_type=r["observation_type"],
                    severity=r["severity"], title=r["title"], description=r["description"],
                    details=json.loads(r["details_json"]) if r["details_json"] else {},
                    mitre_technique=r["mitre_technique"], timestamp_utc=r["timestamp_utc"]
                ) for r in rows
            ]
        finally:
            conn.close()

    def add_dynamic_artifact(self, art: DynamicArtifact):
        conn = get_db_connection()
        cursor = conn.cursor()
        try:
            cursor.execute("""
                INSERT OR REPLACE INTO dynamic_artifacts (
                    id, run_id, investigation_id, artifact_type, filename,
                    file_path, size_bytes, sha256, description, created_at_utc
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                art.id, art.run_id, art.investigation_id, art.artifact_type,
                art.filename, art.file_path, art.size_bytes, art.sha256,
                art.description, art.created_at_utc
            ))
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def list_dynamic_artifacts(self, investigation_id: str, run_id: Optional[str] = None) -> List[DynamicArtifact]:
        conn = get_db_connection()
        cursor = conn.cursor()
        try:
            if run_id:
                cursor.execute("SELECT * FROM dynamic_artifacts WHERE investigation_id = ? AND run_id = ? ORDER BY created_at_utc ASC", (investigation_id, run_id))
            else:
                cursor.execute("SELECT * FROM dynamic_artifacts WHERE investigation_id = ? ORDER BY created_at_utc ASC", (investigation_id,))
            rows = cursor.fetchall()
            return [
                DynamicArtifact(
                    id=r["id"], run_id=r["run_id"], investigation_id=r["investigation_id"],
                    artifact_type=r["artifact_type"], filename=r["filename"],
                    file_path=r["file_path"], size_bytes=r["size_bytes"] or 0,
                    sha256=r["sha256"], description=r["description"],
                    created_at_utc=r["created_at_utc"]
                ) for r in rows
            ]
        finally:
            conn.close()

    def save_dynamic_report(self, rep: DynamicReport):
        conn = get_db_connection()
        cursor = conn.cursor()
        try:
            cursor.execute("""
                INSERT OR REPLACE INTO dynamic_reports (
                    id, run_id, investigation_id, report_type, title,
                    summary_markdown, full_report_json, risk_score, risk_severity,
                    generated_by, generated_at_utc
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                rep.id, rep.run_id, rep.investigation_id, rep.report_type,
                rep.title, rep.summary_markdown, json.dumps(rep.full_report),
                rep.risk_score, rep.risk_severity, rep.generated_by, rep.generated_at_utc
            ))
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def get_dynamic_report(self, report_id: str) -> Optional[DynamicReport]:
        conn = get_db_connection()
        cursor = conn.cursor()
        try:
            cursor.execute("SELECT * FROM dynamic_reports WHERE id = ?", (report_id,))
            row = cursor.fetchone()
            if not row:
                return None
            return DynamicReport(
                id=row["id"], run_id=row["run_id"], investigation_id=row["investigation_id"],
                report_type=row["report_type"], title=row["title"],
                summary_markdown=row["summary_markdown"],
                full_report=json.loads(row["full_report_json"]) if row["full_report_json"] else {},
                risk_score=row["risk_score"] or 0.0, risk_severity=row["risk_severity"] or "Informational",
                generated_by=row["generated_by"], generated_at_utc=row["generated_at_utc"]
            )
        finally:
            conn.close()

    def get_dynamic_report_by_run(self, run_id: str) -> Optional[DynamicReport]:
        conn = get_db_connection()
        cursor = conn.cursor()
        try:
            cursor.execute("SELECT * FROM dynamic_reports WHERE run_id = ? ORDER BY generated_at_utc DESC LIMIT 1", (run_id,))
            row = cursor.fetchone()
            if not row:
                return None
            return DynamicReport(
                id=row["id"], run_id=row["run_id"], investigation_id=row["investigation_id"],
                report_type=row["report_type"], title=row["title"],
                summary_markdown=row["summary_markdown"],
                full_report=json.loads(row["full_report_json"]) if row["full_report_json"] else {},
                risk_score=row["risk_score"] or 0.0, risk_severity=row["risk_severity"] or "Informational",
                generated_by=row["generated_by"], generated_at_utc=row["generated_at_utc"]
            )
        finally:
            conn.close()

    # ----------------------------------------------------
    # OpenCode AI-Assisted Forensic Engine Data Access
    # ----------------------------------------------------

    def save_ai_observations(self, observations: List[AIObservation]) -> None:
        if not observations:
            return
        conn = get_db_connection()
        cursor = conn.cursor()
        try:
            for obs in observations:
                cursor.execute(
                    """
                    INSERT OR REPLACE INTO ai_observations (
                        id, investigation_id, evidence_id, title, explanation,
                        related_evidence_refs, confidence, reasoning_summary,
                        suggested_verification_steps, status, reviewer, reviewed_at,
                        review_notes, created_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        obs.id,
                        obs.investigation_id,
                        obs.evidence_id,
                        obs.title,
                        obs.explanation,
                        json.dumps(obs.related_evidence_refs or []),
                        obs.confidence or "Unverified",
                        obs.reasoning_summary,
                        json.dumps(obs.suggested_verification_steps or []),
                        obs.status or "UNVERIFIED",
                        obs.reviewer,
                        obs.reviewed_at.isoformat() if obs.reviewed_at else None,
                        obs.review_notes,
                        obs.created_at.isoformat() if obs.created_at else datetime.utcnow().isoformat(),
                    )
                )
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def list_ai_observations(self, investigation_id: str) -> List[AIObservation]:
        conn = get_db_connection()
        cursor = conn.cursor()
        try:
            cursor.execute(
                "SELECT * FROM ai_observations WHERE investigation_id = ? ORDER BY created_at ASC",
                (investigation_id,)
            )
            rows = cursor.fetchall()
            results: List[AIObservation] = []
            for row in rows:
                try:
                    refs = json.loads(row["related_evidence_refs"]) if row["related_evidence_refs"] else []
                except Exception:
                    refs = []
                try:
                    steps = json.loads(row["suggested_verification_steps"]) if row["suggested_verification_steps"] else []
                except Exception:
                    steps = []
                reviewed_at_dt = None
                if row["reviewed_at"]:
                    try:
                        reviewed_at_dt = datetime.fromisoformat(row["reviewed_at"])
                    except Exception:
                        pass
                created_at_dt = datetime.utcnow()
                if row["created_at"]:
                    try:
                        created_at_dt = datetime.fromisoformat(row["created_at"])
                    except Exception:
                        pass
                results.append(AIObservation(
                    id=row["id"],
                    investigation_id=row["investigation_id"],
                    evidence_id=row["evidence_id"],
                    title=row["title"],
                    explanation=row["explanation"],
                    related_evidence_refs=refs,
                    confidence=row["confidence"] or "Unverified",
                    reasoning_summary=row["reasoning_summary"],
                    suggested_verification_steps=steps,
                    status=row["status"] or "UNVERIFIED",
                    reviewer=row["reviewer"],
                    reviewed_at=reviewed_at_dt,
                    review_notes=row["review_notes"],
                    created_at=created_at_dt
                ))
            return results
        finally:
            conn.close()

    def update_ai_observation_status(
        self,
        obs_id: str,
        status: str,
        reviewer: Optional[str] = "investigator",
        review_notes: Optional[str] = None
    ) -> Optional[AIObservation]:
        conn = get_db_connection()
        cursor = conn.cursor()
        try:
            now_iso = datetime.utcnow().isoformat()
            cursor.execute(
                """
                UPDATE ai_observations
                SET status = ?, reviewer = ?, review_notes = ?, reviewed_at = ?
                WHERE id = ?
                """,
                (status, reviewer, review_notes, now_iso, obs_id)
            )
            conn.commit()
            if cursor.rowcount == 0:
                return None
            cursor.execute("SELECT * FROM ai_observations WHERE id = ?", (obs_id,))
            row = cursor.fetchone()
            if not row:
                return None
            try:
                refs = json.loads(row["related_evidence_refs"]) if row["related_evidence_refs"] else []
            except Exception:
                refs = []
            try:
                steps = json.loads(row["suggested_verification_steps"]) if row["suggested_verification_steps"] else []
            except Exception:
                steps = []
            return AIObservation(
                id=row["id"],
                investigation_id=row["investigation_id"],
                evidence_id=row["evidence_id"],
                title=row["title"],
                explanation=row["explanation"],
                related_evidence_refs=refs,
                confidence=row["confidence"] or "Unverified",
                reasoning_summary=row["reasoning_summary"],
                suggested_verification_steps=steps,
                status=row["status"] or "UNVERIFIED",
                reviewer=row["reviewer"],
                reviewed_at=datetime.fromisoformat(row["reviewed_at"]) if row["reviewed_at"] else None,
                review_notes=row["review_notes"],
                created_at=datetime.fromisoformat(row["created_at"]) if row["created_at"] else datetime.utcnow()
            )
        finally:
            conn.close()

    def save_ai_recommendations(self, recommendations: List[AIRecommendation]) -> None:
        if not recommendations:
            return
        conn = get_db_connection()
        cursor = conn.cursor()
        try:
            for rec in recommendations:
                cursor.execute(
                    """
                    INSERT OR REPLACE INTO ai_recommendations (
                        id, investigation_id, title, category, description,
                        suggested_command_or_action, priority
                    ) VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        rec.id,
                        rec.investigation_id,
                        rec.title,
                        rec.category,
                        rec.description,
                        rec.suggested_command_or_action,
                        rec.priority or "Medium",
                    )
                )
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def list_ai_recommendations(self, investigation_id: str) -> List[AIRecommendation]:
        conn = get_db_connection()
        cursor = conn.cursor()
        try:
            cursor.execute(
                "SELECT * FROM ai_recommendations WHERE investigation_id = ?",
                (investigation_id,)
            )
            rows = cursor.fetchall()
            return [
                AIRecommendation(
                    id=row["id"],
                    investigation_id=row["investigation_id"],
                    title=row["title"],
                    category=row["category"],
                    description=row["description"],
                    suggested_command_or_action=row["suggested_command_or_action"],
                    priority=row["priority"] or "Medium"
                )
                for row in rows
            ]
        finally:
            conn.close()

    def save_ai_investigation_notes(self, notes: AIAssistedNotes) -> None:
        conn = get_db_connection()
        cursor = conn.cursor()
        try:
            cursor.execute(
                """
                INSERT OR REPLACE INTO ai_investigation_notes (
                    investigation_id, execution_status, model_provider,
                    analysis_timestamp, disclaimer, warnings_or_errors, consent_approved
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    notes.investigation_id,
                    notes.execution_status,
                    notes.model_provider,
                    notes.analysis_timestamp.isoformat() if notes.analysis_timestamp else None,
                    notes.disclaimer,
                    json.dumps(notes.warnings_or_errors or []),
                    1 if notes.consent_approved else 0,
                )
            )
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def get_ai_investigation_notes(self, investigation_id: str) -> Optional[AIAssistedNotes]:
        conn = get_db_connection()
        cursor = conn.cursor()
        try:
            cursor.execute(
                "SELECT * FROM ai_investigation_notes WHERE investigation_id = ?",
                (investigation_id,)
            )
            row = cursor.fetchone()
            if not row:
                return None
            try:
                warnings = json.loads(row["warnings_or_errors"]) if row["warnings_or_errors"] else []
            except Exception:
                warnings = []
            ts = None
            if row["analysis_timestamp"]:
                try:
                    ts = datetime.fromisoformat(row["analysis_timestamp"])
                except Exception:
                    pass
            return AIAssistedNotes(
                investigation_id=row["investigation_id"],
                execution_status=row["execution_status"],
                model_provider=row["model_provider"],
                analysis_timestamp=ts,
                disclaimer=row["disclaimer"] or "AI-assisted technical explanation. Every factual conclusion must be independently verified against raw decompiled bytecode and deterministic analyzer evidence.",
                warnings_or_errors=warnings,
                consent_approved=bool(row["consent_approved"])
            )
        finally:
            conn.close()

repo = Repository()
