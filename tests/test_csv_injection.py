import csv
import io
from datetime import datetime
from pathlib import Path
import pytest

from backend.app.core.security import sanitize_csv_cell
from backend.app.core.models import (
    EvidenceItem, FindingRecord, OSINTIndicator, OSINTObservation,
    SecretExposureFinding, NetworkFlowRecord, ActiveValidationResult,
    StaticDynamicCorrelation, C2Indicator, NetworkIOC
)
from backend.app.reporting.master_report_generator import (
    export_evidence_inventory_csv,
    export_findings_csv,
    export_osint_indicators_csv,
    export_osint_observations_csv,
    export_secret_exposure_csv,
    export_network_flows_csv,
    export_active_validation_csv,
    export_static_dynamic_correlations_csv,
)
from backend.app.reporting.txt_generator import export_iocs_csv
from backend.app.reporting.exe_txt_generator import export_pe_iocs_csv


class TestCSVFormulaNeutralizationUnit:
    """Direct unit testing of the CWE-1236 CSV cell sanitizer."""

    @pytest.mark.parametrize("payload,expected_prefix", [
        ('=HYPERLINK("https://example.com","Click")', "'="),
        ('+SUM(1,1)', "'+"),
        ('-CMD()', "'-"),
        ('@SUM(1,1)', "'@"),
        ('   =HYPERLINK("https://evil.com")', "'   ="),
        ('\t=2+5', "'\t="),
        ('\r@SUM(1,2)', "'\r@"),
        ('\n=CMD()', "'\n="),
        ('-1+2', "'-1+2"),
        ('=-2+3*cmd|', "'=-"),
        ('+cmd|', "'+cmd"),
        ('@IMPORTXML("https://evil.com","//")', "'@IMPORTXML"),
    ])
    def test_formula_injection_payloads_neutralized(self, payload, expected_prefix):
        sanitized = sanitize_csv_cell(payload)
        assert sanitized.startswith(expected_prefix), f"Failed to neutralize formula payload: {payload!r} -> {sanitized!r}"

    @pytest.mark.parametrize("safe_val", [
        "sample_app.apk",
        "invoice_november_2026.pdf",
        "ac481cc21eb946c3e24632d722eec7585b2ba839545bf8ecc365c129ef0e262a",
        "Отчет_экспертизы_2026.docx",
        "调查报告.xlsx",
        "🔐 Sensitive Secret Exposure (API Key)",
        "CASE-FORENSIC-2026-9912",
        "192.168.1.100",
        "https://virustotal.com/gui/file/123",
        123456,
        45.6789,
        -10,
        -0.5,
        +100,
        True,
        False,
        "",
        None,
    ])
    def test_legitimate_forensic_data_preserved(self, safe_val):
        sanitized = sanitize_csv_cell(safe_val)
        if safe_val is None:
            assert sanitized == ""
        else:
            assert sanitized == safe_val, f"Safe value was improperly altered: {safe_val!r} -> {sanitized!r}"


class TestCSVReportGeneratorsIntegration:
    """Integration tests verifying formula injection neutralization across all platform CSV exporters."""

    def test_export_evidence_inventory_csv_sanitizes_malicious_filenames(self):
        items = [
            EvidenceItem(
                id="EVD-001",
                investigation_id="INV-TEST",
                filename='=HYPERLINK("https://evil.com","ClickMe").exe',
                file_size=2048,
                detected_format="exe",
                sha256="ac481cc21eb946c3e24632d722eec7585b2ba839545bf8ecc365c129ef0e262a",
                acquired_at=datetime.utcnow(),
                created_at=datetime.utcnow(),
                source_info="@SUM(1,1) / External USB Drive",
            ),
            EvidenceItem(
                id="EVD-002",
                investigation_id="INV-TEST",
                filename="normal_evidence.apk",
                file_size=10240,
                detected_format="apk",
                sha256="ecca4337477bc4618e6017b6a5df1c199fd3239de1420e11731ece68faeed23a",
                acquired_at=datetime.utcnow(),
                created_at=datetime.utcnow(),
                source_info="Forensic Lab Acquisition",
            ),
        ]
        csv_text = export_evidence_inventory_csv(items)
        rows = list(csv.reader(io.StringIO(csv_text)))

        # Header check
        assert rows[0][0] == "Evidence ID"
        assert rows[0][1] == "Filename"

        # Item 1 checks (formula neutralized with ')
        assert rows[1][1] == '\'=HYPERLINK("https://evil.com","ClickMe").exe'
        assert rows[1][12] == '\'@SUM(1,1) / External USB Drive'

        # Item 2 checks (normal filename intact)
        assert rows[2][1] == "normal_evidence.apk"
        assert rows[2][9] == "ecca4337477bc4618e6017b6a5df1c199fd3239de1420e11731ece68faeed23a"

    def test_export_findings_csv_sanitizes_titles_and_descriptions(self):
        fnds = [
            FindingRecord(
                id="FND-001",
                investigation_id="INV-TEST",
                title="+SUM(1,1) Malicious Finding Title",
                description="Exploit Execution in Description",
                observation="@SUM(1,1) Observation string",
                interpretation="   =HYPERLINK('test') Interpretation",
                analysis_method="STATIC_HEURISTIC",
                analyzer_name="Formula-Tester",
                severity="Critical",
            ),
            FindingRecord(
                id="FND-002",
                investigation_id="INV-TEST",
                title="Normal Hardcoded Secret Detected",
                description="Found OpenAI API Key in server configuration",
                observation="Key ak-live-12345678 found",
                interpretation="High credential exposure risk",
                analysis_method="STATIC_SECRET",
                analyzer_name="SecretScanner",
                severity="High",
            ),
        ]
        csv_text = export_findings_csv(fnds)
        rows = list(csv.reader(io.StringIO(csv_text)))

        # Header check
        assert rows[0][2] == "Title"
        assert rows[0][5] == "Observation"
        assert rows[0][6] == "Interpretation"

        # Neutralized fields
        assert rows[1][2] == "'+SUM(1,1) Malicious Finding Title"
        assert rows[1][5] == "'@SUM(1,1) Observation string"
        assert rows[1][6] == "'   =HYPERLINK('test') Interpretation"

        # Normal finding untouched
        assert rows[2][2] == "Normal Hardcoded Secret Detected"

    def test_export_osint_indicators_csv_sanitizes_values(self):
        indicators = [
            OSINTIndicator(
                id="IND-001",
                investigation_id="INV-TEST",
                indicator_type="ip",
                value="=CMD|' /C calc'!A0",
                normalized_value="=CMD|' /C calc'!A0",
                provenance_type="DIRECT_STATIC",
                extractor_or_provider="PCAP_Parser",
                confidence="High",
                pivot_depth=0,
                first_seen_utc="2026-11-06T12:00:00Z",
            )
        ]
        csv_text = export_osint_indicators_csv(indicators)
        rows = list(csv.reader(io.StringIO(csv_text)))
        assert rows[1][2] == "'=CMD|' /C calc'!A0"

    def test_export_iocs_csv_sanitizes_c2_and_network_values(self):
        c2 = [
            C2Indicator(
                id="C2-001",
                indicator_type="c2_domain",
                value="+SUM(1,1).evil-domain.com",
                normalized_value="+SUM(1,1).evil-domain.com",
                classification="Confirmed_C2",
                source_file="manifest.xml",
                confidence="High",
                why_suspicious="Dynamic C2 beacon",
                recommended_validation="DNS sinkhole"
            )
        ]
        net = [
            NetworkIOC(
                id="NET-001",
                ioc_type="ip",
                value="-CMD().1.2.3",
                classification="Suspicious",
                source_file="classes.dex",
                confidence="Medium",
            )
        ]
        csv_text = export_iocs_csv(net, c2)
        rows = list(csv.reader(io.StringIO(csv_text)))

        # Row 1 is C2
        assert rows[1][1] == "'+SUM(1,1).evil-domain.com"
        # Row 2 is Network IOC
        assert rows[2][1] == "'-CMD().1.2.3"

    def test_export_pe_iocs_csv_sanitizes_values(self):
        c2 = [
            C2Indicator(
                id="C2-PE-01",
                indicator_type="c2_ip",
                value="@SUM(1,1)",
                normalized_value="@SUM(1,1)",
                classification="Malicious",
                confidence="High",
                source_file="sample.exe",
                code_reference="0x401000",
                why_suspicious="=HYPERLINK('http://c2.ru')",
                recommended_validation="Isolate endpoint"
            )
        ]
        csv_text = export_pe_iocs_csv([], c2)
        rows = list(csv.reader(io.StringIO(csv_text)))
        assert rows[1][2] == "'@SUM(1,1)"
        assert rows[1][7] == "'=HYPERLINK('http://c2.ru')"
