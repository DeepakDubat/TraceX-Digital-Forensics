import html
import pytest
from backend.app.core.models import (
    InvestigationRecord, EvidenceItem, FindingRecord,
    EvidenceRelationship, TimelineEvent, ChainOfCustodyEvent,
    UniversalInvestigationDetail
)
from backend.app.reporting.master_report_generator import generate_master_html_report

def test_master_html_report_xss_neutralization():
    """
    Regression Test for SEC-01 / BUG-01:
    Verifies that untrusted filenames, case references, finding titles,
    descriptions, observations, and timeline entries containing harmless XSS
    test payloads are strictly HTML-escaped and cannot execute scripts in a browser.
    """
    xss_filename = 'malicious_<script>alert("xss")</script>.apk'
    xss_case_ref = 'CASE-<img src=x onerror=alert(1)>'
    xss_title = 'Suspicious Payload <svg/onload=alert("title")>'
    xss_desc = 'Desc with unescaped <b>tag</b> & "quotes" <script>steal()</script>'
    xss_obs = 'Observed <iframe src="javascript:alert(1)">'

    evd = EvidenceItem(
        id="EVD-XSS-001",
        investigation_id="CASE-XSS",
        filename=xss_filename,
        file_size=2048,
        sha256="11223344556677889900aabbccddeeff11223344556677889900aabbccddeeff",
        sha512="a" * 128,
        detected_format="apk"
    )

    finding = FindingRecord(
        id="FND-XSS-001",
        investigation_id="CASE-XSS",
        evidence_id="EVD-XSS-001",
        title=xss_title,
        description=xss_desc,
        observation=xss_obs,
        interpretation="Simulated XSS test entry",
        severity="High",
        confidence="High",
        analysis_method="Static Security Parser",
        analyzer_name="test_analyzer",
        alternative_explanation='Safe <script>console.log("alt")</script>'
    )

    rec = InvestigationRecord(
        id="CASE-XSS",
        filename=xss_filename,
        original_size=2048,
        md5="a" * 32,
        sha1="b" * 40,
        sha256="11223344556677889900aabbccddeeff11223344556677889900aabbccddeeff",
        case_reference=xss_case_ref,
        investigator_name='Examiner <script>alert("examiner")</script>',
        local_only_mode=True,
        status="completed",
        progress=100,
        current_stage="Report Ready",
        severity="High",
        confidence="High",
        file_type="multi"
    )

    tml = TimelineEvent(
        id="TML-XSS-001",
        investigation_id="CASE-XSS",
        evidence_id="EVD-XSS-001",
        original_timestamp="2026-11-06T12:00:00Z",
        normalized_utc="2026-11-06 12:00:00 UTC",
        timestamp_source="System Log",
        reliability="HIGH",
        event_type="FILE_INGESTION",
        description='Event <script>alert("timeline")</script>'
    )

    coc = ChainOfCustodyEvent(
        id="COC-XSS-001",
        investigation_id="CASE-XSS",
        event_type="INGESTION",
        timestamp_utc="2026-11-06 12:00:00 UTC",
        examiner='Officer <script>alert("officer")</script>',
        original_hash="112233",
        working_copy_hash="112233",
        verification_result="PASSED",
        event_hash="aabbccddeeff001122334455"
    )

    detail = UniversalInvestigationDetail(
        record=rec,
        evidence_items=[evd],
        extracted_artifacts=[],
        evidence_relationships=[],
        timeline_events=[tml],
        chain_of_custody=[coc],
        findings_register=[finding],
        coverage_matrix=[],
        contradictions=[]
    )

    html_out = generate_master_html_report(detail)

    # 1. Ensure raw malicious tags are NOT present in the generated HTML
    assert '<script>alert("xss")</script>' not in html_out
    assert '<img src=x onerror=alert(1)>' not in html_out
    assert '<svg/onload=alert("title")>' not in html_out
    assert '<script>steal()</script>' not in html_out
    assert '<iframe src="javascript:alert(1)">' not in html_out
    assert '<script>alert("timeline")</script>' not in html_out
    assert '<script>alert("examiner")</script>' not in html_out

    # 2. Ensure properly escaped HTML entities ARE present
    assert '&lt;script&gt;alert(&quot;xss&quot;)&lt;/script&gt;' in html_out or '&lt;script&gt;alert(&#34;xss&#34;)&lt;/script&gt;' in html_out
    assert '&lt;img src=x onerror=alert(1)&gt;' in html_out
    assert '&lt;svg/onload=alert(&quot;title&quot;)&gt;' in html_out or '&lt;svg/onload=alert(&#34;title&#34;)&gt;' in html_out
    assert '&lt;iframe src=&quot;javascript:alert(1)&quot;&gt;' in html_out or '&lt;iframe src=&#34;javascript:alert(1)&#34;&gt;' in html_out

