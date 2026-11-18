import pytest
import logging
from backend.app.analyzers.secret_analyzer import analyze_secrets
from backend.app.core.security import redact_secret
from backend.app.core.redaction import (
    redact_sensitive_text,
    redact_c2_indicator,
    redact_secret_finding,
    redact_investigation_detail,
    RedactingLogFilter
)
from backend.app.core.models import (
    InvestigationDetail, InvestigationRecord, C2Indicator, SecretFinding, StaticFinding
)
from datetime import datetime

def test_secret_redaction():
    assert redact_secret("AIzaSyD-TestKey123456789") == "AIza••••••••6789"
    assert redact_secret("short") == "••••••••"

def test_secret_token_detection():
    strings_pool = [
        ("classes.dex", "AIzaSyD-TestFakeAPIKey_ForForensics9876543"),
        ("classes.dex", "123456789:ABCdefGHIjklMNOpqrsTUVwxyz012345678"), # Telegram Bot
        ("classes.dex", "AKIAIOSFODNN7EXAMPLE"), # AWS Key
        ("classes.dex", "your_api_key_here") # Common false positive
    ]
    methods = ["okhttp3/OkHttpClient->newCall", "Authorization"]

    secrets = analyze_secrets(strings_pool, methods)
    rules_matched = [s.rule_matched for s in secrets]

    assert any("Google API Key" in r for r in rules_matched)
    assert any("Telegram" in r for r in rules_matched)
    assert any("AWS" in r for r in rules_matched)
    # False positive 'your_api_key_here' must be filtered out
    assert not any(s.raw_value == "your_api_key_here" for s in secrets)

def test_centralized_text_redaction_mongo_uri():
    uri = "mongodb://admin:Db@dm1n#2025@118.196.64.77:27017/weddingdb"
    redacted = redact_sensitive_text(uri)
    assert "Db@dm1n#2025" not in redacted
    assert "mongodb://admin:••••••••@118.196.64.77:27017/weddingdb" == redacted

def test_centralized_text_redaction_telegram_url():
    tg_url = "https://api.telegram.org/bot7381920456:AAF3kL2mN9pQ4rT6uV-8wX1yZ0aBcDeF2gH/sendMessage?chat_id=123"
    redacted = redact_sensitive_text(tg_url)
    assert "AAF3kL2mN9pQ4rT6uV-8wX1yZ0aBcDeF2gH" not in redacted
    assert "https://api.telegram.org/bot7381920456:••••••••/sendMessage?chat_id=123" == redacted

def test_centralized_text_redaction_api_keys():
    text = "Keys: ak_live_7f3d92b1e4c05a8f2d6e1b9c3a7f0e52 and AIzaSyD3f7kL2mN9pQ4rT6uV8wX1yZ0aBcDeF2g"
    redacted = redact_sensitive_text(text)
    assert "ak_live_7f3d92b1e4c05a8f2d6e1b9c3a7f0e52" not in redacted
    assert "AIzaSyD3f7kL2mN9pQ4rT6uV8wX1yZ0aBcDeF2g" not in redacted
    assert "••••••••" in redacted

def test_centralized_text_redaction_benign_text():
    benign = "http://118.196.64.77:8080/admin and https://neel-anju-wedding-photos.s3.ap-south-1.amazonaws.com"
    assert redact_sensitive_text(benign) == benign

def test_redact_c2_indicator():
    c2 = C2Indicator(
        id="C2-001",
        indicator_type="url",
        value="https://api.telegram.org/bot7381920456:AAF3kL2mN9pQ4rT6uV-8wX1yZ0aBcDeF2gH/send",
        normalized_value="https://api.telegram.org/bot7381920456:AAF3kL2mN9pQ4rT6uV-8wX1yZ0aBcDeF2gH/send",
        classification="potential_c2",
        why_suspicious="Telegram bot URL",
        confidence="High",
        source_file="assets/config.json",
        recommended_validation="Inspect Telegram bot profile"
    )
    safe_c2 = redact_c2_indicator(c2)
    assert "AAF3kL2mN9pQ4rT6uV-8wX1yZ0aBcDeF2gH" not in safe_c2.value
    assert "AAF3kL2mN9pQ4rT6uV-8wX1yZ0aBcDeF2gH" not in safe_c2.normalized_value

def test_redacting_log_filter():
    filt = RedactingLogFilter()
    record = logging.LogRecord(
        name="test",
        level=logging.INFO,
        pathname="test.py",
        lineno=1,
        msg="Connecting to mongodb://admin:Db@dm1n#2025@10.0.0.1:27017/test with key ak_live_7f3d92b1e4c05a8f2d6e1b9c3a7f0e52",
        args=(),
        exc_info=None
    )
    assert filt.filter(record) is True
    assert "Db@dm1n#2025" not in record.msg
    assert "ak_live_7f3d92b1e4c05a8f2d6e1b9c3a7f0e52" not in record.msg
    assert "••••••••" in record.msg
