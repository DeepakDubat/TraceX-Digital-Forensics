import hashlib
from pathlib import Path
from backend.app.core.security import calculate_hashes
from tests.create_fixtures import create_harmless_test_apk

def test_calculate_hashes(tmp_path):
    apk_path = tmp_path / "sample.apk"
    create_harmless_test_apk(apk_path)
    
    hashes = calculate_hashes(apk_path)
    content = apk_path.read_bytes()
    
    assert hashes["md5"] == hashlib.md5(content).hexdigest()
    assert hashes["sha1"] == hashlib.sha1(content).hexdigest()
    assert hashes["sha256"] == hashlib.sha256(content).hexdigest()
    assert len(hashes["sha256"]) == 64
