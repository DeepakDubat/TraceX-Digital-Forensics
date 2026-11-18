import sqlite3
import json
import sys
from pathlib import Path
from datetime import datetime

# Add project root to sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from backend.app.core.credential_manager import credential_manager

DB_PATH = Path("analysis_workspace/workbench.db")

def migrate_database():
    print(f"Connecting to {DB_PATH}...")
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()

    # Pre-migration validation
    cur.execute("PRAGMA integrity_check;")
    integrity = cur.fetchone()[0]
    assert integrity == "ok", f"DB integrity failed: {integrity}"

    cur.execute("SELECT COUNT(*) FROM investigations;")
    pre_inv = cur.fetchone()[0]
    cur.execute("SELECT COUNT(*) FROM evidence_items;")
    pre_ev = cur.fetchone()[0]
    print(f"[PRE-MIGRATION] Investigations: {pre_inv}, Evidence Items: {pre_ev}")
    assert pre_inv == 342, f"Expected 342 investigations, found {pre_inv}"
    assert pre_ev == 192, f"Expected 192 evidence items, found {pre_ev}"

    # Read current app_settings
    cur.execute("SELECT setting_key, setting_value FROM app_settings;")
    settings = {row["setting_key"]: row["setting_value"] for row in cur.fetchall()}
    print(f"Discovered {len(settings)} app_settings records.")

    # Migrate credentials to encrypted provider_credentials table
    migrated_count = 0
    now = datetime.utcnow().isoformat()

    # 1. VirusTotal
    vt_key = settings.get("virustotal_api_key", "").strip()
    if vt_key and not vt_key.startswith("****"):
        credential_manager.save_credential("virustotal", {"api_key": vt_key})
        migrated_count += 1
        print("  Migrated & Encrypted: VirusTotal")

    # 2. AlienVault OTX
    otx_key = settings.get("alienvault_api_key", "").strip()
    if otx_key and not otx_key.startswith("****"):
        credential_manager.save_credential("alienvault_otx", {"api_key": otx_key})
        migrated_count += 1
        print("  Migrated & Encrypted: AlienVault OTX")

    # 3. AbuseIPDB
    abuse_key = settings.get("abuseipdb_api_key", "").strip()
    if abuse_key and not abuse_key.startswith("****"):
        credential_manager.save_credential("abuseipdb", {"api_key": abuse_key})
        migrated_count += 1
        print("  Migrated & Encrypted: AbuseIPDB")

    # 4. MobSF
    mobsf_key = settings.get("mobsf_api_key", "").strip()
    mobsf_url = settings.get("mobsf_url", "http://127.0.0.1:8001").strip()
    if mobsf_key and not mobsf_key.startswith("****"):
        credential_manager.save_credential("mobsf", {"url": mobsf_url, "api_key": mobsf_key})
        migrated_count += 1
        print("  Migrated & Encrypted: MobSF")

    # 5. JADX Paths - Sanitize personal path in app_settings
    for path_key in ("jadx_path", "jadx_gui_path"):
        val = settings.get(path_key, "")
        if "Deepak" in val:
            portable_val = val.replace(r"C:\Users\Deepak\Tools", r"C:\Tools\jadx")
            cur.execute("UPDATE app_settings SET setting_value = ?, updated_at = ? WHERE setting_key = ?", (portable_val, now, path_key))
            print(f"  Sanitized {path_key}: {val} -> {portable_val}")

    # Purge plaintext API keys from app_settings
    keys_to_purge = ["virustotal_api_key", "alienvault_api_key", "abuseipdb_api_key", "mobsf_api_key"]
    for k in keys_to_purge:
        cur.execute("UPDATE app_settings SET setting_value = '', updated_at = ? WHERE setting_key = ?", (now, k))
    conn.commit()
    print(f"Purged {len(keys_to_purge)} plaintext secrets from app_settings.")

    # Post-migration verification
    cur.execute("PRAGMA integrity_check;")
    post_integrity = cur.fetchone()[0]
    assert post_integrity == "ok"

    cur.execute("SELECT COUNT(*) FROM investigations;")
    post_inv = cur.fetchone()[0]
    cur.execute("SELECT COUNT(*) FROM evidence_items;")
    post_ev = cur.fetchone()[0]
    cur.execute("SELECT COUNT(*) FROM provider_credentials;")
    cred_count = cur.fetchone()[0]

    print(f"[POST-MIGRATION] Investigations: {post_inv}, Evidence Items: {post_ev}")
    print(f"[POST-MIGRATION] Encrypted provider_credentials rows: {cred_count}")
    assert post_inv == pre_inv, "Investigation count mismatch!"
    assert post_ev == pre_ev, "Evidence count mismatch!"

    # Verify that app_settings has no plaintext keys remaining
    cur.execute("SELECT setting_key, setting_value FROM app_settings WHERE setting_key IN ('virustotal_api_key', 'alienvault_api_key', 'abuseipdb_api_key', 'mobsf_api_key');")
    remaining = cur.fetchall()
    for row in remaining:
        assert row["setting_value"] == "", f"Secret still present in app_settings: {row['setting_key']}"

    conn.close()
    print("\nDATABASE MIGRATION COMPLETED SUCCESSFULLY WITH 100% DATA PRESERVATION.")

if __name__ == "__main__":
    migrate_database()

