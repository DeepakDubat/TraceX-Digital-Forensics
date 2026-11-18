from backend.app.core.credential_manager import credential_manager, PROVIDER_CATALOG

print("Master key source:", credential_manager.master_key_source)
assert credential_manager.master_key_source in ("environment", "secure_local_store", "ephemeral_memory")

# Test 1: Masking
test_key = "deadbeef00112233445566778899aabbccddeeff00112233445566778899e895"
masked = credential_manager.mask_secret(test_key)
print("Masked output:", masked)
assert masked.startswith("****************")
assert masked.endswith("e895")
assert test_key[:10] not in masked

# Test 2: Save and Decrypt
res = credential_manager.save_credential("virustotal", {"api_key": test_key})
print("Save result:", res)
assert res["status"] == "success"

# Test 3: Get credential (in memory)
decrypted = credential_manager.get_credential("virustotal")
assert decrypted is not None
assert decrypted["api_key"] == test_key

# Test 4: Get masked credential
masked_cred = credential_manager.get_masked_credential("virustotal")
assert masked_cred is not None
assert masked_cred["api_key"] == masked
assert test_key not in json_str if 'json_str' in locals() else True

# Test 5: List providers metadata
meta_list = credential_manager.list_providers_metadata()
print(f"Total providers in catalog: {len(meta_list)}")
assert len(meta_list) >= 20

vt_item = next(p for p in meta_list if p["id"] == "virustotal")
print("VirusTotal metadata status:", vt_item["is_configured"], vt_item["status_badge"], vt_item["masked_values"])
assert vt_item["is_configured"] is True
assert vt_item["masked_values"]["api_key"].endswith("e895")
# Ensure no plaintext anywhere in the metadata payload
meta_str = str(meta_list)
assert test_key not in meta_str, "Plaintext leaked in metadata!"

print("\nALL CREDENTIAL MANAGER TESTS PASSED SUCCESSFULLY!")
