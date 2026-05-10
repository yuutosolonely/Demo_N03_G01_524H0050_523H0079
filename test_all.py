"""End-to-end test suite for Digital Signature Tool v2.0 (with Database)."""
import sys
import os
import zipfile

sys.path.insert(0, ".")

from app import app
from models import db, User

print("=" * 60)
print("DIGITAL SIGNATURE TOOL v2.0 - END-TO-END TEST")
print("=" * 60)

with app.app_context():
    # Ensure DB is created
    db.create_all()
    
    # Create test user
    test_user = User.query.filter_by(username="testrunner").first()
    if not test_user:
        test_user = User(username="testrunner", password_hash="testpass")
        db.session.add(test_user)
        db.session.commit()
    
    user_id = test_user.id

    # Clean old test keys
    from crypto_engine.key_manager import delete_key
    for name in ["test_rsa_2048", "test_rsa_backup", "test_ecdsa_p256"]:
        try:
            delete_key(name, user_id)
        except:
            pass

    # --- Test 1: RSA Key Generation ---
    print("\n[TEST 1] RSA Key Generation...")
    from crypto_engine.key_manager import generate_rsa_keypair, get_public_key_pem
    meta = generate_rsa_keypair(user_id, key_size=2048, key_name="test_rsa_2048")
    print(f"  OK Generated RSA 2048-bit key: {meta['key_name']}")
    print(f"  OK Fingerprint: {meta['fingerprint']}")

    # --- Test 2: ECDSA Key Generation ---
    print("\n[TEST 2] ECDSA Key Generation...")
    meta2 = generate_rsa_keypair(user_id, key_size=2048, key_name="test_rsa_backup")
    from crypto_engine.key_manager import generate_ecdsa_keypair
    meta_ec = generate_ecdsa_keypair(user_id, curve_name="secp256r1", key_name="test_ecdsa_p256")
    print(f"  OK Generated ECDSA P-256 key: {meta_ec['key_name']}")

    # --- Test 3: Sign PDF with RSA (v2.0 — metadata bound) ---
    print("\n[TEST 3] Sign PDF with RSA (v2.0 — metadata bound)...")
    from crypto_engine.signer import sign_file
    result = sign_file("uploads/test_contract.pdf", "test_rsa_2048", user_id)
    print(f"  OK File signed: {result['file_name']}")
    print(f"  OK File Hash: {result['file_hash']}")
    print(f"  OK TBS Hash:  {result['tbs_hash']}")
    print(f"  OK Algorithm: {result['algorithm']}")
    print(f"  OK Metadata Signed: {result['metadata_signed']}")
    assert result["metadata_signed"] == True, "FAILED: v2.0 should have metadata_signed=True"
    print("  PASS")

    # --- Test 4: Verify Valid Bundle ---
    print("\n[TEST 4] Verify VALID bundle...")
    from crypto_engine.verifier import verify_bundle
    vresult = verify_bundle(result["bundle_path"])
    print(f"  OK Signature Valid: {vresult['signature_valid']}")
    print(f"  OK Hash Match: {vresult['hash_match']}")
    print(f"  OK Metadata Signed: {vresult['metadata_signed']}")
    print(f"  OK Key Fingerprint: {vresult['key_fingerprint']}")
    assert vresult["signature_valid"] == True, "FAILED: Valid bundle should verify!"
    print("  PASS")

    # --- Test 5: Tamper 1 Byte -> Detect ---
    print("\n[TEST 5] Tamper 1 byte -> must detect...")
    from crypto_engine.verifier import tamper_bundle
    tamper_result = tamper_bundle(result["bundle_path"], tamper_type="modify_byte")
    tv = tamper_result["verification_result"]
    print(f"  OK Tampered: {tamper_result['tamper_details']['description']}")
    print(f"  OK Signature Valid after tamper: {tv['signature_valid']}")
    assert tv["signature_valid"] == False, "FAILED: Tampered bundle should NOT verify!"
    print("  PASS - Tamper detected!")

    # --- Test 6: Signature Reuse Attack ---
    print("\n[TEST 6] Signature Reuse Attack (Sign A -> sig to B)...")
    reuse_result = tamper_bundle(result["bundle_path"], tamper_type="signature_reuse")
    rv = reuse_result["verification_result"]
    print(f"  OK Attack type: {reuse_result['tamper_details']['tamper_type']}")
    print(f"  OK Signature Valid after reuse: {rv['signature_valid']}")
    assert rv["signature_valid"] == False, "FAILED: Reused signature should NOT verify!"
    print("  PASS - Signature reuse detected!")

    # --- Test 7: Metadata Tampering (NEW in v2.0) ---
    print("\n[TEST 7] Metadata Tampering (timestamp forgery)...")
    meta_result = tamper_bundle(result["bundle_path"], tamper_type="tamper_metadata")
    mv = meta_result["verification_result"]
    print(f"  OK Attack type: {meta_result['tamper_details']['tamper_type']}")
    print(f"  OK Original time: {meta_result['tamper_details'].get('original_time', 'N/A')}")
    print(f"  OK Forged time:   {meta_result['tamper_details'].get('forged_time', 'N/A')}")
    print(f"  OK Signature Valid after metadata tamper: {mv['signature_valid']}")
    assert mv["signature_valid"] == False, "FAILED: Metadata tampering should be detected in v2.0!"
    print("  PASS - Metadata tampering detected! (v2.0 feature)")

    # --- Test 8: Sign with ECDSA ---
    print("\n[TEST 8] Sign PDF with ECDSA...")
    ec_result = sign_file("uploads/test_contract.pdf", "test_ecdsa_p256", user_id)
    print(f"  OK Algorithm: {ec_result['algorithm']}")
    ec_verify = verify_bundle(ec_result["bundle_path"])
    assert ec_verify["signature_valid"] == True, "FAILED: ECDSA bundle should verify!"
    print("  PASS - ECDSA signature verified!")

    # --- Test 9: Wrong key verification ---
    print("\n[TEST 9] Verify with wrong key...")
    bundle_path = result["bundle_path"]
    wrong_pub = get_public_key_pem("test_rsa_backup", user_id)
    wrong_bundle_path = bundle_path.replace(".sigbundle", "_wrongkey.sigbundle")
    with zipfile.ZipFile(bundle_path, "r") as zin:
        with zipfile.ZipFile(wrong_bundle_path, "w") as zout:
            for item in zin.namelist():
                data = zin.read(item)
                if item == "public_key.pem":
                    data = wrong_pub
                zout.writestr(item, data)
    wk_result = verify_bundle(wrong_bundle_path)
    print(f"  OK Signature Valid with wrong key: {wk_result['signature_valid']}")
    assert wk_result["signature_valid"] == False, "FAILED: Wrong key should NOT verify!"
    print("  PASS - Wrong key detected!")

    # --- Test 10: Hash diff character comparison ---
    print("\n[TEST 10] Hash diff visualization...")
    from crypto_engine.hasher import compare_hashes
    comp = compare_hashes(tamper_result["original_hash"], tamper_result["tampered_hash"])
    total = comp["total_chars"]
    diff = comp["diff_count"]
    pct = diff / total * 100
    print(f"  OK Total chars: {total}")
    print(f"  OK Diff chars: {diff}")
    print(f"  OK Diff percentage: {pct:.1f}%")
    print(f"  OK Match: {comp['match']}")

    # --- Test 11: Corrupted file still detects tamper ---
    print("\n[TEST 11] Corrupted/unreadable file verification...")
    corrupt_bundle_path = bundle_path.replace(".sigbundle", "_corrupt.sigbundle")
    with zipfile.ZipFile(bundle_path, "r") as zin:
        sig = zin.read("signature.bin")
        pub = zin.read("public_key.pem")
        manifest_data = zin.read("manifest.json")
    with zipfile.ZipFile(corrupt_bundle_path, "w") as zout:
        zout.writestr("document.pdf", b"\x00\xFF\xFE\xAB" * 100)
        zout.writestr("signature.bin", sig)
        zout.writestr("public_key.pem", pub)
        zout.writestr("manifest.json", manifest_data)
    corrupt_result = verify_bundle(corrupt_bundle_path)
    print(f"  OK Signature Valid for corrupted file: {corrupt_result['signature_valid']}")
    assert corrupt_result["signature_valid"] == False, "FAILED: Corrupted file should NOT verify!"
    print("  PASS - Binary-level integrity confirmed even for unreadable files!")

    # --- Test 12: Audit Report Generation ---
    print("\n[TEST 12] Audit Report Generation...")
    from crypto_engine.verifier import generate_audit_report
    report = generate_audit_report(vresult)
    assert "VERIFICATION REPORT" in report, "FAILED: Report should contain header!"
    assert vresult["file_name"] in report, "FAILED: Report should contain file name!"
    assert vresult["original_hash"] in report, "FAILED: Report should contain hash!"
    assert "Key Fingerprint" in report, "FAILED: Report should contain fingerprint!"
    assert "Metadata Signed" in report, "FAILED: Report should mention metadata binding!"
    print(f"  OK Report length: {len(report)} chars")
    print(f"  OK Contains file name: {vresult['file_name']}")
    print(f"  OK Contains key fingerprint")
    print(f"  OK Contains metadata binding info")
    print("  PASS - Audit report generated correctly!")

    # --- Summary ---
    print("\n" + "=" * 60)
    print("ALL TESTS PASSED! (v3.0 - with Database & PKI)")
    print("=" * 60)
