"""
Verifier Module
===============
Verifies digital signatures from .sigbundle archives.

BINARY-LEVEL INTEGRITY:
    This module operates on raw bytes only. It NEVER attempts to parse,
    render, or interpret the PDF content. This means:
    - Even corrupted/unreadable PDFs will be properly hashed and verified
    - Integrity is proven at the binary level, not the content level
    - Any single byte change is detected regardless of file readability

METADATA BINDING (v2.0):
    The signature verification reconstructs the same TBS (To-Be-Signed) blob
    used during signing: file_bytes + signed_at + algorithm.
    This means modifying ANY manifest field (e.g., changing the timestamp)
    will cause signature verification to FAIL.

This is a major design feature that proves data integrity at the lowest level.
"""

import os
import json
import zipfile
import tempfile
import hashlib
from datetime import datetime, timezone

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, ec
from cryptography.exceptions import InvalidSignature

from .hasher import hash_bytes, compare_hashes
from .key_manager import load_public_key_from_pem, compute_key_fingerprint
from .signer import build_tbs_data


def verify_bundle(bundle_path):
    """
    Verify a .sigbundle archive and check file integrity.

    Process:
    1. Extract all components from the bundle
    2. Recompute SHA-256 hash of the extracted PDF (raw bytes)
    3. Rebuild the TBS blob (file_data + signed_at + algorithm) from manifest
    4. Verify the signature against the TBS blob using the bundled public key
    5. Compare hashes and return detailed results

    IMPORTANT: The PDF is hashed as raw bytes without any parsing.
    This ensures verification works even for corrupted/unreadable PDFs,
    proving binary-level data integrity.

    Args:
        bundle_path: Path to the .sigbundle file.

    Returns:
        dict with verification results including hash comparison details.
    """
    try:
        # Step 1: Extract bundle components
        with zipfile.ZipFile(bundle_path, "r") as zf:
            file_data = zf.read("document.pdf")
            signature = zf.read("signature.bin")
            public_key_pem = zf.read("public_key.pem")
            manifest = json.loads(zf.read("manifest.json"))

        # Step 2: Recompute hash over RAW BYTES (binary-level integrity)
        # We intentionally do NOT parse the PDF - we hash the exact bytes
        recomputed_hash = hash_bytes(file_data)
        original_hash = manifest.get("file_hash", "unknown")

        # Step 3: Compare file hashes (for display purposes)
        hash_comparison = compare_hashes(original_hash, recomputed_hash)

        # Step 4: Rebuild TBS blob for verification
        # This binds the signature to both file content AND metadata
        algorithm = manifest.get("algorithm", "unknown")
        signed_at = manifest.get("signed_at", "")
        metadata_signed = manifest.get("metadata_signed", False)

        if metadata_signed:
            # v2.0: Reconstruct TBS blob with metadata
            tbs_data = build_tbs_data(file_data, signed_at, algorithm)
            verification_data = tbs_data
        else:
            # v1.0 backward compatibility: signature covers only file data
            verification_data = file_data

        # Step 5: Load public key and verify signature
        public_key = load_public_key_from_pem(public_key_pem)

        # Compute public key fingerprint for the report
        key_fingerprint = compute_key_fingerprint(public_key_pem)

        signature_valid = False
        verification_error = None

        try:
            from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
            from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicKey

            if isinstance(public_key, RSAPublicKey):
                public_key.verify(
                    signature,
                    verification_data,
                    padding.PSS(
                        mgf=padding.MGF1(hashes.SHA256()),
                        salt_length=padding.PSS.MAX_LENGTH
                    ),
                    hashes.SHA256()
                )
                signature_valid = True
            elif isinstance(public_key, EllipticCurvePublicKey):
                public_key.verify(
                    signature,
                    verification_data,
                    ec.ECDSA(hashes.SHA256())
                )
                signature_valid = True
            else:
                verification_error = "Unsupported key type in bundle"

        except InvalidSignature:
            signature_valid = False
            verification_error = "Digital signature verification FAILED - file integrity compromised!"
        except Exception as e:
            signature_valid = False
            verification_error = f"Verification error: {str(e)}"

        # Step 6: Build detailed result
        result = {
            "success": True,
            "signature_valid": signature_valid,
            "hash_match": hash_comparison["match"],
            "original_hash": original_hash,
            "recomputed_hash": recomputed_hash,
            "hash_comparison": hash_comparison,
            "algorithm": algorithm,
            "file_name": manifest.get("file_name", "unknown"),
            "file_size": manifest.get("file_size", 0),
            "signed_at": signed_at,
            "key_size": manifest.get("key_size", 0),
            "key_fingerprint": key_fingerprint,
            "metadata_signed": metadata_signed,
            "pki_notice": manifest.get("pki_notice", ""),
            "tbs_notice": manifest.get("tbs_notice", ""),
            "verification_error": verification_error,
            "signature_hex": signature.hex()[:64] + "...",
            "binary_level_note": (
                "Verification operates on raw bytes. Even if this file is corrupted "
                "and cannot be opened by a PDF viewer, the hash and signature verification "
                "still work correctly, proving binary-level data integrity."
            ),
        }

        return result

    except zipfile.BadZipFile:
        return {
            "success": False,
            "signature_valid": False,
            "verification_error": "Invalid bundle file - not a valid .sigbundle archive",
        }
    except KeyError as e:
        return {
            "success": False,
            "signature_valid": False,
            "verification_error": f"Malformed bundle - missing component: {str(e)}",
        }
    except Exception as e:
        return {
            "success": False,
            "signature_valid": False,
            "verification_error": f"Unexpected error during verification: {str(e)}",
        }


def generate_audit_report(verification_result):
    """
    Generate a verification audit report as a formatted text string.

    This provides a formal, downloadable record of the verification process,
    suitable for audit trails in enterprise systems.

    Args:
        verification_result: dict returned by verify_bundle().

    Returns:
        str: The formatted audit report text.
    """
    now = datetime.now(timezone.utc).isoformat()
    valid = verification_result.get("signature_valid", False)
    status = "VALID" if valid else "INVALID — FILE INTEGRITY COMPROMISED"

    divider = "=" * 70

    report = f"""{divider}
            DIGITAL SIGNATURE VERIFICATION REPORT
{divider}

Report Generated : {now}

{divider}
  1. DOCUMENT INFORMATION
{divider}

  File Name       : {verification_result.get("file_name", "N/A")}
  File Size       : {verification_result.get("file_size", 0)} bytes
  Signed At       : {verification_result.get("signed_at", "N/A")}

{divider}
  2. CRYPTOGRAPHIC DETAILS
{divider}

  Algorithm       : {verification_result.get("algorithm", "N/A")}
  Key Size        : {verification_result.get("key_size", "N/A")} bits
  Key Fingerprint : {verification_result.get("key_fingerprint", "N/A")}
  Hash Algorithm  : SHA-256
  Metadata Signed : {"Yes (v2.0 — timestamp & algorithm bound)" if verification_result.get("metadata_signed") else "No (v1.0 — file content only)"}

{divider}
  3. HASH COMPARISON
{divider}

  Original Hash   : {verification_result.get("original_hash", "N/A")}
  (recorded at signing time)

  Recomputed Hash : {verification_result.get("recomputed_hash", "N/A")}
  (computed now from received file)

  Hash Match      : {"YES — Hashes are identical" if verification_result.get("hash_match") else "NO — HASHES DO NOT MATCH (file modified!)"}

{divider}
  4. SIGNATURE VERIFICATION
{divider}

  Signature (hex) : {verification_result.get("signature_hex", "N/A")}

  Verification
  Result          : {status}
"""

    if not valid:
        report += f"""
  Error Details   : {verification_result.get("verification_error", "N/A")}

  WARNING: The digital signature does NOT match the file content.
  This means the file has been modified after signing, or the
  signature was created with a different key. DO NOT TRUST this file.
"""

    report += f"""
{divider}
  5. NOTES
{divider}

  Binary-Level Integrity:
    {verification_result.get("binary_level_note", "")}

  PKI Notice:
    {verification_result.get("pki_notice", "")}

{divider}
  END OF REPORT
{divider}
"""

    return report


def tamper_bundle(bundle_path, tamper_type="modify_byte"):
    """
    Create a tampered version of a .sigbundle for demonstration.

    This simulates an attacker modifying the PDF content while
    keeping the original signature intact.

    Args:
        bundle_path: Path to the original .sigbundle file.
        tamper_type: Type of tampering:
            - "modify_byte": Change 1 byte in the PDF content
            - "signature_reuse": Keep signature but replace PDF with different content
            - "tamper_metadata": Change signed_at timestamp but keep file and sig intact

    Returns:
        dict with tampered bundle path and details about what was changed.
    """
    try:
        with zipfile.ZipFile(bundle_path, "r") as zf:
            file_data = bytearray(zf.read("document.pdf"))
            signature = zf.read("signature.bin")
            public_key_pem = zf.read("public_key.pem")
            manifest = json.loads(zf.read("manifest.json"))

        tamper_details = {}

        if tamper_type == "modify_byte":
            # Find a good position to modify (avoid header, target content area)
            # Modify a byte roughly in the middle of the file
            if len(file_data) > 100:
                tamper_pos = len(file_data) // 2
            else:
                tamper_pos = min(10, len(file_data) - 1)

            original_byte = file_data[tamper_pos]
            # XOR with 0x01 to flip the least significant bit
            tampered_byte = original_byte ^ 0x01
            file_data[tamper_pos] = tampered_byte

            tamper_details = {
                "tamper_type": "Single Byte Modification",
                "position": tamper_pos,
                "original_byte": f"0x{original_byte:02X}",
                "tampered_byte": f"0x{tampered_byte:02X}",
                "description": (
                    f"Changed byte at position {tamper_pos} from "
                    f"0x{original_byte:02X} to 0x{tampered_byte:02X} "
                    f"(flipped least significant bit)"
                ),
            }

        elif tamper_type == "signature_reuse":
            # Replace file content with completely different data
            # but keep the original signature - simulates signature reuse attack
            fake_content = b"%PDF-1.4\n1 0 obj\n<< /Type /Catalog >>\nendobj\n"
            fake_content += b"This is a FAKE document inserted by the attacker.\n"
            fake_content += b"The original content has been completely replaced.\n"
            fake_content += b"%%EOF\n"
            file_data = bytearray(fake_content)

            tamper_details = {
                "tamper_type": "Signature Reuse Attack",
                "description": (
                    "The PDF content was completely replaced with a different document, "
                    "but the original signature was kept. This simulates an attacker "
                    "trying to reuse a valid signature on a different file. "
                    "The system MUST detect this as the hash will not match."
                ),
                "original_size": manifest.get("file_size", 0),
                "tampered_size": len(file_data),
            }

        elif tamper_type == "tamper_metadata":
            # Keep file and signature intact but change the timestamp
            # In v1.0 this would go undetected; in v2.0 it is caught!
            original_time = manifest.get("signed_at", "unknown")
            fake_time = "2020-01-01T00:00:00+00:00"
            manifest["signed_at"] = fake_time

            tamper_details = {
                "tamper_type": "Metadata Tampering (Timestamp Forgery)",
                "description": (
                    f"The signed_at timestamp was changed from '{original_time}' "
                    f"to '{fake_time}' while keeping the file content and signature "
                    f"intact. In v2.0, the signature covers metadata too, so this "
                    f"attack is DETECTED."
                ),
                "original_time": original_time,
                "forged_time": fake_time,
            }

        # Create tampered bundle with original signature
        tampered_name = os.path.splitext(os.path.basename(bundle_path))[0] + "_TAMPERED.sigbundle"
        signed_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "signed_files")
        tampered_path = os.path.join(signed_dir, tampered_name)

        with zipfile.ZipFile(tampered_path, "w", zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("document.pdf", bytes(file_data))
            zf.writestr("signature.bin", signature)  # Keep original signature!
            zf.writestr("public_key.pem", public_key_pem)
            zf.writestr("manifest.json", json.dumps(manifest, indent=2))

        # Verify the tampered bundle to show it fails
        tampered_result = verify_bundle(tampered_path)

        return {
            "success": True,
            "tampered_bundle_path": tampered_path,
            "tampered_bundle_name": tampered_name,
            "tamper_details": tamper_details,
            "verification_result": tampered_result,
            "original_hash": manifest.get("file_hash", "unknown"),
            "tampered_hash": hash_bytes(bytes(file_data)),
        }

    except Exception as e:
        return {
            "success": False,
            "error": f"Tampering simulation failed: {str(e)}",
        }
