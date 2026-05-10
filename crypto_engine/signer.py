"""
Signer Module
=============
Creates digital signatures using RSA-PSS or ECDSA with SHA-256,
and packages signed files into .sigbundle archives.

BUNDLE FORMAT (.sigbundle):
    A ZIP archive containing:
    - document.pdf     : The original PDF file
    - signature.bin    : The digital signature bytes
    - public_key.pem   : The signer's public key
    - manifest.json    : Metadata (algorithm, hash, timestamp, PKI note)

METADATA BINDING (v2.0):
    The signature covers NOT ONLY the file content but also critical metadata
    (timestamp, algorithm). This prevents an attacker from modifying manifest
    fields (e.g., signed_at) without invalidating the signature.

    Signed data = file_bytes + signed_at_string + algorithm_string
    This is called the "To-Be-Signed" (TBS) blob.

NOTE ON PUBLIC KEY BUNDLING:
    In production, the public key would be distributed via PKI infrastructure
    or a Certificate Authority (CA). Bundling it here is for local simulation
    purposes only. This is explicitly noted in the manifest.json.
"""

import os
import json
import zipfile
import tempfile
from datetime import datetime, timezone

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, ec, utils

from .hasher import hash_file, hash_bytes
from .key_manager import load_private_key, get_public_key_pem


def build_tbs_data(file_data, signed_at, algorithm):
    """
    Build the To-Be-Signed (TBS) data blob.

    The TBS blob binds the signature to BOTH the file content AND
    critical metadata, preventing metadata tampering attacks.

    TBS = file_bytes + b"||METADATA||" + signed_at.encode() + b"||" + algorithm.encode()

    The "||METADATA||" separator ensures there is no ambiguity between
    file content and metadata fields.

    Args:
        file_data: Raw bytes of the file.
        signed_at: ISO timestamp string of when the document was signed.
        algorithm: Algorithm string (e.g., "RSA-PSS" or "ECDSA").

    Returns:
        bytes: The TBS blob to be signed/verified.
    """
    separator = b"||METADATA||"
    field_sep = b"||"
    return file_data + separator + signed_at.encode("utf-8") + field_sep + algorithm.encode("utf-8")


def sign_file(file_path, key_name, user_id, password=None):
    """
    Sign a file and create a .sigbundle archive.

    Process:
    1. Read the file as raw bytes
    2. Compute SHA-256 hash of file content (for display)
    3. Determine algorithm, generate timestamp
    4. Build TBS blob = file_bytes + metadata (timestamp + algorithm)
    5. Sign the TBS blob with the private key (RSA-PSS or ECDSA)
    6. Package everything into a .sigbundle ZIP

    Args:
        file_path: Path to the PDF file to sign.
        key_name: Name of the key pair to use for signing.
        user_id: ID of the user signing the file.
        password: Optional password for the private key.

    Returns:
        dict with signing results including bundle path, hash, signature info.
    """
    # Step 1: Read file and compute hash (for display purposes)
    file_hash = hash_file(file_path)

    with open(file_path, "rb") as f:
        file_data = f.read()

    # Step 2: Load private key and determine algorithm
    private_key = load_private_key(key_name, user_id, password)

    from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
    from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePrivateKey

    if isinstance(private_key, RSAPrivateKey):
        algorithm = "RSA-PSS"
        key_size = private_key.key_size
    elif isinstance(private_key, EllipticCurvePrivateKey):
        algorithm = "ECDSA"
        key_size = private_key.curve.key_size
    else:
        raise ValueError("Unsupported key type")

    # Step 3: Generate timestamp BEFORE signing (it becomes part of signed data)
    signed_at = datetime.now(timezone.utc).isoformat()

    # Step 4: Build TBS (To-Be-Signed) blob — binds file content + metadata
    tbs_data = build_tbs_data(file_data, signed_at, algorithm)
    tbs_hash = hash_bytes(tbs_data)

    # Step 5: Sign the TBS blob (NOT just the file data)
    if isinstance(private_key, RSAPrivateKey):
        signature = private_key.sign(
            tbs_data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
    elif isinstance(private_key, EllipticCurvePrivateKey):
        signature = private_key.sign(
            tbs_data,
            ec.ECDSA(hashes.SHA256())
        )

    # Step 6: Get public key PEM
    public_key_pem = get_public_key_pem(key_name, user_id)

    # Step 7: Create manifest
    manifest = {
        "version": "2.0",
        "algorithm": algorithm,
        "hash_algorithm": "SHA-256",
        "file_hash": file_hash,
        "tbs_hash": tbs_hash,
        "metadata_signed": True,
        "file_name": os.path.basename(file_path),
        "file_size": len(file_data),
        "signature_size": len(signature),
        "key_size": key_size,
        "signer_key_name": key_name,
        "signed_at": signed_at,
        "pki_notice": (
            "IMPORTANT: In production, the public key would be distributed "
            "via a Public Key Infrastructure (PKI) or Certificate Authority (CA). "
            "The public key is bundled in this archive for local simulation "
            "and demonstration purposes only."
        ),
        "tbs_notice": (
            "The digital signature covers BOTH the file content AND metadata "
            "(timestamp, algorithm). Modifying any field in this manifest will "
            "invalidate the signature."
        ),
    }

    # Step 8: Create .sigbundle ZIP
    bundle_name = f"{os.path.splitext(os.path.basename(file_path))[0]}_signed.sigbundle"
    signed_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "signed_files")
    os.makedirs(signed_dir, exist_ok=True)
    bundle_path = os.path.join(signed_dir, bundle_name)

    with zipfile.ZipFile(bundle_path, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("document.pdf", file_data)
        zf.writestr("signature.bin", signature)
        zf.writestr("public_key.pem", public_key_pem)
        zf.writestr("manifest.json", json.dumps(manifest, indent=2))

    return {
        "success": True,
        "bundle_path": bundle_path,
        "bundle_name": bundle_name,
        "file_hash": file_hash,
        "tbs_hash": tbs_hash,
        "algorithm": algorithm,
        "key_size": key_size,
        "signature_hex": signature.hex()[:64] + "...",  # First 64 hex chars for display
        "signature_full_hex": signature.hex(),
        "file_name": os.path.basename(file_path),
        "file_size": len(file_data),
        "signed_at": signed_at,
        "metadata_signed": True,
    }
