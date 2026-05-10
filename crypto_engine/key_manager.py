"""
Key Manager Module
==================
Handles RSA and ECDSA key pair generation, storage, loading, and metadata extraction.
"""

import os
import json
import hashlib
from datetime import datetime, timezone

from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import (
    Encoding, PrivateFormat, PublicFormat, NoEncryption,
    BestAvailableEncryption
)


# Default directory for key storage
KEYS_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "keys")


def ensure_keys_dir():
    """Ensure the keys directory exists."""
    os.makedirs(KEYS_DIR, exist_ok=True)


def generate_rsa_keypair(key_size=2048, key_name=None, password=None):
    """
    Generate an RSA key pair and save to PEM files.
    
    Args:
        key_size: RSA key size in bits (2048 or 4096)
        key_name: Optional name for the key files. Auto-generated if None.
        password: Optional password to encrypt the private key.
    
    Returns:
        dict with key metadata including file paths and fingerprint.
    """
    ensure_keys_dir()
    
    # Generate RSA private key
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size,
    )
    public_key = private_key.public_key()
    
    # Generate key name if not provided
    if not key_name:
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        key_name = f"rsa_{key_size}_{timestamp}"
    
    # Serialize private key
    if password:
        encryption = BestAvailableEncryption(password.encode())
    else:
        encryption = NoEncryption()
    
    private_pem = private_key.private_bytes(
        encoding=Encoding.PEM,
        format=PrivateFormat.PKCS8,
        encryption_algorithm=encryption
    )
    
    # Serialize public key
    public_pem = public_key.public_bytes(
        encoding=Encoding.PEM,
        format=PublicFormat.SubjectPublicKeyInfo
    )
    
    # Save to files
    private_path = os.path.join(KEYS_DIR, f"{key_name}_private.pem")
    public_path = os.path.join(KEYS_DIR, f"{key_name}_public.pem")
    
    with open(private_path, "wb") as f:
        f.write(private_pem)
    with open(public_path, "wb") as f:
        f.write(public_pem)
    
    # Compute public key fingerprint (SHA-256 of DER-encoded public key)
    fingerprint = compute_key_fingerprint(public_pem)
    
    # Save metadata
    metadata = {
        "algorithm": "RSA",
        "key_size": key_size,
        "key_name": key_name,
        "fingerprint": fingerprint,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "private_key_file": os.path.basename(private_path),
        "public_key_file": os.path.basename(public_path),
        "password_protected": password is not None,
    }
    
    meta_path = os.path.join(KEYS_DIR, f"{key_name}_meta.json")
    with open(meta_path, "w") as f:
        json.dump(metadata, f, indent=2)
    
    return metadata


def generate_ecdsa_keypair(curve_name="secp256r1", key_name=None, password=None):
    """
    Generate an ECDSA key pair and save to PEM files.
    
    Args:
        curve_name: Elliptic curve name (secp256r1, secp384r1, secp521r1)
        key_name: Optional name for the key files. Auto-generated if None.
        password: Optional password to encrypt the private key.
    
    Returns:
        dict with key metadata including file paths and fingerprint.
    """
    ensure_keys_dir()
    
    # Select curve
    curves = {
        "secp256r1": ec.SECP256R1(),
        "secp384r1": ec.SECP384R1(),
        "secp521r1": ec.SECP521R1(),
    }
    curve = curves.get(curve_name, ec.SECP256R1())
    
    # Generate ECDSA private key
    private_key = ec.generate_private_key(curve)
    public_key = private_key.public_key()
    
    # Generate key name if not provided
    if not key_name:
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        key_name = f"ecdsa_{curve_name}_{timestamp}"
    
    # Serialize private key
    if password:
        encryption = BestAvailableEncryption(password.encode())
    else:
        encryption = NoEncryption()
    
    private_pem = private_key.private_bytes(
        encoding=Encoding.PEM,
        format=PrivateFormat.PKCS8,
        encryption_algorithm=encryption
    )
    
    # Serialize public key
    public_pem = public_key.public_bytes(
        encoding=Encoding.PEM,
        format=PublicFormat.SubjectPublicKeyInfo
    )
    
    # Save to files
    private_path = os.path.join(KEYS_DIR, f"{key_name}_private.pem")
    public_path = os.path.join(KEYS_DIR, f"{key_name}_public.pem")
    
    with open(private_path, "wb") as f:
        f.write(private_pem)
    with open(public_path, "wb") as f:
        f.write(public_pem)
    
    # Compute public key fingerprint
    fingerprint = compute_key_fingerprint(public_pem)
    
    # Save metadata
    metadata = {
        "algorithm": "ECDSA",
        "curve": curve_name,
        "key_name": key_name,
        "fingerprint": fingerprint,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "private_key_file": os.path.basename(private_path),
        "public_key_file": os.path.basename(public_path),
        "password_protected": password is not None,
    }
    
    meta_path = os.path.join(KEYS_DIR, f"{key_name}_meta.json")
    with open(meta_path, "w") as f:
        json.dump(metadata, f, indent=2)
    
    return metadata


def compute_key_fingerprint(public_pem_bytes):
    """Compute SHA-256 fingerprint of a public key's PEM bytes."""
    digest = hashlib.sha256(public_pem_bytes).hexdigest()
    # Format as colon-separated pairs for readability
    return ":".join(digest[i:i+2] for i in range(0, 32, 2))


def load_private_key(key_name, password=None):
    """Load a private key from PEM file."""
    private_path = os.path.join(KEYS_DIR, f"{key_name}_private.pem")
    
    with open(private_path, "rb") as f:
        private_pem = f.read()
    
    pwd = password.encode() if password else None
    private_key = serialization.load_pem_private_key(private_pem, password=pwd)
    return private_key


def load_public_key(key_name):
    """Load a public key from PEM file."""
    public_path = os.path.join(KEYS_DIR, f"{key_name}_public.pem")
    
    with open(public_path, "rb") as f:
        public_pem = f.read()
    
    public_key = serialization.load_pem_public_key(public_pem)
    return public_key


def load_public_key_from_pem(pem_bytes):
    """Load a public key directly from PEM bytes."""
    return serialization.load_pem_public_key(pem_bytes)


def get_public_key_pem(key_name):
    """Get the raw PEM bytes of a public key."""
    public_path = os.path.join(KEYS_DIR, f"{key_name}_public.pem")
    with open(public_path, "rb") as f:
        return f.read()


def list_keys():
    """List all available key pairs with their metadata."""
    ensure_keys_dir()
    keys = []
    
    for filename in os.listdir(KEYS_DIR):
        if filename.endswith("_meta.json"):
            meta_path = os.path.join(KEYS_DIR, filename)
            with open(meta_path, "r") as f:
                metadata = json.load(f)
            keys.append(metadata)
    
    # Sort by creation time, newest first
    keys.sort(key=lambda k: k.get("created_at", ""), reverse=True)
    return keys


def delete_key(key_name):
    """Delete a key pair and its metadata."""
    for suffix in ["_private.pem", "_public.pem", "_meta.json"]:
        path = os.path.join(KEYS_DIR, f"{key_name}{suffix}")
        if os.path.exists(path):
            os.remove(path)
