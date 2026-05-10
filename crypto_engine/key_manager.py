"""
Key Manager Module
==================
Handles RSA and ECDSA key pair generation, storage, loading, and metadata extraction.
Now uses Database for secure storage.
"""

import hashlib
from datetime import datetime, timezone

from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import (
    Encoding, PrivateFormat, PublicFormat, NoEncryption,
    BestAvailableEncryption
)

from models import db, KeyRecord

def generate_rsa_keypair(user_id, key_size=2048, key_name=None, password=None):
    """Generate an RSA key pair and save to Database."""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size,
    )
    public_key = private_key.public_key()
    
    if not key_name:
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        key_name = f"rsa_{key_size}_{timestamp}"
    
    encryption = BestAvailableEncryption(password.encode()) if password else NoEncryption()
    
    private_pem = private_key.private_bytes(
        encoding=Encoding.PEM,
        format=PrivateFormat.PKCS8,
        encryption_algorithm=encryption
    ).decode('utf-8')
    
    public_pem = public_key.public_bytes(
        encoding=Encoding.PEM,
        format=PublicFormat.SubjectPublicKeyInfo
    ).decode('utf-8')
    
    fingerprint = compute_key_fingerprint(public_pem.encode('utf-8'))
    
    key_record = KeyRecord(
        user_id=user_id,
        key_name=key_name,
        algorithm="RSA",
        key_size=str(key_size),
        fingerprint=fingerprint,
        public_pem=public_pem,
        private_pem=private_pem
    )
    db.session.add(key_record)
    db.session.commit()
    
    return {
        "algorithm": "RSA",
        "key_size": key_size,
        "key_name": key_name,
        "fingerprint": fingerprint,
    }


def generate_ecdsa_keypair(user_id, curve_name="secp256r1", key_name=None, password=None):
    """Generate an ECDSA key pair and save to Database."""
    curves = {
        "secp256r1": ec.SECP256R1(),
        "secp384r1": ec.SECP384R1(),
        "secp521r1": ec.SECP521R1(),
    }
    curve = curves.get(curve_name, ec.SECP256R1())
    
    private_key = ec.generate_private_key(curve)
    public_key = private_key.public_key()
    
    if not key_name:
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        key_name = f"ecdsa_{curve_name}_{timestamp}"
    
    encryption = BestAvailableEncryption(password.encode()) if password else NoEncryption()
    
    private_pem = private_key.private_bytes(
        encoding=Encoding.PEM,
        format=PrivateFormat.PKCS8,
        encryption_algorithm=encryption
    ).decode('utf-8')
    
    public_pem = public_key.public_bytes(
        encoding=Encoding.PEM,
        format=PublicFormat.SubjectPublicKeyInfo
    ).decode('utf-8')
    
    fingerprint = compute_key_fingerprint(public_pem.encode('utf-8'))
    
    key_record = KeyRecord(
        user_id=user_id,
        key_name=key_name,
        algorithm="ECDSA",
        key_size=curve_name,
        fingerprint=fingerprint,
        public_pem=public_pem,
        private_pem=private_pem
    )
    db.session.add(key_record)
    db.session.commit()
    
    return {
        "algorithm": "ECDSA",
        "curve": curve_name,
        "key_name": key_name,
        "fingerprint": fingerprint,
    }


def compute_key_fingerprint(public_pem_bytes):
    """Compute SHA-256 fingerprint of a public key's PEM bytes."""
    digest = hashlib.sha256(public_pem_bytes).hexdigest()
    return ":".join(digest[i:i+2] for i in range(0, 32, 2))


def load_private_key(key_name, user_id, password=None):
    """Load a private key from DB."""
    key_record = KeyRecord.query.filter_by(key_name=key_name, user_id=user_id).first()
    if not key_record:
        raise ValueError(f"Key {key_name} not found")
        
    pwd = password.encode() if password else None
    private_key = serialization.load_pem_private_key(key_record.private_pem.encode('utf-8'), password=pwd)
    return private_key


def load_public_key(key_name, user_id):
    """Load a public key from DB."""
    key_record = KeyRecord.query.filter_by(key_name=key_name, user_id=user_id).first()
    if not key_record:
        raise ValueError(f"Key {key_name} not found")
        
    public_key = serialization.load_pem_public_key(key_record.public_pem.encode('utf-8'))
    return public_key


def load_public_key_from_pem(pem_bytes):
    """Load a public key directly from PEM bytes."""
    return serialization.load_pem_public_key(pem_bytes)


def get_public_key_pem(key_name, user_id):
    """Get the raw PEM bytes of a public key."""
    key_record = KeyRecord.query.filter_by(key_name=key_name, user_id=user_id).first()
    if not key_record:
        raise ValueError(f"Key {key_name} not found")
    return key_record.public_pem.encode('utf-8')


def delete_key(key_name, user_id):
    """Delete a key pair from DB."""
    key_record = KeyRecord.query.filter_by(key_name=key_name, user_id=user_id).first()
    if key_record:
        db.session.delete(key_record)
        db.session.commit()
