"""
Hasher Module
=============
Computes SHA-256 hashes over raw binary file content.

IMPORTANT DESIGN DECISION:
    This module operates EXCLUSIVELY on raw bytes. It never parses, renders,
    or interprets file content. This ensures:
    1. Identical hashes on sender and receiver for the same bytes
    2. Verification works even for corrupted/unreadable files
    3. Integrity is checked at the BINARY level, not the content level
"""

import hashlib


# Chunk size for streaming hash computation (64 KB)
CHUNK_SIZE = 65536


def hash_file(file_path):
    """
    Compute SHA-256 hash of a file by reading its raw bytes.
    
    The file is read in binary mode ('rb') to ensure we hash the exact
    byte sequence. This works for ANY file type, including corrupted files
    that cannot be opened by normal viewers.
    
    Args:
        file_path: Path to the file to hash.
    
    Returns:
        Hex digest string of the SHA-256 hash.
    """
    sha256 = hashlib.sha256()
    
    with open(file_path, "rb") as f:
        while True:
            chunk = f.read(CHUNK_SIZE)
            if not chunk:
                break
            sha256.update(chunk)
    
    return sha256.hexdigest()


def hash_bytes(data):
    """
    Compute SHA-256 hash of raw bytes.
    
    Args:
        data: bytes object to hash.
    
    Returns:
        Hex digest string of the SHA-256 hash.
    """
    return hashlib.sha256(data).hexdigest()


def compare_hashes(hash1, hash2):
    """
    Compare two hash hex strings character by character.
    
    Returns a detailed comparison result showing which characters differ.
    This is used for the visual hash diff display in the demo.
    
    Args:
        hash1: First hash hex string (e.g., original hash).
        hash2: Second hash hex string (e.g., recomputed hash).
    
    Returns:
        dict with:
            - match: bool, True if hashes are identical
            - hash1: the first hash string
            - hash2: the second hash string
            - diff_positions: list of indices where characters differ
            - diff_count: number of differing characters
            - total_chars: total number of characters in the hash
    """
    diff_positions = []
    
    max_len = max(len(hash1), len(hash2))
    for i in range(max_len):
        c1 = hash1[i] if i < len(hash1) else ""
        c2 = hash2[i] if i < len(hash2) else ""
        if c1 != c2:
            diff_positions.append(i)
    
    return {
        "match": hash1 == hash2,
        "hash1": hash1,
        "hash2": hash2,
        "diff_positions": diff_positions,
        "diff_count": len(diff_positions),
        "total_chars": max_len,
    }
