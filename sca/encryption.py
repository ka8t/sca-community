"""
Chiffrement / dechiffrement des regles builtin — 100% stdlib.

Algorithme : HMAC-SHA256 stream cipher + Encrypt-then-MAC.
  - Keystream genere par HMAC-SHA256 en mode compteur (nonce + counter)
  - Chiffrement XOR du plaintext avec le keystream (comme AES-CTR)
  - Authentification via HMAC-SHA256(key_mac, nonce + ciphertext)
  - Cle derivee de la signature RSA via HKDF-SHA256 (RFC 5869)

Format du blob : nonce (12 octets) + tag HMAC (32 octets) + ciphertext.

Pas de dependance externe : utilise uniquement hmac, hashlib, os (stdlib).
Compatible build-time (AuditDistrib) et runtime (binaire compile).
"""
import hashlib
import hmac as _hmac
import json
import logging
import os
from typing import Optional

logger = logging.getLogger("sca.encryption")


# =========================================================================
# KEY DERIVATION — HKDF-SHA256 (RFC 5869)
# =========================================================================

def derive_key(ikm: bytes, salt: bytes = b"sca_builtin_rules_v1",
               info: bytes = b"aes-256-gcm", length: int = 32) -> bytes:
    """Derive a key from a secret via HKDF-SHA256 (RFC 5869, stdlib only)."""
    if not salt:
        salt = b"\x00" * 32
    prk = _hmac.new(salt, ikm, hashlib.sha256).digest()
    n = (length + 31) // 32
    okm = b""
    t = b""
    for i in range(1, n + 1):
        t = _hmac.new(prk, t + info + bytes([i]), hashlib.sha256).digest()
        okm += t
    return okm[:length]


# =========================================================================
# CHIFFREMENT / DECHIFFREMENT — HMAC-SHA256 STREAM CIPHER + MAC
# =========================================================================

def _derive_keys(master_key: bytes):
    """Derive an (enc_key, mac_key) pair from the master key."""
    enc_key = _hmac.new(master_key, b"enc", hashlib.sha256).digest()
    mac_key = _hmac.new(master_key, b"mac", hashlib.sha256).digest()
    return enc_key, mac_key


def _keystream(key: bytes, nonce: bytes, length: int) -> bytes:
    """Generate a pseudo-random keystream via HMAC-SHA256 in counter mode."""
    stream = bytearray()
    counter = 0
    while len(stream) < length:
        block = _hmac.new(key, nonce + counter.to_bytes(4, "big"), hashlib.sha256).digest()
        stream.extend(block)
        counter += 1
    return bytes(stream[:length])


def _xor_bytes(a: bytes, b: bytes) -> bytes:
    """XOR two byte sequences of equal length."""
    return bytes(x ^ y for x, y in zip(a, b))


def encrypt_blob(data: dict, key: bytes) -> bytes:
    """Encrypt a dict into an authenticated blob (HMAC-SHA256 stream + MAC).

    Output format: nonce (12 bytes) + HMAC tag (32 bytes) + ciphertext.
    """
    enc_key, mac_key = _derive_keys(key)

    plaintext = json.dumps(data, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    nonce = os.urandom(12)

    stream = _keystream(enc_key, nonce, len(plaintext))
    ciphertext = _xor_bytes(plaintext, stream)

    tag = _hmac.new(mac_key, nonce + ciphertext, hashlib.sha256).digest()

    return nonce + tag + ciphertext


def decrypt_blob(blob: bytes, key: bytes) -> Optional[dict]:
    """Decrypt an authenticated blob back into a rules dict.

    Verifies the HMAC tag before decrypting (Encrypt-then-MAC). Returns
    None if the blob is malformed, the key is wrong, or the data is corrupt.
    """
    # Minimum size: nonce (12) + tag (32) + at least 1 byte
    if len(blob) < 45:
        logger.warning("Blob trop court pour etre valide")
        return None

    nonce = blob[:12]
    tag = blob[12:44]
    ciphertext = blob[44:]

    enc_key, mac_key = _derive_keys(key)

    # Verify authenticity BEFORE decryption
    expected_tag = _hmac.new(mac_key, nonce + ciphertext, hashlib.sha256).digest()
    if not _hmac.compare_digest(tag, expected_tag):
        logger.warning("Dechiffrement echoue (tag HMAC invalide — cle incorrecte ou blob corrompu)")
        return None

    stream = _keystream(enc_key, nonce, len(ciphertext))
    plaintext = _xor_bytes(ciphertext, stream)

    try:
        return json.loads(plaintext.decode("utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError) as e:
        logger.warning("Dechiffrement echoue (JSON invalide apres dechiffrement) : %s", e)
        return None


# =========================================================================
# WATERMARK
# =========================================================================

def compute_watermark(license_signature: str) -> str:
    """Compute the unique watermark hash for a customer."""
    return hashlib.sha256(
        license_signature[:64].encode() + b"|builtin_rules_v1"
    ).hexdigest()
