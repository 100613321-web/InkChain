"""Authenticated encryption with AES-256-GCM."""
import os

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

KEY_LEN = 32      # 256-bit key
NONCE_LEN = 12    # 96-bit nonce, the size GCM is designed for
TAG_LEN = 16      # GCM appends a 128-bit tag to the ciphertext


class DecryptionError(Exception):
    """Raised when authentication fails or the data is malformed."""


def generate_nonce() -> bytes:
    """Fresh random nonce. Must be new for EVERY encryption."""
    return os.urandom(NONCE_LEN)


def _check_key(key: bytes) -> None:
    if not isinstance(key, bytes) or len(key) != KEY_LEN:
        raise ValueError(f"key must be {KEY_LEN} bytes")


def encrypt(key: bytes, plaintext: bytes, aad: bytes = b"") -> bytes:
    """Return nonce || ciphertext || tag."""
    _check_key(key)
    if not isinstance(plaintext, bytes):
        raise ValueError("plaintext must be bytes")
    nonce = generate_nonce()
    ct_and_tag = AESGCM(key).encrypt(nonce, plaintext, aad)
    return nonce + ct_and_tag


def decrypt(key: bytes, blob: bytes, aad: bytes = b"") -> bytes:
    """Verify the tag and decrypt. Raises DecryptionError on any failure."""
    _check_key(key)
    if not isinstance(blob, bytes) or len(blob) < NONCE_LEN + TAG_LEN:
        raise DecryptionError("data too short")
    nonce, ct_and_tag = blob[:NONCE_LEN], blob[NONCE_LEN:]
    try:
        return AESGCM(key).decrypt(nonce, ct_and_tag, aad)
    except InvalidTag:
        # Deliberately vague: do not reveal whether key, data or AAD was wrong.
        raise DecryptionError("authentication failed") from None