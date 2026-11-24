"""Authenticated encryption with AES-256-GCM.

GCM is an AEAD mode, so one call gives us two things:
  - confidentiality: no key, no reading
  - integrity: if the ciphertext, the tag or the AAD change by even one
    bit, decryption fails.

Layout of one encrypted blob:
    | nonce (12 bytes) | ciphertext (same length as plaintext) | tag (16 bytes) |
"""
import os

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

KEY_LEN = 32     # 256-bit key -> AES-256
NONCE_LEN = 12   # 96 bits, the size GCM is built for
TAG_LEN = 16     # 128-bit authentication tag


class DecryptionError(Exception):
    """Any problem with the data: wrong key, tampering, wrong AAD, too short.

    Only one error type on purpose, so callers catch one thing and the
    message doesn't tell an attacker what exactly went wrong.
    """


def generate_nonce() -> bytes:
    """New random nonce from the OS.

    It has to be new for EVERY encryption. Reusing a nonce with the same key
    leaks the XOR of the plaintexts and lets an attacker forge tags.
    """
    return os.urandom(NONCE_LEN)


def _check_key(key: bytes) -> None:
    # A wrong key size is a programming mistake, not an attack -> ValueError.
    if not isinstance(key, bytes) or len(key) != KEY_LEN:
        raise ValueError(f"key must be {KEY_LEN} bytes")


def encrypt(key: bytes, plaintext: bytes, aad: bytes = b"") -> bytes:
    """Encrypt and authenticate. Returns nonce || ciphertext || tag.

    aad is associated data: it stays readable but the tag covers it, so
    decryption needs the exact same value. We use it to tie an entry to its
    position (index || prev_hash).
    """
    _check_key(key)
    if not isinstance(plaintext, bytes):
        raise ValueError("plaintext must be bytes")

    # The nonce is made in here so a caller can never pass in a reused one.
    nonce = generate_nonce()

    # The library puts the 16-byte tag at the end of the ciphertext for us.
    ct_and_tag = AESGCM(key).encrypt(nonce, plaintext, aad)

    # The nonce isn't secret, we just need it later, so it goes in front.
    return nonce + ct_and_tag


def decrypt(key: bytes, blob: bytes, aad: bytes = b"") -> bytes:
    """Check the tag, then decrypt. Raises DecryptionError if anything is off."""
    _check_key(key)

    # Shortest valid blob is nonce + tag (an empty message).
    if not isinstance(blob, bytes) or len(blob) < NONCE_LEN + TAG_LEN:
        raise DecryptionError("data too short")

    nonce, ct_and_tag = blob[:NONCE_LEN], blob[NONCE_LEN:]

    try:
        # The tag is checked first, plaintext only comes out if it matches.
        return AESGCM(key).decrypt(nonce, ct_and_tag, aad)
    except InvalidTag:
        # Vague on purpose. "from None" drops the internal traceback.
        raise DecryptionError("authentication failed") from None