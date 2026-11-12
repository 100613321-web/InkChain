"""Authenticated encryption with AES-256-GCM.

GCM is an AEAD mode (authenticated encryption with associated data):
one operation gives us
  - confidentiality: nobody can read the data without the key
  - integrity + authenticity: any change to the data (or to the AAD)
    makes decryption fail, because the 16-byte tag no longer matches.

Stored format of one encrypted blob:
    | nonce (12 bytes) | ciphertext (same length as plaintext) | tag (16 bytes) |
"""
import os

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

KEY_LEN = 32      # 256-bit key -> "AES-256"
NONCE_LEN = 12    # 96-bit nonce: the size GCM is designed for
TAG_LEN = 16      # GCM appends a 128-bit authentication tag


class DecryptionError(Exception):
    """Raised when authentication fails or the data is malformed.

    One single error type for every data problem (wrong key, modified
    data, wrong AAD, too short), so upper layers only catch this one
    and the message leaks nothing useful to an attacker.
    """


def generate_nonce() -> bytes:
    """Fresh random nonce, taken from the OS secure random generator.

    Must be new for EVERY encryption: reusing a nonce with the same key
    breaks GCM (the XOR of two plaintexts leaks and tags can be forged).
    """
    return os.urandom(NONCE_LEN)


def _check_key(key: bytes) -> None:
    # Wrong key type/length is a programmer error -> ValueError,
    # not an attack -> not DecryptionError.
    if not isinstance(key, bytes) or len(key) != KEY_LEN:
        raise ValueError(f"key must be {KEY_LEN} bytes")


def encrypt(key: bytes, plaintext: bytes, aad: bytes = b"") -> bytes:
    """Encrypt and authenticate. Returns nonce || ciphertext || tag.

    aad = associated data: NOT encrypted, but covered by the tag.
    At decryption the same aad must be given, otherwise it fails.
    We use it to bind an entry to its position (index || prev_hash).
    """
    _check_key(key)
    if not isinstance(plaintext, bytes):
        raise ValueError("plaintext must be bytes")

    # The nonce is generated HERE so callers cannot reuse one by mistake.
    nonce = generate_nonce()

    # The library appends the 16-byte tag to the ciphertext for us.
    ct_and_tag = AESGCM(key).encrypt(nonce, plaintext, aad)

    # The nonce is not secret, but it is needed to decrypt: store it in front.
    return nonce + ct_and_tag


def decrypt(key: bytes, blob: bytes, aad: bytes = b"") -> bytes:
    """Verify the tag and decrypt. Raises DecryptionError on any failure."""
    _check_key(key)

    # Smallest valid blob = nonce + tag (encryption of an empty text).
    if not isinstance(blob, bytes) or len(blob) < NONCE_LEN + TAG_LEN:
        raise DecryptionError("data too short")

    # Split the blob back into its parts.
    nonce, ct_and_tag = blob[:NONCE_LEN], blob[NONCE_LEN:]

    try:
        # The library checks the tag FIRST; plaintext is returned only
        # if the tag is valid. Nothing is ever released on failure.
        return AESGCM(key).decrypt(nonce, ct_and_tag, aad)
    except InvalidTag:
        # Deliberately vague: do not reveal whether the key, the data
        # or the AAD was wrong. "from None" hides the internal traceback.
        raise DecryptionError("authentication failed") from None