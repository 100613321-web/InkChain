"""Password hashing and key derivation using scrypt."""
import os

from cryptography.exceptions import InvalidKey
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

SALT_LEN = 16  # 128-bit random salt
KEY_LEN = 32  # 256-bit output (AES-256 key / password hash)
SCRYPT_N = 2 ** 17  # cost: ~128 MiB of memory (OWASP minimum)
SCRYPT_R = 8  # block size
SCRYPT_P = 1  # parallelism


def generate_salt() -> bytes:
    """Return a fresh cryptographically secure random salt."""
    return os.urandom(SALT_LEN)


def _scrypt(salt: bytes) -> Scrypt:
    # A Scrypt object is single-use, so we build a new one every time.
    return Scrypt(salt=salt, length=KEY_LEN, n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P)


def _validate(password: str, salt: bytes) -> None:
    if not isinstance(password, str) or not password:
        raise ValueError("password must be a non-empty string")
    if not isinstance(salt, bytes) or len(salt) != SALT_LEN:
        raise ValueError(f"salt must be {SALT_LEN} bytes")


def hash_password(password: str, salt: bytes) -> bytes:
    """Hash for authentication. This is what gets stored on disk."""
    _validate(password, salt)
    return _scrypt(salt).derive(password.encode("utf-8"))


def verify_password(password: str, salt: bytes, expected_hash: bytes) -> bool:
    #Check a password. Scrypt.verify compares in constant time.
    _validate(password, salt)
    try:
        _scrypt(salt).verify(password.encode("utf-8"), expected_hash)
        return True
    except InvalidKey:
        return False


def derive_key(password: str, enc_salt: bytes) -> bytes:
    """256-bit AES key. Use a DIFFERENT salt than for hash_password.
    Never store this key; keep it in memory only."""
    _validate(password, enc_salt)
    return _scrypt(enc_salt).derive(password.encode("utf-8"))
