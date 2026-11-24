"""Password hashing and key derivation with scrypt."""
import os

from cryptography.exceptions import InvalidKey
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

SALT_LEN = 16       # 128-bit random salt
KEY_LEN = 32        # 256-bit output (password hash / AES-256 key)
SCRYPT_N = 2 ** 17  # CPU/memory cost, about 128 MiB of RAM (OWASP minimum)
SCRYPT_R = 8        # block size
SCRYPT_P = 1        # parallelism


def generate_salt() -> bytes:
    """Fresh random salt from the OS."""
    return os.urandom(SALT_LEN)


def _scrypt(salt: bytes) -> Scrypt:
    # A Scrypt object can only be used once, so we make a new one each time.
    # SCRYPT_N is read here (not at import) so tests can lower it.
    return Scrypt(salt=salt, length=KEY_LEN, n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P)


def _validate(password: str, salt: bytes) -> None:
    # Bad input here is a bug in the caller, so ValueError and not an auth error.
    if not isinstance(password, str) or not password:
        raise ValueError("password must be a non-empty string")
    if not isinstance(salt, bytes) or len(salt) != SALT_LEN:
        raise ValueError(f"salt must be {SALT_LEN} bytes")


def hash_password(password: str, salt: bytes) -> bytes:
    """Hash used to check the login. This is what we store on disk."""
    _validate(password, salt)
    return _scrypt(salt).derive(password.encode("utf-8"))


def verify_password(password: str, salt: bytes, expected_hash: bytes) -> bool:
    """Check a password. Scrypt.verify compares in constant time."""
    _validate(password, salt)
    try:
        _scrypt(salt).verify(password.encode("utf-8"), expected_hash)
        return True
    except InvalidKey:
        return False


def derive_key(password: str, enc_salt: bytes) -> bytes:
    """Derive the 256-bit key that protects the user's other keys.

    Needs a DIFFERENT salt than hash_password, otherwise the stored hash
    would be the key itself. Never write this key to disk.
    """
    _validate(password, enc_salt)
    return _scrypt(enc_salt).derive(password.encode("utf-8"))