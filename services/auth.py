"""Handles registration, login, lockout and key unlocking."""
import base64
import binascii
import os
import time
import re

from dataclasses import dataclass
from storage.files import load_users, save_users, StorageError
from crypto.kdf import generate_salt, hash_password, verify_password, derive_key
from crypto import aead, signing, chain
from services.diary import make_head

MAX_FAILED_ATTEMPTS = 5
LOCKOUT_SECONDS = 300
DEK_LEN = 32
DEK_AAD = b"inkchain-diary-key-v1" #AAD for encrypting the diary encrpytion key (domain separation)

MIN_USERNAME_LEN = 3
MAX_USERNAME_LEN = 32
USERNAME_PATTERN = re.compile(r"^[a-z0-9_.-]+$")
MIN_PASSWORD_LEN = 10
MAX_PASSWORD_LEN = 128

#Just a demo list, try finding a bigger one.
COMMON_PASSWORDS = {
    "password12", "password123", "password1234", "passw0rd123", "1234567890",
    "12345678910", "qwertyuiop", "qwerty12345", "iloveyou123", "letmein1234",
    "administrator", "welcome1234", "abc1234567", "changeme123",
}
class AuthError(Exception):
    """Raised when the registration, login or key unlocking has failed."""

@dataclass
class AuthenticatedSession:
    """Contains the keys available to a successfully authenticated user."""
    username: str
    dek: bytes
    signing_private_key: object
    signing_public_key: object
    closed: bool = False

    def close(self) -> None:
        """Needed to drop every reference to the keys when logging out. Limit to this approach mentioned in report."""
        self.dek = None
        self.signing_private_key = None
        self.signing_public_key = None
        self.closed = True

#Wrappers to get from StorageError to AuthError
def auth_load_users() -> dict:
    try:
        return load_users()
    except StorageError:
        raise AuthError("User data could not be read.") from None


def auth_save_users(users: dict) -> None:
    try:
        save_users(users)
    except StorageError:
        raise AuthError("User data could not be saved.") from None

#Functions to validate usernames and passwords.

def check_password(password, username: str = "") -> None:
    """Will raise an AuthError if password is too weak."""
    if not isinstance(password, str) or len(password) < MIN_PASSWORD_LEN:
        raise AuthError(f"Password must be at least {MIN_PASSWORD_LEN} characters long.")
    if len(password) > MAX_PASSWORD_LEN:
        raise AuthError(f"Password can't be longer than {MAX_PASSWORD_LEN} characters.")

    lower = password.lower()
    if lower in COMMON_PASSWORDS:
        raise AuthError("Password used is too common.")
    if username and username in lower:
        raise AuthError("Password must not contain the username.")

    classes = sum([
        any(c.islower() for c in password),
        any(c.isupper() for c in password),
        any(c.isdigit() for c in password),
        any(not c.isalnum() for c in password),
    ])

    if classes < 3:
        raise AuthError("Password must mix at least 3 of: lowercase, uppercase, digits, symbols.")

def normalize_username(username) -> str:
    """Will raise an AuthError is username is not valid."""
    if not isinstance(username, str):
        raise AuthError("Username must be text.")
    username = username.strip().lower()
    if not username:
        raise AuthError("Username can't be empty.")
    if len(username) < MIN_USERNAME_LEN:
        raise AuthError(f"Username must be at least {MIN_USERNAME_LEN} characters long.")
    if len(username) > MAX_USERNAME_LEN:
        raise AuthError(f"Username can't be longer than {MAX_USERNAME_LEN} characters.")
    if not USERNAME_PATTERN.match(username):
        raise AuthError("Username may only contain letters, digits, '.', '_' and '-'.")
    return username

def register_user(username: str, password: str) -> None:
    """Registers a new user."""
    
    username = normalize_username(username)
    check_password(password, username)

    users = auth_load_users()
    if username in users:
        raise AuthError("Username is already registered, please pick another.")

    password_salt = generate_salt()
    password_hash = hash_password(password, password_salt)

    enc_salt = generate_salt()
    key_encryption_key = derive_key(password, enc_salt)

    dek = os.urandom(DEK_LEN)
    encrypted_dek = aead.encrypt(key_encryption_key, dek, aad=DEK_AAD)

    private_key, public_key = signing.generate_keypair()
    encrypted_private_key = signing.encrypt_private_key(private_key, key_encryption_key)
    public_key_bytes = signing.public_key_to_bytes(public_key)

    users[username] = {
        "password_salt": password_salt.hex(),
        "password_hash": password_hash.hex(),
        "enc_salt": enc_salt.hex(),
        "encrypted_dek": base64.b64encode(encrypted_dek).decode("ascii"),
        "encrypted_private_key": base64.b64encode(encrypted_private_key).decode("ascii"),
        "public_key": base64.b64encode(public_key_bytes).decode("ascii"),
        "diary_head": make_head(private_key, 0, chain.GENESIS_HASH),
        "failed_attempts": 0,
        "locked_until": None
    }
    auth_save_users(users)

def check_locked(user: dict) -> None:
    """Checks if the account is locked and unlocks an expired lock."""
    locked_until = user.get("locked_until")
    
    if locked_until is None:
        return

    remaining_time = locked_until - time.time()

    if remaining_time > 0:
        remaining_seconds = int(remaining_time) + 1
        raise AuthError (f"Account temporarily locked. Try again in {remaining_seconds} seconds.")

    user["failed_attempts"] = 0
    user["locked_until"] = None


def login_user(username: str, password: str) -> AuthenticatedSession:
    if not isinstance(username, str):
        raise AuthError("Invalid username or password.")

    if not isinstance(password, str):
        raise AuthError("Invalid username or password.")
    
    username = username.strip().lower()
    users = auth_load_users()

    if username not in users:
        raise AuthError("Invalid username or password.")

    user = users[username]
    if not isinstance(user, dict):
        raise AuthError("The account data is invalid.")

    check_locked(user)

    try:
        password_salt = bytes.fromhex(user["password_salt"])
        stored_hash = bytes.fromhex(user["password_hash"])
        password_correct = verify_password(password, password_salt, stored_hash)

    except (KeyError, ValueError, TypeError):
        raise AuthError("Account data is invalid.") from None

    if not password_correct:
        attempts = user.get("failed_attempts", 0)
        user["failed_attempts"] = (attempts if type(attempts) is int else 0) + 1

        if user["failed_attempts"] >= MAX_FAILED_ATTEMPTS:
            user["locked_until"] = time.time() + LOCKOUT_SECONDS
            auth_save_users(users)
            raise AuthError("Too many failed login attempts. Your account is locked for 5 minutes.")

        auth_save_users(users)
        raise AuthError("Invalid username or password.")

    try:
        enc_salt = bytes.fromhex(user["enc_salt"])
        key_encryption_key = derive_key(password, enc_salt)

    except (KeyError, ValueError, TypeError):
        raise AuthError("Account encryption data is invalid.") from None

    try:
        encrypted_dek = base64.b64decode(user["encrypted_dek"], validate=True)
        dek = aead.decrypt(key_encryption_key, encrypted_dek, aad=DEK_AAD)

    except (KeyError, ValueError, TypeError, binascii.Error, aead.DecryptionError):
        raise AuthError("Diary encryption key could not be unlocked.") from None
    if len(dek) != DEK_LEN:
        raise AuthError("Invalid diary encryption key.")

    try:
        encrypted_private_key = base64.b64decode(user["encrypted_private_key"], validate=True)
        private_key = signing.decrypt_private_key(encrypted_private_key, key_encryption_key)

    except (KeyError, ValueError, TypeError, binascii.Error, aead.DecryptionError, signing.SigningError):
        raise AuthError("Signing key could not be unlocked.") from None

    public_key = private_key.public_key()
    try:
        stored_public_key = base64.b64decode(user["public_key"], validate=True)
    except (KeyError, ValueError, TypeError, binascii.Error):
        raise AuthError("Public signing key is invalid.") from None
    if stored_public_key != signing.load_public_key(public_key):
        raise AuthError("The stored public key doesn't match the private key. The account may have been tampered with.")
    
    user["failed_attempts"] = 0
    user["locked_until"] = None
    auth_save_users(users)
    return AuthenticatedSession(username=username, dek=dek, signing_private_key=private_key, signing_public_key=public_key)
