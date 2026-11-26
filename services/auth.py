"""Registration, login, lockout and unlocking of the user's keys.

How the keys are organised (this is the part to explain in the defense):

  password --scrypt + password_salt--> password_hash   (stored, only used to check the login)
  password --scrypt + enc_salt------> KEK              (never stored, lives in memory)
  KEK encrypts a random DEK  (the key that encrypts the diary entries)
  KEK encrypts the ECDSA private key (used to sign entries)

Two different salts so the stored hash can never be used as the KEK.
The DEK is random and independent of the password, so a password change
would only need to re-encrypt the DEK, not every entry.
"""
import base64
import binascii
import os
import re
import time

from dataclasses import dataclass
from storage.files import load_users, save_users, StorageError
from crypto.kdf import generate_salt, hash_password, verify_password, derive_key
from crypto import aead, signing, chain
from services.diary import make_head

MAX_FAILED_ATTEMPTS = 5     # wrong passwords before the account gets locked
LOCKOUT_SECONDS = 300       # lock lasts 5 minutes
DEK_LEN = 32                # 256-bit diary key
# AAD used when encrypting the DEK: so this blob can't be passed off as
# something else encrypted with the same key (e.g. the private key)
DEK_AAD = b"inkchain-diary-key-v1"

MIN_USERNAME_LEN = 3
MAX_USERNAME_LEN = 32
USERNAME_PATTERN = re.compile(r"^[a-z0-9_.-]+$")
MIN_PASSWORD_LEN = 10
MAX_PASSWORD_LEN = 128      # upper limit so nobody can send a huge password to scrypt

# Just a small demo list. A real app would check against a big leaked-passwords list.
COMMON_PASSWORDS = {
    "password12", "password123", "password1234", "passw0rd123", "1234567890",
    "12345678910", "qwertyuiop", "qwerty12345", "iloveyou123", "letmein1234",
    "administrator", "welcome1234", "abc1234567", "changeme123",
}


class AuthError(Exception):
    """Registration, login or key unlocking failed."""


@dataclass
class AuthenticatedSession:
    """What a logged-in user holds in memory. Nothing here is ever written to disk."""
    username: str
    dek: bytes                    # key that encrypts the diary entries
    signing_private_key: object   # signs the entries
    signing_public_key: object    # verifies them
    closed: bool = False

    def close(self) -> None:
        """Logout: drop every reference to the keys.

        Honest limit (goes in the report): Python bytes can't be wiped from
        memory on purpose, so this only removes our references. The garbage
        collector frees them later.
        """
        self.dek = None
        self.signing_private_key = None
        self.signing_public_key = None
        self.closed = True


# Small wrappers: the storage layer raises StorageError, but the user of
# this module should only have to know about AuthError.
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


# ---------- input checks ----------

def check_password(password, username: str = "") -> None:
    """Refuse weak passwords. Raises AuthError with the reason."""
    if not isinstance(password, str) or len(password) < MIN_PASSWORD_LEN:
        raise AuthError(f"Password must be at least {MIN_PASSWORD_LEN} characters long.")
    if len(password) > MAX_PASSWORD_LEN:
        raise AuthError(f"Password can't be longer than {MAX_PASSWORD_LEN} characters.")

    lower = password.lower()
    if lower in COMMON_PASSWORDS:
        raise AuthError("Password used is too common.")
    if username and username in lower:
        raise AuthError("Password must not contain the username.")

    # count how many kinds of characters it mixes (lower, upper, digits, symbols)
    classes = sum([
        any(c.islower() for c in password),
        any(c.isupper() for c in password),
        any(c.isdigit() for c in password),
        any(not c.isalnum() for c in password),
    ])

    if classes < 3:
        raise AuthError("Password must mix at least 3 of: lowercase, uppercase, digits, symbols.")


def normalize_username(username) -> str:
    """Clean the username (trim, lowercase) and refuse invalid ones."""
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


# ---------- registration ----------

def register_user(username: str, password: str) -> None:
    """Create a new account with all its keys."""
    username = normalize_username(username)
    check_password(password, username)

    users = auth_load_users()
    if username in users:
        raise AuthError("Username is already registered, please pick another.")

    # 1) hash for checking the login (first salt)
    password_salt = generate_salt()
    password_hash = hash_password(password, password_salt)

    # 2) key-encryption key, from the same password but a DIFFERENT salt
    enc_salt = generate_salt()
    key_encryption_key = derive_key(password, enc_salt)

    # 3) random diary key, stored only encrypted by the KEK
    dek = os.urandom(DEK_LEN)
    encrypted_dek = aead.encrypt(key_encryption_key, dek, aad=DEK_AAD)

    # 4) signing key pair, the private half is stored only encrypted by the KEK
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
        # signed "this diary has 0 entries", so deleting the last entries later can be noticed
        "diary_head": make_head(private_key, 0, chain.GENESIS_HASH),
        "failed_attempts": 0,
        "locked_until": None
    }
    auth_save_users(users)


# ---------- login ----------

def check_locked(user: dict) -> None:
    """Refuse the login while the account is locked. An expired lock gets cleared."""
    locked_until = user.get("locked_until")

    if locked_until is None:
        return
    if type(locked_until) not in (int, float):
        # someone edited the file and put garbage here
        raise AuthError("The account data is invalid.")

    remaining_time = locked_until - time.time()

    if remaining_time > 0:
        remaining_seconds = int(remaining_time) + 1
        raise AuthError(f"Account temporarily locked. Try again in {remaining_seconds} seconds.")

    # the lock is over: start fresh
    user["failed_attempts"] = 0
    user["locked_until"] = None


def login_user(username: str, password: str) -> AuthenticatedSession:
    """Check the password and unlock the user's keys. Returns the session."""
    if not isinstance(username, str):
        raise AuthError("Invalid username or password.")

    # an empty or non-text password gets the same vague message as a wrong one
    if not isinstance(password, str) or not password:
        raise AuthError("Invalid username or password.")

    username = username.strip().lower()
    users = auth_load_users()

    # same message for "no such user" and "wrong password", so nobody can
    # use the login to find out which usernames exist
    if username not in users:
        raise AuthError("Invalid username or password.")

    user = users[username]
    if not isinstance(user, dict):
        raise AuthError("The account data is invalid.")

    check_locked(user)

    # --- 1. is the password right? ---
    try:
        password_salt = bytes.fromhex(user["password_salt"])
        stored_hash = bytes.fromhex(user["password_hash"])
        password_correct = verify_password(password, password_salt, stored_hash)

    except (KeyError, ValueError, TypeError):
        raise AuthError("Account data is invalid.") from None

    if not password_correct:
        # count the failure, and lock the account after too many
        attempts = user.get("failed_attempts", 0)
        user["failed_attempts"] = (attempts if type(attempts) is int else 0) + 1

        if user["failed_attempts"] >= MAX_FAILED_ATTEMPTS:
            user["locked_until"] = time.time() + LOCKOUT_SECONDS
            auth_save_users(users)
            raise AuthError("Too many failed login attempts. Your account is locked for 5 minutes.")

        auth_save_users(users)
        raise AuthError("Invalid username or password.")

    # --- 2. password is right: rebuild the KEK in memory ---
    try:
        enc_salt = bytes.fromhex(user["enc_salt"])
        key_encryption_key = derive_key(password, enc_salt)

    except (KeyError, ValueError, TypeError):
        raise AuthError("Account encryption data is invalid.") from None

    # --- 3. unlock the diary key (the GCM tag also proves it wasn't edited) ---
    try:
        encrypted_dek = base64.b64decode(user["encrypted_dek"], validate=True)
        dek = aead.decrypt(key_encryption_key, encrypted_dek, aad=DEK_AAD)

    except (KeyError, ValueError, TypeError, binascii.Error, aead.DecryptionError):
        raise AuthError("Diary encryption key could not be unlocked.") from None
    if len(dek) != DEK_LEN:
        raise AuthError("Invalid diary encryption key.")

    # --- 4. unlock the signing key ---
    try:
        encrypted_private_key = base64.b64decode(user["encrypted_private_key"], validate=True)
        private_key = signing.decrypt_private_key(encrypted_private_key, key_encryption_key)

    except (KeyError, ValueError, TypeError, binascii.Error, aead.DecryptionError, signing.SigningError):
        raise AuthError("Signing key could not be unlocked.") from None

    # --- 5. the public key is computed from the private one. The copy stored
    # on disk must match it, otherwise someone swapped it to fake signatures ---
    public_key = private_key.public_key()
    try:
        stored_public_key = base64.b64decode(user["public_key"], validate=True)
    except (KeyError, ValueError, TypeError, binascii.Error):
        raise AuthError("Public signing key is invalid.") from None
    if stored_public_key != signing.public_key_to_bytes(public_key):
        raise AuthError("The stored public key doesn't match the private key. The account may have been tampered with.")

    # everything worked: reset the failure counter
    user["failed_attempts"] = 0
    user["locked_until"] = None
    auth_save_users(users)
    return AuthenticatedSession(username=username, dek=dek, signing_private_key=private_key, signing_public_key=public_key)
