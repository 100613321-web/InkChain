import base64
import binascii
import os

from dataclasses import dataclass
from storage.files import load_users, save_users
from crypto.kdf import generate_salt, hash_password, verify_password, derive_key
from crypto import aead, signing

MAX_FAILED_ATTEMPTS = 5 #is that too much? maybe 3 is better?
DEK_LEN = 32
DEK_AAD = b"inkchain-diary-key-v1" #additional authenticated data for encrypting the diary encrpytion key

class AuthError(Exception):
    """Raised when the registration, login or key unlocking has failed."""

@dataclass
class AuthenticatedSession:
    #contains the keys available to a successfully authenticated user.
    username: str
    dek: bytes
    signing_private_key: object
    signing_public_key: object

def register_user(username: str, password: str) -> None:
    if not isinstance(username, str):
        raise AuthError("Username must be text.^")
    
    username = username.strip().lower()

    if not username:
        raise AuthError("Username can't be empty.")

    if len(username) < 3:
        raise AuthError("Username must be at least 3 characters long.")

    if not isinstance(password, str) or len(password) < 8:
        raise AuthError("Password must be at least 8 characters long.")

    users = load_users()

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
        "failed_attempts": 0,
        "locked": False #currently locking user after 5 failed attempts, keep?
    }
    save_users(users)

def login_user(username: str, password: str) -> AuthenticatedSession:
    if not isinstance(username, str):
        raise AuthError("Invalid username or password.")

    if not isinstance(password, str):
        raise AuthError("Invalid username or password.")
    
    username = username.strip().lower()
    users = load_users()

    if username not in users:
        raise AuthError("Invalid username or password.")

    user = users[username]

    if user.get("locked", False):
        raise AuthError("This account has been locked.")

    try:
        password_salt = bytes.fromhex(user["password_salt"])
        stored_hash = bytes.fromhex(user["password_hash"])

        password_correct = verify_password(password, password_salt, stored_hash)

    except (KeyError, ValueError, TypeError):
        raise AuthError("Account data is invalid.") from None

    if not password_correct:
        user["failed_attempts"] = user.get("failed_attempts", 0) + 1

        if user["failed_attempts"] >= MAX_FAILED_ATTEMPTS:
            user["locked"] = True

        save_users(users)

        raise AuthError("Invalid username or password.")

    try:
        enc_salt = bytes.fromhex(user["enc_salt"])
        key_encryption_key = derive_key(password, enc_salt)

    except (KeyError, ValueError, TypeError):
        raise AuthError("Account encryption data is invalid.") from None

    try:
        encrypted_dek = base64.b64decode(user["encrypted_dek"], validate=True)
        dek = aead.decrypt(key_encryption_key, encrypted_dek, aad=DEK_AAD)

        if len(dek) != DEK_LEN:
            raise AuthError("Invalid diary encryption key.")

    except (KeyError, ValueError, TypeError, binascii.Error, aead.DecryptionError):
        raise AuthError("Diary encryption key could not be unlocked.") from None

    try:
        encrypted_private_key = base64.b64decode(user["encrypted_private_key"], validate=True)
        private_key = signing.decrypt_private_key(encrypted_private_key, key_encryption_key)

    except (KeyError, ValueError, TypeError, binascii.Error, aead.DecryptionError, signing.SigningError):
        raise AuthError("Signing key could not be unlocked.") from None

    try:
        public_key_bytes = base64.b64decode(user["public_key"], validate=True)
        public_key = signing.load_public_key(public_key_bytes)

    except (KeyError, ValueError, TypeError, binascii.Error, signing.SigningError):
        raise AuthError("Public signing key is invalid.") from None
    

    user["failed_attempts"] = 0
    save_users(users)
    return AuthenticatedSession(username=username, dek=dek, signing_private_key=private_key, signing_public_key=public_key)
