"""Digital signatures with ECDSA P-256 (SHA-256)."""
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from crypto import aead

CURVE = ec.SECP256R1()  # P-256, 256-bit key
# AAD for the encrypted private key: stops a stored entry from being passed
# off as a private key (and the other way round).
PRIVKEY_AAD = b"inkchain-private-key-v1"


class SigningError(Exception):
    """Raised when a key cannot be loaded or has a wrong format."""


def generate_keypair():
    """Return (private_key, public_key). Randomness comes from the OS."""
    private_key = ec.generate_private_key(CURVE)
    return private_key, private_key.public_key()


# ---------- private key: stored ENCRYPTED ----------

def encrypt_private_key(private_key, enc_key: bytes) -> bytes:
    """Serialize the private key and encrypt it with AES-GCM."""
    raw = private_key.private_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),  # we encrypt it ourselves
    )
    return aead.encrypt(enc_key, raw, aad=PRIVKEY_AAD)


def decrypt_private_key(blob: bytes, enc_key: bytes):
    """Decrypt and load the private key. Wrong password -> DecryptionError."""
    raw = aead.decrypt(enc_key, blob, aad=PRIVKEY_AAD)
    try:
        key = serialization.load_der_private_key(raw, password=None)
    except ValueError:
        raise SigningError("invalid private key data") from None
    if not isinstance(key, ec.EllipticCurvePrivateKey):
        raise SigningError("not an EC private key")
    return key


# ---------- public key: stored in the clear ----------

def public_key_to_bytes(public_key) -> bytes:
    return public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def load_public_key(data: bytes):
    try:
        key = serialization.load_der_public_key(data)
    except ValueError:
        raise SigningError("invalid public key data") from None
    if not isinstance(key, ec.EllipticCurvePublicKey):
        raise SigningError("not an EC public key")
    return key


# ---------- sign / verify ----------

def sign(private_key, data: bytes) -> bytes:
    if not isinstance(data, bytes):
        raise ValueError("data must be bytes")
    return private_key.sign(data, ec.ECDSA(hashes.SHA256()))


def verify(public_key, signature: bytes, data: bytes) -> bool:
    """True if the signature is valid, False otherwise (never raises on bad input)."""
    if not isinstance(signature, bytes) or not isinstance(data, bytes):
        return False
    try:
        public_key.verify(signature, data, ec.ECDSA(hashes.SHA256()))
        return True
    except InvalidSignature:
        return False