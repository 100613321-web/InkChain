import pytest
from cryptography.hazmat.primitives import serialization

from crypto import aead, signing


# ---------- normal behaviour ----------

def test_sign_and_verify():
    priv, pub = signing.generate_keypair()
    sig = signing.sign(priv, b"hello")
    assert signing.verify(pub, sig, b"hello")


def test_key_is_p256():
    priv, pub = signing.generate_keypair()
    assert pub.curve.name == "secp256r1"
    assert pub.curve.key_size == 256


def test_two_signatures_of_same_data_differ():
    # ECDSA picks a random k for every signature, so two signatures of the
    # same data look different. Both must still verify.
    priv, pub = signing.generate_keypair()
    s1, s2 = signing.sign(priv, b"hello"), signing.sign(priv, b"hello")
    assert s1 != s2
    assert signing.verify(pub, s1, b"hello") and signing.verify(pub, s2, b"hello")


def test_public_key_roundtrip():
    # what we store in users.json has to come back as a working key
    priv, pub = signing.generate_keypair()
    pub2 = signing.load_public_key(signing.public_key_to_bytes(pub))
    assert signing.verify(pub2, signing.sign(priv, b"x"), b"x")


def test_private_key_roundtrip():
    priv, pub = signing.generate_keypair()
    key = b"\x01" * 32
    blob = signing.encrypt_private_key(priv, key)
    priv2 = signing.decrypt_private_key(blob, key)
    assert signing.verify(pub, signing.sign(priv2, b"x"), b"x")


def test_encrypted_private_key_does_not_contain_plain_key():
    # quick sanity check that we really store it encrypted and not just encoded
    priv, _ = signing.generate_keypair()
    raw = priv.private_bytes(
        serialization.Encoding.DER,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    blob = signing.encrypt_private_key(priv, b"\x01" * 32)
    assert raw not in blob
    assert raw[-32:] not in blob  # the raw 32-byte secret number isn't visible either


# ---------- negative tests: signatures ----------

def test_modified_data_rejected():
    priv, pub = signing.generate_keypair()
    sig = signing.sign(priv, b"hello")
    assert not signing.verify(pub, sig, b"hellO")


def test_modified_signature_rejected():
    # this is the test to screenshot for the report ("tampered signature rejected")
    priv, pub = signing.generate_keypair()
    sig = bytearray(signing.sign(priv, b"hello"))
    sig[-1] ^= 1  # flip one bit
    assert not signing.verify(pub, bytes(sig), b"hello")


def test_wrong_public_key_rejected():
    priv, _ = signing.generate_keypair()
    _, other_pub = signing.generate_keypair()
    sig = signing.sign(priv, b"hello")
    assert not signing.verify(other_pub, sig, b"hello")


@pytest.mark.parametrize("sig", [b"", b"garbage", None])
def test_garbage_signature_returns_false_and_does_not_crash(sig):
    # verify() should answer False for junk, never blow up
    _, pub = signing.generate_keypair()
    assert signing.verify(pub, sig, b"hello") is False


# ---------- negative tests: stored private key ----------

def test_wrong_password_cannot_load_private_key():
    # wrong password -> wrong key -> GCM tag fails, key never comes out
    priv, _ = signing.generate_keypair()
    blob = signing.encrypt_private_key(priv, b"\x01" * 32)
    with pytest.raises(aead.DecryptionError):
        signing.decrypt_private_key(blob, b"\x02" * 32)


def test_tampered_private_key_blob_rejected():
    priv, _ = signing.generate_keypair()
    key = b"\x01" * 32
    blob = bytearray(signing.encrypt_private_key(priv, key))
    blob[20] ^= 1
    with pytest.raises(aead.DecryptionError):
        signing.decrypt_private_key(bytes(blob), key)


def test_blob_with_other_aad_cannot_be_used_as_private_key():
    # something encrypted with the same key but for another purpose (like the
    # DEK) must not be accepted as a private key. That's what the AAD is for.
    key = b"\x01" * 32
    fake = aead.encrypt(key, b"\x00" * 32, aad=b"inkchain-diary-key-v1")
    with pytest.raises(aead.DecryptionError):
        signing.decrypt_private_key(fake, key)


def test_load_public_key_garbage_raises_signing_error():
    with pytest.raises(signing.SigningError):
        signing.load_public_key(b"not a key")

