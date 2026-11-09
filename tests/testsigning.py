import pytest
from crypto import signing, aead


def test_sign_and_verify():
    priv, pub = signing.generate_keypair()
    sig = signing.sign(priv, b"hello")
    assert signing.verify(pub, sig, b"hello")


def test_modified_data_rejected():
    priv, pub = signing.generate_keypair()
    sig = signing.sign(priv, b"hello")
    assert not signing.verify(pub, sig, b"hellO")


def test_modified_signature_rejected():
    priv, pub = signing.generate_keypair()
    sig = bytearray(signing.sign(priv, b"hello"))
    sig[-1] ^= 1  # flip one bit
    assert not signing.verify(pub, bytes(sig), b"hello")


def test_wrong_public_key_rejected():
    priv, _ = signing.generate_keypair()
    _, other_pub = signing.generate_keypair()
    sig = signing.sign(priv, b"hello")
    assert not signing.verify(other_pub, sig, b"hello")


def test_private_key_roundtrip():
    priv, pub = signing.generate_keypair()
    key = b"\x01" * 32
    blob = signing.encrypt_private_key(priv, key)
    priv2 = signing.decrypt_private_key(blob, key)
    assert signing.verify(pub, signing.sign(priv2, b"x"), b"x")


def test_wrong_password_cannot_load_private_key():
    priv, _ = signing.generate_keypair()
    blob = signing.encrypt_private_key(priv, b"\x01" * 32)
    with pytest.raises(aead.DecryptionError):
        signing.decrypt_private_key(blob, b"\x02" * 32)
