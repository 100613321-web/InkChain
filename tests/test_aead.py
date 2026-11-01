import pytest

from crypto import aead

KEY = bytes(range(32))   # fixed key, fine for tests only
AAD = b"user=alice|index=1"


def test_roundtrip():
    text = "caf\u00e9 \u0431\u0443\u043a\u0432\u0430".encode()   # non-ASCII on purpose
    blob = aead.encrypt(KEY, text, AAD)
    assert aead.decrypt(KEY, blob, AAD) == text


def test_same_plaintext_gives_different_ciphertext():
    a = aead.encrypt(KEY, b"same", AAD)
    b = aead.encrypt(KEY, b"same", AAD)
    assert a != b


def test_1000_nonces_are_unique():
    nonces = {aead.generate_nonce() for _ in range(1000)}
    assert len(nonces) == 1000


# --- negative tests ---
def test_flipped_byte_in_ciphertext_rejected():
    blob = bytearray(aead.encrypt(KEY, b"secret", AAD))
    blob[aead.NONCE_LEN] ^= 1
    with pytest.raises(aead.DecryptionError):
        aead.decrypt(KEY, bytes(blob), AAD)


def test_flipped_byte_in_tag_rejected():
    blob = bytearray(aead.encrypt(KEY, b"secret", AAD))
    blob[-1] ^= 1
    with pytest.raises(aead.DecryptionError):
        aead.decrypt(KEY, bytes(blob), AAD)


def test_flipped_byte_in_nonce_rejected():
    blob = bytearray(aead.encrypt(KEY, b"secret", AAD))
    blob[0] ^= 1
    with pytest.raises(aead.DecryptionError):
        aead.decrypt(KEY, bytes(blob), AAD)


def test_wrong_key_rejected():
    blob = aead.encrypt(KEY, b"secret", AAD)
    with pytest.raises(aead.DecryptionError):
        aead.decrypt(bytes(32), blob, AAD)


def test_wrong_aad_rejected():
    blob = aead.encrypt(KEY, b"secret", AAD)
    with pytest.raises(aead.DecryptionError):
        aead.decrypt(KEY, blob, b"user=alice|index=2")


def test_truncated_data_rejected():
    with pytest.raises(aead.DecryptionError):
        aead.decrypt(KEY, b"short", AAD)


@pytest.mark.parametrize("key", [b"short", None, "a" * 32])
def test_invalid_key_rejected(key):
    with pytest.raises(ValueError):
        aead.encrypt(key, b"x")