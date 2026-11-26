import pytest

from crypto import aead

KEY = bytes(range(32))   # fixed key, only OK because this is a test
AAD = b"user=alice|index=1"


# ---------- normal behaviour ----------

def test_roundtrip():
    text = "caf\u00e9 \u0431\u0443\u043a\u0432\u0430".encode()   # non-ASCII on purpose
    blob = aead.encrypt(KEY, text, AAD)
    assert aead.decrypt(KEY, blob, AAD) == text


def test_same_plaintext_gives_different_ciphertext():
    # fresh nonce every time, so the same text never looks the same on disk
    a = aead.encrypt(KEY, b"same", AAD)
    b = aead.encrypt(KEY, b"same", AAD)
    assert a != b


def test_1000_nonces_are_unique():
    nonces = {aead.generate_nonce() for _ in range(1000)}
    assert len(nonces) == 1000


def test_1000_encryptions_use_1000_different_nonces():
    # same idea but through encrypt(), the path the app really uses
    nonces = {aead.encrypt(KEY, b"x")[:aead.NONCE_LEN] for _ in range(1000)}
    assert len(nonces) == 1000


# ---------- negative tests ----------

def test_flipped_byte_in_ciphertext_rejected():
    blob = bytearray(aead.encrypt(KEY, b"secret", AAD))
    blob[aead.NONCE_LEN] ^= 1       # first byte after the nonce
    with pytest.raises(aead.DecryptionError):
        aead.decrypt(KEY, bytes(blob), AAD)


def test_flipped_byte_in_tag_rejected():
    blob = bytearray(aead.encrypt(KEY, b"secret", AAD))
    blob[-1] ^= 1                   # last byte = end of the tag
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
    # the text is intact, only the "context" is different -> still refused
    blob = aead.encrypt(KEY, b"secret", AAD)
    with pytest.raises(aead.DecryptionError):
        aead.decrypt(KEY, blob, b"user=alice|index=2")


def test_truncated_data_rejected():
    with pytest.raises(aead.DecryptionError):
        aead.decrypt(KEY, b"short", AAD)


@pytest.mark.parametrize("key", [b"short", None, bytes(31)])
def test_invalid_key_rejected(key):
    # wrong key size/type is a programming error (ValueError), not an attack
    with pytest.raises(ValueError):
        aead.encrypt(key, b"x")

