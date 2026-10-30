import pytest

from crypto import kdf


def test_salt_has_correct_length_and_is_random():
    a, b = kdf.generate_salt(), kdf.generate_salt()
    assert len(a) == kdf.SALT_LEN
    assert a != b


def test_hash_is_deterministic_for_same_salt():
    salt = kdf.generate_salt()
    assert kdf.hash_password("pw12345!", salt) == kdf.hash_password("pw12345!", salt)


def test_different_salt_gives_different_hash():
    pw = "pw12345!"
    assert kdf.hash_password(pw, kdf.generate_salt()) != kdf.hash_password(pw, kdf.generate_salt())


def test_verify_correct_password():
    salt = kdf.generate_salt()
    h = kdf.hash_password("правильний-пароль", salt)   # unicode works
    assert kdf.verify_password("правильний-пароль", salt, h) is True


# --- negative tests ---
def test_verify_wrong_password_fails():
    salt = kdf.generate_salt()
    h = kdf.hash_password("correct", salt)
    assert kdf.verify_password("wrong", salt, h) is False


def test_verify_tampered_hash_fails():
    salt = kdf.generate_salt()
    h = bytearray(kdf.hash_password("correct", salt))
    h[0] ^= 1                                           # flip one bit
    assert kdf.verify_password("correct", salt, bytes(h)) is False


def test_auth_hash_and_encryption_key_differ_with_two_salts():
    pw = "same-password"
    auth_hash = kdf.hash_password(pw, kdf.generate_salt())
    key = kdf.derive_key(pw, kdf.generate_salt())
    assert auth_hash != key
    assert len(key) == 32


@pytest.mark.parametrize("password", ["", None, 123])
def test_invalid_password_rejected(password):
    with pytest.raises(ValueError):
        kdf.hash_password(password, kdf.generate_salt())


def test_invalid_salt_rejected():
    with pytest.raises(ValueError):
        kdf.hash_password("pw", b"short")