import pytest
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

from crypto import kdf


# ---------- normal behaviour ----------

def test_salt_has_correct_length_and_is_random():
    # two salts must never be the same, otherwise salting is pointless
    a, b = kdf.generate_salt(), kdf.generate_salt()
    assert len(a) == kdf.SALT_LEN
    assert a != b


def test_hash_is_deterministic_for_same_salt():
    # login only works if the same password + salt gives the same hash again
    salt = kdf.generate_salt()
    assert kdf.hash_password("pw12345!", salt) == kdf.hash_password("pw12345!", salt)


def test_different_salt_gives_different_hash():
    # two users with the same password must not end up with the same hash
    pw = "pw12345!"
    assert kdf.hash_password(pw, kdf.generate_salt()) != kdf.hash_password(pw, kdf.generate_salt())


def test_verify_correct_password():
    salt = kdf.generate_salt()
    pw = "p\u00e4ssw\u00f6rd-\u0431\u0443\u043a\u0432\u0430"   # non-ASCII on purpose
    h = kdf.hash_password(pw, salt)
    assert kdf.verify_password(pw, salt, h) is True


def test_scrypt_known_answer_rfc7914():
    # Official test vector from RFC 7914. It doesn't test OUR code, it proves
    # the library really computes scrypt and not something that looks like it.
    expected = bytes.fromhex(
        "77d6576238657b203b19ca42c18a0497f16b4844e3074ae8dfdffa3fede21442"
        "fcd0069ded0948f8326a753a0fc81f17e8d3e0fb2e0d3628cf35e20c38d18906"
    )
    out = Scrypt(salt=b"", length=64, n=16, r=1, p=1).derive(b"")
    assert out == expected


@pytest.mark.prod_params
def test_production_parameters_are_the_expected_ones():
    # The other tests run with a cheap N so they're fast. This one runs with
    # the real settings, so we know the app itself is not using the cheap value.
    assert kdf.SCRYPT_N == 2 ** 17
    assert kdf.SCRYPT_R == 8
    assert kdf.SCRYPT_P == 1
    assert kdf.KEY_LEN == 32
    assert kdf.SALT_LEN == 16
    salt = kdf.generate_salt()
    h = kdf.hash_password("correct horse", salt)
    assert len(h) == 32
    assert kdf.verify_password("correct horse", salt, h)


# ---------- negative tests ----------

def test_verify_wrong_password_fails():
    salt = kdf.generate_salt()
    h = kdf.hash_password("correct", salt)
    assert kdf.verify_password("wrong", salt, h) is False


def test_verify_tampered_hash_fails():
    # someone edits the stored hash: login must fail, not crash
    salt = kdf.generate_salt()
    h = bytearray(kdf.hash_password("correct", salt))
    h[0] ^= 1  # flip one bit
    assert kdf.verify_password("correct", salt, bytes(h)) is False


def test_verify_with_wrong_salt_fails():
    h = kdf.hash_password("correct", kdf.generate_salt())
    assert kdf.verify_password("correct", kdf.generate_salt(), h) is False


def test_verify_with_truncated_hash_fails():
    # a cut hash has the wrong length, still has to give False and not an exception
    salt = kdf.generate_salt()
    h = kdf.hash_password("correct", salt)
    assert kdf.verify_password("correct", salt, h[:-1]) is False


def test_auth_hash_and_encryption_key_differ_with_two_salts():
    # the stored login hash must NOT be usable as the encryption key
    pw = "same-password"
    auth_hash = kdf.hash_password(pw, kdf.generate_salt())
    key = kdf.derive_key(pw, kdf.generate_salt())
    assert auth_hash != key
    assert len(key) == 32


def test_derive_key_is_deterministic_and_needs_same_salt():
    salt = kdf.generate_salt()
    assert kdf.derive_key("pw", salt) == kdf.derive_key("pw", salt)
    assert kdf.derive_key("pw", salt) != kdf.derive_key("pw2", salt)


@pytest.mark.parametrize("password", ["", None, 123, b"bytes"])
def test_invalid_password_rejected(password):
    # empty or not-a-string is a bug in the caller -> ValueError
    with pytest.raises(ValueError):
        kdf.hash_password(password, kdf.generate_salt())


@pytest.mark.parametrize("salt", [b"short", None, "x" * 16, b"x" * 17])
def test_invalid_salt_rejected(salt):
    # wrong length or wrong type (a str of 16 chars is still not bytes)
    with pytest.raises(ValueError):
        kdf.hash_password("pw", salt)