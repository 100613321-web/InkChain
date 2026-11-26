import os

import pytest

import services.auth as auth
import storage.files as storage
from crypto.signing import sign, verify
from services.auth import register_user, login_user, AuthError

# strong test passwords (the weak ones are refused by the app)
PW = "Horse-Battery-42"
PW2 = "Staple-Orange-77"


# ---------- registration ----------

# Registering stores every key field and starts with a clean lockout state.
def test_register_user(isolated_storage):
    register_user("alice", PW)
    user = storage.load_users()["alice"]

    for field in ("password_salt", "password_hash", "enc_salt", "encrypted_dek",
                  "encrypted_private_key", "public_key", "diary_head"):
        assert user[field]
    assert user["failed_attempts"] == 0
    assert user["locked_until"] is None


# The plain password must never end up in users.json.
def test_password_is_not_stored(isolated_storage):
    register_user("alice", PW)
    assert PW not in str(storage.load_users())


# Spaces and capital letters in the username are cleaned up, so "  Alice " and "ALICE" are the same account.
def test_username_is_normalized(isolated_storage):
    register_user("  Alice  ", PW)
    assert "alice" in storage.load_users()
    assert login_user("ALICE", PW).username == "alice"


# The same username can not be registered twice.
def test_duplicate_username(isolated_storage):
    register_user("alice", PW)
    with pytest.raises(AuthError):
        register_user("alice", PW2)


# Empty, too short, too long, with spaces or not text: all refused.
@pytest.mark.parametrize("username", ["", "ab", "a b", "x" * 33, 123])
def test_invalid_usernames_rejected(isolated_storage, username):
    with pytest.raises(AuthError):
        register_user(username, PW)


# Short, one-character-class, common or username-containing passwords are refused ("weak passwords are refused").
@pytest.mark.parametrize("password", [
    "Sh0rt-1",                    # too short
    "alllowercaseletters",        # only one character class
    "Password123",                # in the common list (case-insensitive)
    "Alice-Secret-99",            # contains the username
    None,
])
def test_weak_passwords_rejected(isolated_storage, password):
    with pytest.raises(AuthError):
        register_user("alice", password)


# Same password for two users -> different salts and hashes (that is the point of salting). The second salt differs from the first one too.
def test_same_password_gives_different_salts_and_hashes(isolated_storage):
    register_user("alice", PW)
    register_user("bob", PW)
    users = storage.load_users()
    assert users["alice"]["password_salt"] != users["bob"]["password_salt"]
    assert users["alice"]["password_hash"] != users["bob"]["password_hash"]
    assert users["alice"]["enc_salt"] != users["alice"]["password_salt"]


# users.json can only be read by its owner (not on Windows).
@pytest.mark.skipif(os.name == "nt", reason="POSIX file permissions only")
def test_users_file_has_0600_permissions(isolated_storage):
    register_user("alice", PW)
    assert (isolated_storage / "users.json").stat().st_mode & 0o777 == 0o600


# ---------- login ----------

# Right password: we get a session with the diary key and the signing keys.
def test_successful_login(isolated_storage):
    register_user("alice", PW)
    session = login_user("alice", PW)
    assert session.username == "alice"
    assert len(session.dek) == 32
    assert session.signing_private_key is not None
    assert session.signing_public_key is not None
    assert session.closed is False


# Wrong password: login refused.
def test_wrong_password(isolated_storage):
    register_user("alice", PW)
    with pytest.raises(AuthError):
        login_user("alice", "wrong-password-1")


# Same message either way, so the login does not reveal which usernames exist.
def test_unknown_user_and_wrong_password_give_same_message(isolated_storage):
    register_user("alice", PW)
    with pytest.raises(AuthError) as wrong_pw:
        login_user("alice", "wrong-password-1")
    with pytest.raises(AuthError) as no_user:
        login_user("nobody", "wrong-password-1")
    assert str(wrong_pw.value) == str(no_user.value)


# Empty or non-text password: clean "invalid" message, no crash.
@pytest.mark.parametrize("password", ["", None])
def test_empty_or_invalid_password_on_login(isolated_storage, password):
    register_user("alice", PW)
    with pytest.raises(AuthError, match="Invalid username or password"):
        login_user("alice", password)


# Two logins give the same diary key, so entries written before can be read after.
def test_encryption_key_unlocked_correctly(isolated_storage):
    register_user("alice", PW)
    assert login_user("alice", PW).dek == login_user("alice", PW).dek


# What the private key signs, the public key verifies.
def test_private_and_public_keys_match(isolated_storage):
    register_user("alice", PW)
    session = login_user("alice", PW)
    signature = sign(session.signing_private_key, b"test message")
    assert verify(session.signing_public_key, signature, b"test message")


# Every user gets their own random diary key.
def test_different_users_have_different_keys(isolated_storage):
    register_user("alice", PW)
    register_user("bob", PW2)
    assert login_user("alice", PW).dek != login_user("bob", PW2).dek


# ---------- lockout ----------

# 5 wrong passwords -> the account is locked for 5 minutes (time is faked in the test).
def test_account_locks_after_failed_attempts(isolated_storage, monkeypatch):
    register_user("alice", PW)
    monkeypatch.setattr(auth.time, "time", lambda: 1000)

    for _ in range(auth.MAX_FAILED_ATTEMPTS):
        with pytest.raises(AuthError):
            login_user("alice", "wrong-password-1")

    user = storage.load_users()["alice"]
    assert user["failed_attempts"] == auth.MAX_FAILED_ATTEMPTS
    assert user["locked_until"] == 1000 + auth.LOCKOUT_SECONDS


# While locked, even the correct password is refused.
def test_locked_account_refuses_even_the_right_password(isolated_storage, monkeypatch):
    register_user("alice", PW)
    monkeypatch.setattr(auth.time, "time", lambda: 1000)
    for _ in range(auth.MAX_FAILED_ATTEMPTS):
        with pytest.raises(AuthError):
            login_user("alice", "wrong-password-1")
    with pytest.raises(AuthError, match="temporarily locked"):
        login_user("alice", PW)


# After the 5 minutes pass, login works again.
def test_account_unlocks_after_locked_period(isolated_storage, monkeypatch):
    register_user("alice", PW)
    now = [1000]
    monkeypatch.setattr(auth.time, "time", lambda: now[0])
    for _ in range(auth.MAX_FAILED_ATTEMPTS):
        with pytest.raises(AuthError):
            login_user("alice", "wrong-password-1")
    now[0] += auth.LOCKOUT_SECONDS + 1
    assert login_user("alice", PW).username == "alice"


# ---------- tampering with users.json ----------

# Someone puts another user's public key in users.json: login detects it and refuses.
def test_swapped_public_key_is_detected(isolated_storage):
    register_user("alice", PW)
    register_user("bob", PW2)
    users = storage.load_users()
    users["alice"]["public_key"] = users["bob"]["public_key"]
    storage.save_users(users)
    with pytest.raises(AuthError, match="public key"):
        login_user("alice", PW)


# A broken users.json gives a clean error, not a crash.
def test_corrupted_users_file_gives_auth_error(isolated_storage):
    (isolated_storage / "users.json").write_text("{broken", encoding="utf-8")
    with pytest.raises(AuthError):
        login_user("alice", PW)
    with pytest.raises(AuthError):
        register_user("alice", PW)


# One flipped byte in the stored DEK or private key: the GCM tag fails and login is refused.
@pytest.mark.parametrize("field", ["encrypted_dek", "encrypted_private_key"])
def test_tampered_encrypted_keys_block_login(isolated_storage, field):
    import base64
    register_user("alice", PW)
    users = storage.load_users()
    raw = bytearray(base64.b64decode(users["alice"][field]))
    raw[-1] ^= 1
    users["alice"][field] = base64.b64encode(bytes(raw)).decode()
    storage.save_users(users)
    with pytest.raises(AuthError):
        login_user("alice", PW)


# ---------- logout ----------

# Logout removes the references to all keys.
def test_close_drops_the_keys(isolated_storage):
    register_user("alice", PW)
    session = login_user("alice", PW)
    session.close()
    assert session.closed is True
    assert session.dek is None
    assert session.signing_private_key is None
    assert session.signing_public_key is None
