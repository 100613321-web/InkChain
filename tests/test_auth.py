import pytest
import storage.files as storage
from services.auth import (register_user, login_user, AuthError)

@pytest.fixture
def isolated_storage(tmp_path, monkeypatch):
    monkeypatch.setattr(storage, "DATA_DIR", tmp_path)

def test_register_user(isolated_storage):
    register_user("alice", "password123")
    users = storage.load_users()

    assert "alice" in users
    assert users["alice"]["password_salt"]
    assert users["alice"]["password_hash"]
    assert users["alice"]["enc_salt"]
    assert users["alice"]["encrypted_dek"]
    assert users["alice"]["encrypted_private_key"]
    assert users["alice"]["public_key"]
    assert users["alice"]["failed_attempts"] == 0
    assert users["alice"]["locked"] is False

def test_password_is_not_stored(isolated_storage):
    register_user("alice", "password123")
    users = storage.load_users()
    assert "password123" not in str(users)

def test_duplicate_username(isolated_storage):
    register_user("alice", "anotherpassword")

    with pytest.raises(AuthError):
        register_user("alice", "anotherpassword")

def test_successful_login(isolated_storage):
    register_user("alice", "password123")
    session = login_user("alice", "password123")
    assert session.username == "alice"
    assert len(session.dek) == 32
    assert session.signing_private_key is not None
    assert session.signing_public_key is not None

def test_wrong_password(isolated_storage):
    register_user("alice", "password123")

    with pytest.raises(AuthError):
        login_user("alice", "wrongpassword")

def test_account_locks_after_failed_attempts(isolated_storage):
    register_user("alice", "password123")

    for _ in range(5): #might change if we change the amount of failed attempts
        with pytest.raises(AuthError):
            login_user("alice", "wrongpassword")

    users = storage.load_users()
    assert users["alice"]["locked"] is True

def test_locked_account_cant_login(isolated_storage):
    register_user("alice", "password123")

    for _ in range(5):
        with pytest.raises(AuthError):
            login_user("alice", "wrongpassword")

    with pytest.raises(AuthError):
        login_user("alice", "password123")

def test_encryption_key_unlocked_correctly(isolated_storage):
    register_user("alice", "password123")

    session1 = login_user("alice", "password123")
    session2 = login_user("alice", "password123")

    assert session1.dek == session2.dek

def test_private_and_public_keys_match(isolated_storage):
    from crypto.signing import sign, verify

    register_user("alice", "password123")

    session = login_user("alice", "password123")

    message = b"test message"

    signature = sign(session.signing_private_key, message)
    assert verify(session.signing_public_key, signature, message)

def test_different_users_have_different_keys(isolated_storage):
    register_user("alice", "password123")
    register_user("bob", "password456")

    alice = login_user("alice", "password123")
    bob = login_user("bob", "password456")

    assert alice.dek != bob.dek