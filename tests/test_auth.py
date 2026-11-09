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
    assert users["alice"]["failed_attempts"] == 0

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
    username = login_user("alice", "password123")
    assert username == "alice"

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