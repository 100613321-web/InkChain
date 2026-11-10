import pytest
import storage.files as storage

from services.auth import register_user, login_user
from services.diary import (create_entry, get_entries, verify_diary, DiaryError)

@pytest.fixture
def authenticated_session(tmp_path, monkeypatch):
    monkeypatch.setattr(storage, "DATA_DIR", tmp_path)
    register_user("alice", "password123")
    return login_user("alice", "password123")

def test_create_entry(authenticated_session):
    create_entry(authenticated_session, "My first diary entry")
    entries = storage.load_entries("alice")

    assert len(entries) == 1
    assert entries[0]["index"] == 0

def test_create_multiple_entries(authenticated_session):
    create_entry(authenticated_session, "First entry")
    create_entry(authenticated_session, "Second entry")

    entries = storage.load_entries("alice")

    assert len(entries) == 2
    assert entries[0]["index"] == 0
    assert entries[1]["index"] == 1

def test_empty_entry_is_rejected(authenticated_session):
    with pytest.raises(DiaryError):
        create_entry(authenticated_session, "")

def test_get_entries(authenticated_session):
    create_entry(authenticated_session, "My first entry")
    create_entry(authenticated_session, "My second entry")

    entries = get_entries(authenticated_session)

    assert len(entries) == 2
    assert entries[0]["text"] == "My first entry"
    assert entries[1]["text"] == "My second entry"

def test_verify_valid_diary(authenticated_session):
    create_entry(authenticated_session, "First entry")
    create_entry(authenticated_session, "Second entry")

    results = verify_diary(authenticated_session)

    assert all(ok for _, ok, _ in results)

def test_verify_empty_diary(authenticated_session):
    results = verify_diary(authenticated_session)

    assert results == []

def test_users_have_separate_diaries(tmp_path, monkeypatch):
    monkeypatch.setattr(storage, "DATA_DIR", tmp_path)

    register_user("alice", "password123")
    register_user("bob", "password456")

    alice = login_user("alice", "password123")
    bob = login_user("bob", "password456")

    create_entry(alice, "Alice's private diary")
    create_entry(bob, "Bob's private diary")

    alice_entries = get_entries(alice)
    bob_entries = get_entries(bob)

    assert alice_entries[0]["text"] == "Alice's private diary"
    assert bob_entries[0]["text"] == "Bob's private diary"