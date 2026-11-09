import pytest
import storage.files as storage

from storage.files import( load_json, save_json, load_users, save_users, load_entries, save_entries, StorageError)

@pytest.fixture
def isolated_storage(tmp_path, monkeypatch):
    monkeypatch.setattr(storage, "DATA_DIR", tmp_path)

def test_saving_and_loading_json(tmp_path):
    file_path = tmp_path / "test.json"

    data = {"username": "alice", "attempts": 0}
    save_json(file_path, data)

    loaded_data = load_json(file_path)
    assert loaded_data == data

def test_load_missing_file(tmp_path):
    file_path = tmp_path / "missing.json"
    result = load_json(file_path, default={})
    assert result == {}

def test_load_broken_json(tmp_path):
    file_path = tmp_path / "broken.json"
    file_path.write_text("{invalid json", encoding="utf-8")

    with pytest.raises(StorageError):
        load_json(file_path)

def test_save_and_load_users(isolated_storage):
    users = {"alice": { "failed_attempts": 0}, "bob": {"failed_attempts": 2}}
    save_users(users)
    loaded_users = load_users()
    assert loaded_users == users

def test_save_and_load_entries(isolated_storage):
    entries = [{"idx": 0, "ciphertext": "example"}, {"idx": 1, "ciphertext": "example2"}]
    save_entries("alice", entries)
    loaded_entries = load_entries("alice")
    assert loaded_entries == entries

def test_users_have_separated_entries(isolated_storage):
    alice_entries = [{"idx": 0, "ciphertext": "alice_entry"}]
    bob_entries = [{"idx": 0, "ciphertext": "bob_entry"}]
    save_entries("alice", alice_entries)
    save_entries("bob", bob_entries)

    assert load_entries("alice") == alice_entries
    assert load_entries("bob") == bob_entries

def test_saving_entries_doesnt_overwrite_other_users(isolated_storage):
    alice_entries = [{"idx": 0, "ciphertext": "alice_entry"}]
    bob_entries = [{"idx": 0, "ciphertext": "bob_entry"}]

    save_entries("alice", alice_entries)
    save_entries("bob", bob_entries)

    updated_alice_entries = [{"idx": 0, "ciphertext": "alice_entry"}, {"idx": 1, "ciphertext": "alice_second_entry"}]

    save_entries("alice", updated_alice_entries)
    assert load_entries("bob") == bob_entries

def test_load_entries_for_new_user(isolated_storage):
    entries = load_entries("charlie")
    assert entries == []    