import os

import pytest

from storage.files import (
    load_json, save_json, load_users, save_users,
    load_entries, save_entries, StorageError,
)


# What we save is what we load back.
def test_saving_and_loading_json(tmp_path):
    file_path = tmp_path / "test.json"
    data = {"username": "alice", "attempts": 0}
    save_json(file_path, data)
    assert load_json(file_path) == data


# No file yet -> the default value, not an error.
def test_load_missing_file_returns_default(tmp_path):
    assert load_json(tmp_path / "missing.json", default={}) == {}


# Broken JSON -> StorageError (a clean error, no crash).
def test_load_broken_json_raises_storage_error(tmp_path):
    file_path = tmp_path / "broken.json"
    file_path.write_text("{invalid json", encoding="utf-8")
    with pytest.raises(StorageError):
        load_json(file_path)


# Users roundtrip through users.json.
def test_save_and_load_users(isolated_storage):
    users = {"alice": {"failed_attempts": 0}, "bob": {"failed_attempts": 2}}
    save_users(users)
    assert load_users() == users


# Entries roundtrip through entries.json.
def test_save_and_load_entries(isolated_storage):
    entries = [{"idx": 0, "ciphertext": "example"}, {"idx": 1, "ciphertext": "example2"}]
    save_entries("alice", entries)
    assert load_entries("alice") == entries


# Saving one user's diary leaves the others untouched.
def test_saving_entries_doesnt_overwrite_other_users(isolated_storage):
    bob_entries = [{"idx": 0, "ciphertext": "bob_entry"}]
    save_entries("alice", [{"idx": 0, "ciphertext": "a"}])
    save_entries("bob", bob_entries)
    save_entries("alice", [{"idx": 0, "ciphertext": "a"}, {"idx": 1, "ciphertext": "a2"}])
    assert load_entries("bob") == bob_entries


# A user with no diary yet gets an empty list.
def test_load_entries_for_new_user(isolated_storage):
    assert load_entries("charlie") == []


# ---------- negative tests ----------

# users.json must be an object, a list is refused.
def test_users_file_with_wrong_structure_rejected(isolated_storage):
    (isolated_storage / "users.json").write_text("[1, 2, 3]", encoding="utf-8")
    with pytest.raises(StorageError):
        load_users()


# entries.json must be an object, anything else is refused.
def test_entries_file_with_wrong_structure_rejected(isolated_storage):
    (isolated_storage / "entries.json").write_text('"just a string"', encoding="utf-8")
    with pytest.raises(StorageError):
        load_entries("alice")


# Data JSON can not store -> StorageError, and no temp file is left behind.
def test_unserializable_data_raises_storage_error(tmp_path):
    with pytest.raises(StorageError):
        save_json(tmp_path / "x.json", {"bad": object()})
    assert not (tmp_path / "x.json").exists()
    assert list(tmp_path.iterdir()) == []      # no leftover temp files


# Files are written with 0600 permissions (not on Windows).
@pytest.mark.skipif(os.name == "nt", reason="POSIX file permissions only")
def test_files_are_only_readable_by_the_owner(isolated_storage):
    save_users({"alice": {}})
    mode = (isolated_storage / "users.json").stat().st_mode & 0o777
    assert mode == 0o600


