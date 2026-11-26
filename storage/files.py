"""JSON file storage: reads and writes users.json and entries.json.

This layer knows nothing about crypto. It only saves and loads data, and
turns every file problem into one error type (StorageError) so the layers
above can handle it cleanly instead of crashing.
"""
import json
import os
import tempfile
from pathlib import Path

# <project folder>/data. Tests point this somewhere else (a temp folder),
# so they never touch the real data.
DATA_DIR = Path(__file__).resolve().parent.parent / "data"


def _users_file() -> Path:
    return DATA_DIR / "users.json"


def _entries_file() -> Path:
    return DATA_DIR / "entries.json"


class StorageError(Exception):
    """Anything that goes wrong with reading or writing our files."""


def check_data_directory():
    """Make sure the data folder exists and only the current user can open it."""
    try:
        DATA_DIR.mkdir(parents=True, exist_ok=True)
        os.chmod(DATA_DIR, 0o700)   # rwx for the owner, nothing for anyone else
    except OSError as error:
        raise StorageError("Data directory could not be created/opened.") from error


def load_json(file_path, default=None):
    """Read a JSON file. Missing file -> default, broken file -> StorageError."""
    file_path = Path(file_path)

    if not file_path.exists():
        return default

    try:
        with file_path.open("r", encoding="utf-8") as file:
            return json.load(file)

    except (json.JSONDecodeError, UnicodeDecodeError) as error:
        # the file is there but it's not valid JSON (corrupted or edited by hand)
        raise StorageError(f"Invalid JSON file: {file_path.name}") from error

    except OSError as error:
        raise StorageError(f"File could not be read: {file_path.name}") from error


def save_json(file_path, data) -> None:
    """Write a JSON file in a safe way.

    We write to a temp file first and then swap it in with os.replace().
    That way, if the program dies half way, the old file is still intact
    instead of being left half written.
    """
    file_path = Path(file_path)
    temp_path = None

    try:
        # only the folder of THIS file is created (not the global data dir),
        # so tests that write to a temp folder don't create a real data/
        file_path.parent.mkdir(parents=True, exist_ok=True)

        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=file_path.parent, delete=False) as temp_file:
            temp_path = Path(temp_file.name)
            json.dump(data, temp_file, indent=4, ensure_ascii=False)

            temp_file.flush()
            os.fsync(temp_file.fileno())   # force the bytes onto the disk

        os.chmod(temp_path, 0o600)         # only the owner can read/write the file
        os.replace(temp_path, file_path)   # atomic swap

    except (OSError, TypeError, ValueError) as error:
        raise StorageError(f"File could not be saved: {file_path.name}") from error

    finally:
        # if something failed before the swap, don't leave the temp file lying around
        if temp_path and temp_path.exists():
            temp_path.unlink()


# ---------- users: {username: record} ----------

def load_users():
    """All users, or an empty dict if nobody registered yet."""
    users = load_json(_users_file(), default={})

    if not isinstance(users, dict):
        raise StorageError("Users file has an invalid structure.")

    return users


def save_users(users):
    """Save all users."""
    if not isinstance(users, dict):
        raise StorageError("Users data has to be stored in a dictionary.")

    check_data_directory()
    save_json(_users_file(), users)


# ---------- diary entries: {username: [entry, entry, ...]} ----------

def load_all_entries():
    """The entries of every user (one file holds all the diaries)."""
    all_entries = load_json(_entries_file(), default={})

    if not isinstance(all_entries, dict):
        raise StorageError("Entries file has an invalid structure.")

    return all_entries


def load_entries(username):
    """Entries of one user, or an empty list if they have none yet."""
    entries = load_all_entries().get(username, [])

    if not isinstance(entries, list):
        raise StorageError("Entries of this user have an invalid structure.")

    return entries


def save_entries(username, entries):
    """Replace the entries of one user. The other users' diaries stay as they are."""
    if not isinstance(entries, list):
        raise StorageError("Entries data has to stored in a list.")

    all_entries = load_all_entries()
    all_entries[username] = entries
    check_data_directory()
    save_json(_entries_file(), all_entries)
