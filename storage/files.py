#Handles JSON file storage
import json
import os
import tempfile
from pathlib import Path

DATA_DIR = Path(__file__).resolve().parent / "data"

def _users_file() -> Path:
    return DATA_DIR / "users.json"

def _entries_file() -> Path:
    return DATA_DIR / "entries.json"

class StorageError(Exception):
    """To be thrown when we get an error somewhere in the app related to storage"""

def check_data_directory():
    """Create the data directory (if needed) readable by the current user only."""
    try:
        DATA_DIR.mkdir(parents=True, exist_ok=True)
        os.chmod(DATA_DIR, 0o700)
    except OSError as error:
        raise StorageError("Data directory could not be created/opened.") from error

def load_json(file_path, default=None):
    """Reads a JSON file, if missing file -> default, if broken file -> StorageError."""
    check_data_directory()
    file_path = Path(file_path)

    if not file_path.exists():
        return default

    try:
        with file_path.open("r", encoding="utf-8") as file:
            return json.load(file)

    except (json.JSONDecodeError, UnicodeDecodeError) as error:
        raise StorageError(f"Invalid JSON file: {file_path.name}") from error

    except OSError as error:
        raise StorageError(f"File could not be read: {file_path.name}") from error

def save_json(file_path, data) -> None:
    """Atomically writing the JSON, only parent folder of file_path is touched, never the global data directory,
    so tests that write to tmp_oath don't create an actually real data folder."""

    file_path = Path(file_path)
    temp_path = None

    try:
        file_path.parent.mkdir(parents=True, exist_ok=True)

        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=file_path.parent, delete=False) as temp_file:
            temp_path = Path(temp_file.name)
            json.dump(data, temp_file, indent=4, ensure_ascii=False)

            temp_file.flush()
            os.fsync(temp_file.fileno())

        os.chmod(temp_path, 0o600)
        os.replace(temp_path, file_path)

    except (OSError, TypeError, ValueError) as error:
        raise StorageError(f"File could not be saved: {file_path.name}") from error

    finally:
        if temp_path and temp_path.exists():
            temp_path.unlink()


#USER STORAGE - format: {username: record}

def load_users():
    """Used to load all the users from the data."""
    users = load_json(_users_file(), default={})

    if not isinstance(users, dict):
        raise StorageError("Users file has an invalid structure.")

    return users

def save_users(users):
    """Used to save all the users to the JSON."""
    if not isinstance(users, dict):
        raise StorageError("Users data has to be stored in a dictionary.")

    check_data_directory()
    save_json(_users_file(), users)

#DIARY STORAGE - format: {username: [entry, entry, ...]}

def load_all_entries():
    """Loads all entries of every user."""
    all_entries = load_json(_entries_file(), default={})

    if not isinstance(all_entries, dict):
        raise StorageError("Entries file has an invalid structure.")

    return all_entries

def load_entries(username):
    """Loads entries of one specific user."""
    entries = load_all_entries().get(username, [])

    if not isinstance(entries, list):
        raise StorageError("Entries of this user have an invalid structure.")

    return entries

def save_entries(username, entries):
    """Saves a list of entries for a specified user."""
    if not isinstance(entries, list):
        raise StorageError("Entries data has to stored in a list.")

    all_entries = load_all_entries()
    all_entries[username] = entries
    check_data_directory()
    save_json(_entries_file(), all_entries)