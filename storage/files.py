import json
import os
import tempfile
from pathlib import Path

DATA_DIR = Path(__file__).resolve().parent / "data"

USERS_FILE = DATA_DIR / "users.json"
ENTRIES_FILE = DATA_DIR / "entries.json"

class StorageError(Exception):
    """To be thrown when we get an error somewhere in the app"""

def check_data_directory():
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    os.chmod(DATA_DIR, 0o700) #only current user can access that directory

def load_json(file_path, default=None):
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

def save_json(file_path, data):
    check_data_directory()
    file_path = Path(file_path)

    temp_path = None

    try:
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=DATA_DIR, delete=False) as temp_file:
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


#USER STORAGE

def load_users():
    users = load_json(USERS_FILE, default={})

    if not isinstance(users, dict):
        raise StorageError("Users file has an invalid structure.")

    return users

def save_users(users):
    if not isinstance(users, dict):
        raise StorageError("Users data has to be stored in a dictionary.")

    save_json(USERS_FILE, users)

#DIARY STORAGE

def load_entries():
    entries = load_json(ENTRIES_FILE, default=[]) #no matter what brackets? look up again

    if not isinstance(entries, list):
        raise StorageError("Entries file has an invalid structure.")

    return entries

def save_entries(entries):
    if not isinstance(entries, list):
        raise StorageError("Entries data has to stored in a list.")

    save_json(ENTRIES_FILE, entries)