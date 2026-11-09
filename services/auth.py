from storage.files import load_users, save_users
from crypto.kdf import generate_salt, hash_password, verify_password

MAX_FAILED_ATTEMPTS = 5 #is that too much? maybe 3 is better?

class AuthError(Exception):
    """Raised when the registration or login has failed."""

def register_user(username: str, password: str) -> None:
    username = username.strip().lower()

    if not username:
        raise AuthError("Username can't be empty.")

    if len(username) < 5:
        raise AuthError("Username must be at least 5 characters long.")

    if not isinstance(password, str) or len(password) < 8:
        raise AuthError("Password must be at least 8 characters long.")

    users = load_users()

    if username in users:
        raise AuthError("Username is already registered, please pick another.")

    salt = generate_salt()
    password_hash = hash_password(password, salt)

    users[username] = {
        "password_salt": salt.hex(),
        "password_hash": password_hash.hex(),
        "failed_attempts": 0,
        "locked": False #currently locking user after 5 failed attempts, keep?
    }
    save_users(users)

def login_user(username: str, password: str) -> str:
    username = username.strip().lower()
    users = load_users()

    if username not in users:
        raise AuthError("Invalid username or password.")

    user = users[username]

    if user.get("locked", False):
        raise AuthError("This account has been locked.")

    salt = bytes.fromhex(user["password_salt"])
    stored_hash = bytes.fromhex(user["password_hash"])

    password_correct = verify_password(password, salt, stored_hash)

    if not password_correct:
        user["failed_attempts"] = user.get("failed_attempts", 0) + 1

        if user["failed_attempts"] >= MAX_FAILED_ATTEMPTS:
            user["locked"] = True

        save_users(users)

        raise AuthError("Invalid username or password.")

    user["failed_attempts"] = 0
    save_users(users)
    return username
