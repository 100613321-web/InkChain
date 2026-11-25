"""Creates, lists, reads and verifies the entries."""
import base64
import binascii
import time
import json

from storage.files import load_entries, save_entries, load_users, save_users, StorageError
from crypto import aead, signing, chain

MAX_TITLE_LEN = 100
MAX_TEXT_LEN = 100_000
MAX_INT = 2 ** 63

class DiaryError(Exception):
    """Raised when a diary operation fails."""

def encode_bytes(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")

def decode_bytes(data: str) -> bytes:
    return base64.b64decode(data, validate=True)

def required_int(value, name: str) -> int:
    if type(value) is not int or not 0 <= value < MAX_INT:
        raise ValueError(f"{name} must be a non-negative integer!")
    return value

def serialize_entry(entry: dict) -> dict:
    return {
        "index": entry["index"],
        "timestamp": entry["timestamp"],
        "prev_hash": encode_bytes(entry["prev_hash"]),
        "blob": encode_bytes(entry["blob"]),
        "entry_hash": encode_bytes(entry["entry_hash"]),
        "signature": encode_bytes(entry["signature"])
    }

def deserialize_entry(entry: dict) -> dict:
    if not isinstance(entry, dict):
        raise TypeError("Entry must be an object.")
    return {
        "index": entry["index"],
        "timestamp": entry["timestamp"],
        "prev_hash": decode_bytes(entry["prev_hash"]),
        "blob": decode_bytes(entry["blob"]),
        "entry_hash": decode_bytes(entry["entry_hash"]),
        "signature": decode_bytes(entry["signature"])
    }

def load_decoded_entries(session) -> list:
    try:
        stored_entries = load_entries(session.username)

        return [
            deserialize_entry(entry)
            for entry in stored_entries
        ]
    except (KeyError, TypeError, ValueError, binascii.Error):
        raise DiaryError("Diary data is invalid.") from None

#functions for diary head -> detects deletion of last entries

def make_head(private_key, count: int, last_hash: bytes) -> dict:
    """Signed {count, last_hash} in storage format (also used at registration)."""
    signature = signing.sign(private_key, chain.head_message(count, last_hash))
    return {
        "count": count,
        "last_hash": encode_bytes(last_hash),
        "signature": encode_bytes(signature),
    }

def decode_head(record):
    """Stored head -> dict with bytes fields or none if it's missing/malformed."""
    try:
        return {
            "count": required_int(record["count"], "count"),
            "last_hash": decode_bytes(record["last_hash"]),
            "signature": decode_bytes(record["signature"]),
        }
    except (KeyError, TypeError, ValueError, binascii.Error):
        return None

def load_head(session):
    try:
        user = load_users().get(session.username)
    except StorageError:
        raise DiaryError("User data couldn't be read.") from None
    if not isinstance(user, dict):
        return None
    return decode_head(user.get("diary_head"))

def save_head(session, count: int, last_hash: bytes) -> None:
    users = load_users()
    user = users.get(session.username)
    if not isinstance(user, dict):
        raise DiaryError("User account wasn't found.")
    user["diary_head"] = make_head(session.signing_private_key, count, last_hash)
    save_users(users)

#decoding and encoding entry with text + title together

def encode_entry(title: str, text: str) -> bytes:
    return json.dumps({"title": title, "text": text}, ensure_ascii=False).encode("utf-8")

def decode_entry(raw: bytes, index: int) -> tuple:
    try:
        data = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise DiaryError(f"Entry {index + 1} has an invalid format.") from None
    if (not isinstance(data, dict) or not isinstance(data.get("title"), str) or not isinstance(data.get("text"), str)):
        raise DiaryError(f"Entry {index + 1} has an invalid format.")
    return data["title"], data["text"]

def validate_input(title, text) -> tuple:
    if not isinstance(text, str) or not text.strip():
        raise DiaryError("Diary entry can't be empty.")
    if not isinstance(title, str):
        raise DiaryError("The title must be text.")
    title = title.strip()
    if len(title) > MAX_TITLE_LEN:
        raise DiaryError(f"The title can't be longer than {MAX_TITLE_LEN} characters.")
    if len(text) > MAX_TEXT_LEN:
        raise DiaryError(f"An entry can't be longer than {MAX_TEXT_LEN} characters.")

def required_active(session) -> None:
    if getattr(session, "closed", True):
        raise DiaryError("This session is closed. Please login again.")

def inspect(session):
    """Loading and verifying the whole diary in one entire go."""
    required_active(session)
    entries = load_decoded_entries(session)
    results = chain.verify_chain(entries, session.signing_public_key, signing.verify)
    payloads = {}

    for position, entry in enumerate(entries):
        if not results[position][1]:
            continue
        aad = chain.make_aad(entry["index"], entry["prev_hash"])
        try:
            payloads[position] = aead.decrypt(session.dek, entry["blob"], aad=aad)
        except aead.DecryptionError:
            results[position] = (position, False, "AES-GCM authentication failed.")

    head_ok, head_reason = chain.verify_head(entries, load_head(session), session.signing_public_key, signing.verify)
    if not head_ok:
        results.append(None, False, head_reason)

    return entries, results, payloads

def verified(session):
    """Similar to inspect() but will not continue if failed."""
    entries, results, payloads = inspect(session)
    if any(not ok for _, ok, _ in results):
        raise DiaryError("Integrity check of diary failed.")
    return entries, payloads

def verify_diary(session) -> list:
    return inspect(session)[1]

def create_entry(session, plaintext: str) -> None:
    title, text = validate_input(title, text)

    entries, results, _ = inspect(session)
    if any(not ok for _, ok, _ in results):
        raise DiaryError ("Diary integrity check failed. Can't add entry.")

    index = len(entries)

    if entries:
        prev_hash = entries[-1]["entry_hash"]
    else:
        prev_hash = chain.GENESIS_HASH

    timestamp = int(time.time())
    aad = chain.make_aad(index, prev_hash)
    blob = aead.encrypt(session.dek, encode_entry(title, text), aad=aad)
    entry_hash = chain.compute_entry_hash(index, timestamp, prev_hash, blob)
    signature = signing.sign(session.signing_private_key, entry_hash)

    entry = {
        "index": index,
        "timestamp": timestamp,
        "prev_hash": prev_hash,
        "blob": blob,
        "entry_hash": entry_hash,
        "signature": signature
    }

    stored_entries = [serialize_entry(e) for e in entries] + [serialize_entry(entry)]

    try:
        save_entries(session.username, stored_entries)
        save_head(session, index + 1, entry_hash)
    except StorageError:
        raise DiaryError("Diary entry couldn't be saved.") from None

def get_entries(session) -> list:
    """All entries are decrypted but only if the whole diary verifies."""
    entries, playoads = verified(session)
    plaintext_entries = []

    for position, entry in enumerate(entries):
        title, text = decode_entry(plaintext_entries[position], position)
        plaintext_entries.append({
            "index": entry["index"],
            "timestamp": entry["timestamp"],
            "title": title,
            "text": text,
        })
    return plaintext_entries

def get_entry_list(session) -> list:
    """Index, timestamp and title of every entry."""
    return [
        {"index": e["index"], "timestamp": e["timestamp"], "title": e["title"]}
        for e in get_entries(session)]

def get_entry(session, index: int) -> dict: 
    """One decrypted entry after verifying entire diary."""
    entries, payloads = verified(session)
    if type(index) is not int or not 0 <= index < len(entries):
        raise DiaryError("Entry not found.")
    title, text = decode_entry(payloads[index], index)
    return {
        "index": index,
        "timestamp": entries[index]["timestamp"],
        "title": title,
        "text": text,
    }