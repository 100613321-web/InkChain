"""Diary logic: create, list, read and verify entries.

One stored entry looks like this:
    index       position in the diary (0, 1, 2, ...)
    timestamp   when it was written
    prev_hash   hash of the previous entry (this is the "chain")
    blob        nonce + AES-GCM ciphertext + tag (title and text are inside, encrypted)
    entry_hash  SHA-256 over all the fields above
    signature   ECDSA signature of entry_hash

On top of that, users.json keeps a signed "diary head" (entry count + last
hash). It exists to notice if the newest entries are deleted, which the
chain alone can't see.
"""
import base64
import binascii
import time
import json

from storage.files import load_entries, save_entries, load_users, save_users, StorageError
from crypto import aead, signing, chain

MAX_TITLE_LEN = 100
MAX_TEXT_LEN = 100_000
MAX_INT = 2 ** 63   # numbers from the file must fit in 8 bytes (see chain._int_bytes)


class DiaryError(Exception):
    """A diary operation failed (bad input, broken data, failed integrity check...)."""


# ---------- helpers: bytes <-> text (JSON can't store raw bytes) ----------

def encode_bytes(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def decode_bytes(data: str) -> bytes:
    # validate=True refuses characters that aren't valid base64
    return base64.b64decode(data, validate=True)


def required_int(value, name: str) -> int:
    """Accept only a real, non-negative int (True/False and strings are refused)."""
    if type(value) is not int or not 0 <= value < MAX_INT:
        raise ValueError(f"{name} must be a non-negative integer!")
    return value


def serialize_entry(entry: dict) -> dict:
    """Entry with bytes -> entry with text, ready to be written to JSON."""
    return {
        "index": entry["index"],
        "timestamp": entry["timestamp"],
        "prev_hash": encode_bytes(entry["prev_hash"]),
        "blob": encode_bytes(entry["blob"]),
        "entry_hash": encode_bytes(entry["entry_hash"]),
        "signature": encode_bytes(entry["signature"])
    }


def deserialize_entry(entry: dict) -> dict:
    """The other way round. Raises if the entry looks wrong."""
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
    """Load the user's entries from disk, with bytes decoded. Any problem -> DiaryError."""
    try:
        stored_entries = load_entries(session.username)

        return [
            deserialize_entry(entry)
            for entry in stored_entries
        ]
    except StorageError:
        raise DiaryError("Diary data could not be read.") from None
    except (KeyError, TypeError, ValueError, binascii.Error):
        # missing field, wrong type, broken base64: the file was damaged or edited
        raise DiaryError("Diary data is invalid.") from None


# ---------- the diary head: notices deleted newest entries ----------

def make_head(private_key, count: int, last_hash: bytes) -> dict:
    """Sign "the diary has `count` entries and the last one has this hash".

    Also used at registration, with count 0 and the genesis hash.
    """
    signature = signing.sign(private_key, chain.head_message(count, last_hash))
    return {
        "count": count,
        "last_hash": encode_bytes(last_hash),
        "signature": encode_bytes(signature),
    }


def decode_head(record):
    """Stored head -> dict with bytes, or None if it's missing or malformed."""
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


# ---------- title + text travel together inside the encrypted blob ----------

def encode_entry(title: str, text: str) -> bytes:
    return json.dumps({"title": title, "text": text}, ensure_ascii=False).encode("utf-8")


def decode_entry(raw: bytes, index: int) -> tuple:
    """Decrypted bytes -> (title, text). The format is checked, nothing is trusted."""
    try:
        data = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise DiaryError(f"Entry {index + 1} has an invalid format.") from None
    if (not isinstance(data, dict) or not isinstance(data.get("title"), str) or not isinstance(data.get("text"), str)):
        raise DiaryError(f"Entry {index + 1} has an invalid format.")
    return data["title"], data["text"]


def validate_input(title, text) -> tuple:
    """Check what the user typed. Returns the cleaned (title, text)."""
    if not isinstance(text, str) or not text.strip():
        raise DiaryError("Diary entry can't be empty.")
    if not isinstance(title, str):
        raise DiaryError("The title must be text.")
    title = title.strip()
    if len(title) > MAX_TITLE_LEN:
        raise DiaryError(f"The title can't be longer than {MAX_TITLE_LEN} characters.")
    if len(text) > MAX_TEXT_LEN:
        raise DiaryError(f"An entry can't be longer than {MAX_TEXT_LEN} characters.")
    return title, text


def required_active(session) -> None:
    """Refuse to work with a session that was already closed (logged out)."""
    if getattr(session, "closed", True):
        raise DiaryError("This session is closed. Please login again.")


# ---------- verification ----------

def inspect(session):
    """Load the whole diary and check everything in one go.

    For every entry: chain link, hash, signature, and the AES-GCM tag.
    Then the signed head. Returns (entries, results, payloads) where
    results is a list of (index, ok, reason) and payloads holds the
    decrypted bytes of the entries that passed.
    """
    required_active(session)
    entries = load_decoded_entries(session)
    results = chain.verify_chain(entries, session.signing_public_key, signing.verify)
    payloads = {}

    for position, entry in enumerate(entries):
        if not results[position][1]:
            continue   # already known to be bad, no point in decrypting it
        # the AAD ties the ciphertext to its position: a moved entry fails here
        aad = chain.make_aad(entry["index"], entry["prev_hash"])
        try:
            payloads[position] = aead.decrypt(session.dek, entry["blob"], aad=aad)
        except aead.DecryptionError:
            results[position] = (position, False, "AES-GCM authentication failed.")

    # the head check only adds a row when it FAILS (index None = "the diary as a whole")
    head_ok, head_reason = chain.verify_head(entries, load_head(session), session.signing_public_key, signing.verify)
    if not head_ok:
        results.append((None, False, head_reason))

    return entries, results, payloads


def verified(session):
    """Like inspect(), but stops with an error if anything is wrong."""
    entries, results, payloads = inspect(session)
    if any(not ok for _, ok, _ in results):
        raise DiaryError("Integrity check of diary failed.")
    return entries, payloads


def verify_diary(session) -> list:
    """The table shown in 'Verify diary integrity': list of (index, ok, reason)."""
    return inspect(session)[1]


# ---------- writing and reading ----------

def create_entry(session, text: str, title: str = "") -> None:
    """Encrypt, chain, sign and store a new entry. Refuses if the diary is already broken."""
    title, text = validate_input(title, text)

    # never add to a diary that fails verification, or we'd hide the damage
    entries, results, _ = inspect(session)
    if any(not ok for _, ok, _ in results):
        raise DiaryError("Diary integrity check failed. Can't add entry.")

    index = len(entries)

    if entries:
        prev_hash = entries[-1]["entry_hash"]
    else:
        prev_hash = chain.GENESIS_HASH   # the first entry has nothing before it

    timestamp = int(time.time())
    aad = chain.make_aad(index, prev_hash)
    blob = aead.encrypt(session.dek, encode_entry(title, text), aad=aad)   # fresh nonce inside
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
        # first the entry, then the head. If the program dies in between, the new
        # entry is still valid (signed), so nothing is lost or hidden.
        save_entries(session.username, stored_entries)
        save_head(session, index + 1, entry_hash)
    except StorageError:
        raise DiaryError("Diary entry couldn't be saved.") from None


def get_entries(session) -> list:
    """All entries, decrypted, but only if the whole diary verifies."""
    entries, payloads = verified(session)
    plaintext_entries = []

    for position, entry in enumerate(entries):
        title, text = decode_entry(payloads[position], position)
        plaintext_entries.append({
            "index": entry["index"],
            "timestamp": entry["timestamp"],
            "title": title,
            "text": text,
        })
    return plaintext_entries


def get_entry_list(session) -> list:
    """Index, date and title of every entry (the overview list)."""
    return [
        {"index": e["index"], "timestamp": e["timestamp"], "title": e["title"]}
        for e in get_entries(session)]


def get_entry(session, index: int) -> dict:
    """One decrypted entry, after verifying the whole diary."""
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
