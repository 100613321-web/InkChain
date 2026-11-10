import base64
import binascii
import time

from storage.files import load_entries, save_entries
from crypto import aead, signing, chain

class DiaryError(Exception):
    """Raised when a diary operation fails."""

def encode_bytes(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")

def decode_bytes(data: str) -> bytes:
    return base64.b64decode(data, validate=True)

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

def create_entry(session, plaintext: str) -> None:
    if not isinstance(plaintext, str) or not plaintext.strip():
        raise DiaryError("Diary entry can't be empty.")

    entries = load_decoded_entries(session)

    verification = chain.verify_chain(entries, session.signing_public_key, signing.verify)

    if any(not ok for _, ok, _ in verification):
        raise DiaryError ("Diary integrity check failed. Can't add entry.")

    index = len(entries)

    if entries:
        prev_hash = entries[-1]["entry_hash"]
    else:
        prev_hash = chain.GENESIS_HASH

    timestamp = int(time.time())
    aad = chain.make_aad(index, prev_hash)
    blob = aead.encrypt(session.dek, plaintext.encode("utf-8"), aad=aad)
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

    stored_entries = [
        serialize_entry(existing)
        for existing in entries
    ]

    stored_entries.append(serialize_entry(entry))
    save_entries(session.username, stored_entries)

def get_entries(session) -> list:
    entries = load_decoded_entries(session)

    verification = chain.verify_chain(entries, session.signing_public_key, signing.verify)

    if any(not ok for _, ok, _ in verification):
        raise DiaryError("Diary integrity check failed.")

    plaintext_entries = []

    for entry in entries:
        aad = chain.make_aad(entry["index"], entry["prev_hash"])

        try:
            plaintext = aead.decrypt(session.dek, entry["blob"], aad=aad)
            plaintext_entries.append({
                "index": entry["index"],
                "timestamp": entry["timestamp"],
                "text": plaintext.decode("utf-8")
            })

        except (aead.DecryptionError, UnicodeDecodeError):
            raise DiaryError(f"Could not decrypt diary entry {entry['index']}.") from None
    return plaintext_entries

def verify_diary(session) -> list:
    entries = load_decoded_entries(session)
    results = chain.verify_chain(entries, session.signing_public_key, signing.verify)

    return results

