"""Hash chain: links entries so deletion, reordering or edits are detected."""
import hashlib

GENESIS_HASH = b"\x00" * 32  # prev_hash of the very first entry


def _int_bytes(value: int) -> bytes:
    return value.to_bytes(8, "big")


def compute_entry_hash(index: int, timestamp: int, prev_hash: bytes, blob: bytes) -> bytes:
    """SHA-256 over every field of the entry. Length prefixes avoid ambiguity."""
    h = hashlib.sha256()
    h.update(_int_bytes(index))
    h.update(_int_bytes(timestamp))
    h.update(_int_bytes(len(prev_hash)) + prev_hash)
    h.update(_int_bytes(len(blob)) + blob)
    return h.digest()


def make_aad(index: int, prev_hash: bytes) -> bytes:
    """Associated data for AES-GCM: binds the ciphertext to its position."""
    return _int_bytes(index) + prev_hash


def verify_chain(entries: list, public_key, verify_signature) -> list:
    """Check every entry. Returns a list of (index, ok, reason).

    entries: list of dicts with bytes fields
             index, timestamp, prev_hash, blob, entry_hash, signature
    verify_signature: function (public_key, signature, data) -> bool
    """
    results = []
    expected_prev = GENESIS_HASH

    for position, e in enumerate(entries):
        if e["index"] != position:
            results.append((position, False, "index out of order"))
        elif e["prev_hash"] != expected_prev:
            results.append((position, False, "broken chain link"))
        elif compute_entry_hash(e["index"], e["timestamp"], e["prev_hash"], e["blob"]) != e["entry_hash"]:
            results.append((position, False, "entry hash mismatch"))
        elif not verify_signature(public_key, e["signature"], e["entry_hash"]):
            results.append((position, False, "invalid signature"))
        else:
            results.append((position, True, "ok"))

        # Continue from what the entry CLAIMS, so one bad entry is reported
        # once instead of making every later entry fail too.
        expected_prev = e["entry_hash"]

    return results