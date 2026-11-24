"""Hash chain: makes deleted, reordered or edited entries show up."""
import hashlib

GENESIS_HASH = b"\x00" * 32  # prev_hash of the first entry (nothing before it)


def _int_bytes(value: int) -> bytes:
    # Fixed 8 bytes so every number has one single encoding.
    if type(value) is not int or value < 0:
        raise ValueError("expected a non-negative integer")
    return value.to_bytes(8, "big")


def compute_entry_hash(index: int, timestamp: int, prev_hash: bytes, blob: bytes) -> bytes:
    """SHA-256 over all fields of the entry.

    The lengths go in front of the variable parts, so moving bytes from
    one field to the next can't give the same hash.
    """
    h = hashlib.sha256()
    h.update(_int_bytes(index))
    h.update(_int_bytes(timestamp))
    h.update(_int_bytes(len(prev_hash)) + prev_hash)
    h.update(_int_bytes(len(blob)) + blob)
    return h.digest()


def make_aad(index: int, prev_hash: bytes) -> bytes:
    """AAD for AES-GCM: ties the ciphertext to its place in the chain."""
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
        try:
            recomputed = compute_entry_hash(e["index"], e["timestamp"], e["prev_hash"], e["blob"])
        except (ValueError, TypeError):
            # e.g. a negative index or a timestamp that isn't a number
            results.append((position, False, "malformed entry"))
            expected_prev = e.get("entry_hash", b"")
            continue

        if e["index"] != position:
            results.append((position, False, "index out of order"))
        elif e["prev_hash"] != expected_prev:
            results.append((position, False, "broken chain link"))
        elif recomputed != e["entry_hash"]:
            results.append((position, False, "entry hash mismatch"))
        elif not verify_signature(public_key, e["signature"], e["entry_hash"]):
            results.append((position, False, "invalid signature"))
        else:
            results.append((position, True, "ok"))

        # Next entry is compared against what THIS entry claims as its hash.
        # That way one bad entry is reported once and doesn't make all the
        # later ones fail too.
        expected_prev = e["entry_hash"]

    return results