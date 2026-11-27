"""Hash chain: makes deleted, reordered or edited entries show up."""
import hashlib

GENESIS_HASH = b"\x00" * 32  # prev_hash of the first entry (nothing before it)
HEAD_PREFIX = b"inkchain-head-v1" # domain seperation for the signed diary head

def _int_bytes(value: int) -> bytes:
    # Fixed 8 bytes so every number has one single encoding.
    if type(value) is not int or not 0 <= value < 2**64:
        raise ValueError("expected an integer between 0 and 2**64 - 1")
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

def head_message(count: int, last_hash: bytes) -> bytes:
    """Bytes that are signed for diary head, which consists of entry count + last entry hash"""
    return HEAD_PREFIX + _int_bytes(count) + _int_bytes(len(last_hash)) + last_hash

def verify_head(entries: list, head, public_key, verify_signature) -> tuple:
    """Checks the signed head against the entries and returns a tuple (ok, reason)"""
    if head is None:
        return False, "diary head missing or malformed"

    count, last_hash = head["count"], head["last_hash"]

    if not verify_signature(public_key, head["signature"], head_message(count, last_hash)):
        return False, "diary head signature invalid"
    if count > len(entries):
        return False, f"{count - len(entries)} entries missing at diary end"

    expected_last = entries[count - 1]["entry_hash"] if count > 0 else GENESIS_HASH
    if expected_last != last_hash:
        return False, "diary head doesn't match the chain"
    return True, "ok"