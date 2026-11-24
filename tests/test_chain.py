import pytest

from crypto import aead, chain, signing

KEY = b"\x01" * 32


def make_chain(n):
    """Build n valid entries the same way diary.py does. Returns (entries, public_key, private_key)."""
    priv, pub = signing.generate_keypair()
    entries, prev = [], chain.GENESIS_HASH
    for i in range(n):
        aad = chain.make_aad(i, prev)
        blob = aead.encrypt(KEY, f"text {i}".encode(), aad=aad)
        ts = 1_700_000_000 + i
        h = chain.compute_entry_hash(i, ts, prev, blob)
        entries.append({
            "index": i, "timestamp": ts, "prev_hash": prev,
            "blob": blob, "entry_hash": h, "signature": signing.sign(priv, h),
        })
        prev = h
    return entries, pub, priv


def check(entries, pub):
    # shortcut for "run the full chain check"
    return chain.verify_chain(entries, pub, signing.verify)


def reasons(entries, pub):
    # only the text reasons, handy for asserting WHY an entry failed
    return [r for _, _, r in check(entries, pub)]


def flip(data, pos=15):
    # change one bit of one byte, returns a new bytes object
    b = bytearray(data)
    b[pos] ^= 1
    return bytes(b)


# ---------- normal behaviour ----------
def test_valid_chain():
    entries, pub, _ = make_chain(4)
    assert all(ok for _, ok, _ in check(entries, pub))


def test_empty_chain_is_valid():
    _, pub, _ = make_chain(0)
    assert check([], pub) == []


def test_hash_is_deterministic():
    h1 = chain.compute_entry_hash(0, 5, chain.GENESIS_HASH, b"blob")
    h2 = chain.compute_entry_hash(0, 5, chain.GENESIS_HASH, b"blob")
    assert h1 == h2 and len(h1) == 32


@pytest.mark.parametrize("args", [
    (1, 5, chain.GENESIS_HASH, b"blob"),      # index
    (0, 6, chain.GENESIS_HASH, b"blob"),      # timestamp
    (0, 5, b"\x01" * 32, b"blob"),            # prev_hash
    (0, 5, chain.GENESIS_HASH, b"blob2"),     # blob
])
def test_changing_any_field_changes_the_hash(args):
    base = chain.compute_entry_hash(0, 5, chain.GENESIS_HASH, b"blob")
    assert chain.compute_entry_hash(*args) != base


def test_length_prefix_prevents_field_shifting():
    # Same bytes in total, just split differently between prev_hash and blob.
    # Without the length prefixes these two could give the same hash.
    a = chain.compute_entry_hash(0, 0, b"ab", b"c")
    b = chain.compute_entry_hash(0, 0, b"a", b"bc")
    assert a != b


# ---------- attacks on the structure of the diary ----------
def test_deleted_middle_entry_detected():
    entries, pub, _ = make_chain(4)
    del entries[1]
    assert not all(ok for _, ok, _ in check(entries, pub))


def test_deleted_first_entry_detected():
    entries, pub, _ = make_chain(3)
    del entries[0]
    assert not all(ok for _, ok, _ in check(entries, pub))


def test_swapped_entries_detected():
    entries, pub, _ = make_chain(4)
    entries[1], entries[2] = entries[2], entries[1]
    assert not all(ok for _, ok, _ in check(entries, pub))


def test_replayed_old_entry_detected():
    entries, pub, _ = make_chain(4)
    entries.append(entries[1])          # an old entry pasted again at the end
    assert not all(ok for _, ok, _ in check(entries, pub))


def test_duplicated_entry_detected():
    entries, pub, _ = make_chain(3)
    entries.insert(1, entries[1])
    assert not all(ok for _, ok, _ in check(entries, pub))


# ---------- attacks on fields inside an entry ----------
def test_modified_blob_detected():
    entries, pub, _ = make_chain(3)
    entries[1]["blob"] = flip(entries[1]["blob"])
    assert not check(entries, pub)[1][1]


def test_modified_timestamp_detected():
    entries, pub, _ = make_chain(3)
    entries[1]["timestamp"] += 1
    assert reasons(entries, pub)[1] == "entry hash mismatch"


def test_modified_prev_hash_detected():
    entries, pub, _ = make_chain(3)
    entries[1]["prev_hash"] = flip(entries[1]["prev_hash"], 0)
    assert reasons(entries, pub)[1] == "broken chain link"


def test_modified_signature_detected():
    entries, pub, _ = make_chain(3)
    entries[2]["signature"] = flip(entries[2]["signature"], -1)
    assert reasons(entries, pub)[2] == "invalid signature"


def test_forged_entry_with_recomputed_hash_but_no_private_key():
    """Attacker edits the blob AND recomputes entry_hash. Hashes are public, so
    that part is easy. What they can't do is sign it, so the signature check catches it."""
    entries, pub, _ = make_chain(3)
    e = entries[1]
    e["blob"] = flip(e["blob"])
    e["entry_hash"] = chain.compute_entry_hash(e["index"], e["timestamp"], e["prev_hash"], e["blob"])
    assert reasons(entries, pub)[1] == "invalid signature"


def test_entries_signed_by_another_key_rejected():
    entries, _, _ = make_chain(3)
    _, other_pub = signing.generate_keypair()
    # all of them fail, because none was signed by this user
    assert not any(ok for _, ok, _ in check(entries, other_pub))


def test_one_bad_entry_is_reported_only_once():
    entries, pub, _ = make_chain(4)
    # entry 2 and 3 still point to the hash entry 1 claims, so only entry 1 is red
    entries[1]["blob"] = flip(entries[1]["blob"])
    assert [ok for _, ok, _ in check(entries, pub)] == [True, False, True, True]


@pytest.mark.parametrize("field,value", [
    ("index", -1), ("timestamp", "yesterday"), ("timestamp", None), ("index", 1.5),
])
def test_malformed_numbers_are_reported_not_crashing(field, value):
    entries, pub, _ = make_chain(2)
    entries[1][field] = value   # junk numbers must give a clean "False", not a crash
    assert check(entries, pub)[1] == (1, False, "malformed entry")


# ---------- AAD: the ciphertext is tied to its position ----------
def test_moved_ciphertext_fails_gcm():
    entries, _, _ = make_chain(3)
    # pretend entry 1's ciphertext was copied into position 2
    wrong_aad = chain.make_aad(2, entries[2]["prev_hash"])
    with pytest.raises(aead.DecryptionError):
        aead.decrypt(KEY, entries[1]["blob"], aad=wrong_aad)


def test_correct_aad_decrypts():
    entries, _, _ = make_chain(3)
    aad = chain.make_aad(1, entries[1]["prev_hash"])
    assert aead.decrypt(KEY, entries[1]["blob"], aad=aad) == b"text 1"


# ---------- known limit, kept on purpose (goes in the report) ----------
def test_truncating_the_tail_is_not_detected_known_limit():
    """Cutting the LAST entries (or restoring an old copy of the file)
    leaves a valid chain. A purely local app can't tell. Honest limit."""
    entries, pub, _ = make_chain(4)
    del entries[-2:]
    assert all(ok for _, ok, _ in check(entries, pub))