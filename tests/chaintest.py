from crypto import chain, signing, aead

KEY = b"\x01" * 32


def make_chain(n):
    """Build n valid entries, returns (entries, public_key)."""
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
    return entries, pub


def check(entries, pub):
    return chain.verify_chain(entries, pub, signing.verify)


def test_valid_chain():
    entries, pub = make_chain(4)
    assert all(ok for _, ok, _ in check(entries, pub))


def test_deleted_middle_entry_detected():
    entries, pub = make_chain(4)
    del entries[1]
    assert not all(ok for _, ok, _ in check(entries, pub))


def test_swapped_entries_detected():
    entries, pub = make_chain(4)
    entries[1], entries[2] = entries[2], entries[1]
    assert not all(ok for _, ok, _ in check(entries, pub))


def test_replayed_old_entry_detected():
    entries, pub = make_chain(4)
    entries.append(entries[1])          # old entry pasted at the end
    assert not all(ok for _, ok, _ in check(entries, pub))


def test_modified_blob_detected():
    entries, pub = make_chain(3)
    b = bytearray(entries[1]["blob"])
    b[15] ^= 1
    entries[1]["blob"] = bytes(b)
    assert not check(entries, pub)[1][1]


def test_moved_ciphertext_fails_gcm():
    """AAD binds the blob to its position: same blob, other position -> rejected."""
    entries, _ = make_chain(3)
    wrong_aad = chain.make_aad(2, entries[2]["prev_hash"])
    with __import__("pytest").raises(aead.DecryptionError):
        aead.decrypt(KEY, entries[1]["blob"], aad=wrong_aad)