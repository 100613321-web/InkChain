"""Attacks on the files on disk. The app must notice and refuse, never crash."""
import base64

import pytest

import storage.files as storage
from services.auth import register_user, login_user
from services.diary import create_entry, get_entries, get_entry, verify_diary, DiaryError

PW = "Horse-Battery-42"
PW2 = "Staple-Orange-77"


@pytest.fixture
def session(isolated_storage):
    # alice with three valid entries, ready to be attacked
    register_user("alice", PW)
    s = login_user("alice", PW)
    for text in ("one", "two", "three"):
        create_entry(s, text, title=text.upper())
    return s


def mutate_entries(fn):
    # play the attacker: edit entries.json directly on disk, behind the app's back
    entries = storage.load_entries("alice")
    fn(entries)
    storage.save_entries("alice", entries)


def mutate_user(fn, name="alice"):
    # same, but for users.json (where the keys and the diary head live)
    users = storage.load_users()
    fn(users[name])
    storage.save_users(users)


def flip_b64(value, pos=15):
    # flip one bit inside a base64 value and return it as base64 again
    raw = bytearray(base64.b64decode(value))
    raw[pos] ^= 1
    return base64.b64encode(bytes(raw)).decode()


def all_ok(session):
    # True only if every row of the integrity check is green
    return all(ok for _, ok, _ in verify_diary(session))


def reasons(session):
    # the text reasons of the red rows
    return [r for _, ok, r in verify_diary(session) if not ok]


def assert_diary_refused(session):
    # what "fails safely" means: verification is red, reading is refused, writing is refused
    assert not all_ok(session)
    with pytest.raises(DiaryError):
        get_entries(session)
    with pytest.raises(DiaryError):
        get_entry(session, 0)
    with pytest.raises(DiaryError):          # refuses to add to a broken diary
        create_entry(session, "x")


# ---------- entries.json ----------

# Attacker flips one bit of an entry on disk: caught, and reading and writing are refused.
def test_flipped_ciphertext(session):
    mutate_entries(lambda e: e[1].update(blob=flip_b64(e[1]["blob"])))
    assert_diary_refused(session)


# Attacker deletes an entry from the middle: caught.
def test_deleted_middle_entry(session):
    mutate_entries(lambda e: e.pop(1))
    assert_diary_refused(session)


# Attacker swaps two entries: caught.
def test_swapped_entries(session):
    mutate_entries(lambda e: e.insert(0, e.pop(1)))
    assert_diary_refused(session)


# Attacker copies an old entry to the end (replay): caught.
def test_replayed_old_entry_pasted_at_the_end(session):
    mutate_entries(lambda e: e.append(dict(e[0])))
    assert_diary_refused(session)


# Attacker edits a signature: caught.
def test_modified_signature(session):
    mutate_entries(lambda e: e[2].update(signature=flip_b64(e[2]["signature"], -1)))
    assert_diary_refused(session)


# Garbage where base64 should be: clean error, no crash.
def test_malformed_base64(session):
    mutate_entries(lambda e: e[0].update(blob="!!!not-base64"))
    with pytest.raises(DiaryError):
        get_entries(session)
    with pytest.raises(DiaryError):
        verify_diary(session)


# entries.json is broken: clean error on read and on write.
def test_entries_file_corrupted(session, isolated_storage):
    (isolated_storage / "entries.json").write_text("{broken", encoding="utf-8")
    with pytest.raises(DiaryError):
        get_entries(session)
    with pytest.raises(DiaryError):
        create_entry(session, "x")


# ---------- the signed diary head (tail deletion) ----------

# Deleting the NEWEST entry: only the signed head can notice this, and it does.
def test_deleting_the_last_entry_is_detected(session):
    mutate_entries(lambda e: e.pop())
    assert not all_ok(session)
    assert any("missing" in r for r in reasons(session))
    with pytest.raises(DiaryError):
        get_entries(session)


# Deleting the whole diary is noticed too.
def test_deleting_every_entry_is_detected(session):
    mutate_entries(lambda e: e.clear())
    assert not all_ok(session)
    with pytest.raises(DiaryError):
        get_entries(session)


# After a deletion the app refuses new entries, so the damage can not be hidden.
def test_cannot_add_after_tail_deletion(session):
    mutate_entries(lambda e: e.pop())
    with pytest.raises(DiaryError):
        create_entry(session, "trying to hide it")


# Removing the head record from users.json is noticed.
def test_missing_head_is_detected(session):
    mutate_user(lambda u: u.pop("diary_head"))
    assert not all_ok(session)


# Attacker lowers the count to match the shortened file: the head signature no longer matches.
def test_forged_head_count_is_detected(session):
    # attacker lowers the count to match a truncated file, but can't re-sign
    mutate_user(lambda u: u["diary_head"].update(count=2))
    assert not all_ok(session)


# A valid head of ANOTHER user does not verify with this user's key.
def test_head_copied_from_another_user_is_rejected(isolated_storage):
    register_user("alice", PW)
    register_user("bob", PW2)
    alice, bob = login_user("alice", PW), login_user("bob", PW2)
    create_entry(alice, "a1")
    create_entry(bob, "b1")
    bob_head = storage.load_users()["bob"]["diary_head"]
    mutate_user(lambda u: u.__setitem__("diary_head", bob_head))
    assert not all_ok(alice)


def test_entries_saved_but_head_not_yet_updated_still_verifies(session):
    """Simulates a crash between writing entries.json and users.json.
    The newest entry is valid (signed) so we accept it, nothing is hidden."""
    old_head = storage.load_users()["alice"]["diary_head"]
    create_entry(session, "four")
    mutate_user(lambda u: u.__setitem__("diary_head", old_head))
    assert all_ok(session)


# ---------- users.json ----------

# A modified encrypted diary key: login refuses (GCM tag fails).
def test_tampered_encrypted_dek_blocks_login(isolated_storage):
    register_user("bob", PW)
    mutate_user(lambda u: u.update(encrypted_dek=flip_b64(u["encrypted_dek"], -1)), name="bob")
    from services.auth import AuthError
    with pytest.raises(AuthError):
        login_user("bob", PW)


# ---------- known limit (goes in the report) ----------

def test_rollback_of_both_files_is_NOT_detected_known_limit(session, isolated_storage):
    """Restoring an old COPY of entries.json AND users.json together gives a
    consistent, correctly signed past state. A purely local app can't tell."""
    old_entries = storage.load_entries("alice")[:2]
    old_head_users = storage.load_users()
    # build the "old" state: 2 entries, head for 2 entries
    from services.diary import make_head
    from services.diary import decode_bytes
    head = make_head(session.signing_private_key, 2, decode_bytes(old_entries[1]["entry_hash"]))
    old_head_users["alice"]["diary_head"] = head
    storage.save_entries("alice", old_entries)
    storage.save_users(old_head_users)
    assert all_ok(session)
