import base64

import pytest

import storage.files as storage
from services.auth import register_user, login_user
from services.diary import (
    create_entry, get_entries, get_entry, get_entry_list, verify_diary, DiaryError,
)

PW = "Horse-Battery-42"
PW2 = "Staple-Orange-77"


@pytest.fixture
def session(isolated_storage):
    # a registered, logged-in alice with an empty diary
    register_user("alice", PW)
    return login_user("alice", PW)


def all_ok(results):
    # True if every row of the verification result is ok
    return all(ok for _, ok, _ in results)


# ---------- normal behaviour ----------

# Writing an entry stores it with index 0.
def test_create_entry(session):
    create_entry(session, "My first diary entry", title="Day one")
    entries = storage.load_entries("alice")
    assert len(entries) == 1
    assert entries[0]["index"] == 0


# Each entry points to the hash of the previous one (the chain).
def test_create_multiple_entries_are_chained(session):
    create_entry(session, "First entry")
    create_entry(session, "Second entry")
    entries = storage.load_entries("alice")
    assert [e["index"] for e in entries] == [0, 1]
    assert entries[1]["prev_hash"] == entries[0]["entry_hash"]


# Reading returns the same title and text that were written.
def test_get_entries_returns_title_and_text(session):
    create_entry(session, "My first entry", title="One")
    create_entry(session, "My second entry", title="Two")
    entries = get_entries(session)
    assert [e["text"] for e in entries] == ["My first entry", "My second entry"]
    assert [e["title"] for e in entries] == ["One", "Two"]


# The overview list shows the titles in order.
def test_entry_list_shows_titles(session):
    create_entry(session, "body one", title="Title one")
    create_entry(session, "body two", title="Title two")
    assert [e["title"] for e in get_entry_list(session)] == ["Title one", "Title two"]


# Opening one entry by its index returns the right one.
def test_get_single_entry(session):
    create_entry(session, "first", title="A")
    create_entry(session, "second", title="B")
    entry = get_entry(session, 1)
    assert entry["text"] == "second" and entry["title"] == "B"


# Ukrainian text, accents and emoji survive encrypt + decrypt.
def test_unicode_roundtrip(session):
    text = "\u041f\u0440\u0438\u0432\u0456\u0442, \u0449\u043e\u0434\u0435\u043d\u043d\u0438\u0447\u043a\u0443! caf\u00e9 \U0001F512"
    create_entry(session, text, title="\u0417\u0430\u043f\u0438\u0441")
    entry = get_entries(session)[0]
    assert entry["text"] == text and entry["title"] == "\u0417\u0430\u043f\u0438\u0441"


# A diary nobody touched passes the integrity check.
def test_verify_valid_diary(session):
    create_entry(session, "First entry")
    create_entry(session, "Second entry")
    assert all_ok(verify_diary(session))


# A new empty diary is fine, there is nothing to report.
def test_verify_empty_diary(session):
    assert verify_diary(session) == []
    assert get_entries(session) == []


# Each user only sees their own entries.
def test_users_have_separate_diaries(isolated_storage):
    register_user("alice", PW)
    register_user("bob", PW2)
    alice, bob = login_user("alice", PW), login_user("bob", PW2)
    create_entry(alice, "Alice's private diary")
    create_entry(bob, "Bob's private diary")
    assert get_entries(alice)[0]["text"] == "Alice's private diary"
    assert get_entries(bob)[0]["text"] == "Bob's private diary"


# ---------- what is (not) on disk ----------

# Neither the title nor the text appears in entries.json: it is all encrypted.
def test_title_and_text_are_not_readable_on_disk(session, isolated_storage):
    create_entry(session, "very secret body", title="very secret title")
    raw = (isolated_storage / "entries.json").read_text(encoding="utf-8")
    assert "very secret body" not in raw
    assert "very secret title" not in raw


# Same text twice -> different ciphertext and different nonce (the first 12 bytes).
def test_same_text_gives_different_ciphertext_and_nonce(session):
    create_entry(session, "same text")
    create_entry(session, "same text")
    b0, b1 = (base64.b64decode(e["blob"]) for e in storage.load_entries("alice"))
    assert b0 != b1
    assert b0[:12] != b1[:12]          # the nonces differ


# ---------- input validation ----------

# An empty or whitespace-only entry is refused.
@pytest.mark.parametrize("text", ["", "   ", None])
def test_empty_or_invalid_entry_is_rejected(session, text):
    with pytest.raises(DiaryError):
        create_entry(session, text)


# A title over 100 characters is refused.
def test_too_long_title_rejected(session):
    with pytest.raises(DiaryError):
        create_entry(session, "text", title="x" * 101)


# Asking for an entry that does not exist gives a clean error.
@pytest.mark.parametrize("index", [-1, 5])
def test_get_entry_with_bad_index(session, index):
    create_entry(session, "only one")
    with pytest.raises(DiaryError):
        get_entry(session, index)


# ---------- sessions ----------

# After logout the old session object is useless.
def test_closed_session_cannot_be_used(session):
    create_entry(session, "before logout")
    session.close()
    with pytest.raises(DiaryError):
        create_entry(session, "after logout")
    with pytest.raises(DiaryError):
        get_entries(session)
    with pytest.raises(DiaryError):
        verify_diary(session)


