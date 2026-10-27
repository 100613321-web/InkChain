CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,

    username TEXT NOT NULL UNIQUE,

    salt_auth BLOB NOT NULL,
    auth_hash BLOB NOT NULL,

    salt_kek BLOB NOT NULL,
    wrapped_dek BLOB NOT NULL,
    dek_nonce BLOB NOT NULL,

    pubkey BLOB NOT NULL,
    wrapped_privkey BLOB NOT NULL,
    privkey_nonce BLOB NOT NULL,

    failed_attempts INTEGER NOT NULL DEFAULT 0
        CHECK (failed_attempts >= 0),
    locked_until INTEGER
);

CREATE TABLE IF NOT EXISTS entries (
    id INTEGER PRIMARY KEY AUTOINCREMENT,

    user_id INTEGER NOT NULL,

    idx INTEGER NOT NULL CHECK (idx >= 0),

    timestamp TEXT NOT NULL,

    nonce BLOB NOT NULL,
    ciphertext BLOB NOT NULL,

    prev_hash BLOB,
    entry_hash BLOB NOT NULL,

    signature BLOB NOT NULL,

    FOREIGN KEY (user_id)
        REFERENCES users(id)
        ON DELETE CASCADE,

    UNIQUE (user_id, idx)
);

CREATE INDEX IF NOT EXISTS idx_entries_user_timestamp
ON entries (user_id, timestamp);