CREATE TABLE meta (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE messages (
    message_id TEXT PRIMARY KEY,
    created_at INTEGER NOT NULL,
    k INTEGER NOT NULL,
    n INTEGER NOT NULL,
    ciphertext BLOB NOT NULL,
    nonce BLOB NOT NULL,
    ciphertext_sha256 TEXT NOT NULL,
    owner_page TEXT NOT NULL,
    share_index INTEGER,
    share_nonce BLOB,
    share_cipher BLOB,
    email_nonce BLOB,
    email_cipher BLOB
);

CREATE TABLE events (
    event_hash TEXT PRIMARY KEY,
    message_id TEXT NOT NULL,
    event_type TEXT NOT NULL,
    body TEXT NOT NULL,
    signature TEXT NOT NULL,
    signer_public TEXT NOT NULL,
    received_at INTEGER NOT NULL
);

CREATE INDEX events_message ON events (message_id, received_at);

CREATE TABLE request_contacts (
    request_id TEXT PRIMARY KEY,
    message_id TEXT NOT NULL,
    email_nonce BLOB,
    email_cipher BLOB
);

CREATE TABLE notices (
    dedupe_key TEXT PRIMARY KEY,
    message_id TEXT,
    kind TEXT NOT NULL,
    to_address TEXT NOT NULL,
    subject TEXT NOT NULL,
    body_nonce BLOB,
    body_cipher BLOB,
    attempts INTEGER NOT NULL DEFAULT 0,
    next_attempt_at INTEGER NOT NULL,
    last_error TEXT,
    sent_at INTEGER
);

CREATE TABLE publications (
    request_id TEXT PRIMARY KEY,
    message_id TEXT NOT NULL,
    published_at INTEGER NOT NULL
);

CREATE TABLE failures (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    happened_at INTEGER NOT NULL,
    kind TEXT NOT NULL,
    detail TEXT NOT NULL
);

CREATE TABLE peers (
    endpoint TEXT PRIMARY KEY,
    sign_pubkey TEXT NOT NULL,
    last_sync_at INTEGER,
    last_error TEXT
);

CREATE TABLE key_rotations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    body TEXT NOT NULL,
    signature TEXT NOT NULL,
    signer_public TEXT NOT NULL,
    created_at INTEGER NOT NULL
);

CREATE TABLE admin_auth (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    password_hash TEXT NOT NULL,
    reset_hash TEXT NOT NULL
);

CREATE TABLE rate_limits (
    bucket TEXT PRIMARY KEY,
    hits INTEGER NOT NULL,
    window_start INTEGER NOT NULL
);
