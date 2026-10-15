-- Initial schema of the gim hub (client API v2).
--
-- Timestamps are integer milliseconds since the Unix epoch. Devices are keyed
-- by (user_id, device_id): a device ID is only meaningful together with the
-- DeviceList that certifies it.

CREATE TABLE meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
) WITHOUT ROWID;

-- Users and their current signed DeviceList (gim-core CBOR, stored verbatim).
CREATE TABLE users (
    user_id         TEXT PRIMARY KEY,
    root_pubkey     BLOB NOT NULL,
    device_list     BLOB NOT NULL,
    device_list_seq INTEGER NOT NULL,
    created_at      INTEGER NOT NULL,
    updated_at      INTEGER NOT NULL
);

-- Devices derived from the DeviceCerts of the current DeviceList.
CREATE TABLE devices (
    user_id    TEXT NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
    device_id  TEXT NOT NULL,
    sig_pubkey BLOB NOT NULL,
    active     INTEGER NOT NULL CHECK (active IN (0, 1)),
    updated_at INTEGER NOT NULL,
    PRIMARY KEY (user_id, device_id)
) WITHOUT ROWID;

CREATE TABLE handles (
    handle     TEXT PRIMARY KEY,
    user_id    TEXT NOT NULL UNIQUE REFERENCES users(user_id) ON DELETE CASCADE,
    created_at INTEGER NOT NULL
) WITHOUT ROWID;

CREATE TABLE recovery_backups (
    user_id    TEXT PRIMARY KEY REFERENCES users(user_id) ON DELETE CASCADE,
    backup     BLOB NOT NULL,
    updated_at INTEGER NOT NULL
);

-- Sealed link bundles; deleted on first fetch or after expires_at.
CREATE TABLE link_bundles (
    link_id       TEXT PRIMARY KEY,
    sealed_bundle BLOB NOT NULL,
    created_at    INTEGER NOT NULL,
    expires_at    INTEGER NOT NULL
);
CREATE INDEX link_bundles_expires_at ON link_bundles(expires_at);

-- Single-use sign-in challenges.
CREATE TABLE auth_challenges (
    challenge_id TEXT PRIMARY KEY,
    user_id      TEXT NOT NULL,
    device_id    TEXT NOT NULL,
    challenge    BLOB NOT NULL,
    created_at   INTEGER NOT NULL,
    expires_at   INTEGER NOT NULL
);
CREATE INDEX auth_challenges_expires_at ON auth_challenges(expires_at);

-- Device sessions; only the SHA-256 of the bearer token is stored.
CREATE TABLE sessions (
    token_hash BLOB PRIMARY KEY,
    user_id    TEXT NOT NULL,
    device_id  TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    FOREIGN KEY (user_id, device_id) REFERENCES devices(user_id, device_id) ON DELETE CASCADE
);
CREATE INDEX sessions_device ON sessions(user_id, device_id);
CREATE INDEX sessions_expires_at ON sessions(expires_at);

CREATE TABLE key_packages (
    id          INTEGER PRIMARY KEY,
    user_id     TEXT NOT NULL,
    device_id   TEXT NOT NULL,
    key_package BLOB NOT NULL,
    kp_ref      BLOB NOT NULL,
    last_resort INTEGER NOT NULL DEFAULT 0 CHECK (last_resort IN (0, 1)),
    created_at  INTEGER NOT NULL,
    claimed_at  INTEGER,
    FOREIGN KEY (user_id, device_id) REFERENCES devices(user_id, device_id) ON DELETE CASCADE
);
CREATE INDEX key_packages_device ON key_packages(user_id, device_id, last_resort, claimed_at, id);
CREATE UNIQUE INDEX key_packages_kp_ref ON key_packages(kp_ref);
CREATE UNIQUE INDEX key_packages_one_last_resort
    ON key_packages(user_id, device_id) WHERE last_resort = 1;

CREATE TABLE groups (
    gid                  TEXT PRIMARY KEY,
    kind                 TEXT NOT NULL CHECK (kind IN ('direct', 'group')),
    epoch                INTEGER NOT NULL DEFAULT 0,
    last_seq             INTEGER NOT NULL DEFAULT 0,
    created_by_user_id   TEXT NOT NULL,
    created_by_device_id TEXT NOT NULL,
    created_at           INTEGER NOT NULL
);

-- Delivery-service view of the roster. leaf_index is the member's MLS leaf
-- once known from a Commit.
CREATE TABLE group_members (
    gid        TEXT NOT NULL REFERENCES groups(gid) ON DELETE CASCADE,
    user_id    TEXT NOT NULL,
    device_id  TEXT NOT NULL,
    leaf_index INTEGER,
    added_at   INTEGER NOT NULL,
    PRIMARY KEY (gid, user_id, device_id)
) WITHOUT ROWID;
CREATE INDEX group_members_device ON group_members(user_id, device_id, gid);

-- Per-group message log (Commits and application messages).
CREATE TABLE messages (
    gid              TEXT NOT NULL REFERENCES groups(gid) ON DELETE CASCADE,
    seq              INTEGER NOT NULL,
    epoch            INTEGER NOT NULL,
    kind             TEXT NOT NULL CHECK (kind IN ('commit', 'application')),
    sender_user_id   TEXT NOT NULL,
    sender_device_id TEXT NOT NULL,
    client_id        TEXT NOT NULL,
    payload          BLOB NOT NULL,
    commit_hash      BLOB,
    message_id       TEXT NOT NULL UNIQUE,
    created_at       INTEGER NOT NULL,
    PRIMARY KEY (gid, seq),
    UNIQUE (gid, sender_device_id, client_id),
    UNIQUE (gid, commit_hash)
);

-- Per-device event stream. The global id is the receiving device's cursor.
CREATE TABLE events (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id    TEXT NOT NULL,
    device_id  TEXT NOT NULL,
    type       TEXT NOT NULL,
    payload    TEXT NOT NULL,
    created_at INTEGER NOT NULL
);
CREATE INDEX events_device ON events(user_id, device_id, id);
CREATE INDEX events_created_at ON events(created_at);

-- Welcomes kept until acknowledged, independently of event retention.
CREATE TABLE pending_welcomes (
    id         INTEGER PRIMARY KEY,
    user_id    TEXT NOT NULL,
    device_id  TEXT NOT NULL,
    gid        TEXT NOT NULL,
    payload    TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    acked_at   INTEGER
);
CREATE INDEX pending_welcomes_device ON pending_welcomes(user_id, device_id, acked_at, id);

-- Blob metadata; content lives in $DATA_DIR/blobs/.
CREATE TABLE blobs (
    blob_id            TEXT PRIMARY KEY,
    size               INTEGER NOT NULL,
    uploader_user_id   TEXT NOT NULL,
    uploader_device_id TEXT NOT NULL,
    created_at         INTEGER NOT NULL
);

CREATE TABLE push_registrations (
    user_id    TEXT NOT NULL,
    device_id  TEXT NOT NULL,
    provider   TEXT NOT NULL CHECK (provider IN ('apns', 'fcm', 'unifiedpush', 'log')),
    token      TEXT NOT NULL,
    app_id     TEXT,
    sandbox    INTEGER NOT NULL DEFAULT 0 CHECK (sandbox IN (0, 1)),
    updated_at INTEGER NOT NULL,
    PRIMARY KEY (user_id, device_id),
    FOREIGN KEY (user_id, device_id) REFERENCES devices(user_id, device_id) ON DELETE CASCADE
) WITHOUT ROWID;
