-- Multi-homing (docs/multihoming.md §9.3).

-- When a newer record stopped listing this hub for a local user (§7.3);
-- NULL unless the user is removed. Kept on the tombstone after the purge.
ALTER TABLE hosting_records ADD COLUMN removed_at INTEGER;

-- SQLite cannot alter a CHECK constraint: rebuild s2s_outbox with the
-- multi-homing kinds, keeping ids (and so the FIFO order) of queued entries.
CREATE TABLE s2s_outbox_new (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    peer_hub_id TEXT NOT NULL,
    kind        TEXT NOT NULL CHECK (kind IN ('deliver', 'deliver_welcome', 'device_list',
                                              'hosting_record', 'seed_replica', 'pending_welcomes')),
    gid         TEXT,
    seq         INTEGER,
    user_id     TEXT,
    payload     BLOB,
    size        INTEGER NOT NULL,
    created_at  INTEGER NOT NULL,
    expires_at  INTEGER NOT NULL,
    attempts    INTEGER NOT NULL DEFAULT 0
);
INSERT INTO s2s_outbox_new
    (id, peer_hub_id, kind, gid, seq, user_id, payload, size, created_at, expires_at, attempts)
    SELECT id, peer_hub_id, kind, gid, seq, user_id, payload, size, created_at, expires_at, attempts
    FROM s2s_outbox;
DROP TABLE s2s_outbox;
ALTER TABLE s2s_outbox_new RENAME TO s2s_outbox;

CREATE INDEX s2s_outbox_peer ON s2s_outbox(peer_hub_id, id);
CREATE INDEX s2s_outbox_expires_at ON s2s_outbox(expires_at);
CREATE UNIQUE INDEX s2s_outbox_deliver ON s2s_outbox(peer_hub_id, gid, seq) WHERE kind = 'deliver';
CREATE UNIQUE INDEX s2s_outbox_device_list ON s2s_outbox(peer_hub_id, user_id) WHERE kind = 'device_list';
CREATE UNIQUE INDEX s2s_outbox_hosting_record ON s2s_outbox(peer_hub_id, user_id)
    WHERE kind = 'hosting_record';
CREATE UNIQUE INDEX s2s_outbox_pending_welcomes ON s2s_outbox(peer_hub_id, user_id)
    WHERE kind = 'pending_welcomes';
