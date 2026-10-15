-- Durable S2S outbound queue and per-peer delivery state (docs/federation.md §7.1).

CREATE TABLE s2s_outbox (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    peer_hub_id TEXT NOT NULL,
    kind        TEXT NOT NULL CHECK (kind IN ('deliver', 'deliver_welcome', 'device_list')),
    gid         TEXT,
    seq         INTEGER,
    user_id     TEXT,
    payload     BLOB,
    size        INTEGER NOT NULL,
    created_at  INTEGER NOT NULL,
    expires_at  INTEGER NOT NULL,
    attempts    INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX s2s_outbox_peer ON s2s_outbox(peer_hub_id, id);
CREATE INDEX s2s_outbox_expires_at ON s2s_outbox(expires_at);
CREATE UNIQUE INDEX s2s_outbox_deliver ON s2s_outbox(peer_hub_id, gid, seq) WHERE kind = 'deliver';
CREATE UNIQUE INDEX s2s_outbox_device_list ON s2s_outbox(peer_hub_id, user_id) WHERE kind = 'device_list';

CREATE TABLE s2s_peers (
    hub_id            TEXT PRIMARY KEY,
    peer_id           BLOB,
    runtime_cert      BLOB,
    cert_not_after    INTEGER,
    addrs             BLOB,
    last_connected_at INTEGER,
    failures          INTEGER NOT NULL DEFAULT 0,
    next_attempt_at   INTEGER NOT NULL DEFAULT 0,
    needs_resync      INTEGER NOT NULL DEFAULT 0 CHECK (needs_resync IN (0, 1)),
    updated_at        INTEGER NOT NULL
);
