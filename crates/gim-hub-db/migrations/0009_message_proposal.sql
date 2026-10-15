-- MLS Proposals in the group log (docs/api-v2.md "Membership and wire format").

-- SQLite cannot alter a CHECK constraint: rebuild messages with the
-- 'proposal' kind, keeping every row. commit_hash is the SHA-256 of a
-- handshake message (Commit or Proposal), used to detect retries.
CREATE TABLE messages_new (
    gid              TEXT NOT NULL REFERENCES groups(gid) ON DELETE CASCADE,
    seq              INTEGER NOT NULL,
    epoch            INTEGER NOT NULL,
    kind             TEXT NOT NULL CHECK (kind IN ('commit', 'application', 'proposal')),
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
INSERT INTO messages_new
    (gid, seq, epoch, kind, sender_user_id, sender_device_id, client_id, payload, commit_hash,
     message_id, created_at)
    SELECT gid, seq, epoch, kind, sender_user_id, sender_device_id, client_id, payload,
           commit_hash, message_id, created_at
    FROM messages;
DROP TABLE messages;
ALTER TABLE messages_new RENAME TO messages;

-- Proposals of the group's current epoch that a Commit may reference, by
-- ProposalRef (RFC 9420 §5.2) under each MLS hash function. Deleted when the
-- epoch advances.
CREATE TABLE pending_proposals (
    gid          TEXT NOT NULL REFERENCES groups(gid) ON DELETE CASCADE,
    proposal_ref BLOB NOT NULL,
    epoch        INTEGER NOT NULL,
    seq          INTEGER NOT NULL,
    PRIMARY KEY (gid, proposal_ref)
) WITHOUT ROWID;
