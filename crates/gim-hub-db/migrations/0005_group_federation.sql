-- Group federation (docs/federation.md §5.3, §5.4, §6.6, §8).

-- Membership changes of each Commit, needed to rebuild SequencedMessage for
-- Deliver and FetchLog.
CREATE TABLE commit_membership (
    gid       TEXT NOT NULL REFERENCES groups(gid) ON DELETE CASCADE,
    seq       INTEGER NOT NULL,
    change    TEXT NOT NULL CHECK (change IN ('added', 'removed')),
    user_id   TEXT NOT NULL,
    device_id TEXT NOT NULL,
    PRIMARY KEY (gid, seq, change, user_id, device_id)
) WITHOUT ROWID;

-- Replicas of remote-owned groups: NULL for owned groups, else the first seq
-- held locally. A replica without local members is detached.
ALTER TABLE groups ADD COLUMN replica_from_seq INTEGER;
ALTER TABLE groups ADD COLUMN detached INTEGER NOT NULL DEFAULT 0 CHECK (detached IN (0, 1));

-- Welcomes delivered by an owning hub, deduplicated by its message_id.
ALTER TABLE pending_welcomes ADD COLUMN message_id TEXT;
CREATE UNIQUE INDEX pending_welcomes_message ON pending_welcomes(message_id, user_id, device_id)
    WHERE message_id IS NOT NULL;
