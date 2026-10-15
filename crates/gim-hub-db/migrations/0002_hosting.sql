-- Hosting records (docs/federation.md §4.3): local users' records and the
-- cache of remote users' records.

CREATE TABLE hosting_records (
    user_id      TEXT PRIMARY KEY,
    record       BLOB NOT NULL,      -- SignedHostingRecord CBOR, verbatim
    seq          INTEGER NOT NULL,
    expires_at   INTEGER NOT NULL,
    hosted       INTEGER NOT NULL CHECK (hosted IN (0, 1)),  -- local user AND lists this hub
    hub_ids      TEXT NOT NULL,      -- JSON array of listed hub_ids, canonical record order
    fetched_at   INTEGER NOT NULL,   -- last verification from a remote source (= updated_at for local)
    published_at INTEGER,            -- last successful DHT put (hosted only)
    updated_at   INTEGER NOT NULL,
    -- Last hosting_record.expiring event: the record seq it was for and when.
    expiring_notified_seq INTEGER,
    expiring_notified_at  INTEGER
);
CREATE INDEX hosting_records_hosted ON hosting_records(hosted, published_at);
CREATE INDEX hosting_records_expires_at ON hosting_records(expires_at);
