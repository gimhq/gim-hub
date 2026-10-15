-- Remote identity (docs/federation.md §5.1, §5.2): the cache of remote
-- users' DeviceLists and the ledger of KeyPackages claimed from other hubs.

-- Cache of DeviceLists of remote users (users without a row in `users`).
CREATE TABLE remote_device_lists (
    user_id         TEXT PRIMARY KEY,
    root_pubkey     BLOB NOT NULL,
    device_list     BLOB NOT NULL,   -- SignedDeviceList CBOR, verbatim
    device_list_seq INTEGER NOT NULL,
    fetched_at      INTEGER NOT NULL,
    updated_at      INTEGER NOT NULL
);

-- KeyPackages this hub claimed from other hubs on behalf of its users.
CREATE TABLE remote_kp_claims (
    kp_ref               BLOB PRIMARY KEY,   -- mls::key_package_hash of the KeyPackage
    user_id              TEXT NOT NULL,      -- target user
    device_id            TEXT NOT NULL,      -- target device (as returned by the target hub)
    target_hub_id        TEXT NOT NULL,
    claimed_by_user_id   TEXT NOT NULL,
    claimed_by_device_id TEXT NOT NULL,
    claimed_at           INTEGER NOT NULL
);
CREATE INDEX remote_kp_claims_claimed_at ON remote_kp_claims(claimed_at);
