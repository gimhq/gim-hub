-- Stored settings (docs/operations.md, "Stored settings"): runtime
-- configuration managed from the admin API and `gim-hub config`. An
-- environment variable of the same name takes precedence; a missing row
-- means the built-in default.

-- One row per set setting. `value` is the JSON value; `updated_by` is the
-- admin actor (`token`, `header:<id>`) or `cli`.
CREATE TABLE settings (
    key        TEXT PRIMARY KEY,
    value      TEXT NOT NULL,
    updated_at INTEGER NOT NULL,
    updated_by TEXT NOT NULL
) WITHOUT ROWID;

-- The federation allowlist when GIM_HUB_FEDERATION_ALLOWLIST is unset: one
-- row per allowed hub, `addrs` a JSON array of static multiaddrs (the file
-- format's `hub_id [multiaddr ...]` lines).
CREATE TABLE federation_allowlist (
    hub_id TEXT PRIMARY KEY,
    addrs  TEXT NOT NULL
) WITHOUT ROWID;
