-- The user list of the hub's user policy (docs/operations.md, "User
-- policy"): with GIM_HUB_USER_POLICY=allow only listed users are admitted,
-- with deny every user except the listed ones; with open (the default) the
-- list is kept but not enforced. Managed from the admin API and
-- `gim-hub config users`; every write bumps the settings version.

-- One row per listed user. `added_by` is the admin actor (`token`,
-- `header:<id>`) or `cli`; `note` is free text.
CREATE TABLE user_policy_list (
    user_id  TEXT PRIMARY KEY,
    added_at INTEGER NOT NULL,
    added_by TEXT NOT NULL,
    note     TEXT
) WITHOUT ROWID;
