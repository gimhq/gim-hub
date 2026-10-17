-- Admin API (docs/admin.md): user suspension, device creation times and the
-- admin audit log.

-- Set while an admin has suspended the user: sign-in is refused.
ALTER TABLE users ADD COLUMN suspended_at INTEGER;

-- When the device row was first stored; existing rows count from their last
-- update.
ALTER TABLE devices ADD COLUMN created_at INTEGER;
UPDATE devices SET created_at = updated_at;

-- Every admin action, newest last. `result` is 'ok' or 'error'.
CREATE TABLE admin_audit (
    id        INTEGER PRIMARY KEY,
    at        INTEGER NOT NULL,
    actor     TEXT NOT NULL,
    action    TEXT NOT NULL,
    target    TEXT,
    source_ip TEXT NOT NULL,
    result    TEXT NOT NULL CHECK (result IN ('ok', 'error')),
    detail    TEXT
);
CREATE INDEX admin_audit_at ON admin_audit(at, id);
