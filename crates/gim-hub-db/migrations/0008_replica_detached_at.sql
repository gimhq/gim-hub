-- Detach time of replicas (docs/federation.md §5.4): detached replicas older
-- than the event retention are deleted by the retention task. NULL unless
-- detached; replicas already detached count from the migration.
ALTER TABLE groups ADD COLUMN detached_at INTEGER;
UPDATE groups SET detached_at = CAST((julianday('now') - 2440587.5) * 86400000 AS INTEGER)
    WHERE detached = 1;
