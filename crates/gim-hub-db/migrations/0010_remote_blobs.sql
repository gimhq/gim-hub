-- Cached copies of blobs uploaded on other hubs (docs/federation.md §5.6).
-- `blobs` keeps only the blobs uploaded here; a hub serves `FetchBlob` from
-- `blobs` only, never from this cache.
CREATE TABLE remote_blobs (
    blob_id    TEXT PRIMARY KEY,
    size       INTEGER NOT NULL,
    fetched_at INTEGER NOT NULL
);
