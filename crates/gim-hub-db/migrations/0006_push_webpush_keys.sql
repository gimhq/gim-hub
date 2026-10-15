-- Web Push message encryption keys (RFC 8291) of UnifiedPush registrations:
-- the user agent's P-256 public key (65 bytes, uncompressed) and the 16-byte
-- authentication secret. NULL for other providers.
ALTER TABLE push_registrations ADD COLUMN p256dh BLOB;
ALTER TABLE push_registrations ADD COLUMN auth BLOB;
