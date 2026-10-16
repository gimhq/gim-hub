-- Push registrations with an opaque provider: every provider except `log`
-- is delivered through the push webhook, so the provider CHECK goes.
-- `sandbox` becomes nullable (absent unless the device set it). Rows, the
-- key and the device foreign key are kept.
CREATE TABLE push_registrations_new (
    user_id    TEXT NOT NULL,
    device_id  TEXT NOT NULL,
    provider   TEXT NOT NULL,
    token      TEXT NOT NULL,
    app_id     TEXT,
    sandbox    INTEGER CHECK (sandbox IN (0, 1)),
    updated_at INTEGER NOT NULL,
    p256dh     BLOB,
    auth       BLOB,
    PRIMARY KEY (user_id, device_id),
    FOREIGN KEY (user_id, device_id) REFERENCES devices(user_id, device_id) ON DELETE CASCADE
) WITHOUT ROWID;

INSERT INTO push_registrations_new
    (user_id, device_id, provider, token, app_id, sandbox, updated_at, p256dh, auth)
SELECT user_id, device_id, provider, token, app_id, sandbox, updated_at, p256dh, auth
FROM push_registrations;

DROP TABLE push_registrations;
ALTER TABLE push_registrations_new RENAME TO push_registrations;
