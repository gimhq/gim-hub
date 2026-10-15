# Operating gim-hub

## Configuration

gim-hub reads its configuration from environment variables at startup. Empty
variables count as unset. An invalid value stops the hub with an error naming
the variable.

| Variable | Default | Meaning |
| --- | --- | --- |
| `GIM_HUB_LISTEN` | `0.0.0.0:8080` | Socket address of the client API |
| `GIM_HUB_DATA_DIR` | `./data` | Data directory (see below) |
| `GIM_HUB_DATABASE_PATH` | `$GIM_HUB_DATA_DIR/hub.db` | SQLite database file |
| `GIM_HUB_EVENT_RETENTION_DAYS` | `7` | Events older than this are pruned (minimum 1) |
| `GIM_HUB_KEYPACKAGE_LOW_THRESHOLD` | `10` | A device is sent `keypackages.low` when its one-time KeyPackages drop below this |
| `GIM_HUB_MAX_MESSAGE_BYTES` | `262144` | Largest accepted MLS message (minimum 1) |
| `GIM_HUB_MAX_BLOB_BYTES` | `104857600` | Largest accepted blob (minimum 1) |
| `GIM_HUB_LONGPOLL_MAX_WAIT_SECONDS` | `30` | Upper bound for long-poll `wait` |
| `GIM_HUB_SESSION_TTL_DAYS` | `30` | Lifetime of device bearer tokens (minimum 1) |
| `RUST_LOG` | `info` | Log filter (`tracing_subscriber` `EnvFilter` syntax, e.g. `gim_hub_api=debug,info`) |

## Data directory

```
$GIM_HUB_DATA_DIR/
├── hub.db        SQLite database (WAL mode, with hub.db-wal and hub.db-shm)
├── hub_key       32-byte Ed25519 seed of the hub root key, mode 0600
└── blobs/        Encrypted blob contents, one file per blob
```

- `hub.db` is created on first start; schema migrations are embedded in the
  binary and applied automatically (tracked in `PRAGMA user_version`). A hub
  refuses to open a database written by a newer schema version.
- `hub_key` is generated on first start. It is the hub ROOT key and
  determines the hub's `hub_id` (gim-core identity spec): the audience of
  sign-in challenges and the hub named in users' hosting records. Replacing it
  changes `hub_id`, so it must be kept secret, backed up with the database and
  never replaced on a running deployment. Until runtime keys certified by the root key are implemented,
  the root key's libp2p PeerId is still the owner prefix of group IDs. Both
  `hub_id` and PeerId are logged at startup.
- Back up `hub.db` with SQLite's online backup (`sqlite3 hub.db ".backup
  out.db"`) or while the hub is stopped; copying the file alone while running
  can miss the WAL.

## Retention

An hourly background task (also run at startup) deletes events older than
`GIM_HUB_EVENT_RETENTION_DAYS`. A client whose cursor is older than the
newest pruned event receives 410 `cursor_expired` with the head cursor and
must resync. Pending Welcomes are kept until acknowledged, independently of
event retention.

## Shutdown

The hub stops accepting connections on SIGINT or SIGTERM and finishes
in-flight requests before exiting.
