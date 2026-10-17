//! GET /admin/api/config: the effective configuration, secrets redacted.

use axum::{extract::State, Json};
use gim_hub_api::{dto::Error, Config};
use gim_hub_s2s::FederationConfig;

use crate::{
    config::AdminConfig,
    dto::{ConfigItem, ConfigView},
    state::AdminState,
};

#[utoipa::path(
    get,
    path = "/admin/api/config",
    tag = "config",
    summary = "Effective configuration",
    description = "Every `GIM_HUB_*` setting with its effective value (defaults applied). Secrets \
(the webhook secret, the PSK, any `*_SECRET`, `*_TOKEN` or `*_KEY` value) are redacted: `value` \
is `null` and `redacted` is true when one is set. File paths are shown, never file contents.",
    security(("adminSession" = [])),
    responses(
        (status = 200, description = "Configuration", body = ConfigView),
        (status = 401, description = "No session (`unauthorized`)", body = Error),
    ),
)]
pub async fn get_config(State(state): State<AdminState>) -> Json<ConfigView> {
    Json(ConfigView {
        items: effective_config(&state.app.config, &state.federation_config, &state.config),
    })
}

/// Whether the value of `key` is a secret.
fn is_secret(key: &str) -> bool {
    key == "GIM_HUB_P2P_PSK_FILE"
        || ["_SECRET", "_TOKEN", "_KEY", "_PSK"]
            .iter()
            .any(|suffix| key.ends_with(suffix))
}

fn item(key: &str, value: Option<String>) -> ConfigItem {
    if is_secret(key) {
        ConfigItem {
            key: key.to_owned(),
            redacted: value.is_some(),
            value: None,
        }
    } else {
        ConfigItem {
            key: key.to_owned(),
            value,
            redacted: false,
        }
    }
}

fn join<T: ToString>(values: &[T]) -> Option<String> {
    (!values.is_empty()).then(|| {
        values
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(",")
    })
}

/// The effective configuration as `(GIM_HUB_* key, value)` items.
pub(crate) fn effective_config(
    hub: &Config,
    federation: &FederationConfig,
    admin: &AdminConfig,
) -> Vec<ConfigItem> {
    let s = |value: &dyn ToString| Some(value.to_string());
    let path = |path: &std::path::Path| Some(path.display().to_string());
    let webhook = hub.push.webhook.as_ref();
    let mut items = vec![
        item("GIM_HUB_LISTEN", s(&hub.listen)),
        item("GIM_HUB_DATA_DIR", path(&hub.data_dir)),
        item("GIM_HUB_DATABASE_PATH", path(&hub.database_path)),
        item("GIM_HUB_PUBLIC_URL", hub.public_url.clone()),
        item("GIM_HUB_EVENT_RETENTION_DAYS", s(&hub.event_retention_days)),
        item(
            "GIM_HUB_KEYPACKAGE_LOW_THRESHOLD",
            s(&hub.keypackage_low_threshold),
        ),
        item("GIM_HUB_MAX_MESSAGE_BYTES", s(&hub.max_message_bytes)),
        item("GIM_HUB_MAX_BLOB_BYTES", s(&hub.max_blob_bytes)),
        item(
            "GIM_HUB_LONGPOLL_MAX_WAIT_SECONDS",
            s(&hub.longpoll_max_wait_seconds),
        ),
        item("GIM_HUB_SESSION_TTL_DAYS", s(&hub.session_ttl_days)),
        item(
            "GIM_HUB_PUBLIC_READ_PER_IP_PER_MIN",
            s(&hub.public_read_per_ip_per_min),
        ),
        item(
            "GIM_HUB_PUBLIC_READ_PER_USER_PER_MIN",
            s(&hub.public_read_per_user_per_min),
        ),
        item(
            "GIM_HUB_RECOVERY_READ_PER_IP_PER_MIN",
            s(&hub.recovery_read_per_ip_per_min),
        ),
        item(
            "GIM_HUB_RECOVERY_READ_PER_USER_PER_MIN",
            s(&hub.recovery_read_per_user_per_min),
        ),
        item("GIM_HUB_TRUST_FORWARDED_FOR", s(&hub.trust_forwarded_for)),
        item("GIM_HUB_UNHOSTED_GRACE_HOURS", s(&hub.unhosted_grace_hours)),
        item("GIM_HUB_PUSH_MEMBER_EVENTS", s(&hub.push.member_events)),
        item("GIM_HUB_PUSH_MINIMAL", s(&hub.push.minimal)),
        item("GIM_HUB_PUSH_QUEUE_CAPACITY", s(&hub.push.queue_capacity)),
        item("GIM_HUB_PUSH_LOG_ENDPOINT", s(&hub.push.log_endpoint)),
        item("GIM_HUB_PUSH_WEBHOOK_URL", webhook.map(|w| w.url.clone())),
        item(
            "GIM_HUB_PUSH_WEBHOOK_SECRET",
            webhook.map(|w| w.secret.clone()),
        ),
        item(
            "GIM_HUB_PUSH_WEBHOOK_TIMEOUT_SECONDS",
            webhook.map(|w| w.timeout.as_secs().to_string()),
        ),
        item("GIM_HUB_FEDERATION", s(&federation.enabled)),
    ];
    if federation.enabled {
        items.extend([
            item("GIM_HUB_P2P_LISTEN", join(&federation.listen)),
            item(
                "GIM_HUB_P2P_EXTERNAL_ADDRS",
                join(&federation.external_addrs),
            ),
            item("GIM_HUB_P2P_BOOTSTRAP", join(&federation.bootstrap)),
            item(
                "GIM_HUB_FEDERATION_ALLOWLIST",
                path(&federation.allowlist_path),
            ),
            item(
                "GIM_HUB_P2P_PSK_FILE",
                federation.psk.map(|_| String::new()),
            ),
            item(
                "GIM_HUB_RUNTIME_CERT_DAYS",
                s(&federation.runtime_cert_days),
            ),
            item(
                "GIM_HUB_S2S_TIMEOUT_SECONDS",
                s(&federation.s2s_timeout.as_secs()),
            ),
            item(
                "GIM_HUB_DHT_REPUBLISH_HOURS",
                s(&federation.dht_republish_hours),
            ),
            item(
                "GIM_HUB_HOSTING_CACHE_SECONDS",
                s(&federation.hosting_cache_seconds),
            ),
            item(
                "GIM_HUB_DEVICE_LIST_CACHE_HOURS",
                s(&federation.device_list_cache_hours),
            ),
            item("GIM_HUB_OUTBOX_TTL_HOURS", s(&federation.outbox_ttl_hours)),
            item(
                "GIM_HUB_OUTBOX_MAX_ENTRIES_PER_PEER",
                s(&federation.outbox_max_entries_per_peer),
            ),
            item(
                "GIM_HUB_OUTBOX_MAX_BYTES_PER_PEER",
                s(&federation.outbox_max_bytes_per_peer),
            ),
            item(
                "GIM_HUB_OUTBOX_BACKOFF_MAX_SECONDS",
                s(&federation.outbox_backoff_max_seconds),
            ),
            item(
                "GIM_HUB_PUSH_FAILOVER_SECONDS",
                s(&federation.push_failover_seconds),
            ),
            item(
                "GIM_HUB_FETCH_BLOB_PER_MINUTE",
                s(&federation.fetch_blob_per_minute),
            ),
        ]);
    }
    items.extend([
        item("GIM_HUB_ADMIN_LISTEN", admin.listen.map(|a| a.to_string())),
        item(
            "GIM_HUB_ADMIN_TOKEN_FILE",
            admin.token_file.as_deref().and_then(path),
        ),
        item(
            "GIM_HUB_ADMIN_TRUSTED_HEADER",
            admin.trusted_header.as_ref().map(ToString::to_string),
        ),
        item(
            "GIM_HUB_ADMIN_TRUSTED_PROXIES",
            join(
                &admin
                    .trusted_proxies
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>(),
            ),
        ),
        item("GIM_HUB_ADMIN_COOKIE_SECURE", s(&admin.cookie_secure)),
    ]);
    items
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secrets_are_recognized() {
        for key in [
            "GIM_HUB_PUSH_WEBHOOK_SECRET",
            "GIM_HUB_P2P_PSK_FILE",
            "GIM_HUB_FOO_TOKEN",
            "GIM_HUB_FOO_KEY",
        ] {
            assert!(is_secret(key), "{key}");
        }
        for key in [
            "GIM_HUB_ADMIN_TOKEN_FILE",
            "GIM_HUB_LISTEN",
            "GIM_HUB_DATA_DIR",
        ] {
            assert!(!is_secret(key), "{key}");
        }
        let set = item("GIM_HUB_PUSH_WEBHOOK_SECRET", Some("s3cret".into()));
        assert_eq!((set.value, set.redacted), (None, true));
        let unset = item("GIM_HUB_PUSH_WEBHOOK_SECRET", None);
        assert_eq!((unset.value, unset.redacted), (None, false));
    }
}
