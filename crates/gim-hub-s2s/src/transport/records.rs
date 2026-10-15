//! DHT record validation hooks (docs/federation.md §4.4) and the hub
//! locator record (§3.5).
//!
//! Every inbound `PUT_VALUE` and every `GET_VALUE` result passes the
//! validator registered for its key prefix; keys without one are rejected.
//! `/gim/hub/` is validated here; `/gim/user/` is registered by the hosting
//! module.

use std::{
    collections::HashMap,
    sync::{Arc, RwLock},
};

use gim_hub_identity::{HubId, HubRuntimeCert};
use gim_hub_proto::{s2s::HubLocator, HUB_RECORD_KEY_PREFIX};
use libp2p::Multiaddr;
use prost::Message;

use super::binding::verify_cert;

/// Outcome of validating a DHT record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RecordDecision {
    /// Valid; store it (replacing `existing`).
    Store,
    /// Valid but not newer than `existing`; keep the stored record.
    Keep,
    /// Invalid; never stored or returned.
    Reject(String),
}

/// Validator for the DHT records under one key prefix.
pub trait RecordValidator: Send + Sync + 'static {
    /// Validates `value` stored under `key` at `now_ms` (Unix ms), against
    /// the currently stored value, if any.
    fn validate(
        &self,
        key: &str,
        value: &[u8],
        existing: Option<&[u8]>,
        now_ms: u64,
    ) -> RecordDecision;
}

/// Validators by key prefix.
pub(crate) struct Validators(RwLock<HashMap<String, Arc<dyn RecordValidator>>>);

impl Validators {
    pub fn new() -> Self {
        let validators = Self(RwLock::default());
        validators.register(HUB_RECORD_KEY_PREFIX, Arc::new(HubLocatorValidator));
        validators
    }

    pub fn register(&self, prefix: &str, validator: Arc<dyn RecordValidator>) {
        self.0
            .write()
            .expect("validators lock")
            .insert(prefix.to_owned(), validator);
    }

    pub fn validate(
        &self,
        key: &[u8],
        value: &[u8],
        existing: Option<&[u8]>,
        now_ms: u64,
    ) -> RecordDecision {
        let Ok(key) = std::str::from_utf8(key) else {
            return RecordDecision::Reject("key is not UTF-8".into());
        };
        let validator = self
            .0
            .read()
            .expect("validators lock")
            .iter()
            .find(|(prefix, _)| key.starts_with(prefix.as_str()))
            .map(|(_, validator)| validator.clone());
        match validator {
            Some(validator) => validator.validate(key, value, existing, now_ms),
            None => RecordDecision::Reject("unknown key prefix".into()),
        }
    }
}

/// A verified [`HubLocator`].
#[derive(Debug, Clone)]
pub(crate) struct Locator {
    pub cert: HubRuntimeCert,
    pub addrs: Vec<Multiaddr>,
}

/// Decodes a locator and verifies its certificate (§3.2 steps 1-2) and that
/// it belongs to the hub named by `key`.
pub(crate) fn decode_locator(key: &str, value: &[u8], now_ms: u64) -> Result<Locator, String> {
    let hub = key
        .strip_prefix(HUB_RECORD_KEY_PREFIX)
        .ok_or("not a hub locator key")?;
    let hub_id = HubId::parse(hub).map_err(|err| err.to_string())?;
    let locator = HubLocator::decode(value).map_err(|err| err.to_string())?;
    let cert = verify_cert(&locator.runtime_cert, now_ms)?;
    if cert.hub_id() != hub_id {
        return Err("certificate is for another hub".into());
    }
    let addrs = locator
        .multiaddrs
        .into_iter()
        .filter_map(|bytes| Multiaddr::try_from(bytes).ok())
        .collect();
    Ok(Locator { cert, addrs })
}

/// `/gim/hub/<hub_id>`: valid certificate of that hub; the greatest
/// `not_before` wins.
struct HubLocatorValidator;

impl RecordValidator for HubLocatorValidator {
    fn validate(
        &self,
        key: &str,
        value: &[u8],
        existing: Option<&[u8]>,
        now_ms: u64,
    ) -> RecordDecision {
        let locator = match decode_locator(key, value, now_ms) {
            Ok(locator) => locator,
            Err(reason) => return RecordDecision::Reject(reason),
        };
        match existing.and_then(|old| decode_locator(key, old, now_ms).ok()) {
            Some(old) if old.cert.not_before() > locator.cert.not_before() => RecordDecision::Keep,
            _ => RecordDecision::Store,
        }
    }
}

/// Encodes this hub's locator.
pub(crate) fn encode_locator(runtime_cert: &[u8], addrs: &[Multiaddr]) -> Vec<u8> {
    HubLocator {
        runtime_cert: runtime_cert.to_vec(),
        multiaddrs: addrs.iter().map(|addr| addr.to_vec()).collect(),
    }
    .encode_to_vec()
}

#[cfg(test)]
mod tests {
    use gim_hub_identity::SigningKey;

    use super::*;

    const NOW: u64 = 1_792_000_000_000;

    fn locator(root: &SigningKey, not_before: u64) -> Vec<u8> {
        let runtime = SigningKey::from_bytes(&[9; 32]).verifying_key();
        let cert = HubRuntimeCert::issue(root, &runtime, not_before, NOW + 1000);
        encode_locator(&cert, &["/ip4/127.0.0.1/tcp/1".parse().unwrap()])
    }

    #[test]
    fn hub_locator_validation() {
        let root = SigningKey::from_bytes(&[1; 32]);
        let key = format!(
            "{HUB_RECORD_KEY_PREFIX}{}",
            HubId::from_root_pubkey(&root.verifying_key())
        );
        let validators = Validators::new();
        let validate = |value: &[u8], existing: Option<&[u8]>| {
            validators.validate(key.as_bytes(), value, existing, NOW)
        };
        let old = locator(&root, NOW - 100);
        let new = locator(&root, NOW - 10);
        assert_eq!(validate(&new, None), RecordDecision::Store);
        assert_eq!(validate(&new, Some(&old)), RecordDecision::Store);
        assert_eq!(validate(&old, Some(&new)), RecordDecision::Keep);
        assert_eq!(
            decode_locator(&key, &new, NOW).unwrap().addrs,
            vec!["/ip4/127.0.0.1/tcp/1".parse::<Multiaddr>().unwrap()]
        );

        // Another hub's certificate under this key, expired, or garbage.
        let other = locator(&SigningKey::from_bytes(&[2; 32]), NOW - 10);
        assert!(matches!(validate(&other, None), RecordDecision::Reject(_)));
        assert!(matches!(
            validators.validate(key.as_bytes(), &new, None, NOW + 1000),
            RecordDecision::Reject(_)
        ));
        assert!(matches!(validate(b"\xff", None), RecordDecision::Reject(_)));
        assert!(matches!(
            validators.validate(b"/gim/hub/hnothub", &new, None, NOW),
            RecordDecision::Reject(_)
        ));
    }

    #[test]
    fn unknown_prefixes_are_rejected_until_registered() {
        struct AcceptAll;
        impl RecordValidator for AcceptAll {
            fn validate(&self, _: &str, _: &[u8], _: Option<&[u8]>, _: u64) -> RecordDecision {
                RecordDecision::Store
            }
        }
        let validators = Validators::new();
        let key = b"/gim/user/u1";
        assert!(matches!(
            validators.validate(key, b"v", None, NOW),
            RecordDecision::Reject(_)
        ));
        validators.register(gim_hub_proto::USER_RECORD_KEY_PREFIX, Arc::new(AcceptAll));
        assert_eq!(
            validators.validate(key, b"v", None, NOW),
            RecordDecision::Store
        );
        assert!(matches!(
            validators.validate(b"/other/x", b"v", None, NOW),
            RecordDecision::Reject(_)
        ));
        assert!(matches!(
            validators.validate(b"\xff", b"v", None, NOW),
            RecordDecision::Reject(_)
        ));
    }
}
