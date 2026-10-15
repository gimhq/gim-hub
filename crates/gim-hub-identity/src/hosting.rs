use std::cmp::Ordering;
use std::collections::HashSet;

use ciborium::Value;
use ed25519_dalek::{SigningKey, VerifyingKey};

use crate::keys::{sign, verify};
use crate::{cbor, HubId, IdentityError, UserId, FORMAT_VERSION};

/// Signature context of a `SignedHostingRecord` (user root key).
pub const HOSTING_RECORD_CONTEXT: &[u8] = b"gim/hosting-record/v1";
/// Signature context of `HostingEntry.hub_sig` (hub root key).
pub const HOSTING_ENTRY_CONTEXT: &[u8] = b"gim/hosting-entry/v1";

/// Maximum number of hubs in a hosting record.
pub const MAX_HUBS: usize = 16;

/// One hub of a hosting record. In a verified [`HostingRecord`], `hub_sig`
/// is a valid hub root key signature over the entry for that record's user.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostingEntry {
    hub_root_pubkey: VerifyingKey,
    hub_id: HubId,
    priority: u8,
    hub_sig: [u8; 64],
}

impl HostingEntry {
    /// The hub co-signs its entry: signs `HostingEntryTbs` for `user_id` at
    /// `priority` with its own root key.
    pub fn sign(hub_root: &SigningKey, user_id: &UserId, priority: u8) -> Self {
        let hub_root_pubkey = hub_root.verifying_key();
        let hub_sig = sign(
            hub_root,
            HOSTING_ENTRY_CONTEXT,
            &entry_tbs(user_id, &hub_root_pubkey, priority),
        );
        Self {
            hub_id: HubId::from_root_pubkey(&hub_root_pubkey),
            hub_root_pubkey,
            priority,
            hub_sig,
        }
    }

    pub fn hub_root_pubkey(&self) -> &VerifyingKey {
        &self.hub_root_pubkey
    }

    pub fn hub_id(&self) -> &HubId {
        &self.hub_id
    }

    /// Lower is preferred.
    pub fn priority(&self) -> u8 {
        self.priority
    }

    pub fn hub_sig(&self) -> &[u8; 64] {
        &self.hub_sig
    }

    fn decode(value: Value) -> Result<Self, IdentityError> {
        let [hub_root, priority, hub_sig] = cbor::array(value)?;
        let hub_root_pubkey = cbor::public_key(hub_root)?;
        let priority = u8::try_from(cbor::uint(priority)?)
            .map_err(|_| IdentityError::Malformed("priority is not 0..=255".into()))?;
        Ok(Self {
            hub_id: HubId::from_root_pubkey(&hub_root_pubkey),
            hub_root_pubkey,
            priority,
            hub_sig: cbor::sized(hub_sig, "hub signature")?,
        })
    }

    /// The canonical record order: `(priority, hub_root_pubkey bytes)`.
    fn order_key(&self) -> (u8, &[u8; 32]) {
        (self.priority, self.hub_root_pubkey.as_bytes())
    }

    fn verify(&self, user_id: &UserId) -> Result<(), IdentityError> {
        let tbs = entry_tbs(user_id, &self.hub_root_pubkey, self.priority);
        verify(
            &self.hub_root_pubkey,
            HOSTING_ENTRY_CONTEXT,
            &tbs,
            &self.hub_sig,
        )
        .map_err(|_| IdentityError::BadHubSignature(self.hub_id.clone()))
    }
}

/// Sorts entries into the order a hosting record must list them in:
/// ascending `(priority, hub_root_pubkey bytes)`.
pub fn sort_hosting_entries(entries: &mut [HostingEntry]) {
    entries.sort_by(|a, b| a.order_key().cmp(&b.order_key()));
}

/// `HostingEntryTbs = [1, user_id, hub_root_pubkey, priority]`.
fn entry_tbs(user_id: &UserId, hub_root_pubkey: &VerifyingKey, priority: u8) -> Vec<u8> {
    cbor::encode(&Value::Array(vec![
        Value::Integer(FORMAT_VERSION.into()),
        Value::Text(user_id.to_string()),
        Value::Bytes(hub_root_pubkey.as_bytes().to_vec()),
        Value::Integer(priority.into()),
    ]))
}

/// A verified `SignedHostingRecord`: signed by the root key of `user_id`,
/// 1 to 16 distinct hubs each co-signed by its hub root key, sorted by
/// `(priority, hub_root_pubkey)`, none of them the user's root key, not
/// expired at verification time.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostingRecord {
    user_id: UserId,
    user_root_pubkey: VerifyingKey,
    seq: u64,
    expires_at: u64,
    hubs: Vec<HostingEntry>,
    tbs: Vec<u8>,
    signed: Vec<u8>,
}

impl HostingRecord {
    /// [`HostingRecord::verify_claimed`], then the record's `user_id` must
    /// equal `expected_user_id`.
    pub fn verify(
        signed: &[u8],
        expected_user_id: &UserId,
        now: u64,
    ) -> Result<Self, IdentityError> {
        let record = Self::verify_claimed(signed, now)?;
        if &record.user_id != expected_user_id {
            return Err(IdentityError::UserIdMismatch);
        }
        Ok(record)
    }

    /// Decodes the `SignedHostingRecord` bytes and verifies them at `now`
    /// (Unix milliseconds) for the user they claim, in the spec's
    /// verification order: envelope; the embedded `user_root_pubkey`
    /// (element 2) derives the claimed `user_id` (element 1); the user
    /// signature; then the body (version, shape, entries, hub count, each
    /// entry's hub signature then uniqueness, canonical order, no hub key
    /// equal to the user root key, `now < expires_at`).
    pub fn verify_claimed(signed: &[u8], now: u64) -> Result<Self, IdentityError> {
        let (tbs, sig) = cbor::decode_signed(signed)?;
        let body = cbor::decode(&tbs)?;
        let claimed = cbor::text(cbor::item(&body, 1)?)?;
        let user_root_pubkey = cbor::public_key(cbor::item(&body, 2)?)?;
        let user_id = UserId::from_root_pubkey(&user_root_pubkey);
        if claimed != user_id.as_str() {
            return Err(IdentityError::UserIdMismatch);
        }
        verify(&user_root_pubkey, HOSTING_RECORD_CONTEXT, &tbs, &sig)?;

        let [_version, _user_id, _user_root, seq, expires_at, hubs] = cbor::body(body)?;
        let seq = cbor::uint(seq)?;
        let expires_at = cbor::uint(expires_at)?;
        let hubs = cbor::list(hubs)?
            .into_iter()
            .map(HostingEntry::decode)
            .collect::<Result<Vec<_>, _>>()?;
        if hubs.is_empty() || hubs.len() > MAX_HUBS {
            return Err(IdentityError::HubCount(hubs.len()));
        }
        let mut seen = HashSet::new();
        for entry in &hubs {
            entry.verify(&user_id)?;
            if !seen.insert(entry.hub_root_pubkey.as_bytes()) {
                return Err(IdentityError::DuplicateHub(entry.hub_id.clone()));
            }
        }
        if hubs
            .windows(2)
            .any(|pair| pair[0].order_key() > pair[1].order_key())
        {
            return Err(IdentityError::HubsNotSorted);
        }
        if seen.contains(user_root_pubkey.as_bytes()) {
            return Err(IdentityError::UserRootIsHub);
        }
        if now >= expires_at {
            return Err(IdentityError::Expired);
        }

        Ok(Self {
            user_id,
            user_root_pubkey,
            seq,
            expires_at,
            hubs,
            tbs,
            signed: signed.to_vec(),
        })
    }

    pub fn user_id(&self) -> &UserId {
        &self.user_id
    }

    pub fn user_root_pubkey(&self) -> &VerifyingKey {
        &self.user_root_pubkey
    }

    pub fn seq(&self) -> u64 {
        self.seq
    }

    /// Unix time in milliseconds, exclusive.
    pub fn expires_at(&self) -> u64 {
        self.expires_at
    }

    /// Hub entries, in record (canonical) order.
    pub fn hubs(&self) -> &[HostingEntry] {
        &self.hubs
    }

    /// The entry of `hub_id`, if the record lists that hub.
    pub fn entry(&self, hub_id: &HubId) -> Option<&HostingEntry> {
        self.hubs.iter().find(|entry| &entry.hub_id == hub_id)
    }

    /// The entry with the lowest priority; ties go to the lexicographically
    /// smallest hub id.
    pub fn primary(&self) -> &HostingEntry {
        self.hubs
            .iter()
            .min_by(|a, b| (a.priority, &a.hub_id).cmp(&(b.priority, &b.hub_id)))
            .expect("a verified record has at least one hub")
    }

    /// Whether `self` (received) replaces `other` (stored), per the spec's
    /// "Update and seq rules": `Ok(true)` for a strictly higher seq;
    /// `Ok(false)` (an idempotent no-op) for the same seq and identical body
    /// bytes; [`IdentityError::SeqConflict`] for the same seq and different
    /// body bytes; [`IdentityError::StaleSeq`] for a lower seq;
    /// [`IdentityError::UserIdMismatch`] for another user.
    pub fn supersedes(&self, other: &HostingRecord) -> Result<bool, IdentityError> {
        if self.user_id != other.user_id {
            return Err(IdentityError::UserIdMismatch);
        }
        match self.seq.cmp(&other.seq) {
            Ordering::Greater => Ok(true),
            Ordering::Less => Err(IdentityError::StaleSeq(self.seq)),
            Ordering::Equal if self.tbs == other.tbs => Ok(false),
            Ordering::Equal => Err(IdentityError::SeqConflict(self.seq)),
        }
    }

    /// The record with the highest seq among records of one user, or `None`
    /// for no records. Fails on records of different users or two different
    /// records with the same seq.
    pub fn latest<'a>(
        records: impl IntoIterator<Item = &'a HostingRecord>,
    ) -> Result<Option<&'a HostingRecord>, IdentityError> {
        let mut latest: Option<&HostingRecord> = None;
        for record in records {
            latest = match latest {
                None => Some(record),
                Some(current) => match record.supersedes(current) {
                    Ok(true) => Some(record),
                    Ok(false) | Err(IdentityError::StaleSeq(_)) => Some(current),
                    Err(err) => return Err(err),
                },
            };
        }
        Ok(latest)
    }

    /// The `SignedHostingRecord` bytes this record was verified from.
    pub fn as_bytes(&self) -> &[u8] {
        &self.signed
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::*;

    fn user_of(seed: u8) -> UserId {
        UserId::from_root_pubkey(&key(seed).verifying_key())
    }

    fn entry_value(entry: &HostingEntry) -> Value {
        Value::Array(vec![
            Value::Bytes(entry.hub_root_pubkey().as_bytes().to_vec()),
            Value::Integer(entry.priority().into()),
            Value::Bytes(entry.hub_sig().to_vec()),
        ])
    }

    fn record_items(user: &SigningKey, seq: u64, expires_at: u64, hubs: Vec<Value>) -> Vec<Value> {
        let root = user.verifying_key();
        vec![
            Value::Integer(1.into()),
            Value::Text(UserId::from_root_pubkey(&root).to_string()),
            Value::Bytes(root.as_bytes().to_vec()),
            Value::Integer(seq.into()),
            Value::Integer(expires_at.into()),
            Value::Array(hubs),
        ]
    }

    fn record(user: &SigningKey, seq: u64, hubs: &[(u8, u8)]) -> Vec<u8> {
        let user_id = UserId::from_root_pubkey(&user.verifying_key());
        let mut entries: Vec<_> = hubs
            .iter()
            .map(|&(seed, priority)| HostingEntry::sign(&key(seed), &user_id, priority))
            .collect();
        sort_hosting_entries(&mut entries);
        let items = record_items(user, seq, 1000, entries.iter().map(entry_value).collect());
        sign_value(user, HOSTING_RECORD_CONTEXT, &Value::Array(items))
    }

    #[test]
    fn verifies_and_picks_primary() {
        let bytes = record(&key(1), 3, &[(10, 5), (11, 0), (12, 0)]);
        let record = HostingRecord::verify(&bytes, &user_of(1), 999).unwrap();
        assert_eq!(record.user_id(), &user_of(1));
        assert_eq!(record.user_root_pubkey(), &key(1).verifying_key());
        assert_eq!((record.seq(), record.expires_at()), (3, 1000));
        assert_eq!(record.hubs().len(), 3);
        assert_eq!(record.as_bytes(), bytes);
        let h11 = HubId::from_root_pubkey(&key(11).verifying_key());
        let h12 = HubId::from_root_pubkey(&key(12).verifying_key());
        assert_eq!(record.primary().hub_id(), &h11.clone().min(h12.clone()));
        assert_eq!(record.entry(&h11).unwrap().priority(), 0);
        assert!(record
            .entry(&HubId::from_root_pubkey(&key(13).verifying_key()))
            .is_none());
    }

    #[test]
    fn rejects_expired_and_wrong_user() {
        let bytes = record(&key(1), 1, &[(10, 0)]);
        assert_eq!(
            HostingRecord::verify(&bytes, &user_of(1), 1000),
            Err(IdentityError::Expired)
        );
        assert_eq!(
            HostingRecord::verify(&bytes, &user_of(2), 0),
            Err(IdentityError::UserIdMismatch)
        );
        let mut tampered = bytes;
        let last = tampered.len() - 1;
        tampered[last] ^= 1;
        assert_eq!(
            HostingRecord::verify(&tampered, &user_of(1), 0),
            Err(IdentityError::BadSignature)
        );
    }

    #[test]
    fn rejects_bad_hub_entries() {
        let user = key(1);
        let hub = key(10);
        let hub_id = HubId::from_root_pubkey(&hub.verifying_key());
        let resign = |hubs: Vec<Value>| {
            let items = record_items(&user, 1, 1000, hubs);
            sign_value(&user, HOSTING_RECORD_CONTEXT, &Value::Array(items))
        };
        let verify = |bytes: &[u8]| HostingRecord::verify(bytes, &user_of(1), 0);

        // Entry signed for another user, or with another priority.
        let foreign = HostingEntry::sign(&hub, &user_of(2), 0);
        assert_eq!(
            verify(&resign(vec![entry_value(&foreign)])),
            Err(IdentityError::BadHubSignature(hub_id.clone()))
        );
        let mut moved = entry_value(&HostingEntry::sign(&hub, &user_of(1), 0));
        if let Value::Array(items) = &mut moved {
            items[1] = Value::Integer(1.into());
        }
        assert_eq!(
            verify(&resign(vec![moved])),
            Err(IdentityError::BadHubSignature(hub_id.clone()))
        );

        let ok = entry_value(&HostingEntry::sign(&hub, &user_of(1), 0));
        assert_eq!(
            verify(&resign(vec![ok.clone(), ok.clone()])),
            Err(IdentityError::DuplicateHub(hub_id))
        );
        assert_eq!(verify(&resign(vec![])), Err(IdentityError::HubCount(0)));
        let many: Vec<Value> = (20..37)
            .map(|seed| entry_value(&HostingEntry::sign(&key(seed), &user_of(1), 0)))
            .collect();
        assert_eq!(verify(&resign(many)), Err(IdentityError::HubCount(17)));

        let high = Value::Array(vec![
            Value::Bytes(hub.verifying_key().as_bytes().to_vec()),
            Value::Integer(256.into()),
            Value::Bytes(vec![0; 64]),
        ]);
        assert!(matches!(
            verify(&resign(vec![high])),
            Err(IdentityError::Malformed(_))
        ));
        let short = Value::Array(vec![
            Value::Bytes(hub.verifying_key().as_bytes().to_vec()),
            Value::Integer(0.into()),
        ]);
        assert!(matches!(
            verify(&resign(vec![short])),
            Err(IdentityError::Malformed(_))
        ));
    }

    #[test]
    fn requires_canonical_hub_order() {
        let user = key(1);
        let resign = |entries: &[HostingEntry]| {
            let items = record_items(&user, 1, 1000, entries.iter().map(entry_value).collect());
            sign_value(&user, HOSTING_RECORD_CONTEXT, &Value::Array(items))
        };
        let verify = |bytes: &[u8]| HostingRecord::verify(bytes, &user_of(1), 0);
        let mut entries: Vec<_> = [(10, 5), (11, 0), (12, 0), (13, 5)]
            .into_iter()
            .map(|(seed, priority)| HostingEntry::sign(&key(seed), &user_of(1), priority))
            .collect();
        assert_eq!(verify(&resign(&entries)), Err(IdentityError::HubsNotSorted));

        sort_hosting_entries(&mut entries);
        let keys: Vec<_> = entries.iter().map(HostingEntry::order_key).collect();
        assert!(keys.windows(2).all(|pair| pair[0] < pair[1]));
        assert_eq!(entries[0].priority(), 0);
        let record = verify(&resign(&entries)).unwrap();
        assert_eq!(record.hubs(), entries);

        // Equal priority, keys out of byte order.
        let mut same_priority = entries[..2].to_vec();
        same_priority.swap(0, 1);
        assert_eq!(
            verify(&resign(&same_priority)),
            Err(IdentityError::HubsNotSorted)
        );
    }

    #[test]
    fn rejects_user_root_as_hub() {
        let user = key(1);
        let mut entries = vec![
            HostingEntry::sign(&user, &user_of(1), 0),
            HostingEntry::sign(&key(10), &user_of(1), 0),
        ];
        sort_hosting_entries(&mut entries);
        let items = record_items(&user, 1, 1000, entries.iter().map(entry_value).collect());
        let bytes = sign_value(&user, HOSTING_RECORD_CONTEXT, &Value::Array(items));
        assert_eq!(
            HostingRecord::verify(&bytes, &user_of(1), 0),
            Err(IdentityError::UserRootIsHub)
        );
    }

    #[test]
    fn verify_checks_expected_user_after_record() {
        let bytes = record(&key(1), 1, &[(10, 0)]);
        assert!(HostingRecord::verify_claimed(&bytes, 0).is_ok());
        assert_eq!(
            HostingRecord::verify(&bytes, &user_of(2), 0),
            Err(IdentityError::UserIdMismatch)
        );
        // An invalid record fails with its own error, not the user check.
        assert_eq!(
            HostingRecord::verify(&bytes, &user_of(2), 1000),
            Err(IdentityError::Expired)
        );
    }

    #[test]
    fn ordering_and_latest() {
        let v1 = HostingRecord::verify(&record(&key(1), 1, &[(10, 0)]), &user_of(1), 0).unwrap();
        let v2 = HostingRecord::verify(&record(&key(1), 2, &[(10, 0)]), &user_of(1), 0).unwrap();
        assert_eq!(v2.supersedes(&v1), Ok(true));
        assert_eq!(v1.supersedes(&v2), Err(IdentityError::StaleSeq(1)));
        assert_eq!(v2.supersedes(&v2.clone()), Ok(false));
        let other = HostingRecord::verify(&record(&key(1), 2, &[(11, 0)]), &user_of(1), 0).unwrap();
        assert_eq!(v2.supersedes(&other), Err(IdentityError::SeqConflict(2)));
        let stranger =
            HostingRecord::verify(&record(&key(2), 9, &[(10, 0)]), &user_of(2), 0).unwrap();
        assert_eq!(v2.supersedes(&stranger), Err(IdentityError::UserIdMismatch));

        assert_eq!(HostingRecord::latest([&v1, &v2, &v1]), Ok(Some(&v2)));
        assert_eq!(HostingRecord::latest([&v2, &v1]), Ok(Some(&v2)));
        assert_eq!(HostingRecord::latest([]), Ok(None));
        assert_eq!(
            HostingRecord::latest([&v1, &v2, &other]),
            Err(IdentityError::SeqConflict(2))
        );
    }
}
