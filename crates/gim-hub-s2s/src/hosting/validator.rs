//! DHT validator of `/gim/user/<user_id>` records (docs/federation.md §4.4).
//! Step 4 (inbound puts only from bound peers) is enforced by the
//! transport before any validator runs.

use gim_hub_identity::UserId;
use gim_hub_proto::USER_RECORD_KEY_PREFIX;

use super::{decode_stored, verify};
use crate::transport::{RecordDecision, RecordValidator};

/// Accepts valid hosting records of the user named by the key; a stored
/// record is replaced only by a higher seq.
#[derive(Debug, Clone, Copy, Default)]
pub struct UserRecordValidator;

impl RecordValidator for UserRecordValidator {
    fn validate(
        &self,
        key: &str,
        value: &[u8],
        existing: Option<&[u8]>,
        now_ms: u64,
    ) -> RecordDecision {
        // 1. Key prefix and a syntactically valid user_id.
        let Some(user_id) = key.strip_prefix(USER_RECORD_KEY_PREFIX) else {
            return RecordDecision::Reject("not a user record key".into());
        };
        let user_id = match UserId::parse(user_id) {
            Ok(user_id) => user_id,
            Err(err) => return RecordDecision::Reject(err.code().into()),
        };
        // 2. A valid record of that user.
        let now = i64::try_from(now_ms).unwrap_or(i64::MAX);
        let record = match verify(value, &user_id, now) {
            Ok(record) => record,
            Err(err) => return RecordDecision::Reject(err.code().into()),
        };
        // 3. The seq rules against the stored record.
        let Some(stored) = existing.and_then(|old| decode_stored(old).ok()) else {
            return RecordDecision::Store;
        };
        match record.supersedes(&stored) {
            Ok(true) => RecordDecision::Store,
            Ok(false) => RecordDecision::Keep,
            Err(err) => RecordDecision::Reject(err.code().into()),
        }
    }
}
