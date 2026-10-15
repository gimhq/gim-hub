//! Parsing of the MLS (RFC 9420) objects the hub inspects: uploaded
//! KeyPackages and PublicMessage Commits.
//!
//! The hub never processes MLS state; it reads the framing (group ID, epoch,
//! sender) and the proposals carried by value in a Commit to keep its
//! delivery-service roster. Clients use the UTF-8 bytes of the `gid` as the
//! MLS group ID.

use std::collections::BTreeSet;

use openmls::prelude::{
    tls_codec::{Deserialize, Serialize, VLBytes},
    ContentType, KeyPackageIn, MlsMessageBodyIn, MlsMessageIn, ProposalIn, ProposalOrRefIn,
    ProtocolVersion, Sender,
};
use openmls_rust_crypto::RustCrypto;
use sha2::{Digest, Sha256};

use crate::error::ApiError;

/// `MLSMessage.wire_format` of a PublicMessage.
const WIRE_FORMAT_PUBLIC_MESSAGE: u16 = 1;

fn invalid(message: impl Into<String>) -> ApiError {
    ApiError::ValidationFailed(message.into())
}

/// Hash under which a KeyPackage is stored and looked up when it is added by
/// a Commit: SHA-256 of its TLS encoding.
pub fn key_package_hash(key_package: &KeyPackageIn) -> Result<[u8; 32], ApiError> {
    let bytes = key_package
        .tls_serialize_detached()
        .map_err(|err| ApiError::Internal(format!("re-encode KeyPackage: {err}")))?;
    Ok(Sha256::digest(bytes).into())
}

/// Parses and verifies (signatures, version, lifetime) a serialized MLS
/// KeyPackage; returns its [`key_package_hash`].
pub fn parse_key_package(bytes: &[u8]) -> Result<[u8; 32], ApiError> {
    let key_package = KeyPackageIn::tls_deserialize_exact(bytes)
        .map_err(|err| invalid(format!("malformed KeyPackage: {err}")))?;
    let hash = key_package_hash(&key_package)?;
    key_package
        .validate(&RustCrypto::default(), ProtocolVersion::Mls10)
        .map_err(|err| invalid(format!("invalid KeyPackage: {err}")))?;
    Ok(hash)
}

/// The parts of a PublicMessage Commit the hub acts on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedCommit {
    /// MLS group ID from the framing.
    pub group_id: Vec<u8>,
    /// Epoch the Commit was created in.
    pub epoch: u64,
    /// Leaf index of the committer.
    pub sender_leaf: u32,
    /// [`key_package_hash`] of each added KeyPackage, in proposal order.
    pub added: Vec<[u8; 32]>,
    /// Leaf indexes removed, in proposal order.
    pub removed: Vec<u32>,
}

/// Parses an `MLSMessage` that must be a PublicMessage Commit from a member,
/// with every proposal carried by value.
pub fn parse_commit(bytes: &[u8]) -> Result<ParsedCommit, ApiError> {
    let message = MlsMessageIn::tls_deserialize_exact(bytes)
        .map_err(|err| invalid(format!("malformed MLSMessage: {err}")))?;
    let MlsMessageBodyIn::PublicMessage(public) = message.extract() else {
        return Err(invalid("mls_message is not a PublicMessage"));
    };
    if public.content_type() != ContentType::Commit {
        return Err(invalid("mls_message is not a Commit"));
    }
    let Sender::Member(sender) = public.sender() else {
        return Err(invalid("Commit sender is not a group member"));
    };

    let mut parsed = ParsedCommit {
        group_id: public.group_id().as_slice().to_vec(),
        epoch: public.epoch().as_u64(),
        sender_leaf: sender.u32(),
        added: Vec::new(),
        removed: Vec::new(),
    };
    for proposal in commit_proposals(bytes)? {
        let ProposalOrRefIn::Proposal(proposal) = proposal else {
            return Err(invalid("proposals by reference are not supported"));
        };
        match *proposal {
            ProposalIn::Add(add) => {
                // An Add proposal encodes exactly its KeyPackage.
                let key_package = add
                    .tls_serialize_detached()
                    .map_err(|err| ApiError::Internal(format!("re-encode Add proposal: {err}")))?;
                parsed.added.push(Sha256::digest(key_package).into());
            }
            ProposalIn::Remove(remove) => parsed.removed.push(remove.removed().u32()),
            // Roster-neutral proposals.
            ProposalIn::Update(_)
            | ProposalIn::PreSharedKey(_)
            | ProposalIn::ReInit(_)
            | ProposalIn::GroupContextExtensions(_)
            | ProposalIn::Custom(_) => {}
            ProposalIn::ExternalInit(_) | ProposalIn::SelfRemove => {
                return Err(invalid("unsupported proposal type in Commit"));
            }
        }
    }
    Ok(parsed)
}

/// Reads the proposal list of a PublicMessage Commit. openmls does not
/// expose the Commit body of a received message, so this walks the framing
/// (RFC 9420 §6) of a message already validated by [`MlsMessageIn`]:
///
/// ```text
/// MLSMessage: version u16, wire_format u16, PublicMessage
/// FramedContent: group_id<V>, epoch u64, sender, authenticated_data<V>,
///                content_type u8, Commit { ProposalOrRef proposals<V>; ... }
/// ```
fn commit_proposals(mut bytes: &[u8]) -> Result<Vec<ProposalOrRefIn>, ApiError> {
    let reader = &mut bytes;
    let malformed = |err: openmls::prelude::tls_codec::Error| invalid(format!("malformed Commit: {err}"));
    let _version = u16::tls_deserialize(reader).map_err(malformed)?;
    let wire_format = u16::tls_deserialize(reader).map_err(malformed)?;
    if wire_format != WIRE_FORMAT_PUBLIC_MESSAGE {
        return Err(invalid("mls_message is not a PublicMessage"));
    }
    let _group_id = VLBytes::tls_deserialize(reader).map_err(malformed)?;
    let _epoch = u64::tls_deserialize(reader).map_err(malformed)?;
    let _sender = Sender::tls_deserialize(reader).map_err(malformed)?;
    let _authenticated_data = VLBytes::tls_deserialize(reader).map_err(malformed)?;
    let _content_type = u8::tls_deserialize(reader).map_err(malformed)?;
    Vec::<ProposalOrRefIn>::tls_deserialize(reader).map_err(malformed)
}

/// Leaf indexes for `count` new members per RFC 9420 §12.1.1: each Add takes
/// the leftmost blank leaf, after the Commit's Removes were applied.
/// `occupied` holds the leaves of the remaining members.
pub fn assign_leaves(occupied: &BTreeSet<u32>, count: usize) -> Vec<u32> {
    (0u32..)
        .filter(|leaf| !occupied.contains(leaf))
        .take(count)
        .collect()
}

/// A device added by a Commit, as identified from its claimed KeyPackage.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AddedMember<'a> {
    pub gid: &'a str,
    pub user_id: &'a str,
    pub device_id: &'a str,
}

/// Validation of the MLS credential of a member added by a Commit.
pub trait CredentialPolicy {
    /// Rejects the Add with a `validation_failed` reason.
    fn check_added_member(&self, member: &AddedMember<'_>) -> Result<(), String>;
}

/// Accepts every added member.
///
/// TODO: replace with validation of the gim-core credential (type 0xF001)
/// against the member's DeviceList once gim-core identity part 2 defines the
/// credential format.
#[derive(Debug, Clone, Copy, Default)]
pub struct AcceptAllCredentials;

impl CredentialPolicy for AcceptAllCredentials {
    fn check_added_member(&self, _member: &AddedMember<'_>) -> Result<(), String> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn leaves_fill_leftmost_blanks_first() {
        let occupied = BTreeSet::from([0, 2, 3]);
        assert_eq!(assign_leaves(&occupied, 3), [1, 4, 5]);
        assert_eq!(assign_leaves(&BTreeSet::new(), 2), [0, 1]);
        assert!(assign_leaves(&occupied, 0).is_empty());
    }

    #[test]
    fn garbage_is_rejected() {
        assert!(matches!(
            parse_commit(&[0, 1, 0, 1, 0xff]),
            Err(ApiError::ValidationFailed(_))
        ));
        assert!(matches!(
            parse_key_package(b"nope"),
            Err(ApiError::ValidationFailed(_))
        ));
    }
}
