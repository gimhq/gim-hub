//! Parsing of the MLS (RFC 9420) objects the hub inspects: uploaded
//! KeyPackages and PublicMessage Commits and Proposals.
//!
//! The hub never processes MLS state; it reads the framing (group ID, epoch,
//! sender), the proposals of a Commit (by value, or by reference to
//! Proposals it sequenced) and of a Proposal to keep its delivery-service
//! roster. Clients use the UTF-8 bytes of the `gid` as the
//! MLS group ID.

use std::collections::{BTreeSet, HashMap};

use gim_hub_identity::{
    parse_public_key, CredentialError, DeviceId, DeviceList, GimCredential, UserId,
};
use openmls::{
    ciphersuite::hash_ref::make_proposal_ref,
    prelude::{
        tls_codec::{Deserialize, Serialize, VLBytes},
        Ciphersuite, ContentType, Credential, KeyPackageIn, MlsMessageBodyIn, MlsMessageIn,
        ProposalIn, ProposalOrRefIn, ProtocolVersion, Sender,
    },
};
use openmls_rust_crypto::RustCrypto;
use sha2::{Digest, Sha256};

use crate::error::ApiError;

/// `MLSMessage.wire_format` of a PublicMessage.
const WIRE_FORMAT_PUBLIC_MESSAGE: u16 = 1;

/// 400 message for an Add whose KeyPackage is not in this hub's claim
/// ledger (docs/multihoming.md §5.4): the client re-claims through this hub.
pub const KP_NOT_CLAIMED: &str = "key package not claimed through this hub (kp_not_claimed)";

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
/// KeyPackage; returns its [`key_package_hash`] and leaf credential.
pub fn parse_key_package(bytes: &[u8]) -> Result<([u8; 32], LeafCredential), ApiError> {
    let key_package = KeyPackageIn::tls_deserialize_exact(bytes)
        .map_err(|err| invalid(format!("malformed KeyPackage: {err}")))?;
    let hash = key_package_hash(&key_package)?;
    let leaf = LeafCredential::of_key_package(&key_package);
    key_package
        .validate(&RustCrypto::default(), ProtocolVersion::Mls10)
        .map_err(|err| invalid(format!("invalid KeyPackage: {err}")))?;
    Ok((hash, leaf))
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
    /// The Commit's proposals, in order, with references unresolved.
    pub proposals: Vec<CommitProposal>,
    /// The leaf node of the UpdatePath, if any.
    pub path_leaf: Option<LeafCredential>,
    /// Whether `added`, `removed` and `own_leaves` hold the effect of every
    /// proposal: false until [`ParsedCommit::resolve`] resolved the
    /// references.
    pub resolved: bool,
    /// [`key_package_hash`] and leaf credential of each added KeyPackage,
    /// in proposal order.
    pub added: Vec<([u8; 32], LeafCredential)>,
    /// Leaf indexes removed, in proposal order.
    pub removed: Vec<u32>,
    /// Leaves the committer sets for itself: those of Update proposals
    /// carried by value and of the UpdatePath, if any.
    pub own_leaves: Vec<LeafCredential>,
}

/// One proposal of a Commit (RFC 9420 §12.4 `ProposalOrRef`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CommitProposal {
    Value(RosterProposal),
    /// A ProposalRef (RFC 9420 §5.2) to a proposal sequenced in the
    /// Commit's epoch.
    Reference(Vec<u8>),
}

/// What a proposal does to the hub's roster.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RosterProposal {
    /// [`key_package_hash`] and leaf credential of the added KeyPackage.
    Add([u8; 32], LeafCredential),
    /// Removed leaf index.
    Remove(u32),
    /// The proposer's new leaf.
    Update(LeafCredential),
    /// PreSharedKey, ReInit, GroupContextExtensions or custom proposals.
    Neutral,
}

impl ParsedCommit {
    /// ProposalRefs the Commit covers by reference.
    pub fn references(&self) -> impl Iterator<Item = &[u8]> {
        self.proposals.iter().filter_map(|proposal| match proposal {
            CommitProposal::Reference(proposal_ref) => Some(proposal_ref.as_slice()),
            CommitProposal::Value(_) => None,
        })
    }

    /// Computes `added`, `removed` and `own_leaves`, taking each referenced
    /// proposal from `resolved` (an unknown reference fails). An Update by
    /// reference sets the proposer's leaf, which was checked when the
    /// proposal was submitted, so it is not one of `own_leaves`.
    pub fn resolve(&mut self, resolved: &HashMap<Vec<u8>, RosterProposal>) -> Result<(), ApiError> {
        let (mut added, mut removed) = (Vec::new(), Vec::new());
        let mut own_leaves: Vec<LeafCredential> = self.path_leaf.iter().cloned().collect();
        for proposal in &self.proposals {
            let (proposal, by_value) = match proposal {
                CommitProposal::Value(proposal) => (proposal, true),
                CommitProposal::Reference(proposal_ref) => (
                    resolved
                        .get(proposal_ref)
                        .ok_or_else(|| invalid("unknown proposal reference"))?,
                    false,
                ),
            };
            match proposal {
                RosterProposal::Add(hash, leaf) => added.push((*hash, leaf.clone())),
                RosterProposal::Remove(leaf) => removed.push(*leaf),
                RosterProposal::Update(leaf) if by_value => own_leaves.push(leaf.clone()),
                RosterProposal::Update(_) | RosterProposal::Neutral => {}
            }
        }
        (self.added, self.removed, self.own_leaves) = (added, removed, own_leaves);
        self.resolved = true;
        Ok(())
    }
}

/// The parts of a PublicMessage Proposal the hub acts on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedProposal {
    /// MLS group ID from the framing.
    pub group_id: Vec<u8>,
    /// Epoch the Proposal was created in.
    pub epoch: u64,
    /// Leaf index of the proposer.
    pub sender_leaf: u32,
    pub proposal: RosterProposal,
    /// The ProposalRef under each MLS hash function (SHA-256, SHA-384,
    /// SHA-512): the hub does not know the group's ciphersuite, a
    /// reference's length selects the hash.
    pub refs: Vec<Vec<u8>>,
}

/// A PublicMessage handshake message from a member.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Handshake {
    Commit(ParsedCommit),
    Proposal(ParsedProposal),
}

/// Parses an `MLSMessage` that must be a PublicMessage Commit or Proposal
/// from a member. A Commit without proposals by reference is resolved.
pub fn parse_handshake(bytes: &[u8]) -> Result<Handshake, ApiError> {
    let message = MlsMessageIn::tls_deserialize_exact(bytes)
        .map_err(|err| invalid(format!("malformed MLSMessage: {err}")))?;
    let MlsMessageBodyIn::PublicMessage(public) = message.extract() else {
        return Err(invalid("mls_message is not a PublicMessage"));
    };
    let content_type = public.content_type();
    if !matches!(content_type, ContentType::Commit | ContentType::Proposal) {
        return Err(invalid("mls_message is not a Commit or a Proposal"));
    }
    let Sender::Member(sender) = public.sender() else {
        return Err(invalid("handshake sender is not a group member"));
    };
    let (group_id, epoch, sender_leaf) = (
        public.group_id().as_slice().to_vec(),
        public.epoch().as_u64(),
        sender.u32(),
    );
    let mut reader = framed_body(bytes)?;
    if content_type == ContentType::Proposal {
        let malformed =
            |err: openmls::prelude::tls_codec::Error| invalid(format!("malformed Proposal: {err}"));
        let proposal = ProposalIn::tls_deserialize(&mut reader).map_err(malformed)?;
        let _signature = VLBytes::tls_deserialize(&mut reader).map_err(malformed)?;
        // AuthenticatedContent (RFC 9420 §6.1): the message without its
        // version and the trailing membership tag.
        let content = &bytes[2..bytes.len() - reader.len()];
        let proposal = match proposal {
            // A SelfRemove proposal (draft-ietf-mls-extensions) removes its
            // sender.
            ProposalIn::SelfRemove => RosterProposal::Remove(sender_leaf),
            proposal => match roster_proposal(proposal)? {
                RosterProposal::Neutral => {
                    return Err(invalid(
                        "unsupported proposal type (only Add, Remove, SelfRemove and Update)",
                    ))
                }
                proposal => proposal,
            },
        };
        return Ok(Handshake::Proposal(ParsedProposal {
            group_id,
            epoch,
            sender_leaf,
            proposal,
            refs: proposal_refs(content)?,
        }));
    }
    let malformed =
        |err: openmls::prelude::tls_codec::Error| invalid(format!("malformed Commit: {err}"));
    let proposals = Vec::<ProposalOrRefIn>::tls_deserialize(&mut reader).map_err(malformed)?;
    let path_leaf = match u8::tls_deserialize(&mut reader).map_err(malformed)? {
        0 => None,
        _ => Some(LeafCredential::read(&mut reader)?),
    };
    let mut parsed = ParsedCommit {
        group_id,
        epoch,
        sender_leaf,
        proposals: proposals
            .into_iter()
            .map(|proposal| match proposal {
                ProposalOrRefIn::Proposal(proposal) => {
                    roster_proposal(*proposal).map(CommitProposal::Value)
                }
                ProposalOrRefIn::Reference(proposal_ref) => {
                    Ok(CommitProposal::Reference(proposal_ref.as_slice().to_vec()))
                }
            })
            .collect::<Result<_, _>>()?,
        path_leaf,
        resolved: false,
        added: Vec::new(),
        removed: Vec::new(),
        own_leaves: Vec::new(),
    };
    if parsed.references().next().is_none() {
        parsed.resolve(&HashMap::new())?;
    }
    Ok(Handshake::Commit(parsed))
}

/// Parses an `MLSMessage` that must be a PublicMessage Commit from a member.
pub fn parse_commit(bytes: &[u8]) -> Result<ParsedCommit, ApiError> {
    match parse_handshake(bytes)? {
        Handshake::Commit(commit) => Ok(commit),
        Handshake::Proposal(_) => Err(invalid("mls_message is not a Commit")),
    }
}

/// Parses an `MLSMessage` that must be a PublicMessage Proposal from a
/// member.
pub fn parse_proposal(bytes: &[u8]) -> Result<ParsedProposal, ApiError> {
    match parse_handshake(bytes)? {
        Handshake::Proposal(proposal) => Ok(proposal),
        Handshake::Commit(_) => Err(invalid("mls_message is not a Proposal")),
    }
}

/// The roster effect of a proposal carried by value.
fn roster_proposal(proposal: ProposalIn) -> Result<RosterProposal, ApiError> {
    Ok(match proposal {
        ProposalIn::Add(add) => {
            // An Add proposal encodes exactly its KeyPackage.
            let bytes = add
                .tls_serialize_detached()
                .map_err(|err| ApiError::Internal(format!("re-encode Add proposal: {err}")))?;
            let key_package = KeyPackageIn::tls_deserialize_exact(&bytes)
                .map_err(|err| invalid(format!("malformed Add proposal: {err}")))?;
            RosterProposal::Add(
                Sha256::digest(&bytes).into(),
                LeafCredential::of_key_package(&key_package),
            )
        }
        ProposalIn::Remove(remove) => RosterProposal::Remove(remove.removed().u32()),
        // An Update proposal encodes exactly its LeafNode.
        ProposalIn::Update(update) => {
            let bytes = update
                .tls_serialize_detached()
                .map_err(|err| ApiError::Internal(format!("re-encode Update proposal: {err}")))?;
            RosterProposal::Update(LeafCredential::read(&mut bytes.as_slice())?)
        }
        ProposalIn::PreSharedKey(_)
        | ProposalIn::ReInit(_)
        | ProposalIn::GroupContextExtensions(_)
        | ProposalIn::Custom(_) => RosterProposal::Neutral,
        ProposalIn::ExternalInit(_) | ProposalIn::SelfRemove => {
            return Err(invalid("unsupported proposal type"));
        }
    })
}

/// `MakeProposalRef(content)` (RFC 9420 §5.2) under SHA-256, SHA-384 and
/// SHA-512.
fn proposal_refs(content: &[u8]) -> Result<Vec<Vec<u8>>, ApiError> {
    let crypto = RustCrypto::default();
    [
        Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519,
        Ciphersuite::MLS_256_DHKEMP384_AES256GCM_SHA384_P384,
        Ciphersuite::MLS_256_DHKEMX448_AES256GCM_SHA512_Ed448,
    ]
    .into_iter()
    .map(|ciphersuite| {
        make_proposal_ref(content, ciphersuite, &crypto)
            .map(|proposal_ref| proposal_ref.as_slice().to_vec())
            .map_err(|err| ApiError::Internal(format!("proposal ref: {err:?}")))
    })
    .collect()
}

/// The content of a PublicMessage handshake message, after its framing.
/// openmls does not expose the content of a received message, so this
/// walks the framing (RFC 9420 §6) of a message already validated by
/// [`MlsMessageIn`]:
///
/// ```text
/// MLSMessage: version u16, wire_format u16, PublicMessage
/// FramedContent: group_id<V>, epoch u64, sender, authenticated_data<V>,
///                content_type u8, then the Proposal or
///                Commit { ProposalOrRef proposals<V>;
///                         optional<UpdatePath { LeafNode leaf_node; ... }> path; }
/// ```
fn framed_body(mut bytes: &[u8]) -> Result<&[u8], ApiError> {
    let reader = &mut bytes;
    let malformed =
        |err: openmls::prelude::tls_codec::Error| invalid(format!("malformed MLSMessage: {err}"));
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
    Ok(bytes)
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

/// The credential and MLS signature key of a leaf node, not yet validated
/// (see [`check_leaf_credential`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LeafCredential {
    pub credential_type: u16,
    pub content: Vec<u8>,
    pub signature_key: Vec<u8>,
}

impl LeafCredential {
    fn new(credential: &Credential, signature_key: &[u8]) -> Self {
        Self {
            credential_type: credential.credential_type().into(),
            content: credential.serialized_content().to_vec(),
            signature_key: signature_key.to_vec(),
        }
    }

    /// Reads the start of a `LeafNode` (RFC 9420 §7.2):
    /// `encryption_key<V>, signature_key<V>, Credential credential, ...`.
    /// openmls does not expose the leaf nodes of received proposals and
    /// UpdatePaths.
    fn read(reader: &mut &[u8]) -> Result<Self, ApiError> {
        let malformed =
            |err: openmls::prelude::tls_codec::Error| invalid(format!("malformed LeafNode: {err}"));
        let _encryption_key = VLBytes::tls_deserialize(reader).map_err(malformed)?;
        let signature_key = VLBytes::tls_deserialize(reader).map_err(malformed)?;
        let credential = Credential::tls_deserialize(reader).map_err(malformed)?;
        Ok(Self::new(&credential, signature_key.as_slice()))
    }

    fn of_key_package(key_package: &KeyPackageIn) -> Self {
        let credential = key_package.unverified_credential();
        Self::new(&credential.credential, credential.signature_key.as_slice())
    }
}

/// Validates the gim credential (type `0xF001`) of a leaf that must belong
/// to the device `(user_id, device_id)`, against `device_list`, the stored
/// `SignedDeviceList` of `user_id` on this hub. Fails closed: without a
/// valid stored list (`device_list_unknown`), and for a device the list does
/// not certify with the leaf's key (`device_not_in_list`), the leaf is
/// rejected. The `validation_failed` message carries the
/// [`CredentialError::code`] or the hub's code `identity_mismatch`.
pub fn check_leaf_credential(
    leaf: &LeafCredential,
    device_list: Option<&[u8]>,
    user_id: &str,
    device_id: &str,
) -> Result<(), ApiError> {
    let reject = |code: &str| invalid(format!("invalid MLS credential ({code})"));
    let credential = GimCredential::decode_typed(leaf.credential_type, &leaf.content)
        .map_err(|err| reject(err.code()))?;
    let list = UserId::parse(user_id)
        .ok()
        .zip(device_list)
        .and_then(|(user, bytes)| DeviceList::verify(bytes, &user).ok());
    let (user, device) = credential
        .verify(list.as_ref(), &leaf.signature_key)
        .map_err(|err| match err {
            // The credential certifies another user.
            CredentialError::DeviceListUserMismatch { .. } => reject("identity_mismatch"),
            err => reject(err.code()),
        })?;
    if user.as_str() != user_id || device.as_str() != device_id {
        return Err(reject("identity_mismatch"));
    }
    Ok(())
}

/// The `(user_id, device_id)` a leaf's gim credential claims: the user of
/// its root key and the device of its MLS signature key. Not a validation:
/// [`check_leaf_credential`] still has to accept the leaf for that
/// identity. Used for members added by Commits from other hubs, whose claim
/// ledger the owning hub cannot see (docs/federation.md §5.3).
pub fn credential_identity(leaf: &LeafCredential) -> Option<(String, String)> {
    let credential = GimCredential::decode_typed(leaf.credential_type, &leaf.content).ok()?;
    let device_key = parse_public_key(&leaf.signature_key).ok()?;
    Some((
        UserId::from_root_pubkey(credential.root_pubkey()).to_string(),
        DeviceId::from_device_pubkey(&device_key).to_string(),
    ))
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
