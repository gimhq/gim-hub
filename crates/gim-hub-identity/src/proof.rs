//! Hub proof of possession (hub-proposed, `GET /v2/hub?nonce=`): the hub
//! root key signs a client nonce together with the hub's id and public URL,
//! so a client can check that a URL belongs to a `hub_id`.

use ed25519_dalek::SigningKey;

use crate::keys::{sign, verify};
use crate::{HubId, IdentityError, VerifyingKey};

/// Signature context of the hub proof (hub root key).
pub const HUB_PROOF_CONTEXT: &[u8] = b"gim-hub-proof-v1";

/// The signed part after the context: `nonce || UTF-8(hub_id) ||
/// UTF-8(public_url)`, concatenated without separators or lengths.
fn proof_tbs(nonce: &[u8; 32], hub_id: &HubId, public_url: &str) -> Vec<u8> {
    [
        nonce.as_slice(),
        hub_id.as_str().as_bytes(),
        public_url.as_bytes(),
    ]
    .concat()
}

/// The hub's proof: Ed25519 by its root key over
/// `"gim-hub-proof-v1" || 0x00 || nonce || hub_id || public_url`, where
/// `hub_id` is derived from `root`.
pub fn sign_hub_proof(root: &SigningKey, nonce: &[u8; 32], public_url: &str) -> [u8; 64] {
    let hub_id = HubId::from_root_pubkey(&root.verifying_key());
    sign(
        root,
        HUB_PROOF_CONTEXT,
        &proof_tbs(nonce, &hub_id, public_url),
    )
}

/// Client-side check of a hub proof: `root` must be the key behind `hub_id`
/// and `sig` its strict signature over the proof message.
pub fn verify_hub_proof(
    root: &VerifyingKey,
    hub_id: &HubId,
    nonce: &[u8; 32],
    public_url: &str,
    sig: &[u8; 64],
) -> Result<(), IdentityError> {
    if &HubId::from_root_pubkey(root) != hub_id {
        return Err(IdentityError::HubKeyMismatch);
    }
    verify(
        root,
        HUB_PROOF_CONTEXT,
        &proof_tbs(nonce, hub_id, public_url),
        sig,
    )
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::{Signature, Verifier};

    use super::*;
    use crate::testutil::key;

    const URL: &str = "https://hub.example.eu";

    #[test]
    fn signs_the_exact_message() {
        let root = key(9);
        let hub_id = HubId::from_root_pubkey(&root.verifying_key());
        let nonce = [5u8; 32];
        let sig = sign_hub_proof(&root, &nonce, URL);
        let message = [
            b"gim-hub-proof-v1".as_slice(),
            &[0],
            &nonce,
            hub_id.as_str().as_bytes(),
            URL.as_bytes(),
        ]
        .concat();
        root.verifying_key()
            .verify(&message, &Signature::from_bytes(&sig))
            .unwrap();
        assert_eq!(
            verify_hub_proof(&root.verifying_key(), &hub_id, &nonce, URL, &sig),
            Ok(())
        );
        assert_ne!(sign_hub_proof(&root, &[6u8; 32], URL), sig);
    }

    #[test]
    fn rejects_other_inputs() {
        let root = key(9);
        let hub_id = HubId::from_root_pubkey(&root.verifying_key());
        let nonce = [5u8; 32];
        let sig = sign_hub_proof(&root, &nonce, URL);
        let check = |key: &VerifyingKey, id: &HubId, nonce: &[u8; 32], url: &str| {
            verify_hub_proof(key, id, nonce, url, &sig)
        };
        assert_eq!(
            check(&root.verifying_key(), &hub_id, &[6; 32], URL),
            Err(IdentityError::BadSignature)
        );
        assert_eq!(
            check(&root.verifying_key(), &hub_id, &nonce, "https://other.eu"),
            Err(IdentityError::BadSignature)
        );
        let other = key(8).verifying_key();
        assert_eq!(
            check(&other, &hub_id, &nonce, URL),
            Err(IdentityError::HubKeyMismatch)
        );
        assert_eq!(
            check(&other, &HubId::from_root_pubkey(&other), &nonce, URL),
            Err(IdentityError::BadSignature)
        );
    }
}
