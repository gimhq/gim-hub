//! Hub proof of possession (hub-proposed, `GET /v2/hub?nonce=`): the hub
//! root key signs a client nonce together with the hub's id and public URL,
//! so a client can check that a URL belongs to a `hub_id`.

use ed25519_dalek::SigningKey;

use crate::keys::{sign, verify};
use crate::{HubId, IdentityError, VerifyingKey};

/// Signature context of the hub proof (hub root key).
pub const HUB_PROOF_CONTEXT: &[u8] = b"gim-hub-proof-v1";

/// Longest `public_url` a proof can carry: its length is a `u16`.
pub const HUB_PROOF_MAX_URL_LEN: usize = u16::MAX as usize;

/// The signed part after the context: `nonce || u16be(len(hub_id)) ||
/// hub_id || u16be(len(public_url)) || public_url` (UTF-8, lengths in
/// bytes).
fn proof_tbs(nonce: &[u8; 32], hub_id: &HubId, public_url: &str) -> Result<Vec<u8>, IdentityError> {
    let prefixed = |field: &str| -> Result<Vec<u8>, IdentityError> {
        let len = u16::try_from(field.len())
            .map_err(|_| IdentityError::Malformed("proof field longer than 65535 bytes".into()))?;
        Ok([&len.to_be_bytes(), field.as_bytes()].concat())
    };
    Ok([
        nonce.to_vec(),
        prefixed(hub_id.as_str())?,
        prefixed(public_url)?,
    ]
    .concat())
}

/// The hub's proof: Ed25519 by its root key over `"gim-hub-proof-v1" ||
/// 0x00 || nonce || u16be(len(hub_id)) || hub_id || u16be(len(public_url))
/// || public_url`, where `hub_id` is derived from `root`. Fails only for a
/// `public_url` longer than [`HUB_PROOF_MAX_URL_LEN`].
pub fn sign_hub_proof(
    root: &SigningKey,
    nonce: &[u8; 32],
    public_url: &str,
) -> Result<[u8; 64], IdentityError> {
    let hub_id = HubId::from_root_pubkey(&root.verifying_key());
    Ok(sign(
        root,
        HUB_PROOF_CONTEXT,
        &proof_tbs(nonce, &hub_id, public_url)?,
    ))
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
        &proof_tbs(nonce, hub_id, public_url)?,
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
        let sig = sign_hub_proof(&root, &nonce, URL).unwrap();
        let message = [
            b"gim-hub-proof-v1".as_slice(),
            &[0],
            &nonce,
            &(hub_id.as_str().len() as u16).to_be_bytes(),
            hub_id.as_str().as_bytes(),
            &(URL.len() as u16).to_be_bytes(),
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
        assert_ne!(sign_hub_proof(&root, &[6u8; 32], URL).unwrap(), sig);
        let long = "x".repeat(HUB_PROOF_MAX_URL_LEN + 1);
        assert!(matches!(
            sign_hub_proof(&root, &nonce, &long),
            Err(IdentityError::Malformed(_))
        ));
        assert!(sign_hub_proof(&root, &nonce, &long[1..]).is_ok());
    }

    #[test]
    fn rejects_other_inputs() {
        let root = key(9);
        let hub_id = HubId::from_root_pubkey(&root.verifying_key());
        let nonce = [5u8; 32];
        let sig = sign_hub_proof(&root, &nonce, URL).unwrap();
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
