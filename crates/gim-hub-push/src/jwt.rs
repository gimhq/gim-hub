//! Compact JWS signing (ES256 for APNs, RS256 for Google OAuth) with ring.

use base64::{
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
    Engine,
};
use ring::{
    rand::SystemRandom,
    signature::{EcdsaKeyPair, RsaKeyPair, ECDSA_P256_SHA256_FIXED_SIGNING, RSA_PKCS1_SHA256},
};
use serde_json::Value;

/// DER of the first PEM block in `pem`.
pub(crate) fn pem_to_der(pem: &str) -> Result<Vec<u8>, String> {
    let body: String = pem
        .lines()
        .map(str::trim)
        .skip_while(|line| !line.starts_with("-----BEGIN"))
        .skip(1)
        .take_while(|line| !line.starts_with("-----END"))
        .collect();
    if body.is_empty() {
        return Err("no PEM block found".into());
    }
    STANDARD
        .decode(body)
        .map_err(|err| format!("invalid PEM base64: {err}"))
}

/// An ES256 key from a PKCS#8 DER document (an APNs `.p8` key).
pub(crate) fn es256_key(pkcs8: &[u8]) -> Result<EcdsaKeyPair, String> {
    EcdsaKeyPair::from_pkcs8(
        &ECDSA_P256_SHA256_FIXED_SIGNING,
        pkcs8,
        &SystemRandom::new(),
    )
    .map_err(|err| format!("invalid P-256 PKCS#8 key: {err}"))
}

/// An RS256 key from a PKCS#8 DER document.
pub(crate) fn rs256_key(pkcs8: &[u8]) -> Result<RsaKeyPair, String> {
    RsaKeyPair::from_pkcs8(pkcs8).map_err(|err| format!("invalid RSA PKCS#8 key: {err}"))
}

fn signing_input(header: &Value, claims: &Value) -> String {
    format!(
        "{}.{}",
        URL_SAFE_NO_PAD.encode(header.to_string()),
        URL_SAFE_NO_PAD.encode(claims.to_string())
    )
}

/// `header.claims.signature` signed with ES256.
pub(crate) fn sign_es256(
    key: &EcdsaKeyPair,
    header: &Value,
    claims: &Value,
) -> Result<String, String> {
    let input = signing_input(header, claims);
    let signature = key
        .sign(&SystemRandom::new(), input.as_bytes())
        .map_err(|_| "ES256 signing failed".to_owned())?;
    Ok(format!("{input}.{}", URL_SAFE_NO_PAD.encode(signature)))
}

/// `header.claims.signature` signed with RS256.
pub(crate) fn sign_rs256(
    key: &RsaKeyPair,
    header: &Value,
    claims: &Value,
) -> Result<String, String> {
    let input = signing_input(header, claims);
    let mut signature = vec![0; key.public().modulus_len()];
    key.sign(
        &RSA_PKCS1_SHA256,
        &SystemRandom::new(),
        input.as_bytes(),
        &mut signature,
    )
    .map_err(|_| "RS256 signing failed".to_owned())?;
    Ok(format!("{input}.{}", URL_SAFE_NO_PAD.encode(signature)))
}

#[cfg(test)]
pub(crate) mod tests {
    use ring::signature::{KeyPair, UnparsedPublicKey, ECDSA_P256_SHA256_FIXED};
    use serde_json::json;

    use super::*;

    /// A fresh P-256 PKCS#8 key as PEM.
    pub(crate) fn p256_pem() -> String {
        let der =
            EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &SystemRandom::new())
                .unwrap();
        format!(
            "-----BEGIN PRIVATE KEY-----\n{}\n-----END PRIVATE KEY-----\n",
            STANDARD.encode(der.as_ref())
        )
    }

    /// Splits a JWT and decodes its header and claims.
    pub(crate) fn decode(jwt: &str) -> (Value, Value, String, Vec<u8>) {
        let parts: Vec<&str> = jwt.split('.').collect();
        assert_eq!(parts.len(), 3);
        let part = |i: usize| -> Value {
            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(parts[i]).unwrap()).unwrap()
        };
        (
            part(0),
            part(1),
            format!("{}.{}", parts[0], parts[1]),
            URL_SAFE_NO_PAD.decode(parts[2]).unwrap(),
        )
    }

    #[test]
    fn es256_signature_verifies() {
        let key = es256_key(&pem_to_der(&p256_pem()).unwrap()).unwrap();
        let jwt = sign_es256(&key, &json!({"alg": "ES256"}), &json!({"iss": "T"})).unwrap();
        let (header, claims, input, signature) = decode(&jwt);
        assert_eq!(header, json!({"alg": "ES256"}));
        assert_eq!(claims, json!({"iss": "T"}));
        UnparsedPublicKey::new(&ECDSA_P256_SHA256_FIXED, key.public_key().as_ref())
            .verify(input.as_bytes(), &signature)
            .unwrap();
    }

    #[test]
    fn pem_errors() {
        assert!(pem_to_der("nothing").is_err());
        assert!(pem_to_der("-----BEGIN X-----\n!!\n-----END X-----").is_err());
        assert!(es256_key(b"junk").is_err());
        assert!(rs256_key(b"junk").is_err());
    }
}
