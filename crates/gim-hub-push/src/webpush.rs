//! Web Push message encryption (RFC 8291) with the `aes128gcm` content
//! coding (RFC 8188): a single record, record size 4096, keyid = the
//! application server's ephemeral P-256 public key.

use ring::{
    aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_128_GCM},
    agreement::{self, EphemeralPrivateKey, UnparsedPublicKey, ECDH_P256},
    hkdf::{self, KeyType, Salt, HKDF_SHA256},
    rand::{SecureRandom, SystemRandom},
};

/// Length of an uncompressed P-256 public key.
pub const PUBLIC_KEY_LEN: usize = 65;
/// Length of the authentication secret.
pub const AUTH_LEN: usize = 16;
/// Header length: salt (16) + rs (4) + idlen (1) + keyid (65).
pub const HEADER_LEN: usize = 16 + 4 + 1 + PUBLIC_KEY_LEN;
/// Bytes the encryption adds to the plaintext: header, padding delimiter
/// and AEAD tag.
pub const OVERHEAD: usize = HEADER_LEN + 1 + 16;
/// Record size announced in the header.
const RECORD_SIZE: u32 = 4096;
/// Padding delimiter of the last (only) record.
const LAST_RECORD: u8 = 0x02;

/// HKDF output length marker.
struct Len(usize);

impl KeyType for Len {
    fn len(&self) -> usize {
        self.0
    }
}

fn expand(prk: &hkdf::Prk, info: &[&[u8]], len: usize) -> Result<Vec<u8>, String> {
    let mut out = vec![0; len];
    prk.expand(info, Len(len))
        .and_then(|okm| okm.fill(&mut out))
        .map_err(|_| "HKDF expand failed".to_owned())?;
    Ok(out)
}

/// RFC 8291 section 3.4 and RFC 8188 section 2.2: the content encryption
/// key and nonce.
fn derive(
    ecdh_secret: &[u8],
    auth: &[u8],
    ua_public: &[u8],
    as_public: &[u8],
    salt: &[u8],
) -> Result<(LessSafeKey, Nonce), String> {
    let prk_key = Salt::new(HKDF_SHA256, auth).extract(ecdh_secret);
    let ikm = expand(&prk_key, &[b"WebPush: info\0", ua_public, as_public], 32)?;
    let prk = Salt::new(HKDF_SHA256, salt).extract(&ikm);
    let cek = expand(&prk, &[b"Content-Encoding: aes128gcm\0"], 16)?;
    let nonce = expand(&prk, &[b"Content-Encoding: nonce\0"], 12)?;
    let key = UnboundKey::new(&AES_128_GCM, &cek).map_err(|_| "invalid CEK".to_owned())?;
    let nonce = Nonce::try_assume_unique_for_key(&nonce).map_err(|_| "invalid nonce")?;
    Ok((LessSafeKey::new(key), nonce))
}

/// Encrypts `plaintext` for the user agent key `ua_public` (uncompressed
/// P-256 point) and authentication secret `auth`, with a fresh ephemeral
/// key and random salt. Returns the `aes128gcm` body.
pub fn encrypt(ua_public: &[u8], auth: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, String> {
    let rng = SystemRandom::new();
    let mut salt = [0; 16];
    rng.fill(&mut salt).map_err(|_| "no randomness")?;
    let as_private =
        EphemeralPrivateKey::generate(&ECDH_P256, &rng).map_err(|_| "key generation failed")?;
    encrypt_with(ua_public, auth, plaintext, &salt, as_private)
}

/// [`encrypt`] with a given salt and application server key (known-answer
/// tests).
fn encrypt_with(
    ua_public: &[u8],
    auth: &[u8],
    plaintext: &[u8],
    salt: &[u8; 16],
    as_private: EphemeralPrivateKey,
) -> Result<Vec<u8>, String> {
    if ua_public.len() != PUBLIC_KEY_LEN || auth.len() != AUTH_LEN {
        return Err("invalid p256dh or auth length".into());
    }
    if plaintext.len() + 1 + 16 > RECORD_SIZE as usize {
        return Err("plaintext exceeds one record".into());
    }
    let as_public = as_private
        .compute_public_key()
        .map_err(|_| "public key computation failed")?;
    let as_public = as_public.as_ref();
    let ecdh_secret = agreement::agree_ephemeral(
        as_private,
        &UnparsedPublicKey::new(&ECDH_P256, ua_public),
        |secret| secret.to_vec(),
    )
    .map_err(|_| "invalid p256dh key")?;
    let (key, nonce) = derive(&ecdh_secret, auth, ua_public, as_public, salt)?;

    let mut record = Vec::with_capacity(plaintext.len() + 1 + 16);
    record.extend_from_slice(plaintext);
    record.push(LAST_RECORD);
    key.seal_in_place_append_tag(nonce, Aad::empty(), &mut record)
        .map_err(|_| "encryption failed")?;

    let mut body = Vec::with_capacity(HEADER_LEN + record.len());
    body.extend_from_slice(salt);
    body.extend_from_slice(&RECORD_SIZE.to_be_bytes());
    body.push(PUBLIC_KEY_LEN as u8);
    body.extend_from_slice(as_public);
    body.extend_from_slice(&record);
    Ok(body)
}

/// Decrypts a single-record `aes128gcm` body as the user agent holding
/// `ua_private` and `auth` (tests and client reference).
pub fn decrypt(
    ua_private: EphemeralPrivateKey,
    auth: &[u8],
    body: &[u8],
) -> Result<Vec<u8>, String> {
    if body.len() < HEADER_LEN + 1 + 16 || usize::from(body[20]) != PUBLIC_KEY_LEN {
        return Err("malformed header".into());
    }
    let (salt, as_public, record) = (&body[..16], &body[21..HEADER_LEN], &body[HEADER_LEN..]);
    let ua_public = ua_private
        .compute_public_key()
        .map_err(|_| "public key computation failed")?;
    let ua_public = ua_public.as_ref().to_vec();
    let ecdh_secret = agreement::agree_ephemeral(
        ua_private,
        &UnparsedPublicKey::new(&ECDH_P256, as_public),
        |secret| secret.to_vec(),
    )
    .map_err(|_| "invalid keyid")?;
    let (key, nonce) = derive(&ecdh_secret, auth, &ua_public, as_public, salt)?;
    let mut record = record.to_vec();
    let plaintext = key
        .open_in_place(nonce, Aad::empty(), &mut record)
        .map_err(|_| "decryption failed")?;
    let end = plaintext
        .iter()
        .rposition(|&b| b != 0)
        .ok_or("missing padding delimiter")?;
    if plaintext[end] != LAST_RECORD {
        return Err("not a last record".into());
    }
    Ok(plaintext[..end].to_vec())
}

/// Whether `key` is a valid uncompressed P-256 public key.
pub fn is_valid_public_key(key: &[u8]) -> bool {
    if key.len() != PUBLIC_KEY_LEN || key[0] != 0x04 {
        return false;
    }
    let Ok(private) = EphemeralPrivateKey::generate(&ECDH_P256, &SystemRandom::new()) else {
        return false;
    };
    agreement::agree_ephemeral(private, &UnparsedPublicKey::new(&ECDH_P256, key), |_| ()).is_ok()
}

#[cfg(test)]
pub(crate) mod tests {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};

    use super::*;

    pub(crate) fn b64(s: &str) -> Vec<u8> {
        URL_SAFE_NO_PAD.decode(s.replace([' ', '\n'], "")).unwrap()
    }

    /// A P-256 key from fixed private scalar bytes (ring draws the scalar
    /// from the RNG).
    #[allow(deprecated)]
    pub(crate) fn fixed_key(private: &[u8]) -> EphemeralPrivateKey {
        let rng = ring::test::rand::FixedSliceRandom { bytes: private };
        EphemeralPrivateKey::generate(&ECDH_P256, &rng).unwrap()
    }

    // RFC 8291 Appendix A.
    const PLAINTEXT: &str = "V2hlbiBJIGdyb3cgdXAsIEkgd2FudCB0byBiZSBhIHdhdGVybWVsb24";
    const AS_PRIVATE: &str = "yfWPiYE-n46HLnH0KqZOF1fJJU3MYrct3AELtAQ-oRw";
    const UA_PUBLIC: &str = "BCVxsr7N_eNgVRqvHtD0zTZsEc6-VV-JvLexhqUzORcx \
        aOzi6-AYWXvTBHm4bjyPjs7Vd8pZGH6SRpkNtoIAiw4";
    const UA_PRIVATE: &str = "q1dXpw3UpT5VOmu_cf_v6ih07Aems3njxI-JWgLcM94";
    const SALT: &str = "DGv6ra1nlYgDCS1FRnbzlw";
    const AUTH: &str = "BTBZMqHH6r4Tts7J_aSIgg";
    const HEADER: &str = "DGv6ra1nlYgDCS1FRnbzlwAAEABBBP4z 9KsN6nGRTbVYI_c7VJSPQTBtkgcy27ml \
        mlMoZIIgDll6e3vCYLocInmYWAmS6Tlz AC8wEqKK6PBru3jl7A8";
    const CIPHERTEXT: &str = "8pfeW0KbunFT06SuDKoJH9Ql87S1QUrd irN6GcG7sFz1y1sqLgVi1VhjVkHsUoEs \
        bI_0LpXMuGvnzQ";

    /// The RFC's example body: header || ciphertext.
    fn rfc_body() -> Vec<u8> {
        [b64(HEADER), b64(CIPHERTEXT)].concat()
    }

    #[test]
    fn rfc8291_appendix_a_encrypts_byte_for_byte() {
        let salt: [u8; 16] = b64(SALT).try_into().unwrap();
        let body = encrypt_with(
            &b64(UA_PUBLIC),
            &b64(AUTH),
            &b64(PLAINTEXT),
            &salt,
            fixed_key(&b64(AS_PRIVATE)),
        )
        .unwrap();
        assert_eq!(body[..HEADER_LEN], b64(HEADER));
        assert_eq!(body, rfc_body());
        assert_eq!(body.len(), b64(PLAINTEXT).len() + OVERHEAD);
    }

    #[test]
    fn rfc8291_appendix_a_decrypts() {
        let plaintext = decrypt(fixed_key(&b64(UA_PRIVATE)), &b64(AUTH), &rfc_body()).unwrap();
        assert_eq!(plaintext, b64(PLAINTEXT));
        assert!(decrypt(fixed_key(&b64(UA_PRIVATE)), &[0; 16], &rfc_body()).is_err());
    }

    #[test]
    fn encrypt_decrypt_round_trips() {
        let ua_private = EphemeralPrivateKey::generate(&ECDH_P256, &SystemRandom::new()).unwrap();
        let ua_public = ua_private.compute_public_key().unwrap().as_ref().to_vec();
        assert!(is_valid_public_key(&ua_public));
        let auth = [7; AUTH_LEN];
        let body = encrypt(&ua_public, &auth, b"{\"v\":1}").unwrap();
        assert_eq!(&body[16..20], &4096u32.to_be_bytes());
        assert_eq!(decrypt(ua_private, &auth, &body).unwrap(), b"{\"v\":1}");

        let mut off_curve = ua_public.clone();
        off_curve[64] ^= 1;
        assert!(!is_valid_public_key(&off_curve));
        assert!(encrypt(&off_curve, &auth, b"x").is_err());
        assert!(encrypt(&ua_public, &auth[..15], b"x").is_err());
    }
}
