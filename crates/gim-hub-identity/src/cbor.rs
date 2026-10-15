//! Strict deterministic CBOR decoding for the signed identity formats.

use ciborium::Value;

use ed25519_dalek::VerifyingKey;

use crate::{parse_public_key, IdentityError, FORMAT_VERSION};

fn malformed(reason: impl Into<String>) -> IdentityError {
    IdentityError::Malformed(reason.into())
}

pub(crate) fn encode(value: &Value) -> Vec<u8> {
    let mut out = Vec::new();
    ciborium::into_writer(value, &mut out).expect("writing CBOR to a Vec cannot fail");
    out
}

/// Decodes one data item. `bytes` must be exactly its deterministic
/// encoding: definite lengths, shortest heads, no trailing bytes. ciborium
/// always writes that form, so a re-encoding must reproduce the input;
/// otherwise the input is [`IdentityError::NonCanonical`].
pub(crate) fn decode(bytes: &[u8]) -> Result<Value, IdentityError> {
    let value: Value = ciborium::from_reader(bytes).map_err(|e| malformed(e.to_string()))?;
    if encode(&value) != bytes {
        return Err(IdentityError::NonCanonical);
    }
    Ok(value)
}

/// Encodes `[tbs: bstr, sig: bstr .size 64]`.
pub(crate) fn encode_signed(tbs: &[u8], sig: &[u8; 64]) -> Vec<u8> {
    encode(&Value::Array(vec![
        Value::Bytes(tbs.to_vec()),
        Value::Bytes(sig.to_vec()),
    ]))
}

/// Decodes `[tbs: bstr, sig: bstr .size 64]`.
pub(crate) fn decode_signed(bytes: &[u8]) -> Result<(Vec<u8>, [u8; 64]), IdentityError> {
    let [tbs, sig] = array(decode(bytes)?)?;
    Ok((byte_string(tbs)?, sized(sig, "signature")?))
}

/// Decodes a body: an array whose first item is [`FORMAT_VERSION`] (checked
/// before the length) and that has exactly `N` items.
pub(crate) fn decode_body<const N: usize>(tbs: &[u8]) -> Result<[Value; N], IdentityError> {
    body(decode(tbs)?)
}

/// [`decode_body`] for an already decoded item.
pub(crate) fn body<const N: usize>(value: Value) -> Result<[Value; N], IdentityError> {
    let Value::Array(items) = value else {
        return Err(malformed("body is not an array"));
    };
    let version = uint(
        items
            .first()
            .cloned()
            .ok_or_else(|| malformed("empty body"))?,
    )?;
    if version != FORMAT_VERSION {
        return Err(IdentityError::UnsupportedVersion(version));
    }
    array(Value::Array(items))
}

pub(crate) fn array<const N: usize>(value: Value) -> Result<[Value; N], IdentityError> {
    list(value)?
        .try_into()
        .map_err(|_| malformed(format!("expected an array of {N} items")))
}

/// Element `index` of a decoded array, before the version and length are
/// checked: reads an embedded key ahead of the signature check.
pub(crate) fn item(value: &Value, index: usize) -> Result<Value, IdentityError> {
    match value {
        Value::Array(items) => items
            .get(index)
            .cloned()
            .ok_or_else(|| malformed("array too short")),
        _ => Err(malformed("body is not an array")),
    }
}

pub(crate) fn list(value: Value) -> Result<Vec<Value>, IdentityError> {
    match value {
        Value::Array(items) => Ok(items),
        _ => Err(malformed("expected an array")),
    }
}

pub(crate) fn uint(value: Value) -> Result<u64, IdentityError> {
    match value {
        Value::Integer(int) => u64::try_from(int).map_err(|_| malformed("expected a uint")),
        _ => Err(malformed("expected a uint")),
    }
}

pub(crate) fn text(value: Value) -> Result<String, IdentityError> {
    match value {
        Value::Text(text) => Ok(text),
        _ => Err(malformed("expected a text string")),
    }
}

pub(crate) fn byte_string(value: Value) -> Result<Vec<u8>, IdentityError> {
    match value {
        Value::Bytes(bytes) => Ok(bytes),
        _ => Err(malformed("expected a byte string")),
    }
}

/// Decodes a `bstr .size 32` public key: a wrong size is malformed input,
/// an invalid point [`IdentityError::InvalidKey`].
pub(crate) fn public_key(value: Value) -> Result<VerifyingKey, IdentityError> {
    parse_public_key(&sized::<32>(value, "public key")?)
}

/// Decodes a `bstr .size N`.
pub(crate) fn sized<const N: usize>(value: Value, what: &str) -> Result<[u8; N], IdentityError> {
    byte_string(value)?
        .try_into()
        .map_err(|_| malformed(format!("{what} is not {N} bytes")))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn one() -> Value {
        Value::Integer(1.into())
    }

    #[test]
    fn rejects_non_deterministic_input() {
        let non_canonical = |bytes: &[u8]| decode(bytes) == Err(IdentityError::NonCanonical);
        // uint 1 with a one-byte argument.
        assert!(non_canonical(&[0x18, 0x01]));
        // Indefinite-length array.
        assert!(non_canonical(&[0x9f, 0x01, 0xff]));
        // Indefinite-length byte string.
        assert!(non_canonical(&[0x5f, 0x41, 0x00, 0xff]));
        // Trailing byte.
        assert!(non_canonical(&[0x01, 0x01]));
        // Truncated input is malformed, not non-canonical.
        assert!(matches!(
            decode(&[0x82, 0x01]),
            Err(IdentityError::Malformed(_))
        ));
        assert_eq!(
            decode(&[0x82, 0x01, 0x40]).unwrap(),
            Value::Array(vec![one(), Value::Bytes(vec![])])
        );
    }

    #[test]
    fn signed_shape() {
        let signed = |items| encode(&Value::Array(items));
        let tbs = Value::Bytes(vec![1, 2]);
        assert!(decode_signed(&signed(vec![tbs.clone(), Value::Bytes(vec![0; 64])])).is_ok());
        assert!(decode_signed(&signed(vec![tbs.clone(), Value::Bytes(vec![0; 63])])).is_err());
        assert!(decode_signed(&signed(vec![tbs.clone()])).is_err());
        assert!(decode_signed(&signed(vec![Value::Text("x".into()), tbs])).is_err());
    }

    #[test]
    fn body_version_checked_before_length() {
        let body = |items| encode(&Value::Array(items));
        assert_eq!(
            decode_body::<2>(&body(vec![Value::Integer(2.into())])).unwrap_err(),
            IdentityError::UnsupportedVersion(2)
        );
        assert!(matches!(
            decode_body::<2>(&body(vec![one()])),
            Err(IdentityError::Malformed(_))
        ));
        assert!(decode_body::<2>(&body(vec![one(), one()])).is_ok());
        assert!(decode_body::<2>(&body(vec![])).is_err());
    }
}
