//! What the KMS wrappers share: a private key in base64 without an unwiped copy, and a
//! request that is timed, counted and logged the same way for each KMS.

use std::time::Duration;

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use bytes::Bytes;
use http::{Request, StatusCode};
use http_body_util::Full;
use seal_format::PrivateKey;
use zeroize::Zeroizing;

use crate::KeyError;
use crate::https::{Https, PREALLOCATED_BYTES};

/// The most a private key takes in base64, with room to spare.
pub(crate) const KEY_BASE64_BYTES: usize = 128;

/// Appends a private key, in standard base64, to a buffer that must have room for it:
/// the caller sizes the buffer up front, so that it never grows and leaves a copy.
pub(crate) fn push_key_base64(key: &PrivateKey, out: &mut Vec<u8>) -> Result<(), KeyError> {
    let mut encoded = Zeroizing::new([0_u8; KEY_BASE64_BYTES]);
    let length = key
        .expose(|bytes| STANDARD.encode_slice(bytes, encoded.as_mut_slice()))
        .map_err(|_| KeyError::Unavailable)?;
    if out.capacity() - out.len() < length {
        return Err(KeyError::Unavailable);
    }
    out.extend_from_slice(encoded.get(..length).ok_or(KeyError::Unavailable)?);
    Ok(())
}

/// Reads a private key from standard base64.
pub(crate) fn key_from_base64(encoded: &str) -> Result<PrivateKey, KeyError> {
    let mut decoded = Zeroizing::new([0_u8; KEY_BASE64_BYTES]);
    let length = STANDARD
        .decode_slice(encoded.as_bytes(), decoded.as_mut_slice())
        .map_err(|_| KeyError::Unavailable)?;
    PrivateKey::from_bytes(decoded.get(..length).ok_or(KeyError::Unavailable)?)
        .map_err(|_| KeyError::Unavailable)
}

/// What a KMS said when it did not do as asked.
pub(crate) struct Refusal {
    /// The status.
    pub status: StatusCode,
    /// The body, which says why.
    pub body: Zeroizing<Vec<u8>>,
}

/// Sends a request to a KMS and returns the body of a 200, or the refusal. Counts the
/// outcome, and logs a KMS that cannot be reached or does not answer in time; the
/// caller logs a refusal, since each KMS says why in its own way.
///
/// # Errors
///
/// Returns [`KeyError::Unavailable`] if the KMS cannot be reached in time.
pub(crate) async fn exchange(
    https: &Https,
    request: Request<Full<Bytes>>,
    timeout: Duration,
    kms: &'static str,
    operation: &'static str,
) -> Result<Result<Zeroizing<Vec<u8>>, Refusal>, KeyError> {
    let sent = tokio::time::timeout(timeout, https.send(request, PREALLOCATED_BYTES)).await;
    let outcome = match &sent {
        Ok(Ok((StatusCode::OK, _))) => "ok",
        Ok(Ok(_)) => "refused",
        Ok(Err(_)) => "unreachable",
        Err(_) => "timeout",
    };
    metrics::counter!(
        "seal_kms_requests_total",
        "kms" => kms,
        "operation" => operation,
        "outcome" => outcome,
    )
    .increment(1);
    match sent {
        Ok(Ok((StatusCode::OK, body))) => Ok(Ok(body)),
        Ok(Ok((status, body))) => Ok(Err(Refusal { status, body })),
        Ok(Err(error)) => {
            tracing::warn!(kms, operation, "the KMS could not be reached");
            Err(error)
        }
        Err(_) => {
            tracing::warn!(kms, operation, "the KMS did not answer in time");
            Err(KeyError::Unavailable)
        }
    }
}
