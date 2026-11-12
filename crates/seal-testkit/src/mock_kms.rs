//! Stand-ins for a KMS, served by a [`MockProvider`]. They keep no key: a ciphertext
//! is the plaintext and its context, lightly disguised, which is enough to check what
//! seal sends and what it does with the answers.

use std::sync::Arc;

use base64::Engine;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use serde_json::{Value, json};

use crate::mock_provider::{CannedResponse, MockProvider, Received};

/// The byte a fake ciphertext's plaintext is masked with, so that a test can check
/// that a wrapped key does not hold the key as it is.
const MASK: u8 = 0x5a;

fn json_response(status: u16, body: &Value) -> CannedResponse {
    CannedResponse {
        status,
        headers: vec![("content-type".to_owned(), "application/json".to_owned())],
        body: body.to_string().into_bytes(),
    }
}

fn ovh_error(status: u16, code: i64) -> CannedResponse {
    json_response(
        status,
        &json!({
            "error_code": code,
            "error_id": "fake",
            "errors": ["refused by the fake KMS"],
            "request_id": "79b66eba-273e-4f7a-b954-78ed7e70b85d",
        }),
    )
}

fn masked(bytes: &[u8]) -> Vec<u8> {
    bytes.iter().map(|byte| byte ^ MASK).collect()
}

fn ovh_encrypt(request: &Received) -> Option<CannedResponse> {
    let body: Value = serde_json::from_slice(&request.body).ok()?;
    let plaintext = STANDARD.decode(body.get("plaintext")?.as_str()?).ok()?;
    let context = body.get("context").and_then(Value::as_str).unwrap_or("");
    let ciphertext = format!(
        "fake.{}.{}",
        URL_SAFE_NO_PAD.encode(context),
        URL_SAFE_NO_PAD.encode(masked(&plaintext)),
    );
    Some(json_response(200, &json!({ "ciphertext": ciphertext })))
}

fn ovh_decrypt(request: &Received) -> Option<CannedResponse> {
    let body: Value = serde_json::from_slice(&request.body).ok()?;
    let context = body.get("context").and_then(Value::as_str).unwrap_or("");
    let mut parts = body.get("ciphertext")?.as_str()?.split('.');
    let (Some("fake"), Some(sealed_context), Some(sealed), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return None;
    };
    if URL_SAFE_NO_PAD.decode(sealed_context).ok()? != context.as_bytes() {
        return None;
    }
    let plaintext = masked(&URL_SAFE_NO_PAD.decode(sealed).ok()?);
    Some(json_response(
        200,
        &json!({ "plaintext": STANDARD.encode(plaintext) }),
    ))
}

/// Makes `provider` answer as OVHcloud KMS does for one service key: `encrypt` and
/// `decrypt` under `/api/<okms id>/v1/servicekey/<key id>/`. With `token`, a request
/// must carry it as a bearer token. A ciphertext decrypts only with the context it was
/// encrypted with; anything else is a 400 with the KMS's error body.
pub fn serve_ovh(provider: &MockProvider, okms_id: &str, key_id: &str, token: Option<&str>) {
    let prefix = format!("/api/{okms_id}/v1/servicekey/{key_id}/");
    let authorization = token.map(|token| format!("Bearer {token}"));
    let handler_prefix = prefix.clone();
    provider.handle(
        &prefix,
        Arc::new(move |request: &Received| {
            if request.method != "POST" {
                return ovh_error(405, 1);
            }
            if let Some(expected) = &authorization
                && request.header("authorization") != Some(expected.as_str())
            {
                return ovh_error(401, 2);
            }
            let path = request.uri.split('?').next().unwrap_or_default();
            let answer = match path.strip_prefix(handler_prefix.as_str()) {
                Some("encrypt") => ovh_encrypt(request),
                Some("decrypt") => ovh_decrypt(request),
                _ => return ovh_error(404, 3),
            };
            answer.unwrap_or_else(|| ovh_error(400, 4))
        }),
    );
}
