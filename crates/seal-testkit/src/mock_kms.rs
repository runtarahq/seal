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

fn aws_error(kind: &str) -> CannedResponse {
    CannedResponse {
        status: 400,
        headers: vec![(
            "content-type".to_owned(),
            "application/x-amz-json-1.1".to_owned(),
        )],
        body: json!({ "__type": kind, "message": "refused by the fake KMS" })
            .to_string()
            .into_bytes(),
    }
}

/// The context of a request, in one canonical form.
fn aws_context(body: &Value) -> String {
    body.get("EncryptionContext")
        .filter(|context| context.is_object())
        .map_or_else(|| "{}".to_owned(), Value::to_string)
}

fn aws_encrypt(body: &Value, key_arn: &str) -> Option<CannedResponse> {
    let plaintext = STANDARD.decode(body.get("Plaintext")?.as_str()?).ok()?;
    let blob = format!(
        "fake.{}.{}",
        URL_SAFE_NO_PAD.encode(aws_context(body)),
        URL_SAFE_NO_PAD.encode(masked(&plaintext)),
    );
    Some(json_response(
        200,
        &json!({
            "CiphertextBlob": STANDARD.encode(blob),
            "KeyId": key_arn,
            "EncryptionAlgorithm": "SYMMETRIC_DEFAULT",
        }),
    ))
}

fn aws_decrypt(body: &Value, key_arn: &str) -> Option<CannedResponse> {
    let blob = STANDARD
        .decode(body.get("CiphertextBlob")?.as_str()?)
        .ok()?;
    let blob = String::from_utf8(blob).ok()?;
    let mut parts = blob.split('.');
    let (Some("fake"), Some(sealed_context), Some(sealed), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return None;
    };
    if URL_SAFE_NO_PAD.decode(sealed_context).ok()? != aws_context(body).as_bytes() {
        return None;
    }
    let plaintext = masked(&URL_SAFE_NO_PAD.decode(sealed).ok()?);
    Some(json_response(
        200,
        &json!({
            "Plaintext": STANDARD.encode(plaintext),
            "KeyId": key_arn,
            "EncryptionAlgorithm": "SYMMETRIC_DEFAULT",
        }),
    ))
}

/// Makes `provider` answer as AWS KMS does for one key: `Encrypt` and `Decrypt`, as
/// `POST /` with the operation in `X-Amz-Target`. A request must be signed with
/// `access_key_id` for the key's region; the signature itself is not checked, which
/// the wrapper's own tests do against the AWS SDK. A ciphertext decrypts only with the
/// encryption context it was encrypted with.
pub fn serve_aws(provider: &MockProvider, key_arn: &str, access_key_id: &str) {
    let region = key_arn.split(':').nth(3).unwrap_or_default();
    let credential = format!("AWS4-HMAC-SHA256 Credential={access_key_id}/");
    let scope = format!("/{region}/kms/aws4_request, SignedHeaders=");
    let key_arn = key_arn.to_owned();
    provider.handle(
        "/",
        Arc::new(move |request: &Received| {
            let authorization = request.header("authorization").unwrap_or_default();
            let signed = authorization.starts_with(&credential)
                && authorization.contains(&scope)
                && authorization.contains("host;x-amz-date")
                && authorization.contains(", Signature=")
                && request.header("x-amz-date").is_some();
            if !signed {
                return aws_error("UnrecognizedClientException");
            }
            if request.method != "POST"
                || request.uri != "/"
                || request.header("content-type") != Some("application/x-amz-json-1.1")
            {
                return aws_error("ValidationException");
            }
            let Ok(body) = serde_json::from_slice::<Value>(&request.body) else {
                return aws_error("SerializationException");
            };
            if body.get("KeyId").and_then(Value::as_str) != Some(key_arn.as_str()) {
                return aws_error("NotFoundException");
            }
            let (answer, failure) = match request.header("x-amz-target") {
                Some("TrentService.Encrypt") => {
                    (aws_encrypt(&body, &key_arn), "ValidationException")
                }
                Some("TrentService.Decrypt") => {
                    (aws_decrypt(&body, &key_arn), "InvalidCiphertextException")
                }
                _ => (None, "UnknownOperationException"),
            };
            answer.unwrap_or_else(|| aws_error(failure))
        }),
    );
}
