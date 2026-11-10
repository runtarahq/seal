//! Named claims of a sealed JWT, returned in plaintext beside it.
//!
//! A policy may name claims of a response field to expose, such as `exp` or the tenant a
//! token is for. They are read from the token's payload without checking its signature:
//! the token came from the provider, over the connection seal made. The signature is
//! never returned, so the claims are no use as a credential.

use std::collections::BTreeMap;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde_json::value::RawValue;
use serde_json::{Map, Value};
use zeroize::Zeroizing;

/// The largest claim that is exposed, as JSON. A larger one is left out.
pub const MAX_CLAIM_BYTES: usize = 1024;

/// The named claims of a token, as a JSON object, if it is a JWT that has any of them.
///
/// A token that is not a signed JWT with a JSON object as its payload exposes nothing,
/// and that is not an error: providers may issue opaque tokens, and a response already
/// holds tokens that must reach the application sealed.
#[must_use]
pub fn exposed(token: &[u8], names: &[String]) -> Option<String> {
    if names.is_empty() {
        return None;
    }
    let mut parts = token.split(|byte| *byte == b'.');
    let (header, payload, signature) = (parts.next()?, parts.next()?, parts.next()?);
    if parts.next().is_some() || !is_signed(header, signature) {
        return None;
    }
    let payload = Zeroizing::new(URL_SAFE_NO_PAD.decode(payload).ok()?);
    // To a reader built with `arbitrary_precision`, an object with this key is a number
    // written however the token likes, which would let it write claims of its own
    // choosing into what the application reads.
    if crate::inject::mentions_number_token(&payload) {
        return None;
    }
    // Each claim is kept as the token wrote it, so a number keeps its digits.
    let claims: BTreeMap<String, &RawValue> = serde_json::from_slice(&payload).ok()?;
    let mut chosen: BTreeMap<&str, &RawValue> = BTreeMap::new();
    for name in names {
        let Some(value) = claims.get(name) else {
            continue;
        };
        // A claim is passed on only if it reads as JSON in full, which checking the
        // payload as a whole does not quite promise.
        let readable = serde_json::from_str::<serde_json::Value>(value.get()).is_ok();
        if readable && value.get().len() <= MAX_CLAIM_BYTES {
            chosen.insert(name, value);
        }
    }
    if chosen.is_empty() {
        return None;
    }
    serde_json::to_string(&chosen).ok()
}

/// Whether a token's header says it is signed, and it has a signature. The signature
/// itself is not checked, since seal has no key to check it with: this only keeps a
/// token that says it is unsigned from being read as if it were not.
fn is_signed(header: &[u8], signature: &[u8]) -> bool {
    let Ok(header) = URL_SAFE_NO_PAD.decode(header) else {
        return false;
    };
    let Ok(header) = serde_json::from_slice::<Map<String, Value>>(&header) else {
        return false;
    };
    let algorithm = header.get("alg").and_then(Value::as_str);
    !signature.is_empty()
        && algorithm.is_some_and(|alg| !alg.is_empty() && !alg.eq_ignore_ascii_case("none"))
}

#[cfg(test)]
mod tests {
    use serde_json::{Value, json};

    use super::*;

    fn jwt(payload: &[u8]) -> Vec<u8> {
        format!(
            "{}.{}.SIGNATURE",
            URL_SAFE_NO_PAD.encode(br#"{"alg":"RS256"}"#),
            URL_SAFE_NO_PAD.encode(payload)
        )
        .into_bytes()
    }

    fn names(names: &[&str]) -> Vec<String> {
        names.iter().map(|name| (*name).to_owned()).collect()
    }

    fn exposed_json(token: &[u8], claims: &[&str]) -> Option<Value> {
        exposed(token, &names(claims)).map(|json| serde_json::from_str(&json).unwrap())
    }

    #[test]
    fn only_the_named_claims_are_exposed() {
        let token = jwt(
            br#"{"authentication_event_id":"e-1","exp":1700000000,"scope":["a","b"],"sub":"u"}"#,
        );
        assert_eq!(
            exposed_json(
                &token,
                &["authentication_event_id", "exp", "scope", "missing"]
            ),
            Some(json!({
                "authentication_event_id": "e-1", "exp": 1_700_000_000, "scope": ["a", "b"]
            }))
        );
        assert_eq!(exposed_json(&token, &["missing"]), None);
        assert_eq!(exposed_json(&token, &[]), None);
    }

    #[test]
    fn nothing_of_the_token_but_the_claims_is_returned() {
        let token = jwt(br#"{"exp":1,"secret":"PAYLOADCANARY"}"#);
        let json = exposed(&token, &names(&["exp"])).unwrap();
        assert_eq!(json, r#"{"exp":1}"#);
        assert!(!json.contains("SIGNATURE") && !json.contains("PAYLOADCANARY"));
    }

    #[test]
    fn a_token_that_is_not_a_jwt_exposes_nothing() {
        let payload = URL_SAFE_NO_PAD.encode(br#"{"exp":1}"#);
        for token in [
            "opaque-token".to_owned(),
            format!("a.{payload}"),
            format!("a.{payload}.c.d"),
            format!("a.{payload}.c.d.e"),
            format!("a.{payload}=.c"),
            "a.!!!.c".to_owned(),
            format!("a.{}.c", URL_SAFE_NO_PAD.encode(b"[1]")),
            format!("a.{}.c", URL_SAFE_NO_PAD.encode(b"not json")),
            String::new(),
        ] {
            assert_eq!(exposed_json(token.as_bytes(), &["exp"]), None, "{token}");
        }
    }

    #[test]
    fn a_token_that_is_not_signed_exposes_nothing() {
        let payload = URL_SAFE_NO_PAD.encode(br#"{"exp":1}"#);
        let header = |json: &[u8]| URL_SAFE_NO_PAD.encode(json);
        for token in [
            format!("{}.{payload}.sig", header(br#"{"alg":"none"}"#)),
            format!("{}.{payload}.sig", header(br#"{"alg":"NoNe"}"#)),
            format!("{}.{payload}.sig", header(br#"{"alg":""}"#)),
            format!("{}.{payload}.sig", header(br#"{"typ":"JWT"}"#)),
            format!("{}.{payload}.sig", header(br#"{"alg":1}"#)),
            format!("{}.{payload}.sig", header(b"[]")),
            format!("{}.{payload}.", header(br#"{"alg":"RS256"}"#)),
        ] {
            assert_eq!(exposed_json(token.as_bytes(), &["exp"]), None, "{token}");
        }
        let signed = format!(
            "{}.{payload}.sig",
            header(br#"{"alg":"ES256","typ":"JWT"}"#)
        );
        assert_eq!(
            exposed_json(signed.as_bytes(), &["exp"]),
            Some(json!({ "exp": 1 }))
        );
    }

    #[test]
    fn a_claim_over_the_size_limit_is_left_out() {
        let long = "x".repeat(MAX_CLAIM_BYTES);
        let token = jwt(json!({ "big": long, "exp": 1 }).to_string().as_bytes());
        assert_eq!(
            exposed_json(&token, &["big", "exp"]),
            Some(json!({ "exp": 1 }))
        );
    }

    /// With `arbitrary_precision` such an object would be written out as a number of
    /// the token's choosing: here, further claims.
    #[test]
    fn a_token_cannot_write_claims_through_the_number_token() {
        let token = jwt(br#"{"exp":{"$serde_json::private::Number":"1,\"tenant\":\"other\""}}"#);
        assert_eq!(exposed(&token, &names(&["exp"])), None);
    }

    /// A claim that passes as JSON only loosely, here half of a surrogate pair, is left
    /// out, and the others are still exposed.
    #[test]
    fn a_claim_that_does_not_read_as_json_in_full_is_left_out() {
        let token = jwt(br#"{"tenant":"\ud800","exp":1,"other":"\ud800"}"#);
        assert_eq!(
            exposed(&token, &names(&["tenant", "exp"])).unwrap(),
            r#"{"exp":1}"#
        );
    }

    /// A claim is exposed as the token wrote it.
    #[test]
    fn a_claim_is_exposed_as_written() {
        let token = jwt(br#"{"scope": [ "a" , "b" ], "amount":1.50}"#);
        assert_eq!(
            exposed(&token, &names(&["scope", "amount"])).unwrap(),
            r#"{"amount":1.50,"scope":[ "a" , "b" ]}"#
        );
    }

    #[test]
    fn numbers_keep_their_digits() {
        let token = jwt(br#"{"exp":17000000000000000000000.5}"#);
        assert_eq!(
            exposed(&token, &names(&["exp"])).unwrap(),
            r#"{"exp":17000000000000000000000.5}"#
        );
    }
}
