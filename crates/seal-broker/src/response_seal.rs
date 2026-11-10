//! Replaces declared fields of a buffered response with sealed values.
//!
//! Only the declared fields at their declared locations are sealed. Anything that
//! prevents finding them for certain refuses the response, because passing it through
//! would hand a token to the caller.

use std::collections::BTreeMap;

use http::HeaderMap;
use http::header;
use seal_format::policy::{ResponseFormat, SealResponse, SealedField};
use seal_format::{Envelope, FieldName};
use serde_json::Value;
use zeroize::{Zeroize, Zeroizing};

use crate::error::{BrokerError, ErrorCode};
use crate::inject::{is_form, is_json, media_type_is};

/// A response with its fields sealed.
#[derive(Debug, PartialEq, Eq)]
pub struct SealedResponse {
    /// The new body.
    pub body: Vec<u8>,
    /// Each sealed value, by its new field name.
    pub fields: BTreeMap<FieldName, Envelope>,
}

/// Seals the declared fields of a response.
///
/// `seal_field` seals one field's plaintext into an envelope.
///
/// # Errors
///
/// Returns [`ErrorCode::ResponseUnparseable`] if the response is compressed, has the
/// wrong content type or cannot be parsed, or a field is not a string or repeats. The
/// error never includes any of the response.
pub fn seal_response_fields(
    sealing: &SealResponse,
    headers: &HeaderMap,
    body: &[u8],
    mut seal_field: impl FnMut(&SealedField, &[u8]) -> Result<Envelope, BrokerError>,
) -> Result<SealedResponse, BrokerError> {
    let refuse = |detail| BrokerError::new(ErrorCode::ResponseUnparseable, detail);
    if let Some(encoding) = headers.get(header::CONTENT_ENCODING)
        && !encoding.as_bytes().eq_ignore_ascii_case(b"identity")
    {
        return Err(refuse("a compressed response cannot be sealed"));
    }
    // An empty body holds no tokens, whatever its type: a 204 or a 304.
    if body.is_empty() {
        return Ok(SealedResponse {
            body: Vec::new(),
            fields: BTreeMap::new(),
        });
    }
    match sealing.format {
        ResponseFormat::Json => {
            if !media_type_is(headers, is_json) {
                return Err(refuse("the response's content type is not JSON"));
            }
            seal_json(sealing, body, &mut seal_field)
        }
        ResponseFormat::Form => {
            if !media_type_is(headers, is_form) {
                return Err(refuse("the response's content type is not a form"));
            }
            seal_form(sealing, body, &mut seal_field)
        }
        ResponseFormat::Xml => {
            if !media_type_is(headers, is_xml) {
                return Err(refuse("the response's content type is not XML"));
            }
            seal_xml(sealing, body, &mut seal_field)
        }
    }
}

/// Whether a media type means XML.
#[must_use]
pub fn is_xml(media_type: &str) -> bool {
    matches!(media_type, "application/xml" | "text/xml")
        || (media_type.starts_with("application/") && media_type.ends_with("+xml"))
}

/// One element to seal: where its content starts and ends, and its text.
struct XmlTarget<'f> {
    field: &'f SealedField,
    content_start: usize,
    text: Zeroizing<String>,
}

/// Seals elements found by their path from the root, such as
/// `AssumeRoleResponse/AssumeRoleResult/Credentials/SecretAccessKey`, by element
/// names as written. Everything outside the sealed elements' content is copied byte
/// for byte. A document type declaration, a field that repeats or holds markup, or a
/// reference other than a character or predefined entity refuses the response.
fn seal_xml(
    sealing: &SealResponse,
    body: &[u8],
    seal_field: &mut impl FnMut(&SealedField, &[u8]) -> Result<Envelope, BrokerError>,
) -> Result<SealedResponse, BrokerError> {
    use quick_xml::events::Event;

    let refuse = |detail| BrokerError::new(ErrorCode::ResponseUnparseable, detail);
    let text = std::str::from_utf8(body).map_err(|_| refuse("the response is not valid UTF-8"))?;
    // The reader skips a byte order mark and counts positions after it, so seal skips
    // it itself and adds it back to every position.
    let (offset, text) = match text.strip_prefix('\u{feff}') {
        Some(rest) => (3, rest),
        None => (0, text),
    };
    if text.starts_with('\u{feff}') {
        return Err(refuse("the response has two byte order marks"));
    }
    let mut reader = quick_xml::Reader::from_str(text);
    reader.config_mut().check_end_names = true;
    reader.config_mut().trim_text(false);

    let mut path: Vec<String> = Vec::new();
    let mut target: Option<XmlTarget<'_>> = None;
    let mut seen: Vec<&FieldName> = Vec::new();
    // Each sealed element's content range, and what replaces it.
    let mut replacements: Vec<(usize, usize, String)> = Vec::new();
    let mut fields = BTreeMap::new();
    let position = |reader: &quick_xml::Reader<&[u8]>| {
        usize::try_from(reader.buffer_position())
            .unwrap_or(usize::MAX)
            .saturating_add(offset)
    };

    loop {
        let before = position(&reader);
        let event = reader
            .read_event()
            .map_err(|_| refuse("the response is not well-formed XML"))?;
        match event {
            Event::Eof => break,
            Event::DocType(_) => return Err(refuse("a document type declaration is refused")),
            Event::Start(start) => {
                if target.is_some() {
                    return Err(refuse("a sealed response field holds markup"));
                }
                let name = start.name().as_ref().to_owned();
                path.push(name);
                let joined = path.join("/");
                if let Some(field) = sealing.fields.iter().find(|field| field.at == joined) {
                    if seen.contains(&&field.as_field) {
                        return Err(refuse("a sealed response field repeats"));
                    }
                    seen.push(&field.as_field);
                    // Room for the rest of the body, so the text never grows: a growing
                    // buffer would leave copies of the token behind.
                    let content_start = position(&reader);
                    target = Some(XmlTarget {
                        field,
                        content_start,
                        text: Zeroizing::new(String::with_capacity(
                            body.len().saturating_sub(content_start),
                        )),
                    });
                }
            }
            Event::Empty(start) => {
                if target.is_some() {
                    return Err(refuse("a sealed response field holds markup"));
                }
                // An empty field holds nothing to seal, but it still counts once.
                let qname = start.name();
                let name: &str = qname.as_ref();
                let joined = format!(
                    "{}{}{name}",
                    path.join("/"),
                    if path.is_empty() { "" } else { "/" }
                );
                if let Some(field) = sealing.fields.iter().find(|field| field.at == joined) {
                    if seen.contains(&&field.as_field) {
                        return Err(refuse("a sealed response field repeats"));
                    }
                    seen.push(&field.as_field);
                }
            }
            Event::End(_) => {
                if let Some(XmlTarget {
                    field,
                    content_start,
                    text,
                }) = target.take()
                {
                    let envelope = seal_field(field, text.as_bytes())?;
                    let json = envelope.to_json().map_err(|_| {
                        BrokerError::new(ErrorCode::Internal, "could not write an envelope")
                    })?;
                    replacements.push((
                        content_start,
                        before,
                        quick_xml::escape::escape(json).into_owned(),
                    ));
                    fields.insert(field.as_field.clone(), envelope);
                }
                path.pop();
            }
            Event::Text(content) => {
                if let Some(target) = &mut target {
                    target.text.push_str(&content);
                }
            }
            Event::CData(content) => {
                if let Some(target) = &mut target {
                    target.text.push_str(&content);
                }
            }
            Event::GeneralRef(reference) => {
                if let Some(target) = &mut target {
                    if reference.is_char_ref() {
                        let character = reference
                            .resolve_char_ref()
                            .ok()
                            .flatten()
                            .ok_or_else(|| refuse("a character reference is not valid"))?;
                        target.text.push(character);
                    } else {
                        let resolved = quick_xml::escape::resolve_predefined_entity(&reference)
                            .ok_or_else(|| refuse("an entity reference is refused"))?;
                        target.text.push_str(resolved);
                    }
                }
            }
            Event::Comment(_) | Event::Decl(_) | Event::PI(_) => {}
        }
    }
    if target.is_some() || !path.is_empty() {
        return Err(refuse("the response is not well-formed XML"));
    }

    // Each replaced range must be exactly an element's content: after the start tag's
    // `>` and up to the end tag's `</`. Anything else would leave part of a token behind.
    let exactly_content = replacements.iter().all(|(start, end, _)| {
        start <= end
            && start.checked_sub(1).and_then(|before| body.get(before)) == Some(&b'>')
            && body.get(*end..).is_some_and(|rest| rest.starts_with(b"</"))
    });
    if !exactly_content {
        return Err(refuse(
            "a sealed response field could not be located exactly",
        ));
    }
    let mut out = Vec::with_capacity(body.len());
    let mut copied = 0;
    for (start, end, replacement) in replacements {
        out.extend_from_slice(&body[copied..start]);
        out.extend_from_slice(replacement.as_bytes());
        copied = end;
    }
    out.extend_from_slice(&body[copied..]);
    Ok(SealedResponse { body: out, fields })
}

fn seal_json(
    sealing: &SealResponse,
    body: &[u8],
    seal_field: &mut impl FnMut(&SealedField, &[u8]) -> Result<Envelope, BrokerError>,
) -> Result<SealedResponse, BrokerError> {
    let refuse = |detail| BrokerError::new(ErrorCode::ResponseUnparseable, detail);
    let mut document: Value =
        serde_json::from_slice(body).map_err(|_| refuse("the response is not valid JSON"))?;
    if crate::inject::mentions_number_token(body) {
        return Err(refuse("the response has a key seal cannot pass on"));
    }
    let mut fields = BTreeMap::new();
    for field in &sealing.fields {
        let Some(location) = document.pointer_mut(&field.at) else {
            continue;
        };
        let Value::String(plaintext) = location else {
            return Err(refuse("a sealed response field is not a string"));
        };
        let mut plaintext = Zeroizing::new(std::mem::take(plaintext));
        let envelope = seal_field(field, plaintext.as_bytes())?;
        plaintext.zeroize();
        *location = serde_json::to_value(&envelope)
            .map_err(|_| BrokerError::new(ErrorCode::Internal, "could not write an envelope"))?;
        fields.insert(field.as_field.clone(), envelope);
    }
    let body = serde_json::to_vec(&document)
        .map_err(|_| BrokerError::new(ErrorCode::Internal, "could not write the response"))?;
    Ok(SealedResponse { body, fields })
}

fn seal_form(
    sealing: &SealResponse,
    body: &[u8],
    seal_field: &mut impl FnMut(&SealedField, &[u8]) -> Result<Envelope, BrokerError>,
) -> Result<SealedResponse, BrokerError> {
    let refuse = |detail| BrokerError::new(ErrorCode::ResponseUnparseable, detail);
    if std::str::from_utf8(body).is_err() {
        return Err(refuse("the response is not valid UTF-8"));
    }
    let pairs: Vec<(Zeroizing<String>, Zeroizing<String>)> = form_urlencoded::parse(body)
        .map(|(key, value)| {
            (
                Zeroizing::new(key.into_owned()),
                Zeroizing::new(value.into_owned()),
            )
        })
        .collect();
    let mut fields = BTreeMap::new();
    let mut serializer = form_urlencoded::Serializer::new(String::new());
    for field in &sealing.fields {
        let occurrences = pairs.iter().filter(|(key, _)| **key == field.at).count();
        if occurrences > 1 {
            return Err(refuse("a sealed response field repeats"));
        }
    }
    for (key, value) in &pairs {
        match sealing.fields.iter().find(|field| field.at == **key) {
            Some(field) => {
                let envelope = seal_field(field, value.as_bytes())?;
                serializer.append_pair(
                    key,
                    &envelope.to_json().map_err(|_| {
                        BrokerError::new(ErrorCode::Internal, "could not write an envelope")
                    })?,
                );
                fields.insert(field.as_field.clone(), envelope);
            }
            None => {
                serializer.append_pair(key, value);
            }
        }
    }
    Ok(SealedResponse {
        body: serializer.finish().into_bytes(),
        fields,
    })
}

#[cfg(test)]
mod tests {
    use http::HeaderValue;
    use seal_format::id::KeyId;
    use seal_format::policy::builder;
    use seal_format::{Binding, ItemId, KeysetId, PolicyName, PrivateKey, PublicKey, seal};
    use serde_json::json;

    use super::*;

    fn sealing(format: ResponseFormat, ats: &[(&str, &str)]) -> SealResponse {
        SealResponse {
            format,
            fields: ats
                .iter()
                .map(|(at, name)| SealedField {
                    at: (*at).to_owned(),
                    as_field: FieldName::new(*name).unwrap(),
                    policy: PolicyName::new("api").unwrap(),
                    expose_claims: Vec::new(),
                })
                .collect(),
        }
    }

    fn headers(content_type: &str) -> HeaderMap {
        let mut map = HeaderMap::new();
        map.insert(
            header::CONTENT_TYPE,
            HeaderValue::from_str(content_type).unwrap(),
        );
        map
    }

    fn sealer(
        public: &PublicKey,
    ) -> impl FnMut(&SealedField, &[u8]) -> Result<Envelope, BrokerError> {
        let public = *public;
        move |field, plaintext| {
            let (keyset, item) = (KeysetId::new("acme").unwrap(), ItemId::new("c_1").unwrap());
            let binding = Binding {
                keyset: &keyset,
                item: &item,
                field: &field.as_field,
            };
            let policy = builder::bearer("https://api.example.com/").unwrap();
            seal(
                &public,
                &KeyId::new("k1").unwrap(),
                binding,
                plaintext,
                &policy,
            )
            .map_err(|_| BrokerError::new(ErrorCode::Internal, "sealing failed"))
        }
    }

    fn opened(private: &PrivateKey, envelope: &Envelope, name: &str) -> Vec<u8> {
        let (keyset, item, field) = (
            KeysetId::new("acme").unwrap(),
            ItemId::new("c_1").unwrap(),
            FieldName::new(name).unwrap(),
        );
        seal_format::open(
            private,
            envelope,
            Binding {
                keyset: &keyset,
                item: &item,
                field: &field,
            },
        )
        .unwrap()
        .secret
        .expose(<[u8]>::to_vec)
    }

    #[test]
    fn json_fields_are_replaced_by_envelopes_and_open() {
        let (private, public) = PrivateKey::generate();
        let body = br#"{"access_token":"at-secret","refresh_token":"rt-secret","expires_in":3600}"#;
        let spec = sealing(
            ResponseFormat::Json,
            &[
                ("/access_token", "access_token"),
                ("/refresh_token", "refresh_token"),
            ],
        );
        let sealed =
            seal_response_fields(&spec, &headers("application/json"), body, sealer(&public))
                .unwrap();

        let text = String::from_utf8(sealed.body.clone()).unwrap();
        assert!(
            !text.contains("at-secret") && !text.contains("rt-secret"),
            "{text}"
        );
        let value: Value = serde_json::from_slice(&sealed.body).unwrap();
        assert_eq!(value["expires_in"], 3600);
        let envelope = Envelope::from_json(value["access_token"].to_string().as_bytes()).unwrap();
        assert_eq!(opened(&private, &envelope, "access_token"), b"at-secret");
        let named = &sealed.fields[&FieldName::new("refresh_token").unwrap()];
        assert_eq!(opened(&private, named, "refresh_token"), b"rt-secret");
    }

    #[test]
    fn a_nested_json_field_is_found() {
        let (private, public) = PrivateKey::generate();
        let spec = sealing(ResponseFormat::Json, &[("/data/0/token", "token")]);
        let body = br#"{"data":[{"token":"t"}]}"#;
        let sealed =
            seal_response_fields(&spec, &headers("application/json"), body, sealer(&public))
                .unwrap();
        assert_eq!(
            opened(
                &private,
                &sealed.fields[&FieldName::new("token").unwrap()],
                "token"
            ),
            b"t"
        );
    }

    #[test]
    fn an_absent_field_is_fine() {
        let (_, public) = PrivateKey::generate();
        let spec = sealing(ResponseFormat::Json, &[("/access_token", "access_token")]);
        let body = br#"{"error":"invalid_grant"}"#;
        let sealed =
            seal_response_fields(&spec, &headers("application/json"), body, sealer(&public))
                .unwrap();
        assert!(sealed.fields.is_empty());
        assert_eq!(
            serde_json::from_slice::<Value>(&sealed.body).unwrap(),
            json!({ "error": "invalid_grant" })
        );
    }

    #[test]
    fn a_duplicated_json_key_cannot_smuggle_a_token_past_sealing() {
        let (_, public) = PrivateKey::generate();
        let spec = sealing(ResponseFormat::Json, &[("/access_token", "access_token")]);
        let body = br#"{"access_token":"first-secret","access_token":"second-secret"}"#;
        let sealed =
            seal_response_fields(&spec, &headers("application/json"), body, sealer(&public))
                .unwrap();
        let text = String::from_utf8(sealed.body).unwrap();
        assert!(
            !text.contains("first-secret") && !text.contains("second-secret"),
            "{text}"
        );
    }

    #[test]
    fn an_escaped_json_key_is_found_as_the_same_key() {
        let (_, public) = PrivateKey::generate();
        let spec = sealing(ResponseFormat::Json, &[("/access_token", "access_token")]);
        let body = br#"{"access_token":"the-secret"}"#;
        let sealed =
            seal_response_fields(&spec, &headers("application/json"), body, sealer(&public))
                .unwrap();
        assert_eq!(sealed.fields.len(), 1);
        assert!(
            !String::from_utf8(sealed.body)
                .unwrap()
                .contains("the-secret")
        );
    }

    #[test]
    fn a_field_that_is_not_a_string_is_refused() {
        let (_, public) = PrivateKey::generate();
        let spec = sealing(ResponseFormat::Json, &[("/token", "token")]);
        for body in [
            &br#"{"token":1}"#[..],
            br#"{"token":{"a":"b"}}"#,
            br#"{"token":["x"]}"#,
            br#"{"token":null}"#,
        ] {
            let error =
                seal_response_fields(&spec, &headers("application/json"), body, sealer(&public))
                    .unwrap_err();
            assert_eq!(error.code(), ErrorCode::ResponseUnparseable);
        }
    }

    #[test]
    fn what_is_undeclared_passes_through_which_marks_the_guarantees_boundary() {
        let (_, public) = PrivateKey::generate();
        let spec = sealing(ResponseFormat::Json, &[("/access_token", "access_token")]);
        let body = br#"{"access_token":"same-value","debug":"same-value"}"#;
        let sealed =
            seal_response_fields(&spec, &headers("application/json"), body, sealer(&public))
                .unwrap();
        let value: Value = serde_json::from_slice(&sealed.body).unwrap();
        assert_eq!(value["debug"], "same-value");
        assert!(value["access_token"].is_object());
    }

    #[test]
    fn numbers_keep_their_precision() {
        let (_, public) = PrivateKey::generate();
        let spec = sealing(ResponseFormat::Json, &[("/t", "t")]);
        let body = br#"{"t":"x","big":12345678901234567890123}"#;
        let sealed =
            seal_response_fields(&spec, &headers("application/json"), body, sealer(&public))
                .unwrap();
        assert!(
            String::from_utf8(sealed.body)
                .unwrap()
                .contains("12345678901234567890123")
        );
    }

    #[test]
    fn form_fields_are_replaced_and_others_kept() {
        let (private, public) = PrivateKey::generate();
        let spec = sealing(ResponseFormat::Form, &[("access_token", "access_token")]);
        let body = b"access_token=gh-secret&scope=repo%20user&token_type=bearer";
        let sealed = seal_response_fields(
            &spec,
            &headers("application/x-www-form-urlencoded"),
            body,
            sealer(&public),
        )
        .unwrap();
        let text = String::from_utf8(sealed.body.clone()).unwrap();
        assert!(!text.contains("gh-secret"));
        let pairs: BTreeMap<String, String> =
            form_urlencoded::parse(&sealed.body).into_owned().collect();
        assert_eq!(pairs["scope"], "repo user");
        assert_eq!(pairs["token_type"], "bearer");
        let envelope = Envelope::from_json(pairs["access_token"].as_bytes()).unwrap();
        assert_eq!(opened(&private, &envelope, "access_token"), b"gh-secret");
    }

    #[test]
    fn a_form_key_is_compared_decoded() {
        let (_, public) = PrivateKey::generate();
        let spec = sealing(ResponseFormat::Form, &[("access_token", "access_token")]);
        let body = b"access%5Ftoken=the-secret";
        let sealed = seal_response_fields(
            &spec,
            &headers("application/x-www-form-urlencoded"),
            body,
            sealer(&public),
        )
        .unwrap();
        assert_eq!(sealed.fields.len(), 1);
        assert!(
            !String::from_utf8(sealed.body)
                .unwrap()
                .contains("the-secret")
        );
    }

    #[test]
    fn a_repeated_form_field_is_refused() {
        let (_, public) = PrivateKey::generate();
        let spec = sealing(ResponseFormat::Form, &[("access_token", "access_token")]);
        let error = seal_response_fields(
            &spec,
            &headers("application/x-www-form-urlencoded"),
            b"access_token=a&access_token=b",
            sealer(&public),
        )
        .unwrap_err();
        assert_eq!(error.code(), ErrorCode::ResponseUnparseable);
    }

    #[test]
    fn the_wrong_content_type_or_a_bad_body_is_refused_rather_than_passed_through() {
        let (_, public) = PrivateKey::generate();
        let json_spec = sealing(ResponseFormat::Json, &[("/t", "t")]);
        let form_spec = sealing(ResponseFormat::Form, &[("t", "t")]);
        let cases: Vec<(&SealResponse, HeaderMap, &[u8])> = vec![
            (&json_spec, headers("text/html"), b"{\"t\":\"secret\"}"),
            (
                &json_spec,
                headers("application/x-www-form-urlencoded"),
                b"t=secret",
            ),
            (&json_spec, HeaderMap::new(), b"{\"t\":\"secret\"}"),
            (&json_spec, headers("application/json"), b"not json secret"),
            (
                &form_spec,
                headers("application/json"),
                b"{\"t\":\"secret\"}",
            ),
            (
                &form_spec,
                headers("application/x-www-form-urlencoded"),
                b"t=\xff",
            ),
        ];
        for (spec, map, body) in cases {
            let error = seal_response_fields(spec, &map, body, sealer(&public)).unwrap_err();
            assert_eq!(error.code(), ErrorCode::ResponseUnparseable);
            assert!(!error.to_string().contains("secret"));
        }
    }

    #[test]
    fn a_compressed_response_is_refused() {
        let (_, public) = PrivateKey::generate();
        let spec = sealing(ResponseFormat::Json, &[("/t", "t")]);
        let mut map = headers("application/json");
        map.insert(header::CONTENT_ENCODING, HeaderValue::from_static("gzip"));
        let error = seal_response_fields(&spec, &map, b"x", sealer(&public)).unwrap_err();
        assert_eq!(error.code(), ErrorCode::ResponseUnparseable);
        map.insert(
            header::CONTENT_ENCODING,
            HeaderValue::from_static("identity"),
        );
        seal_response_fields(&spec, &map, b"{}", sealer(&public)).unwrap();
    }

    #[test]
    fn an_empty_body_passes_whatever_its_type() {
        let (_, public) = PrivateKey::generate();
        let spec = sealing(ResponseFormat::Json, &[("/t", "t")]);
        let sealed = seal_response_fields(&spec, &HeaderMap::new(), b"", sealer(&public)).unwrap();
        assert!(sealed.body.is_empty() && sealed.fields.is_empty());
    }

    /// An STS AssumeRole response, as AWS documents it.
    const ASSUME_ROLE: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<AssumeRoleResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">
  <AssumeRoleResult>
    <SourceIdentity>DevUser123</SourceIdentity>
    <AssumedRoleUser>
      <Arn>arn:aws:sts::123456789012:assumed-role/demo/John</Arn>
      <AssumedRoleId>ARO123EXAMPLE123:John</AssumedRoleId>
    </AssumedRoleUser>
    <Credentials>
      <AccessKeyId>ASIAIOSFODNN7EXAMPLE</AccessKeyId>
      <SecretAccessKey>wJalrXUtnFEMI/K7MDENG/bPxRfiCYzEXAMPLEKEY</SecretAccessKey>
      <SessionToken>AQoDYXdzEPT//////////wEXAMPLEtc764&amp;b+&#47;=</SessionToken>
      <Expiration>2019-11-09T13:34:41Z</Expiration>
    </Credentials>
    <PackedPolicySize>6</PackedPolicySize>
  </AssumeRoleResult>
  <ResponseMetadata>
    <RequestId>c6104cbe-af31-11e0-8154-cbc7ccf896c7</RequestId>
  </ResponseMetadata>
</AssumeRoleResponse>
"#;

    const CREDENTIALS: &str = "AssumeRoleResponse/AssumeRoleResult/Credentials";

    fn sts_sealing() -> SealResponse {
        sealing(
            ResponseFormat::Xml,
            &[
                (
                    &format!("{CREDENTIALS}/SecretAccessKey"),
                    "secret_access_key",
                ),
                (&format!("{CREDENTIALS}/SessionToken"), "session_token"),
            ],
        )
    }

    fn seal_xml_text(spec: &SealResponse, body: &str) -> Result<SealedResponse, BrokerError> {
        let (_, public) = PrivateKey::generate();
        seal_response_fields(spec, &headers("text/xml"), body.as_bytes(), sealer(&public))
    }

    #[test]
    fn sts_credentials_are_sealed_and_the_rest_is_unchanged() {
        let (private, public) = PrivateKey::generate();
        let sealed = seal_response_fields(
            &sts_sealing(),
            &headers("text/xml; charset=utf-8"),
            ASSUME_ROLE.as_bytes(),
            sealer(&public),
        )
        .unwrap();
        let text = String::from_utf8(sealed.body.clone()).unwrap();
        assert!(
            !text.contains("wJalrXUtnFEMI") && !text.contains("AQoDYXdz"),
            "{text}"
        );

        // Only the two elements' content changed.
        let secret = &sealed.fields[&FieldName::new("secret_access_key").unwrap()];
        let token = &sealed.fields[&FieldName::new("session_token").unwrap()];
        let escape = |envelope: &Envelope| {
            quick_xml::escape::escape(envelope.to_json().unwrap()).into_owned()
        };
        let expected = ASSUME_ROLE
            .replace("wJalrXUtnFEMI/K7MDENG/bPxRfiCYzEXAMPLEKEY", &escape(secret))
            .replace(
                "AQoDYXdzEPT//////////wEXAMPLEtc764&amp;b+&#47;=",
                &escape(token),
            );
        assert_eq!(text, expected);

        assert_eq!(
            opened(&private, secret, "secret_access_key"),
            b"wJalrXUtnFEMI/K7MDENG/bPxRfiCYzEXAMPLEKEY"
        );
        // References are resolved before sealing.
        assert_eq!(
            opened(&private, token, "session_token"),
            b"AQoDYXdzEPT//////////wEXAMPLEtc764&b+/="
        );
        // The replaced text reads back as the envelope.
        let start = text.find("<SecretAccessKey>").unwrap() + "<SecretAccessKey>".len();
        let end = text.find("</SecretAccessKey>").unwrap();
        let unescaped = quick_xml::escape::unescape(&text[start..end]).unwrap();
        assert_eq!(&Envelope::from_json(unescaped.as_bytes()).unwrap(), secret);
    }

    #[test]
    fn xml_cdata_and_split_text_are_sealed_whole() {
        let (private, public) = PrivateKey::generate();
        let spec = sealing(ResponseFormat::Xml, &[("A/B", "t")]);
        let sealed = seal_response_fields(
            &spec,
            &headers("application/xml"),
            b"<A><B>one<!-- c --><![CDATA[<two>]]>&lt;3</B><C/></A>",
            sealer(&public),
        )
        .unwrap();
        let envelope = &sealed.fields[&FieldName::new("t").unwrap()];
        assert_eq!(opened(&private, envelope, "t"), b"one<two><3");
        assert!(sealed.body.ends_with(b"</B><C/></A>"));
    }

    #[test]
    fn an_absent_or_empty_xml_field_is_fine() {
        let spec = sealing(ResponseFormat::Xml, &[("A/B", "t")]);
        for body in ["<A><C>x</C></A>", "<A><B/></A>", "<A/>"] {
            let sealed = seal_xml_text(&spec, body).unwrap();
            assert!(sealed.fields.is_empty(), "{body}");
            assert_eq!(sealed.body, body.as_bytes());
        }
    }

    #[test]
    fn xml_that_could_hide_a_token_is_refused() {
        let spec = sealing(ResponseFormat::Xml, &[("A/B", "t")]);
        for body in [
            // The field twice: which one is the token?
            "<A><B>one</B><B>two</B></A>",
            "<A><B/><B>two</B></A>",
            // Markup inside the field.
            "<A><B>one<C>two</C></B></A>",
            // A DTD could define entities.
            "<!DOCTYPE A [<!ENTITY e \"secret\">]><A><B>&e;</B></A>",
            "<A><B>&e;</B></A>",
            "<A><B>&#0;</B></A>",
            // Not well-formed.
            "<A><B>one</C></A>",
            "<A><B>one",
            "<A><B>one</B>",
        ] {
            let error = seal_xml_text(&spec, body).unwrap_err();
            assert_eq!(error.code(), ErrorCode::ResponseUnparseable, "{body}");
        }
        let error = seal_response_fields(
            &spec,
            &headers("application/json"),
            b"<A><B>x</B></A>",
            sealer(&PrivateKey::generate().1),
        )
        .unwrap_err();
        assert_eq!(error.code(), ErrorCode::ResponseUnparseable);
    }

    /// Found by fuzzing: positions after a byte order mark were three bytes short, which
    /// would have left the end of a token in the response.
    #[test]
    fn a_byte_order_mark_does_not_shift_what_is_sealed() {
        let (private, public) = PrivateKey::generate();
        let spec = sealing(ResponseFormat::Xml, &[("A/B", "t")]);
        let body = "\u{feff}<A><B>secret</B></A>";
        let sealed = seal_response_fields(
            &spec,
            &headers("text/xml"),
            body.as_bytes(),
            sealer(&public),
        )
        .unwrap();
        let text = String::from_utf8(sealed.body).unwrap();
        assert!(
            text.starts_with("\u{feff}<A><B>") && text.ends_with("</B></A>"),
            "{text}"
        );
        assert!(!text.contains("secret") && !text.contains("ret<"), "{text}");
        let envelope = &sealed.fields[&FieldName::new("t").unwrap()];
        assert_eq!(opened(&private, envelope, "t"), b"secret");
        // The fuzzer's input, which must now seal or refuse, never pass a fragment.
        let found = b"\xef\xbb\xbf<A><B>a8![>\0\0\0\0\0\0\0\0\x10\0\0\x08d</B></A>";
        if let Ok(sealed) =
            seal_response_fields(&spec, &headers("text/xml"), found, sealer(&public))
        {
            assert!(sealed.body.ends_with(b"</B></A>"));
            assert!(!sealed.body.windows(4).any(|window| window == b"8![>"));
        }
        let twice = "\u{feff}\u{feff}<A><B>secret</B></A>";
        assert!(
            seal_response_fields(
                &spec,
                &headers("text/xml"),
                twice.as_bytes(),
                sealer(&public)
            )
            .is_err()
        );
    }

    /// Found by fuzzing: a response with `serde_json`'s private number token as a key
    /// could come out, with its keys sorted, reading as a number to a reader like
    /// seal's own, so it is refused.
    #[test]
    fn a_response_with_the_number_token_as_a_key_is_refused() {
        let (_, public) = PrivateKey::generate();
        let spec = sealing(ResponseFormat::Json, &[("/token", "token")]);
        let body = include_bytes!("../../../fuzz/seeds/response_seal_json/number-token-crash.json");
        let error =
            seal_response_fields(&spec, &headers("application/json"), body, sealer(&public))
                .unwrap_err();
        assert_eq!(error.code(), ErrorCode::ResponseUnparseable);
    }

    #[test]
    fn xml_paths_name_elements_as_written() {
        // A prefixed element is not the unprefixed path.
        let spec = sealing(ResponseFormat::Xml, &[("A/B", "t")]);
        let sealed = seal_xml_text(&spec, r#"<A xmlns:x="urn:x"><x:B>s</x:B></A>"#).unwrap();
        assert!(sealed.fields.is_empty());
        let spec = sealing(ResponseFormat::Xml, &[("A/x:B", "t")]);
        let sealed = seal_xml_text(&spec, r#"<A xmlns:x="urn:x"><x:B>s</x:B></A>"#).unwrap();
        assert_eq!(sealed.fields.len(), 1);
        // A deeper element with the same name is not the field.
        let spec = sealing(ResponseFormat::Xml, &[("A/B", "t")]);
        let sealed = seal_xml_text(&spec, "<A><C><B>s</B></C></A>").unwrap();
        assert!(sealed.fields.is_empty());
    }

    #[test]
    fn a_sealing_failure_is_passed_on_and_nothing_comes_back() {
        let spec = sealing(ResponseFormat::Json, &[("/t", "t")]);
        let result = seal_response_fields(
            &spec,
            &headers("application/json"),
            b"{\"t\":\"x\"}",
            |_, _| Err(BrokerError::new(ErrorCode::KeysUnavailable, "keys")),
        );
        assert_eq!(result.unwrap_err().code(), ErrorCode::KeysUnavailable);
    }
}
