//! Whatever a provider returns, a declared XML field never comes back in plaintext:
//! if seal passes the response on, the field's content is an envelope.

#![no_main]

use http::{HeaderMap, HeaderValue, header};
use libfuzzer_sys::fuzz_target;
use quick_xml::events::Event;
use seal_broker::response_seal::seal_response_fields;
use seal_format::id::KeyId;
use seal_format::policy::{ResponseFormat, SealResponse, SealedField, builder};
use seal_format::{Binding, Envelope, FieldName, ItemId, KeysetId, PolicyName, PublicKey, seal};

fuzz_target!(|data: &[u8]| {
    let mut headers = HeaderMap::new();
    headers.insert(header::CONTENT_TYPE, HeaderValue::from_static("text/xml"));
    let sealing = SealResponse {
        format: ResponseFormat::Xml,
        fields: vec![SealedField {
            at: "A/B".to_owned(),
            as_field: FieldName::new("token").expect("valid"),
            policy: PolicyName::new("api").expect("valid"),
            expose_claims: Vec::new(),
        }],
    };
    let public = PublicKey::from_bytes(&[9; 32]).expect("valid");
    let policy = builder::bearer("https://api.example.com/").expect("valid");
    let (keyset, item) = (KeysetId::new("a").expect("valid"), ItemId::new("b").expect("valid"));
    let result = seal_response_fields(&sealing, &headers, data, |field, plaintext| {
        let binding = Binding { keyset: &keyset, item: &item, field: &field.as_field };
        Ok(seal(&public, &KeyId::new("k").expect("valid"), binding, plaintext, &policy)
            .expect("sealing works"))
    });
    let Ok(output) = result else { return };
    let text = std::str::from_utf8(&output.body).expect("the output is UTF-8");
    let mut reader = quick_xml::Reader::from_str(text);
    let mut path: Vec<String> = Vec::new();
    let mut content: Option<String> = None;
    loop {
        match reader.read_event().expect("the output parses as the input did") {
            Event::Eof => break,
            Event::Start(start) => {
                assert!(content.is_none(), "a sealed field holds no markup");
                path.push(AsRef::<str>::as_ref(&start.name()).to_owned());
                if path.join("/") == "A/B" {
                    content = Some(String::new());
                }
            }
            Event::End(_) => {
                if let Some(value) = content.take() {
                    Envelope::from_json(value.as_bytes()).expect("a declared field is an envelope");
                }
                path.pop();
            }
            Event::Text(part) => {
                if let Some(value) = &mut content {
                    value.push_str(&part);
                }
            }
            Event::GeneralRef(reference) => {
                if let Some(value) = &mut content {
                    let resolved = quick_xml::escape::resolve_predefined_entity(&reference)
                        .expect("seal escapes with predefined entities only");
                    value.push_str(resolved);
                }
            }
            Event::CData(_) => assert!(content.is_none(), "an envelope is written as text"),
            _ => {}
        }
    }
});
