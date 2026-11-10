//! Changes one place in a JSON document and passes the rest on as it was written.
//!
//! seal adds a secret to a request body, or replaces a token in a response. Everything
//! else in the document belongs to the caller or the provider, and must mean the same
//! after seal as before: a number keeps every digit, a string its escapes, an object its
//! members. So only the objects and arrays on the way to the change are read, one level
//! at a time, and every other value is kept as the bytes it arrived as.
//!
//! `serde_json` does all the parsing. Nothing here decides where a value starts or ends.

use std::collections::BTreeMap;

use serde_json::value::RawValue;
use zeroize::Zeroizing;

/// An object or array on the way to a change could not be read, though the document
/// passed as JSON. The document is then refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Unreadable;

/// A JSON value: as it was written, or read one level deep to change something in it.
#[derive(Debug)]
pub(crate) enum Node<'a> {
    /// A value kept exactly as it was written.
    Raw(&'a RawValue),
    /// An object that was read. Members are written in key order; a key that repeats
    /// keeps its last value, as `serde_json` reads one.
    Object(BTreeMap<String, Node<'a>>),
    /// An array that was read.
    Array(Vec<Node<'a>>),
    /// A string to write, such as a secret. It is borrowed, so no copy is made here.
    Text(&'a str),
    /// JSON to write as it is: an envelope.
    Json(String),
}

impl<'a> Node<'a> {
    /// Reads a document. `None` if it is not valid JSON.
    pub(crate) fn parse(document: &'a [u8]) -> Option<Self> {
        serde_json::from_slice::<&RawValue>(document)
            .ok()
            .map(Self::Raw)
    }

    /// An empty object.
    pub(crate) fn empty_object() -> Self {
        Self::Object(BTreeMap::new())
    }

    /// Whether this is an object.
    pub(crate) fn is_object(&self) -> bool {
        match self {
            Self::Raw(raw) => raw.get().trim_start().starts_with('{'),
            Self::Object(_) => true,
            Self::Array(_) | Self::Text(_) | Self::Json(_) => false,
        }
    }

    /// Reads one level of an object or array kept as written, so that a member can be
    /// reached. The members themselves stay as written.
    ///
    /// # Errors
    ///
    /// [`Unreadable`] if the level cannot be read. Checking a whole document accepts a
    /// little more than reading one does, such as a key with half of a surrogate pair.
    /// Such a level must not be treated as having no members: another reader might
    /// find in it the very member seal is looking for, so the document is refused.
    fn open(&mut self) -> Result<(), Unreadable> {
        let Self::Raw(raw) = self else {
            return Ok(());
        };
        let text = raw.get().trim_start();
        if text.starts_with('{') {
            let members = serde_json::from_str::<BTreeMap<String, &'a RawValue>>(text)
                .map_err(|_| Unreadable)?;
            *self = Self::Object(
                members
                    .into_iter()
                    .map(|(key, value)| (key, Self::Raw(value)))
                    .collect(),
            );
        } else if text.starts_with('[') {
            let items = serde_json::from_str::<Vec<&'a RawValue>>(text).map_err(|_| Unreadable)?;
            *self = Self::Array(items.into_iter().map(Self::Raw).collect());
        }
        Ok(())
    }

    /// This value's members, or `None` if it is not an object.
    ///
    /// # Errors
    ///
    /// [`Unreadable`] if it is an object that cannot be read.
    pub(crate) fn object_mut(
        &mut self,
    ) -> Result<Option<&mut BTreeMap<String, Node<'a>>>, Unreadable> {
        self.open()?;
        Ok(match self {
            Self::Object(members) => Some(members),
            _ => None,
        })
    }

    /// The value at an RFC 6901 pointer, as `serde_json::Value::pointer_mut` finds one:
    /// through objects by key and arrays by index. `None` if there is nothing there.
    ///
    /// # Errors
    ///
    /// [`Unreadable`] if an object or array on the way cannot be read.
    pub(crate) fn pointer_mut(
        &mut self,
        pointer: &str,
    ) -> Result<Option<&mut Node<'a>>, Unreadable> {
        if pointer.is_empty() {
            return Ok(Some(self));
        }
        if !pointer.starts_with('/') {
            return Ok(None);
        }
        let mut current = self;
        for token in pointer.split('/').skip(1) {
            let token = token.replace("~1", "/").replace("~0", "~");
            current.open()?;
            let next = match current {
                Self::Object(members) => members.get_mut(&token),
                Self::Array(items) => array_index(&token).and_then(|index| items.get_mut(index)),
                _ => None,
            };
            let Some(next) = next else {
                return Ok(None);
            };
            current = next;
        }
        Ok(Some(current))
    }

    /// The string this value is, if it is one that was written in the document.
    pub(crate) fn as_string(&self) -> Option<Zeroizing<String>> {
        match self {
            Self::Raw(raw) if raw.get().trim_start().starts_with('"') => {
                serde_json::from_str::<String>(raw.get())
                    .ok()
                    .map(Zeroizing::new)
            }
            _ => None,
        }
    }

    /// Writes the document. A value kept as written is copied byte for byte.
    ///
    /// # Errors
    ///
    /// Fails only if a string cannot be written, which `serde_json` does not do for a
    /// `Vec`.
    pub(crate) fn write(&self, out: &mut Vec<u8>) -> Result<(), serde_json::Error> {
        match self {
            Self::Raw(raw) => out.extend_from_slice(raw.get().as_bytes()),
            Self::Json(json) => out.extend_from_slice(json.as_bytes()),
            Self::Text(text) => serde_json::to_writer(&mut *out, text)?,
            Self::Object(members) => {
                out.push(b'{');
                for (index, (key, value)) in members.iter().enumerate() {
                    if index > 0 {
                        out.push(b',');
                    }
                    serde_json::to_writer(&mut *out, key)?;
                    out.push(b':');
                    value.write(out)?;
                }
                out.push(b'}');
            }
            Self::Array(items) => {
                out.push(b'[');
                for (index, item) in items.iter().enumerate() {
                    if index > 0 {
                        out.push(b',');
                    }
                    item.write(out)?;
                }
                out.push(b']');
            }
        }
        Ok(())
    }
}

/// An array index in a JSON pointer: digits, with no sign and no leading zero.
fn array_index(token: &str) -> Option<usize> {
    if token.starts_with('+') || (token.starts_with('0') && token.len() != 1) {
        return None;
    }
    token.parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn written(node: &Node<'_>) -> String {
        let mut out = Vec::new();
        node.write(&mut out).unwrap();
        String::from_utf8(out).unwrap()
    }

    #[test]
    fn a_document_that_is_not_changed_is_written_byte_for_byte() {
        for document in [
            r#"{"a": 1.0, "b" : [ 1e400, -0, 0.1000000000000000000001 ],"c":"\u00e9\/"}"#,
            "  [1,\n 2]  ",
            r#""text""#,
            "12345678901234567890123",
            "null",
        ] {
            let node = Node::parse(document.as_bytes()).unwrap();
            assert_eq!(written(&node), document.trim(), "{document}");
        }
    }

    #[test]
    fn what_is_not_json_is_refused() {
        for document in ["", "{", r#"{"a":}"#, "[1,]", "1 2", "{'a':1}", "\u{feff}1"] {
            assert!(Node::parse(document.as_bytes()).is_none(), "{document}");
        }
        assert!(Node::parse(&[b'"', 0xff, b'"']).is_none());
    }

    /// Only the levels on the way to a change are rewritten. Every other value, however
    /// it was written, is passed on as it was.
    #[test]
    fn a_change_leaves_every_other_value_as_it_was_written() {
        let document = br#"{ "z": 1.50, "a": {"keep": [ 1 , 2.0 ], "big":12345678901234567890123},
                           "s": "\u0041\/", "n": {"x": {"deep" : 1e999}} }"#;
        let mut node = Node::parse(document).unwrap();
        node.pointer_mut("/a")
            .unwrap()
            .unwrap()
            .object_mut()
            .unwrap()
            .unwrap()
            .insert("new".to_owned(), Node::Text("v"));

        assert_eq!(
            written(&node),
            // The two objects that were read are written compactly, in key order.
            r#"{"a":{"big":12345678901234567890123,"keep":[ 1 , 2.0 ],"new":"v"},"#.to_owned()
                + r#""n":{"x": {"deep" : 1e999}},"s":"\u0041\/","z":1.50}"#
        );
    }

    #[test]
    fn a_pointer_goes_through_objects_and_arrays_like_serde_jsons() {
        let document = r#"{"a":[{"b":"x"},{"b":"y"}],"m~n":{"o/p":"z"},"":"empty","t":"s"}"#;
        let value: serde_json::Value = serde_json::from_str(document).unwrap();
        for pointer in [
            "",
            "/a",
            "/a/0",
            "/a/1/b",
            "/a/2",
            "/a/01",
            "/a/+1",
            "/a/-",
            "/a/x",
            "/m~0n/o~1p",
            "/",
            "/t/x",
            "/missing",
            "/a/0/b/c",
            "a",
            "/a/0/",
            "/m~n",
        ] {
            let mut node = Node::parse(document.as_bytes()).unwrap();
            // The same value, whatever its spacing or key order.
            let found = node
                .pointer_mut(pointer)
                .unwrap()
                .map(|found| serde_json::from_str::<serde_json::Value>(&written(found)).unwrap());
            let expected = value.pointer(pointer).cloned();
            assert_eq!(found, expected, "{pointer:?}");
        }
    }

    #[test]
    fn a_repeated_key_keeps_its_last_value_where_an_object_is_read() {
        let mut node = Node::parse(br#"{"a":1,"a":{"b":2},"c":{"d":1,"d":2}}"#).unwrap();
        assert_eq!(written(node.pointer_mut("/a/b").unwrap().unwrap()), "2");
        // The object that was read has the key once; one that was not is as written.
        assert_eq!(written(&node), r#"{"a":{"b":2},"c":{"d":1,"d":2}}"#);
    }

    #[test]
    fn only_a_string_written_in_the_document_reads_as_one() {
        let mut node = Node::parse(br#"{"s":"a\n\u00e9","n":1,"o":{},"l":[],"z":null}"#).unwrap();
        assert_eq!(
            node.pointer_mut("/s")
                .unwrap()
                .unwrap()
                .as_string()
                .unwrap()
                .as_str(),
            "a\n\u{e9}"
        );
        for pointer in ["/n", "/o", "/l", "/z", ""] {
            assert!(
                node.pointer_mut(pointer)
                    .unwrap()
                    .unwrap()
                    .as_string()
                    .is_none()
            );
        }
        assert!(Node::Text("t").as_string().is_none());
        assert!(Node::Json("\"j\"".to_owned()).as_string().is_none());
    }

    #[test]
    fn what_is_an_object_is_told_without_reading_it() {
        for (document, object) in [
            ("{}", true),
            (" {\"a\":1}", true),
            ("[]", false),
            ("1", false),
        ] {
            assert_eq!(
                Node::parse(document.as_bytes()).unwrap().is_object(),
                object
            );
        }
        assert!(Node::empty_object().is_object());
        assert!(!Node::Text("{").is_object());
    }

    #[test]
    fn written_text_is_escaped_and_written_json_is_not() {
        let mut node = Node::empty_object();
        let members = node.object_mut().unwrap().unwrap();
        members.insert("t\"".to_owned(), Node::Text("a\"b\\c\n\u{1}"));
        members.insert("j".to_owned(), Node::Json(r#"{"v":1}"#.to_owned()));
        assert_eq!(written(&node), r#"{"j":{"v":1},"t\"":"a\"b\\c\n\u0001"}"#);
        let _: serde_json::Value = serde_json::from_str(&written(&node)).unwrap();
    }

    /// A document can pass as JSON and still have a level seal cannot read: here, a key
    /// with half of a surrogate pair. Had that level been taken to have no members,
    /// seal would have found no `token` in it and passed the document on, token and
    /// all, to a reader that does find it.
    #[test]
    fn a_level_that_cannot_be_read_is_an_error_not_an_empty_one() {
        let document = br#"{"BADKEY":1,"token":"secret","list":[{"BADKEY":1,"token":"s"}]}"#;
        let document = String::from_utf8(document.to_vec())
            .unwrap()
            .replace("BADKEY", "\\ud800");
        assert!(Node::parse(document.as_bytes()).is_some());

        let mut node = Node::parse(document.as_bytes()).unwrap();
        assert_eq!(node.pointer_mut("/token").unwrap_err(), Unreadable);
        let mut node = Node::parse(document.as_bytes()).unwrap();
        assert_eq!(node.object_mut().unwrap_err(), Unreadable);

        // The same inside a level that reads: the bad level is the array's member.
        let good = format!(r#"{{"a":{}}}"#, document);
        let mut node = Node::parse(good.as_bytes()).unwrap();
        assert_eq!(node.pointer_mut("/a/list/0/token").unwrap_err(), Unreadable);
        // What is off the path is not read, and is passed on.
        let mut node = Node::parse(good.as_bytes()).unwrap();
        assert!(node.pointer_mut("/b").unwrap().is_none());
    }

    /// seal is not built with `serde_json`'s `arbitrary_precision`, which Cargo would
    /// turn on for every crate an embedding application builds. With it, this object
    /// reads as a number.
    #[test]
    fn serde_json_reads_numbers_the_ordinary_way() {
        let value: serde_json::Value =
            serde_json::from_str(r#"{"$serde_json::private::Number":"1"}"#).unwrap();
        assert!(value.is_object());
    }

    /// A value is never read deeper than the change needs, so nesting that `serde_json`
    /// would refuse to read into a tree passes through.
    #[test]
    fn deep_nesting_off_the_path_is_passed_on() {
        let deep = "[".repeat(500) + &"]".repeat(500);
        let document = format!(r#"{{"deep":{deep},"t":"x"}}"#);
        let mut node = Node::parse(document.as_bytes()).unwrap();
        *node.pointer_mut("/t").unwrap().unwrap() = Node::Text("y");
        assert_eq!(written(&node), format!(r#"{{"deep":{deep},"t":"y"}}"#));
    }
}
