//! Azure Storage Shared Key, with the account key as the rule's own secret.
//!
//! seal sets `x-ms-date` (and `Date` for Table), `x-ms-version` if the caller did
//! not, and `Authorization`, over the final request. A caller cannot set
//! `Authorization`, `x-ms-date` or `Date`. SAS generation is not implemented: a SAS
//! is a usable credential.

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use http::header::{HeaderMap, HeaderName, HeaderValue};
use percent_encoding::percent_decode_str;
use ring::hmac;
use seal_format::policy::AzureService;
use zeroize::Zeroizing;

use crate::error::{BrokerError, ErrorCode};
use crate::inject::civil::Civil;

/// The service version seal sends if the caller sends none.
pub const DEFAULT_VERSION: &str = "2021-12-02";

/// The standard headers in the Blob, Queue and File string to sign, in order.
const STANDARD_HEADERS: &[&str] = &[
    "content-encoding",
    "content-language",
    "content-length",
    "content-md5",
    "content-type",
    "date",
    "if-modified-since",
    "if-match",
    "if-none-match",
    "if-unmodified-since",
    "range",
];

fn bad(detail: &'static str) -> BrokerError {
    BrokerError::new(ErrorCode::BadRequest, detail)
}

/// A header's one value, or an empty string. Shared Key refuses repeated headers.
fn single<'a>(headers: &'a HeaderMap, name: &str) -> Result<&'a str, BrokerError> {
    let mut values = headers.get_all(name).iter();
    let value = values.next();
    if values.next().is_some() {
        return Err(bad("Shared Key refuses a repeated header"));
    }
    value.map_or(Ok(""), |value| {
        value
            .to_str()
            .map_err(|_| bad("a signed header is not printable ASCII"))
    })
}

/// A value with each run of whitespace made one space, and its ends trimmed. Azure
/// keeps whitespace inside quoted strings, so those are copied as they are.
fn collapse(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    let mut quoted = false;
    let mut pending_space = false;
    for character in value.trim().chars() {
        if character == '"' {
            quoted = !quoted;
        }
        if !quoted && character.is_ascii_whitespace() {
            pending_space = true;
            continue;
        }
        if pending_space {
            out.push(' ');
            pending_space = false;
        }
        out.push(character);
    }
    out
}

/// Every `x-ms-*` header, lowercase and sorted, each as `name:value\n`.
///
/// # Errors
///
/// [`ErrorCode::BadRequest`] for a repeated or unprintable header.
pub fn canonical_headers(headers: &HeaderMap) -> Result<String, BrokerError> {
    let mut names: Vec<&str> = headers
        .keys()
        .map(HeaderName::as_str)
        .filter(|name| name.starts_with("x-ms-"))
        .collect();
    names.sort_unstable();
    names.dedup();
    let mut out = String::new();
    for name in names {
        out.push_str(name);
        out.push(':');
        out.push_str(&collapse(single(headers, name)?));
        out.push('\n');
    }
    Ok(out)
}

/// The canonical resource for Blob, Queue and File: the account and path as sent,
/// then each query parameter decoded, by lowercase name, with its values sorted.
#[must_use]
pub fn canonical_resource(account: &str, path: &str, query: &str) -> String {
    let mut parameters: std::collections::BTreeMap<String, Vec<String>> =
        std::collections::BTreeMap::new();
    for (name, value) in form_urlencoded::parse(query.as_bytes()) {
        parameters
            .entry(name.to_lowercase())
            .or_default()
            .push(value.into_owned());
    }
    let mut out = format!("/{account}{}", if path.is_empty() { "/" } else { path });
    for (name, mut values) in parameters {
        values.sort();
        out.push('\n');
        out.push_str(&name);
        out.push(':');
        out.push_str(&values.join(","));
    }
    out
}

/// The canonical resource for Table: the account and path, and `comp` alone.
#[must_use]
pub fn table_resource(account: &str, path: &str, query: &str) -> String {
    let mut out = format!("/{account}{}", if path.is_empty() { "/" } else { path });
    if let Some((_, comp)) =
        form_urlencoded::parse(query.as_bytes()).find(|(name, _)| name == "comp")
    {
        out.push_str("?comp=");
        out.push_str(&comp);
    }
    out
}

/// The string to sign for Blob, Queue and File, from the final headers.
///
/// # Errors
///
/// [`ErrorCode::BadRequest`] for a repeated or unprintable header.
pub fn string_to_sign(
    method: &str,
    headers: &HeaderMap,
    account: &str,
    path: &str,
    query: &str,
) -> Result<String, BrokerError> {
    let mut out = format!("{method}\n");
    for name in STANDARD_HEADERS {
        let value = single(headers, name)?;
        // A zero length is an empty string, from version 2015-02-21. The date is
        // always in x-ms-date, which seal sets.
        let value = match *name {
            "content-length" if value == "0" => "",
            "date" if headers.contains_key("x-ms-date") => "",
            _ => value,
        };
        out.push_str(value);
        out.push('\n');
    }
    out.push_str(&canonical_headers(headers)?);
    out.push_str(&canonical_resource(account, path, query));
    Ok(out)
}

/// The string to sign for Table.
///
/// # Errors
///
/// [`ErrorCode::BadRequest`] for a repeated or unprintable header.
pub fn table_string_to_sign(
    method: &str,
    headers: &HeaderMap,
    account: &str,
    path: &str,
    query: &str,
) -> Result<String, BrokerError> {
    let date = match single(headers, "x-ms-date")? {
        "" => single(headers, "date")?,
        date => date,
    };
    Ok(format!(
        "{method}\n{}\n{}\n{date}\n{}",
        single(headers, "content-md5")?,
        single(headers, "content-type")?,
        table_resource(account, path, query)
    ))
}

/// Signs one request.
pub struct Signer {
    key: Zeroizing<Vec<u8>>,
    account: String,
    service: AzureService,
    date: String,
}

impl std::fmt::Debug for Signer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Signer")
            .field("account", &self.account)
            .field("service", &self.service)
            .finish_non_exhaustive()
    }
}

impl Signer {
    /// A signer for a request made now, from the base64 account key.
    ///
    /// # Errors
    ///
    /// [`ErrorCode::BadRequest`] if the key is not base64 or the account name is not
    /// a valid storage account name.
    pub fn new(
        account_key: &[u8],
        account: &[u8],
        service: AzureService,
        now: std::time::SystemTime,
    ) -> Result<Self, BrokerError> {
        let key = Zeroizing::new(
            STANDARD
                .decode(account_key)
                .map_err(|_| bad("the account key is not base64"))?,
        );
        let account = std::str::from_utf8(account)
            .ok()
            .filter(|name| {
                !name.is_empty()
                    && name.len() <= 64
                    && name
                        .bytes()
                        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
            })
            .ok_or_else(|| bad("the storage account name is not valid"))?;
        Ok(Self {
            key,
            account: account.to_owned(),
            service,
            date: Civil::at(now).http_date(),
        })
    }

    /// Adds the date, the version if missing, and `Authorization` to the final headers.
    ///
    /// # Errors
    ///
    /// [`ErrorCode::BadRequest`] for a repeated or unprintable header.
    pub fn sign(
        &self,
        method: &str,
        path: &str,
        query: &str,
        headers: &mut HeaderMap,
    ) -> Result<(), BrokerError> {
        let date = HeaderValue::from_str(&self.date).map_err(|_| bad("the date is not valid"))?;
        headers.insert("x-ms-date", date.clone());
        if !headers.contains_key("x-ms-version") {
            headers.insert("x-ms-version", HeaderValue::from_static(DEFAULT_VERSION));
        }
        let path = percent_decode_check(path)?;
        let to_sign = match self.service {
            AzureService::Table => {
                headers.insert(http::header::DATE, date);
                table_string_to_sign(method, headers, &self.account, path, query)?
            }
            AzureService::Blob | AzureService::Queue | AzureService::File => {
                string_to_sign(method, headers, &self.account, path, query)?
            }
        };
        let key = hmac::Key::new(hmac::HMAC_SHA256, &self.key);
        let signature = Zeroizing::new(STANDARD.encode(hmac::sign(&key, to_sign.as_bytes())));
        let header = Zeroizing::new(format!("SharedKey {}:{}", self.account, signature.as_str()));
        let mut value = HeaderValue::from_str(&header)
            .map_err(|_| bad("the authorization cannot be a header"))?;
        value.set_sensitive(true);
        headers.insert(http::header::AUTHORIZATION, value);
        Ok(())
    }
}

/// The path goes into the string to sign as sent, but it must decode, so that seal
/// and the service read the same resource.
fn percent_decode_check(path: &str) -> Result<&str, BrokerError> {
    percent_decode_str(path)
        .decode_utf8()
        .map_err(|_| bad("the path does not decode as UTF-8"))?;
    Ok(path)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use std::time::{Duration, UNIX_EPOCH};

    use super::*;

    fn headers(pairs: &[(&'static str, &str)]) -> HeaderMap {
        let mut map = HeaderMap::new();
        for (name, value) in pairs {
            map.append(*name, HeaderValue::from_str(value).unwrap());
        }
        map
    }

    /// The Get Container Metadata example in "Authorize with Shared Key".
    #[test]
    fn the_documented_blob_string_to_sign() {
        let map = headers(&[
            ("x-ms-date", "Fri, 26 Jun 2015 23:39:12 GMT"),
            ("x-ms-version", "2015-02-21"),
        ]);
        assert_eq!(
            string_to_sign(
                "GET",
                &map,
                "myaccount",
                "/mycontainer",
                "restype=container&comp=metadata&timeout=20"
            )
            .unwrap(),
            "GET\n\n\n\n\n\n\n\n\n\n\n\nx-ms-date:Fri, 26 Jun 2015 23:39:12 GMT\nx-ms-version:2015-02-21\n/myaccount/mycontainer\ncomp:metadata\nrestype:container\ntimeout:20"
        );
    }

    /// The Content-Length example: zero is an empty string from 2015-02-21.
    #[test]
    fn a_zero_length_is_an_empty_string() {
        let map = headers(&[
            ("x-ms-version", "2015-02-21"),
            ("x-ms-date", "Fri, 26 Jun 2015 23:39:12 GMT"),
            ("content-length", "0"),
        ]);
        assert_eq!(
            string_to_sign(
                "PUT",
                &map,
                "myaccount",
                "/mycontainer",
                "restype=container&timeout=30"
            )
            .unwrap(),
            "PUT\n\n\n\n\n\n\n\n\n\n\n\nx-ms-date:Fri, 26 Jun 2015 23:39:12 GMT\nx-ms-version:2015-02-21\n/myaccount/mycontainer\nrestype:container\ntimeout:30"
        );
    }

    #[test]
    fn the_documented_canonical_resources() {
        assert_eq!(
            canonical_resource(
                "myaccount",
                "/mycontainer",
                "restype=container&comp=metadata"
            ),
            "/myaccount/mycontainer\ncomp:metadata\nrestype:container"
        );
        assert_eq!(
            canonical_resource(
                "myaccount",
                "/mycontainer",
                "restype=container&comp=list&include=snapshots&include=metadata&include=uncommittedblobs"
            ),
            "/myaccount/mycontainer\ncomp:list\ninclude:metadata,snapshots,uncommittedblobs\nrestype:container"
        );
        assert_eq!(
            canonical_resource("myaccount", "/mycontainer/myblob", ""),
            "/myaccount/mycontainer/myblob"
        );
        assert_eq!(
            canonical_resource("acct", "/c/a%20b", "Prefix=x%2Fy&MaxResults=5"),
            "/acct/c/a%20b\nmaxresults:5\nprefix:x/y"
        );
        assert_eq!(
            canonical_resource("acct", "", "comp=list"),
            "/acct/\ncomp:list"
        );
    }

    #[test]
    fn the_documented_canonical_headers() {
        let map = headers(&[
            ("x-ms-version", "2014-02-14"),
            ("x-ms-date", "Sat, 21 Feb 2015 00:48:38 GMT"),
            ("content-type", "text/plain"),
        ]);
        assert_eq!(
            canonical_headers(&map).unwrap(),
            "x-ms-date:Sat, 21 Feb 2015 00:48:38 GMT\nx-ms-version:2014-02-14\n"
        );
        let map = headers(&[
            ("x-ms-meta-a", "  one   two\t three "),
            ("x-ms-meta-b", "\"a   b\"  c"),
            ("x-ms-meta-c", ""),
        ]);
        assert_eq!(
            canonical_headers(&map).unwrap(),
            "x-ms-meta-a:one two three\nx-ms-meta-b:\"a   b\" c\nx-ms-meta-c:\n"
        );
        let map = headers(&[("x-ms-meta-a", "1"), ("x-ms-meta-a", "2")]);
        assert_eq!(
            canonical_headers(&map).err().unwrap().code(),
            ErrorCode::BadRequest
        );
    }

    #[test]
    fn the_table_string_to_sign_has_the_date_and_comp_only() {
        let map = headers(&[
            ("x-ms-date", "Sun, 11 Oct 2009 19:52:39 GMT"),
            ("content-type", "application/json"),
            ("x-ms-version", "2021-12-02"),
        ]);
        assert_eq!(
            table_string_to_sign("POST", &map, "testaccount1", "/Tables", "timeout=5").unwrap(),
            "POST\n\napplication/json\nSun, 11 Oct 2009 19:52:39 GMT\n/testaccount1/Tables"
        );
        assert_eq!(
            table_resource("a", "/mytable", "comp=acl&timeout=5"),
            "/a/mytable?comp=acl"
        );
    }

    /// The signature is base64 HMAC-SHA-256 under the decoded key; the expected value
    /// is from Python's `hmac` module, independently of this code.
    #[test]
    fn signs_with_the_decoded_account_key() {
        // Azurite's well-known development key.
        let key = b"Eby8vdM02xNOcqFlqUwJPLlmEtlCDXJ1OUzFT50uSRZ6IFsuFq2UVErCz4I6tq/K1SZFPTOtr/KBHBeksoGMGw==";
        let now = UNIX_EPOCH + Duration::from_secs(1_440_938_160);
        let signer = Signer::new(key, b"devstoreaccount1", AzureService::Blob, now).unwrap();
        let mut map = headers(&[("x-ms-version", "2021-12-02")]);
        signer
            .sign("GET", "/devstoreaccount1/c", "restype=container", &mut map)
            .unwrap();
        assert_eq!(map["x-ms-date"], "Sun, 30 Aug 2015 12:36:00 GMT");
        assert!(map["authorization"].is_sensitive());
        assert_eq!(
            map["authorization"],
            "SharedKey devstoreaccount1:zWchiuEUV0f8cRfN8Gc+ZepW+CLWsJZAluQSKknUTzY="
        );
        assert!(!map.contains_key("date"));

        let table = Signer::new(key, b"devstoreaccount1", AzureService::Table, now).unwrap();
        let mut map = HeaderMap::new();
        table
            .sign("GET", "/devstoreaccount1/Tables", "", &mut map)
            .unwrap();
        assert_eq!(map["date"], "Sun, 30 Aug 2015 12:36:00 GMT");
        assert_eq!(map["x-ms-version"], DEFAULT_VERSION);
    }

    #[test]
    fn a_bad_key_or_account_is_refused() {
        let now = UNIX_EPOCH;
        for (key, account) in [
            (&b"not base64!"[..], &b"acct"[..]),
            (b"AAAA", b"Acct"),
            (b"AAAA", b""),
            (b"AAAA", b"a-b"),
        ] {
            let error = Signer::new(key, account, AzureService::Blob, now)
                .err()
                .unwrap();
            assert_eq!(error.code(), ErrorCode::BadRequest);
        }
    }
}
