//! Azure Storage Shared Key, with the account key as the rule's own secret.
//!
//! seal sets `x-ms-date` (and `Date` for Table), `x-ms-version` if the caller did
//! not, and `Authorization`, over the final request. A caller cannot set
//! `Authorization`, `x-ms-date` or `Date`.
//!
//! A shared access signature is a credential the caller can copy, so one is made only
//! for a rule that allows it, for one blob, within the lifetime the rule gives.

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

/// Whether a value has the form of a storage API version: `YYYY-MM-DD`.
fn is_api_version(value: &[u8]) -> bool {
    value.len() == 10
        && value.iter().enumerate().all(|(index, byte)| match index {
            4 | 7 => *byte == b'-',
            _ => byte.is_ascii_digit(),
        })
}

/// A value with each run of whitespace made one space, and its ends trimmed. Azure
/// keeps whitespace inside quoted strings, so those are copied as they are.
fn collapse(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    let mut quoted = false;
    let mut pending_space = false;
    for character in value
        .trim_matches(|character: char| character.is_ascii_whitespace())
        .chars()
    {
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
        // The caller may choose the API version, which changes what a request means
        // but not where it goes. It must be one version, written as a date.
        let mut versions = headers.get_all("x-ms-version").iter();
        match (versions.next(), versions.next()) {
            (None, _) => {
                headers.insert("x-ms-version", HeaderValue::from_static(DEFAULT_VERSION));
            }
            (Some(version), None) if is_api_version(version.as_bytes()) => {}
            _ => return Err(bad("x-ms-version must be one date, as in 2021-12-02")),
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

/// The container and blob a URL names, decoded. With the account in the host name,
/// they are the path. Otherwise the path must start with the account, as an emulator
/// has it: a host that names no account, such as a custom domain, is refused, since
/// seal could not tell which blob the service would take the path to mean.
fn blob_of(account: &str, host: &str, path: &str) -> Result<String, BrokerError> {
    let in_host = host
        .strip_prefix(account)
        .is_some_and(|rest| rest.starts_with('.'));
    let resource = if in_host {
        path.strip_prefix('/')
    } else {
        path.strip_prefix('/')
            .and_then(|rest| rest.strip_prefix(account))
            .and_then(|rest| rest.strip_prefix('/'))
    }
    .ok_or_else(|| bad("the URL does not name the storage account"))?;
    let decoded = percent_decode_str(resource)
        .decode_utf8()
        .map_err(|_| bad("the path does not decode as UTF-8"))?;
    let names_a_blob = decoded
        .split_once('/')
        .is_some_and(|(container, blob)| !container.is_empty() && !blob.is_empty());
    if !names_a_blob {
        return Err(bad("the URL does not name a blob"));
    }
    Ok(decoded.into_owned())
}

/// The query parameters a caller may put on a URL that gets a shared access signature,
/// in the order they are signed: how a download's response is described. They set
/// `Cache-Control`, `Content-Disposition`, `Content-Encoding`, `Content-Language` and
/// `Content-Type`.
pub const SAS_QUERY: &[&str] = &["rscc", "rscd", "rsce", "rscl", "rsct"];

/// What the URL of a shared access signature names.
#[derive(Clone, Copy, Debug)]
pub struct SasUrl<'a> {
    /// The host, without a port.
    pub host: &'a str,
    /// The path, as sent.
    pub path: &'a str,
    /// The query, as sent: only [`SAS_QUERY`] parameters, each at most once.
    pub query: &'a str,
}

/// The caller's response headers, decoded, in the order of [`SAS_QUERY`]. A `+` is a
/// plus sign, never a space, so that seal and the service read the same value.
fn response_headers(query: &str) -> Result<[Option<String>; 5], BrokerError> {
    let mut values: [Option<String>; 5] = Default::default();
    for pair in query.split('&').filter(|pair| !pair.is_empty()) {
        let (name, value) = pair.split_once('=').unwrap_or((pair, ""));
        let slot = SAS_QUERY
            .iter()
            .position(|allowed| *allowed == name)
            .and_then(|index| values.get_mut(index))
            .filter(|slot| slot.is_none())
            .ok_or_else(|| bad("a shared access signature cannot carry this query parameter"))?;
        let decoded = percent_decode_str(value)
            .decode_utf8()
            .ok()
            .filter(|decoded| !decoded.is_empty() && !decoded.chars().any(char::is_control))
            .ok_or_else(|| bad("a response header in the query is not valid"))?;
        *slot = Some(decoded.into_owned());
    }
    Ok(values)
}

impl Signer {
    /// The query of a shared access signature for the one blob a URL names: these
    /// permissions, until `expiry`, with no start time, and the response headers the
    /// URL's own query asks for. Over HTTPS only, unless the rule itself is for plain
    /// HTTP.
    ///
    /// # Errors
    ///
    /// [`ErrorCode::BadRequest`] if the URL does not name a blob of this account, or
    /// its query has anything but response headers.
    pub fn sas(
        &self,
        permissions: &str,
        url: SasUrl<'_>,
        expiry: std::time::SystemTime,
        https_only: bool,
    ) -> Result<Zeroizing<String>, BrokerError> {
        self.sas_as_of(DEFAULT_VERSION, permissions, url, expiry, https_only)
    }

    fn sas_as_of(
        &self,
        version: &str,
        permissions: &str,
        url: SasUrl<'_>,
        expiry: std::time::SystemTime,
        https_only: bool,
    ) -> Result<Zeroizing<String>, BrokerError> {
        let blob = blob_of(&self.account, url.host, url.path)?;
        let response = response_headers(url.query)?;
        let header = |index: usize| response[index].as_deref().unwrap_or("");
        let expiry = Civil::at(expiry).iso8601();
        let protocol = if https_only { "https" } else { "https,http" };
        // Permissions, start, expiry, resource, identifier, IP, protocol, version,
        // resource type, snapshot, encryption scope, and five response headers.
        let to_sign = format!(
            "{permissions}\n\n{expiry}\n/blob/{}/{blob}\n\n\n{protocol}\n{version}\nb\n\n\n{}\n{}\n{}\n{}\n{}",
            self.account,
            header(0),
            header(1),
            header(2),
            header(3),
            header(4),
        );
        let key = hmac::Key::new(hmac::HMAC_SHA256, &self.key);
        let signature = Zeroizing::new(STANDARD.encode(hmac::sign(&key, to_sign.as_bytes())));
        let mut query = form_urlencoded::Serializer::new(String::new());
        query
            .append_pair("se", &expiry)
            .append_pair("sp", permissions)
            .append_pair("spr", protocol)
            .append_pair("sv", version)
            .append_pair("sr", "b")
            .append_pair("sig", &signature);
        let mut query = Zeroizing::new(query.finish());
        // Percent-encoded, so that a space or a plus sign cannot be read as the other.
        for (name, value) in SAS_QUERY.iter().zip(&response) {
            if let Some(value) = value {
                query.push('&');
                query.push_str(name);
                query.push('=');
                query.extend(percent_encoding::utf8_percent_encode(
                    value,
                    percent_encoding::NON_ALPHANUMERIC,
                ));
            }
        }
        Ok(query)
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

    fn sas_signer() -> Signer {
        // base64 of "0123456789abcdef0123456789abcdef".
        let key = b"MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=";
        Signer::new(key, b"account", AzureService::Blob, UNIX_EPOCH).unwrap()
    }

    /// 2026-11-10T12:00:00Z.
    fn sas_expiry() -> std::time::SystemTime {
        UNIX_EPOCH + Duration::from_secs(1_794_312_000)
    }

    fn url<'a>(host: &'a str, path: &'a str) -> SasUrl<'a> {
        SasUrl {
            host,
            path,
            query: "",
        }
    }

    /// What `generate_blob_sas` returns with every response header set.
    #[test]
    fn a_signature_covers_the_response_headers_the_url_asks_for() {
        let asked = "rsct=text/csv%3B%20charset%3Dutf-8\
                     &rscd=attachment%3B%20filename%3D%22q3%2Ba.csv%22\
                     &rscc=no-store&rsce=identity&rscl=en";
        let query = sas_signer()
            .sas_as_of(
                "2026-06-06",
                "r",
                SasUrl {
                    host: "account.blob.core.windows.net",
                    path: "/exports/dir/report%201.csv",
                    query: asked,
                },
                sas_expiry(),
                true,
            )
            .unwrap();
        let expected = "se=2026-11-10T12%3A00%3A00Z&sp=r&spr=https&sv=2026-06-06&sr=b\
             &rscc=no-store&rscd=attachment%3B%20filename%3D%22q3%2Ba.csv%22&rsce=identity\
             &rscl=en&rsct=text/csv%3B%20charset%3Dutf-8\
             &sig=d6XgFWooyTj0bDtXQMcgZvu3PR2wZQEXXCEHiS6F2zM%3D";
        // Compared as sent: a decoder that took `+` for a space would hide a difference.
        let split = |query: &str| -> std::collections::BTreeMap<String, String> {
            let pairs = query.split('&').map(|pair| pair.split_once('=').unwrap());
            pairs
                .map(|(name, value)| {
                    let decoded = percent_decode_str(value).decode_utf8().unwrap();
                    (name.to_owned(), decoded.into_owned())
                })
                .collect()
        };
        assert_eq!(split(&query), split(expected));
        assert!(!query.contains('+') && !query.contains(' '));
    }

    #[test]
    fn a_url_carries_only_response_headers_each_once() {
        let sas = |query: &str| {
            let url = SasUrl {
                host: "account.blob.core.windows.net",
                path: "/c/b",
                query,
            };
            sas_signer().sas("r", url, sas_expiry(), true)
        };
        sas("rsct=text/plain").unwrap();
        for refused in [
            "sp=rwd",
            "se=2099-01-01T00%3A00%3A00Z",
            "sig=AAAA",
            "comp=metadata",
            "snapshot=2020",
            "rsct=a&rsct=b",
            "RSCT=text/plain",
            "rsct=",
            "rsct",
            "rsct=a%0d%0aSet-Cookie:%20x",
            "rsct=%ff",
        ] {
            let error = sas(refused).unwrap_err();
            assert_eq!(error.code(), ErrorCode::BadRequest, "{refused}");
        }
    }

    fn pairs(query: &str) -> Vec<(String, String)> {
        form_urlencoded::parse(query.as_bytes())
            .into_owned()
            .collect()
    }

    /// Each expected query is what `generate_blob_sas` of `azure-storage-blob` 12.30.3
    /// returns for the same key, blob and expiry, which signs as version 2026-06-06.
    #[test]
    fn a_shared_access_signature_matches_the_azure_sdks() {
        let host = "account.blob.core.windows.net";
        let path = "/exports/dir/report%201.csv";
        for (permissions, expected) in [
            (
                "r",
                "se=2026-11-10T12%3A00%3A00Z&sp=r&spr=https&sv=2026-06-06&sr=b&sig=9m5AH0wk0LU8q2tySS5V573/eHDAjwxNQH76WdPILSU%3D",
            ),
            (
                "cw",
                "se=2026-11-10T12%3A00%3A00Z&sp=cw&spr=https&sv=2026-06-06&sr=b&sig=RYLG8qp7vXKbjEFHhdvQ7TENdo/hlLIGJUh1RzX4pQA%3D",
            ),
            (
                "d",
                "se=2026-11-10T12%3A00%3A00Z&sp=d&spr=https&sv=2026-06-06&sr=b&sig=HVw3Jckdw/o47sAsQz/YFCE%2BCBYEW76l/13yvQA2Z90%3D",
            ),
        ] {
            let query = sas_signer()
                .sas_as_of(
                    "2026-06-06",
                    permissions,
                    url(host, path),
                    sas_expiry(),
                    true,
                )
                .unwrap();
            assert_eq!(pairs(&query), pairs(expected), "{permissions}");
            // An emulator has the account in the path, and names the same blob.
            let emulated = sas_signer()
                .sas_as_of(
                    "2026-06-06",
                    permissions,
                    url("127.0.0.1", &format!("/account{path}")),
                    sas_expiry(),
                    true,
                )
                .unwrap();
            assert_eq!(pairs(&emulated), pairs(expected));
        }
    }

    #[test]
    fn a_signature_is_for_the_version_seal_sends_and_says_if_http_is_allowed() {
        let query = sas_signer()
            .sas(
                "r",
                url("account.blob.core.windows.net", "/c/b"),
                sas_expiry(),
                false,
            )
            .unwrap();
        let pairs = pairs(&query);
        let value = |name: &str| {
            let found = pairs.iter().find(|(key, _)| key == name);
            found.map(|(_, value)| value.as_str())
        };
        assert_eq!(value("sv"), Some(DEFAULT_VERSION));
        assert_eq!(value("spr"), Some("https,http"));
        assert_eq!(value("sr"), Some("b"));
        assert_eq!(value("st"), None);
    }

    /// seal signs for the blob it reads the URL to mean, so a URL it cannot read for
    /// certain is refused: the signature could otherwise be for another blob.
    #[test]
    fn a_url_that_does_not_name_one_blob_of_the_account_is_refused() {
        for (host, path) in [
            ("account.blob.core.windows.net", "/"),
            ("account.blob.core.windows.net", "/container"),
            ("account.blob.core.windows.net", "/container/"),
            ("account.blob.core.windows.net", "//blob"),
            ("account.blob.core.windows.net", "/c/%ff"),
            ("files.example.com", "/container/blob"),
            ("accountx.blob.core.windows.net", "/container/blob"),
            ("127.0.0.1", "/other/container/blob"),
            ("127.0.0.1", "/account/container"),
            ("127.0.0.1", "/accountx/container/blob"),
        ] {
            let error = sas_signer()
                .sas("r", url(host, path), sas_expiry(), true)
                .unwrap_err();
            assert_eq!(error.code(), ErrorCode::BadRequest, "{host}{path}");
        }
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
    fn a_callers_api_version_must_be_one_date() {
        let key = b"Eby8vdM02xNOcqFlqUwJPLlmEtlCDXJ1OUzFT50uSRZ6IFsuFq2UVErCz4I6tq/K1SZFPTOtr/KBHBeksoGMGw==";
        let signer = Signer::new(key, b"devstoreaccount1", AzureService::Blob, UNIX_EPOCH).unwrap();
        for version in [
            "latest",
            "2021-12-02 ",
            "2021-12-2",
            "2021/12/02",
            "20211202",
        ] {
            let mut map = headers(&[("x-ms-version", version)]);
            let error = signer.sign("GET", "/devstoreaccount1/c", "", &mut map);
            assert_eq!(
                error.unwrap_err().code(),
                ErrorCode::BadRequest,
                "{version}"
            );
            assert!(!map.contains_key("authorization"));
        }
        let mut map = headers(&[("x-ms-version", "2021-12-02")]);
        map.append("x-ms-version", HeaderValue::from_static("2019-02-02"));
        let error = signer.sign("GET", "/devstoreaccount1/c", "", &mut map);
        assert_eq!(error.unwrap_err().code(), ErrorCode::BadRequest);
        let mut map = headers(&[("x-ms-version", "2019-02-02")]);
        signer
            .sign("GET", "/devstoreaccount1/c", "", &mut map)
            .unwrap();
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
