//! Wrapped keys in a bucket of an S3-compatible object store, so that several instances
//! on separate machines share them: `<prefix><keyset>/<kid>.json`, the files a
//! [`DirKeySource`](crate::DirKeySource) keeps, so that a directory and a bucket can be
//! copied into each other.
//!
//! The bucket holds only wrapped keys. Whoever can write to it can take keys away from
//! seal or put deleted ones back, and opens nothing without the wrapping key.
//!
//! Requests are signed with AWS Signature Version 4 and addressed in the path style,
//! `https://<endpoint>/<bucket>/<key>`. A key is stored only if none is there
//! (`If-None-Match: *`), and replaced only if it is still the one that was read
//! (`If-Match`), so the store must support conditional writes. Destroying a keyset
//! deletes every version of its objects, so that a bucket with versioning keeps no
//! copy of them.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Mutex, PoisonError};
use std::time::{Duration, SystemTime};

use async_trait::async_trait;
use bytes::Bytes;
use http::{Request, StatusCode, header};
use http_body_util::Full;
use percent_encoding::percent_encode;
use seal_format::KeysetId;
use zeroize::Zeroizing;

use crate::KeyError;
use crate::civil::Civil;
use crate::credentials::read_credentials;
use crate::https::{Https, Names, Roots};
use crate::sigv4::{
    ALGORITHM, AWS_ENCODE, CanonicalParts, canonical_request, canonical_uri, scope, sha256_hex,
    signature, signing_key, string_to_sign,
};
use crate::source::{KeySource, MAX_WRAPPED_KEY_BYTES, WrappedKey, is_rewrap_of};

/// How to reach the bucket.
#[derive(Clone, Debug)]
pub struct S3KeySourceConfig {
    /// The store's endpoint, such as `https://s3.gra.io.cloud.ovh.net`. `https` only.
    pub endpoint: String,
    /// The region requests are signed for.
    pub region: String,
    /// The bucket.
    pub bucket: String,
    /// What every object's name starts with: empty, or a path that ends in `/`.
    pub prefix: String,
    /// A file in the AWS shared credentials format that only seal's user can read, with
    /// an access key id and a secret access key. It is read for every request, so new
    /// credentials need no restart.
    pub credentials_file: PathBuf,
    /// The profile in that file.
    pub profile: String,
    /// The CA that issued the endpoint's certificate, if it is not a public one.
    pub ca_pem: Option<String>,
    /// How long one request may take.
    pub timeout: Duration,
    /// The most keys accepted per keyset.
    pub max_keys: usize,
}

/// The most keysets whose keys are remembered between fetches.
const MAX_REMEMBERED_KEYSETS: usize = 4096;

/// The most a listing may be: a thousand entries, generously.
const MAX_LISTING_BYTES: usize = 2 * 1024 * 1024;

/// How many entries one listing asks for.
const PAGE: usize = 1000;

/// How many pages of versions are deleted before a keyset's deletion gives up.
const MAX_DELETE_ROUNDS: usize = 64;

const NAMES: Names = Names {
    url: "the key source endpoint",
    not_https: "the key source endpoint must be plain https",
    no_host: "the key source endpoint has no host",
    ca: "the key source CA",
};

/// A key as last fetched, by its object's name in the keyset.
type Remembered = HashMap<String, (String, WrappedKey)>;

/// A key source in an S3 bucket.
pub struct S3KeySource {
    https: Https,
    region: String,
    bucket: String,
    prefix: String,
    credentials_file: PathBuf,
    profile: String,
    timeout: Duration,
    max_keys: usize,
    /// Each keyset's keys with their `ETag`s, so that a refresh downloads only the
    /// objects that changed. A stored key changes only when it is wrapped again.
    remembered: Mutex<HashMap<KeysetId, Remembered>>,
}

impl std::fmt::Debug for S3KeySource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("S3KeySource")
            .field("host", &self.https.host())
            .field("bucket", &self.bucket)
            .field("prefix", &self.prefix)
            .finish_non_exhaustive()
    }
}

/// An object, or one version of one, in a listing.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct Entry {
    key: String,
    etag: String,
    version: Option<String>,
}

/// One page of a listing of objects or of versions.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct Listing {
    entries: Vec<Entry>,
    prefixes: Vec<String>,
    truncated: bool,
    /// The query parameters that ask for the next page.
    next: Vec<(&'static str, String)>,
}

/// Reads a `ListBucketResult` or a `ListVersionsResult`.
fn parse_listing(xml: &[u8]) -> Result<Listing, KeyError> {
    use quick_xml::events::Event;
    const BAD: KeyError = KeyError::Invalid("the key source's listing");
    let text = std::str::from_utf8(xml).map_err(|_| BAD)?;
    let mut reader = quick_xml::Reader::from_str(text);
    reader.config_mut().check_end_names = true;
    reader.config_mut().trim_text(false);

    let mut listing = Listing::default();
    let mut path: Vec<String> = Vec::new();
    let mut entry: Option<Entry> = None;
    let mut content = String::new();
    loop {
        match reader.read_event().map_err(|_| BAD)? {
            Event::Eof => break,
            Event::DocType(_) => return Err(BAD),
            Event::Start(start) => {
                let name = start.local_name();
                let name: &str = name.as_ref();
                if path.len() == 1 && matches!(name, "Contents" | "Version" | "DeleteMarker") {
                    entry = Some(Entry::default());
                }
                path.push(name.to_owned());
                content.clear();
            }
            Event::End(_) => {
                let name = path.pop().ok_or(BAD)?;
                let value = std::mem::take(&mut content);
                match (path.len(), path.last().map(String::as_str), name.as_str()) {
                    (1, _, "Contents" | "Version" | "DeleteMarker") => {
                        listing.entries.push(entry.take().ok_or(BAD)?);
                    }
                    (2, Some("Contents" | "Version" | "DeleteMarker"), field) => {
                        let entry = entry.as_mut().ok_or(BAD)?;
                        match field {
                            "Key" => entry.key = value,
                            "ETag" => entry.etag = value,
                            "VersionId" => entry.version = Some(value),
                            _ => {}
                        }
                    }
                    (2, Some("CommonPrefixes"), "Prefix") => listing.prefixes.push(value),
                    (1, _, "IsTruncated") => listing.truncated = value == "true",
                    (1, _, "NextContinuationToken") => {
                        listing.next.push(("continuation-token", value));
                    }
                    (1, _, "NextKeyMarker") => listing.next.push(("key-marker", value)),
                    (1, _, "NextVersionIdMarker") => {
                        listing.next.push(("version-id-marker", value));
                    }
                    _ => {}
                }
            }
            Event::Text(part) => content.push_str(&part),
            Event::CData(part) => content.push_str(&part),
            Event::GeneralRef(reference) => {
                if reference.is_char_ref() {
                    content.push(reference.resolve_char_ref().ok().flatten().ok_or(BAD)?);
                } else {
                    content.push_str(
                        quick_xml::escape::resolve_predefined_entity(&reference).ok_or(BAD)?,
                    );
                }
            }
            Event::Empty(_) | Event::Comment(_) | Event::Decl(_) | Event::PI(_) => {}
        }
    }
    if !path.is_empty() || (listing.truncated && listing.next.is_empty()) {
        return Err(BAD);
    }
    Ok(listing)
}

/// A condition on a write.
enum Only {
    /// Nothing is stored under the name.
    IfAbsent,
    /// What is stored has this `ETag`.
    IfStill(String),
}

impl S3KeySource {
    /// Configures the source. Connects to nothing.
    ///
    /// # Errors
    ///
    /// Returns [`KeyError::Invalid`] if the endpoint, region, bucket, prefix or CA is
    /// not valid.
    pub fn new(config: &S3KeySourceConfig) -> Result<Self, KeyError> {
        let roots = config.ca_pem.as_deref().map_or(Roots::Public, Roots::Pem);
        let https = Https::new(&config.endpoint, roots, None, NAMES)?;
        if !https.base_path().is_empty() {
            return Err(KeyError::Invalid("the key source endpoint has a path"));
        }
        let plain = |value: &str, more: &[u8]| {
            !value.is_empty()
                && value
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || more.contains(&byte))
        };
        if !plain(&config.region, b"-") {
            return Err(KeyError::Invalid("the key source region"));
        }
        let bucket = &config.bucket;
        if !(3..=63).contains(&bucket.len())
            || !plain(bucket, b".-")
            || bucket.bytes().any(|byte| byte.is_ascii_uppercase())
            || bucket.starts_with(['.', '-'])
        {
            return Err(KeyError::Invalid("the key source bucket"));
        }
        let prefix = &config.prefix;
        let segments_are_names = prefix
            .strip_suffix('/')
            .is_some_and(|path| path.split('/').all(|segment| plain(segment, b"._-")));
        if !prefix.is_empty() && !segments_are_names {
            return Err(KeyError::Invalid(
                "the key source prefix is empty, or names ending in a slash",
            ));
        }
        Ok(Self {
            https,
            region: config.region.clone(),
            bucket: bucket.clone(),
            prefix: prefix.clone(),
            credentials_file: config.credentials_file.clone(),
            profile: config.profile.clone(),
            timeout: config.timeout,
            max_keys: config.max_keys,
            remembered: Mutex::new(HashMap::new()),
        })
    }

    /// The name of a keyset's objects' common start.
    fn keyset_prefix(&self, keyset: &KeysetId) -> String {
        format!("{}{}/", self.prefix, keyset.as_str())
    }

    /// The path of an object, each segment encoded once.
    fn path(&self, object: &str) -> String {
        let mut path = format!("/{}", self.bucket);
        for segment in object.split('/') {
            path.push('/');
            path.push_str(&percent_encode(segment.as_bytes(), AWS_ENCODE).to_string());
        }
        path
    }

    /// Sends one signed request, and gives the status and the body, which may be at
    /// most `limit` bytes.
    async fn call(
        &self,
        method: &'static str,
        path: &str,
        query: &[(&str, &str)],
        body: Vec<u8>,
        only: Option<&Only>,
        limit: usize,
    ) -> Result<(StatusCode, Zeroizing<Vec<u8>>), KeyError> {
        let credentials = read_credentials(&self.credentials_file, &self.profile)?;
        let civil = Civil::at(SystemTime::now());
        let (amz_date, date_stamp) = (civil.amz_date(), civil.date_stamp());
        let payload_hash = sha256_hex(&body);
        let encode = |part: &str| percent_encode(part.as_bytes(), AWS_ENCODE).to_string();
        let mut pairs: Vec<(String, String)> = query
            .iter()
            .map(|(name, value)| (encode(name), encode(value)))
            .collect();
        pairs.sort();
        let query = pairs
            .iter()
            .map(|(name, value)| format!("{name}={value}"))
            .collect::<Vec<_>>()
            .join("&");

        let authority = self.https.authority();
        let mut signed_headers = vec![
            ("host".to_owned(), authority.clone()),
            ("x-amz-content-sha256".to_owned(), payload_hash.clone()),
            ("x-amz-date".to_owned(), amz_date.clone()),
        ];
        if let Some(token) = &credentials.session_token {
            signed_headers.push(("x-amz-security-token".to_owned(), token.to_string()));
        }
        let (canonical, signed) = canonical_request(&CanonicalParts {
            method,
            uri: canonical_uri(path, true),
            query: query.clone(),
            headers: &signed_headers,
            payload_hash: &payload_hash,
        });
        let scope = scope(&date_stamp, &self.region, "s3");
        let key = signing_key(
            credentials.secret_access_key.as_bytes(),
            &date_stamp,
            &self.region,
            "s3",
        );
        let signature = signature(&key, &string_to_sign(&amz_date, &scope, &canonical));
        let authorization = format!(
            "{ALGORITHM} Credential={}/{scope}, SignedHeaders={signed}, Signature={signature}",
            credentials.access_key_id
        );

        let uri = if query.is_empty() {
            path.to_owned()
        } else {
            format!("{path}?{query}")
        };
        let mut request = Request::builder().method(method).uri(uri);
        for (name, value) in &signed_headers {
            request = request.header(name.as_str(), value.as_str());
        }
        request = request.header(header::AUTHORIZATION, authorization);
        if !body.is_empty() {
            request = request.header(header::CONTENT_TYPE, "application/json");
        }
        request = match only {
            Some(Only::IfAbsent) => request.header(header::IF_NONE_MATCH, "*"),
            Some(Only::IfStill(etag)) => request.header(header::IF_MATCH, etag.as_str()),
            None => request,
        };
        let request = request
            .body(Full::new(Bytes::from(body)))
            .map_err(|_| KeyError::Invalid("the key source request"))?;
        let (status, body) = tokio::time::timeout(self.timeout, self.https.send(request, limit))
            .await
            .map_err(|_| KeyError::Unavailable)??;
        if !status.is_success() && status != StatusCode::NOT_FOUND {
            // The store's reason, without the body, which may quote the request.
            tracing::warn!(status = status.as_u16(), method, "the key source refused");
        }
        Ok((status, body))
    }

    /// One page of the objects whose names start with `prefix`, or with a `delimiter`
    /// the next parts of their names.
    async fn list(
        &self,
        prefix: &str,
        delimiter: Option<&str>,
        page: usize,
        next: &[(&'static str, String)],
    ) -> Result<Listing, KeyError> {
        let page = page.min(PAGE).to_string();
        let mut query = vec![("list-type", "2"), ("prefix", prefix), ("max-keys", &page)];
        if let Some(delimiter) = delimiter {
            query.push(("delimiter", delimiter));
        }
        query.extend(next.iter().map(|(name, value)| (*name, value.as_str())));
        let bucket = format!("/{}", self.bucket);
        let (status, body) = self
            .call("GET", &bucket, &query, Vec::new(), None, MAX_LISTING_BYTES)
            .await?;
        if status != StatusCode::OK {
            return Err(KeyError::Unavailable);
        }
        parse_listing(&body)
    }

    /// Downloads and reads one key, if it is there.
    async fn get(&self, object: &str) -> Result<Option<WrappedKey>, KeyError> {
        let (status, body) = self
            .call(
                "GET",
                &self.path(object),
                &[],
                Vec::new(),
                None,
                MAX_WRAPPED_KEY_BYTES,
            )
            .await?;
        match status {
            StatusCode::NOT_FOUND => Ok(None),
            StatusCode::OK => serde_json::from_slice(&body)
                .map(Some)
                .map_err(|_| KeyError::Invalid("a wrapped key object is not valid")),
            _ => Err(KeyError::Unavailable),
        }
    }

    /// Uploads a key under a condition. Gives whether the condition held.
    async fn put(&self, key: &WrappedKey, only: &Only) -> Result<bool, KeyError> {
        let object = format!("{}{}.json", self.keyset_prefix(&key.keyset), key.kid);
        let json = serde_json::to_vec_pretty(key).map_err(|_| KeyError::Unavailable)?;
        let (status, _) = self
            .call("PUT", &self.path(&object), &[], json, Some(only), 64 * 1024)
            .await?;
        match status {
            StatusCode::OK | StatusCode::CREATED | StatusCode::NO_CONTENT => Ok(true),
            StatusCode::PRECONDITION_FAILED => Ok(false),
            // A store without conditional writes, or one busy with another write to
            // the same name: nothing was stored.
            _ => Err(KeyError::Unavailable),
        }
    }

    /// The objects of a keyset that are keys: their names within it, and their entries.
    fn key_objects<'a>(prefix: &str, listing: &'a Listing) -> Vec<(&'a str, &'a Entry)> {
        listing
            .entries
            .iter()
            .filter_map(|entry| {
                let name = entry.key.strip_prefix(prefix)?;
                let is_key =
                    name.ends_with(".json") && !name.starts_with('.') && !name.contains('/');
                is_key.then_some((name, entry))
            })
            .collect()
    }

    fn remembered(&self) -> std::sync::MutexGuard<'_, HashMap<KeysetId, Remembered>> {
        self.remembered
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }

    /// Deletes one version of an object, or the object where there are no versions.
    async fn delete(&self, entry: &Entry) -> Result<(), KeyError> {
        let version = entry
            .version
            .as_deref()
            .filter(|version| !version.is_empty() && *version != "null");
        let query: Vec<(&str, &str)> = version
            .map(|version| ("versionId", version))
            .into_iter()
            .collect();
        let (status, _) = self
            .call(
                "DELETE",
                &self.path(&entry.key),
                &query,
                Vec::new(),
                None,
                64 * 1024,
            )
            .await?;
        if status.is_success() || status == StatusCode::NOT_FOUND {
            Ok(())
        } else {
            Err(KeyError::Unavailable)
        }
    }

    /// One page of every version of the objects whose names start with `prefix`, and
    /// of the markers their deletions left. `None` if the store has no such listing.
    async fn list_versions(&self, prefix: &str) -> Result<Option<Listing>, KeyError> {
        let page = PAGE.to_string();
        let query = [("versions", ""), ("prefix", prefix), ("max-keys", &page)];
        let bucket = format!("/{}", self.bucket);
        let (status, body) = self
            .call("GET", &bucket, &query, Vec::new(), None, MAX_LISTING_BYTES)
            .await?;
        match status {
            StatusCode::OK => parse_listing(&body).map(Some),
            StatusCode::NOT_IMPLEMENTED => Ok(None),
            _ => Err(KeyError::Unavailable),
        }
    }
}

#[async_trait]
impl KeySource for S3KeySource {
    async fn wrapped_keys(&self, keyset: &KeysetId) -> Result<Vec<WrappedKey>, KeyError> {
        let prefix = self.keyset_prefix(keyset);
        let listing = self
            .list(&prefix, None, self.max_keys.saturating_add(1), &[])
            .await?;
        let objects = Self::key_objects(&prefix, &listing);
        if listing.truncated || objects.len() > self.max_keys {
            return Err(KeyError::Unavailable);
        }
        let before = self.remembered().get(keyset).cloned().unwrap_or_default();
        let mut now = Remembered::new();
        let mut keys = Vec::with_capacity(objects.len());
        for (name, entry) in objects {
            let unchanged = before
                .get(name)
                .filter(|(etag, _)| !etag.is_empty() && *etag == entry.etag);
            let key = match unchanged {
                Some((_, key)) => key.clone(),
                // Deleted since the listing.
                None => match self.get(&entry.key).await? {
                    Some(key) => key,
                    None => continue,
                },
            };
            let kid = name.strip_suffix(".json").unwrap_or(name);
            if key.keyset != *keyset || key.kid.as_str() != kid {
                return Err(KeyError::Invalid(
                    "a wrapped key object's keyset or kid differs from its name",
                ));
            }
            now.insert(name.to_owned(), (entry.etag.clone(), key.clone()));
            keys.push(key);
        }
        let mut remembered = self.remembered();
        if now.is_empty() {
            remembered.remove(keyset);
        } else {
            if remembered.len() >= MAX_REMEMBERED_KEYSETS && !remembered.contains_key(keyset) {
                remembered.clear();
            }
            remembered.insert(keyset.clone(), now);
        }
        Ok(keys)
    }

    async fn store(&self, key: &WrappedKey) -> Result<(), KeyError> {
        if self.put(key, &Only::IfAbsent).await? {
            Ok(())
        } else {
            Err(KeyError::AlreadyExists)
        }
    }

    async fn delete_keyset(&self, keyset: &KeysetId) -> Result<(), KeyError> {
        let prefix = self.keyset_prefix(keyset);
        self.remembered().remove(keyset);
        for _ in 0..MAX_DELETE_ROUNDS {
            // Every version and every deletion marker, where the store keeps them:
            // otherwise a bucket with versioning would keep the keys.
            let listing = match self.list_versions(&prefix).await? {
                Some(listing) => listing,
                None => self.list(&prefix, None, PAGE, &[]).await?,
            };
            if listing.entries.is_empty() {
                return Ok(());
            }
            for entry in &listing.entries {
                if entry.key.starts_with(&prefix) {
                    self.delete(entry).await?;
                }
            }
        }
        Err(KeyError::Unavailable)
    }

    async fn keysets(&self) -> Result<Vec<KeysetId>, KeyError> {
        let mut keysets = Vec::new();
        let mut next = Vec::new();
        loop {
            let listing = self.list(&self.prefix, Some("/"), PAGE, &next).await?;
            for found in &listing.prefixes {
                let keyset = found
                    .strip_prefix(self.prefix.as_str())
                    .and_then(|name| name.strip_suffix('/'))
                    .and_then(|name| KeysetId::new(name).ok())
                    .ok_or(KeyError::Invalid("a prefix that is not a keyset's"))?;
                keysets.push(keyset);
            }
            if !listing.truncated {
                break;
            }
            next = listing.next;
        }
        keysets.sort();
        keysets.dedup();
        Ok(keysets)
    }

    async fn replace(&self, old: &WrappedKey, new: &WrappedKey) -> Result<(), KeyError> {
        const CHANGED: KeyError = KeyError::Invalid("a key changed while it was wrapped again");
        if !is_rewrap_of(old, new) {
            return Err(KeyError::Invalid("a key may only be wrapped another way"));
        }
        let object = format!("{}{}.json", self.keyset_prefix(&old.keyset), old.kid);
        let listing = self.list(&object, None, 1, &[]).await?;
        let entry = listing
            .entries
            .iter()
            .find(|entry| entry.key == object)
            .ok_or(CHANGED)?;
        if self.get(&object).await?.as_ref() != Some(old) {
            return Err(CHANGED);
        }
        // Only if it is still the object that was just read.
        if self.put(new, &Only::IfStill(entry.etag.clone())).await? {
            Ok(())
        } else {
            Err(CHANGED)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config() -> S3KeySourceConfig {
        S3KeySourceConfig {
            endpoint: "https://s3.gra.io.cloud.ovh.net".to_owned(),
            region: "gra".to_owned(),
            bucket: "seal-keys".to_owned(),
            prefix: "keys/".to_owned(),
            credentials_file: PathBuf::from("/etc/seal/s3-credentials"),
            profile: "default".to_owned(),
            ca_pem: None,
            timeout: Duration::from_secs(5),
            max_keys: 16,
        }
    }

    #[test]
    fn only_a_plain_endpoint_region_bucket_and_prefix_are_accepted() {
        assert!(S3KeySource::new(&config()).is_ok());
        let with = |change: fn(&mut S3KeySourceConfig)| {
            let mut config = config();
            change(&mut config);
            S3KeySource::new(&config).is_ok()
        };
        assert!(with(|config| config.prefix = String::new()));
        assert!(with(|config| config.prefix = "a/b.c/".to_owned()));
        assert!(!with(|config| config.prefix = "keys".to_owned()));
        assert!(!with(|config| config.prefix = "/keys/".to_owned()));
        assert!(!with(|config| config.prefix = "a//b/".to_owned()));
        assert!(!with(|config| config.prefix = "a b/".to_owned()));
        assert!(!with(|config| config.bucket = "ab".to_owned()));
        assert!(!with(|config| config.bucket = "Seal-Keys".to_owned()));
        assert!(!with(|config| config.bucket = "seal/keys".to_owned()));
        assert!(!with(|config| config.region = String::new()));
        assert!(!with(|config| config.region = "gra/s3".to_owned()));
        assert!(!with(
            |config| config.endpoint = "http://s3.example".to_owned()
        ));
        assert!(!with(
            |config| config.endpoint = "https://s3.example/path".to_owned()
        ));
        assert!(!with(
            |config| config.ca_pem = Some("not a certificate".to_owned())
        ));
    }

    #[test]
    fn an_objects_path_has_each_segment_encoded_once() {
        let source = S3KeySource::new(&config()).unwrap();
        assert_eq!(
            source.path("keys/acme/k-1.json"),
            "/seal-keys/keys/acme/k-1.json"
        );
        assert_eq!(
            source.path("keys/a:b/k.json"),
            "/seal-keys/keys/a%3Ab/k.json"
        );
    }

    #[test]
    fn a_listing_of_objects_is_read() {
        let xml = br#"<?xml version="1.0" encoding="UTF-8"?>
<ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Name>seal-keys</Name><Prefix>keys/acme/</Prefix><KeyCount>2</KeyCount>
  <IsTruncated>true</IsTruncated>
  <NextContinuationToken>a+b/c=</NextContinuationToken>
  <Contents><Key>keys/acme/k-1.json</Key><ETag>&quot;abc&quot;</ETag><Size>10</Size>
    <Owner><ID>x</ID></Owner></Contents>
  <Contents><Key>keys/acme/a&amp;b.json</Key><ETag>"def"</ETag></Contents>
  <CommonPrefixes><Prefix>keys/acme/</Prefix></CommonPrefixes>
  <CommonPrefixes><Prefix>keys/beta/</Prefix></CommonPrefixes>
</ListBucketResult>"#;
        let listing = parse_listing(xml).unwrap();
        assert_eq!(
            listing.entries,
            [
                Entry {
                    key: "keys/acme/k-1.json".to_owned(),
                    etag: "\"abc\"".to_owned(),
                    version: None,
                },
                Entry {
                    key: "keys/acme/a&b.json".to_owned(),
                    etag: "\"def\"".to_owned(),
                    version: None,
                },
            ]
        );
        assert_eq!(listing.prefixes, ["keys/acme/", "keys/beta/"]);
        assert!(listing.truncated);
        assert_eq!(listing.next, [("continuation-token", "a+b/c=".to_owned())]);
    }

    #[test]
    fn a_listing_of_versions_is_read_with_its_deletion_markers() {
        let xml = br"<ListVersionsResult>
  <IsTruncated>false</IsTruncated>
  <Version><Key>keys/acme/k-1.json</Key><VersionId>v2</VersionId><IsLatest>false</IsLatest>
    <ETag>e2</ETag></Version>
  <DeleteMarker><Key>keys/acme/k-1.json</Key><VersionId>v3</VersionId></DeleteMarker>
  <Version><Key>keys/acme/k-2.json</Key><VersionId>null</VersionId><ETag>e1</ETag></Version>
</ListVersionsResult>";
        let listing = parse_listing(xml).unwrap();
        let versions: Vec<_> = listing
            .entries
            .iter()
            .map(|entry| (entry.key.as_str(), entry.version.as_deref()))
            .collect();
        assert_eq!(
            versions,
            [
                ("keys/acme/k-1.json", Some("v2")),
                ("keys/acme/k-1.json", Some("v3")),
                ("keys/acme/k-2.json", Some("null")),
            ]
        );
        assert!(!listing.truncated);
    }

    #[test]
    fn a_listing_that_is_not_one_is_refused() {
        for bad in [
            &b"not xml <"[..],
            b"<ListBucketResult><Contents></ListBucketResult>",
            b"<!DOCTYPE x><ListBucketResult/>",
            // More to come, and no way to ask for it.
            b"<ListBucketResult><IsTruncated>true</IsTruncated></ListBucketResult>",
            b"\xff\xfe",
        ] {
            assert!(parse_listing(bad).is_err(), "{bad:?}");
        }
        assert_eq!(
            parse_listing(b"<ListBucketResult></ListBucketResult>").unwrap(),
            Listing::default()
        );
    }

    #[test]
    fn only_key_objects_of_the_keyset_itself_count() {
        let entry = |key: &str| Entry {
            key: key.to_owned(),
            ..Entry::default()
        };
        let listing = Listing {
            entries: vec![
                entry("keys/acme/k-1.json"),
                entry("keys/acme/notes.txt"),
                entry("keys/acme/.k-2.json"),
                entry("keys/acme/deeper/k-3.json"),
                entry("keys/acmeother/k-4.json"),
            ],
            ..Listing::default()
        };
        let names: Vec<_> = S3KeySource::key_objects("keys/acme/", &listing)
            .into_iter()
            .map(|(name, _)| name)
            .collect();
        assert_eq!(names, ["k-1.json"]);
    }

    use std::sync::Arc;

    use crate::keyring::KeyringConfig;
    use crate::{FileKeyWrap, KeyWrap, KeyWraps, Keyring, Keys, RewrapOptions, rewrap};

    /// RustFS in a container, behind a proxy that gives it the TLS the source insists
    /// on, with a bucket that keeps versions.
    struct Store {
        _container: seal_testkit::containers::Container,
        _directory: tempfile::TempDir,
        proxy: seal_testkit::tls_proxy::TlsProxy,
        config: S3KeySourceConfig,
    }

    impl Store {
        async fn start() -> Self {
            use seal_testkit::containers::{RUSTFS_ACCESS_KEY, RUSTFS_SECRET_KEY, rustfs};

            let container = rustfs().await.expect("RustFS starts");
            let proxy =
                seal_testkit::tls_proxy::TlsProxy::start(container.port(9000).unwrap()).await;
            let directory = tempfile::tempdir().unwrap();
            let credentials_file = directory.path().join("credentials");
            std::fs::write(
                &credentials_file,
                format!(
                    "[default]\naws_access_key_id = {RUSTFS_ACCESS_KEY}\n\
                     aws_secret_access_key = {RUSTFS_SECRET_KEY}\n\
                     [wrong]\naws_access_key_id = {RUSTFS_ACCESS_KEY}\n\
                     aws_secret_access_key = not-the-secret\n"
                ),
            )
            .unwrap();
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(&credentials_file, std::fs::Permissions::from_mode(0o600))
                    .unwrap();
            }
            let config = S3KeySourceConfig {
                endpoint: format!("https://localhost:{}", proxy.port()),
                region: "us-east-1".to_owned(),
                bucket: "seal-keys".to_owned(),
                prefix: "keys/".to_owned(),
                credentials_file,
                profile: "default".to_owned(),
                ca_pem: Some(proxy.ca_pem().to_owned()),
                timeout: Duration::from_secs(20),
                max_keys: 16,
            };
            let store = Self {
                _container: container,
                _directory: directory,
                proxy,
                config,
            };
            let source = store.source();
            let (status, body) = source
                .call("PUT", "/seal-keys", &[], Vec::new(), None, 64 * 1024)
                .await
                .unwrap();
            assert!(
                status.is_success(),
                "create the bucket: {status} {}",
                String::from_utf8_lossy(&body)
            );
            let versioning =
                b"<VersioningConfiguration xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">\
                <Status>Enabled</Status></VersioningConfiguration>";
            let (status, body) = source
                .call(
                    "PUT",
                    "/seal-keys",
                    &[("versioning", "")],
                    versioning.to_vec(),
                    None,
                    64 * 1024,
                )
                .await
                .unwrap();
            assert!(
                status.is_success(),
                "keep versions: {status} {}",
                String::from_utf8_lossy(&body)
            );
            store
        }

        fn source(&self) -> S3KeySource {
            S3KeySource::new(&self.config).unwrap()
        }

        /// How many requests the store has had: the source opens a connection for each.
        fn requests(&self) -> usize {
            self.proxy.connections()
        }
    }

    fn keyset(name: &str) -> KeysetId {
        KeysetId::new(name).unwrap()
    }

    fn file_wrap(byte: u8) -> Arc<dyn KeyWrap> {
        Arc::new(FileKeyWrap::from_bytes(&[byte; 32]).unwrap())
    }

    fn keyring(config: &S3KeySourceConfig, wraps: impl Into<KeyWraps>) -> Keyring {
        Keyring::new(
            Arc::new(S3KeySource::new(config).unwrap()) as Arc<dyn KeySource>,
            wraps,
            KeyringConfig::default(),
        )
        .unwrap()
    }

    /// A key made and wrapped as the keyring does it, and not stored.
    async fn fresh_key(wrap: &dyn KeyWrap, keyset: &KeysetId, kid: &str) -> WrappedKey {
        use base64::Engine;
        let kid = seal_format::id::KeyId::new(kid.to_owned()).unwrap();
        let (private, public) = seal_format::PrivateKey::generate();
        let wrapped = wrap.wrap(keyset, &kid, &private).await.unwrap();
        WrappedKey {
            keyset: keyset.clone(),
            kid,
            public: public.to_base64url(),
            created: 1,
            wrap_id: wrap.id().to_owned(),
            wrapped: base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(wrapped),
        }
    }

    /// One version of an object, as the store kept it.
    async fn version_of(source: &S3KeySource, entry: &Entry) -> Option<WrappedKey> {
        let version = entry.version.as_deref()?;
        let query: Vec<(&str, &str)> = if version.is_empty() || version == "null" {
            Vec::new()
        } else {
            vec![("versionId", version)]
        };
        let (status, body) = source
            .call(
                "GET",
                &source.path(&entry.key),
                &query,
                Vec::new(),
                None,
                MAX_WRAPPED_KEY_BYTES,
            )
            .await
            .unwrap();
        // A deletion marker has no content.
        status
            .is_success()
            .then(|| serde_json::from_slice(&body).unwrap())
    }

    /// Every version the store keeps under a prefix, with what each holds. `None` if
    /// the store does not list versions.
    async fn versions(source: &S3KeySource, prefix: &str) -> Option<Vec<(Entry, WrappedKey)>> {
        let listing = source.list_versions(prefix).await.unwrap()?;
        let mut kept = Vec::new();
        for entry in listing.entries {
            if let Some(key) = version_of(source, &entry).await {
                kept.push((entry, key));
            }
        }
        Some(kept)
    }

    /// What every store must do for seal, whichever it is: the one in a container, and
    /// a real one. `acme` and `beta` are keysets under a prefix nothing else uses. The
    /// keysets are destroyed at the end.
    async fn a_store_does_what_seal_needs(
        config: &S3KeySourceConfig,
        old: &Arc<dyn KeyWrap>,
        new: &Arc<dyn KeyWrap>,
    ) {
        let (acme, beta) = (keyset("acme"), keyset("beta"));
        let source = S3KeySource::new(config).unwrap();
        assert!(
            source.keysets().await.unwrap().is_empty(),
            "the prefix is not empty"
        );
        assert!(source.wrapped_keys(&acme).await.unwrap().is_empty());

        // One instance makes keys, and another, with nothing but the bucket, has them.
        let first = keyring(config, Arc::clone(old));
        let made = first.generate(&acme).await.unwrap();
        let rotated = first.rotate(&acme).await.unwrap();
        first.generate(&beta).await.unwrap();
        let second = keyring(config, Arc::clone(old));
        assert_eq!(
            second.current_public_key(&acme).await.unwrap().0,
            rotated.kid
        );
        assert_eq!(second.public_keys(&acme).await.unwrap().len(), 2);
        assert_eq!(
            source.keysets().await.unwrap(),
            [acme.clone(), beta.clone()]
        );

        // `If-None-Match`: a key is never replaced by storing.
        assert_eq!(source.store(&made).await, Err(KeyError::AlreadyExists));

        // Stored by several at once, one key is stored once. A store may refuse the
        // others as already there, or as busy with the same name.
        let contested = fresh_key(old.as_ref(), &beta, "k-contested").await;
        let attempts = (0..8).map(|_| {
            let (source, key) = (S3KeySource::new(config).unwrap(), contested.clone());
            async move { source.store(&key).await }
        });
        let outcomes = futures_util::future::join_all(attempts).await;
        let stored = outcomes.iter().filter(|outcome| outcome.is_ok()).count();
        assert_eq!(stored, 1, "{outcomes:?}");
        assert!(
            outcomes.iter().all(|outcome| matches!(
                outcome,
                Ok(()) | Err(KeyError::AlreadyExists | KeyError::Unavailable)
            )),
            "{outcomes:?}"
        );
        assert!(
            source
                .wrapped_keys(&beta)
                .await
                .unwrap()
                .contains(&contested)
        );

        // `If-Match`: an upload that names another `ETag` than the object's is refused,
        // and the object is as it was.
        let changed = WrappedKey {
            wrapped: "AAAA".to_owned(),
            ..contested.clone()
        };
        let stale = Only::IfStill("\"00000000000000000000000000000000\"".to_owned());
        assert_eq!(source.put(&changed, &stale).await, Ok(false));
        assert!(
            source
                .wrapped_keys(&beta)
                .await
                .unwrap()
                .contains(&contested)
        );

        // The wrapping key is replaced in place, while both instances could be running.
        let both = KeyWraps::new(Arc::clone(new), vec![Arc::clone(old)]).unwrap();
        let done = rewrap(&source, &both, RewrapOptions::default())
            .await
            .unwrap();
        assert_eq!((done.rewrapped, done.left), (4, 0));
        assert_eq!(
            keyring(config, Arc::clone(new))
                .current_public_key(&acme)
                .await
                .unwrap(),
            second.current_public_key(&acme).await.unwrap()
        );
        assert!(
            keyring(config, Arc::clone(old))
                .current_public_key(&acme)
                .await
                .is_err(),
            "the old wrapping key alone no longer reads the keys"
        );
        let again = rewrap(&source, &both, RewrapOptions::default())
            .await
            .unwrap();
        assert_eq!((again.rewrapped, again.left), (0, 4));

        // A key that is no longer the one that was read is not replaced.
        assert!(matches!(
            source.replace(&made, &made).await,
            Err(KeyError::Invalid(_))
        ));

        // Destroying a keyset leaves no version of its keys, and no other keyset's.
        source.delete_keyset(&acme).await.unwrap();
        if let Some(kept) = versions(&source, &source.keyset_prefix(&acme)).await {
            assert!(kept.is_empty(), "{} versions were kept", kept.len());
        }
        assert!(source.wrapped_keys(&acme).await.unwrap().is_empty());
        assert_eq!(source.keysets().await.unwrap(), std::slice::from_ref(&beta));
        assert_eq!(source.wrapped_keys(&beta).await.unwrap().len(), 2);
        source.delete_keyset(&beta).await.unwrap();
        assert!(source.keysets().await.unwrap().is_empty());
    }

    #[tokio::test(flavor = "multi_thread")]
    #[ignore = "needs Docker"]
    async fn keys_are_stored_shared_wrapped_again_and_destroyed_in_a_bucket() {
        let store = Store::start().await;
        let (old, new) = (file_wrap(7), file_wrap(8));
        a_store_does_what_seal_needs(&store.config, &old, &new).await;

        let source = store.source();
        let first = keyring(&store.config, Arc::clone(&old));
        first.generate(&keyset("acme")).await.unwrap();
        first.rotate(&keyset("acme")).await.unwrap();

        // Something that is not a key is not a key of the keyset.
        let (status, _) = source
            .call(
                "PUT",
                &source.path("keys/acme/notes.txt"),
                &[],
                b"x".to_vec(),
                None,
                64 * 1024,
            )
            .await
            .unwrap();
        assert!(status.is_success());
        assert_eq!(source.wrapped_keys(&keyset("acme")).await.unwrap().len(), 2);

        // More keys than a keyset may have is refused, not cut short.
        let crowded = S3KeySource::new(&S3KeySourceConfig {
            max_keys: 1,
            ..store.config.clone()
        })
        .unwrap();
        assert_eq!(
            crowded.wrapped_keys(&keyset("acme")).await,
            Err(KeyError::Unavailable)
        );

        // With the wrong secret, nothing is read.
        let wrong = S3KeySource::new(&S3KeySourceConfig {
            profile: "wrong".to_owned(),
            ..store.config.clone()
        })
        .unwrap();
        assert_eq!(
            wrong.wrapped_keys(&keyset("acme")).await,
            Err(KeyError::Unavailable)
        );
    }

    /// What the operations guide says of the load on the store: one request for each
    /// loaded keyset every `refresh_interval`, and a download only for a key that is
    /// new or was wrapped again.
    #[tokio::test(flavor = "multi_thread")]
    #[ignore = "needs Docker"]
    async fn a_refresh_costs_one_request_for_each_loaded_keyset() {
        const KEYSETS: usize = 5;
        const REFRESHES: usize = 4;
        let store = Store::start().await;
        let (old, new) = (file_wrap(7), file_wrap(8));
        let names: Vec<KeysetId> = (0..KEYSETS)
            .map(|index| keyset(&format!("tenant-{index}")))
            .collect();
        {
            let maker = keyring(&store.config, Arc::clone(&old));
            for name in &names {
                maker.generate(name).await.unwrap();
                maker.rotate(name).await.unwrap();
            }
        }

        // At the source: a first fetch lists and downloads each key, and a second only
        // lists.
        let source = store.source();
        let before = store.requests();
        assert_eq!(source.wrapped_keys(&names[0]).await.unwrap().len(), 2);
        assert_eq!(store.requests() - before, 1 + 2);
        let before = store.requests();
        assert_eq!(source.wrapped_keys(&names[0]).await.unwrap().len(), 2);
        assert_eq!(store.requests() - before, 1);

        // A key wrapped again is downloaded once more, and the others are not.
        let both = KeyWraps::new(Arc::clone(&new), vec![Arc::clone(&old)]).unwrap();
        let one = source.wrapped_keys(&names[0]).await.unwrap().remove(0);
        let private = old
            .unwrap(&one.keyset, &one.kid, &one.wrapped_bytes().unwrap())
            .await
            .unwrap();
        let rewrapped = {
            use base64::Engine;
            WrappedKey {
                wrap_id: new.id().to_owned(),
                wrapped: base64::engine::general_purpose::URL_SAFE_NO_PAD
                    .encode(new.wrap(&one.keyset, &one.kid, &private).await.unwrap()),
                ..one.clone()
            }
        };
        store.source().replace(&one, &rewrapped).await.unwrap();
        let before = store.requests();
        assert!(
            source
                .wrapped_keys(&names[0])
                .await
                .unwrap()
                .contains(&rewrapped)
        );
        assert_eq!(store.requests() - before, 1 + 1);

        // A running instance, with every keyset loaded and nothing changing.
        let refresh_interval = Duration::from_secs(1);
        let running = Keyring::new(
            Arc::new(store.source()) as Arc<dyn KeySource>,
            both,
            KeyringConfig {
                refresh_interval,
                max_stale: Duration::from_secs(30),
                ..KeyringConfig::default()
            },
        )
        .unwrap();
        for name in &names {
            running.current_public_key(name).await.unwrap();
        }
        // Past the refreshes that the loading itself set off.
        tokio::time::sleep(refresh_interval * 2).await;
        let before = store.requests();
        tokio::time::sleep(refresh_interval * u32::try_from(REFRESHES).unwrap()).await;
        let requests = store.requests() - before;
        println!(
            "{requests} requests for {KEYSETS} loaded keysets over {REFRESHES} refresh intervals"
        );
        // At most one for each keyset each interval, and the interval a measurement
        // starts or ends in: a refresh waits for the maintenance tick after its
        // interval, so there are fewer. A download for each key would be three times
        // as many. And the keysets were refreshed, not left alone.
        let most = KEYSETS * (REFRESHES + 1);
        assert!(
            (KEYSETS * REFRESHES / 2..=most).contains(&requests),
            "{requests} requests, and at most {most} were expected"
        );
        for name in &names {
            running.current_public_key(name).await.unwrap();
        }
    }

    /// What the operations guide says of a bucket with versioning when the wrapping
    /// key is replaced: the earlier versions stay, the old wrapping key still opens
    /// them, and removing them, as a lifecycle rule does, takes nothing seal needs.
    #[tokio::test(flavor = "multi_thread")]
    #[ignore = "needs Docker"]
    async fn earlier_versions_stay_under_the_old_wrapping_key_until_they_are_removed() {
        let store = Store::start().await;
        let (old, new) = (file_wrap(7), file_wrap(8));
        let acme = keyset("acme");
        let source = store.source();
        let prefix = source.keyset_prefix(&acme);
        let maker = keyring(&store.config, Arc::clone(&old));
        maker.generate(&acme).await.unwrap();
        maker.rotate(&acme).await.unwrap();
        let before = keyring(&store.config, Arc::clone(&old))
            .public_keys(&acme)
            .await
            .unwrap();

        let both = KeyWraps::new(Arc::clone(&new), vec![Arc::clone(&old)]).unwrap();
        let done = rewrap(&source, &both, RewrapOptions::default())
            .await
            .unwrap();
        assert_eq!((done.rewrapped, done.left), (2, 0));

        // Each key now has two versions: the one seal reads, under the new wrapping
        // key, and the earlier one, which the old wrapping key still opens.
        let kept = versions(&source, &prefix)
            .await
            .expect("versions are listed");
        assert_eq!(kept.len(), 4);
        let earlier: Vec<_> = kept
            .iter()
            .filter(|(_, key)| key.wrap_id == old.id())
            .collect();
        assert_eq!(earlier.len(), 2);
        for (_, key) in &earlier {
            let private = old
                .unwrap(&key.keyset, &key.kid, &key.wrapped_bytes().unwrap())
                .await
                .expect("the old wrapping key opens the earlier version");
            assert_eq!(private.public_key().unwrap(), key.public_key().unwrap());
            assert!(
                new.unwrap(&key.keyset, &key.kid, &key.wrapped_bytes().unwrap())
                    .await
                    .is_err()
            );
        }
        // seal itself reads only the current versions, so it no longer needs the old
        // wrapping key.
        assert!(
            source
                .wrapped_keys(&acme)
                .await
                .unwrap()
                .iter()
                .all(|key| key.wrap_id == new.id())
        );
        assert_eq!(
            keyring(&store.config, Arc::clone(&new))
                .public_keys(&acme)
                .await
                .unwrap(),
            before
        );

        // The earlier versions are removed, as a lifecycle rule that expires them does.
        for (entry, _) in &earlier {
            source.delete(entry).await.unwrap();
        }
        let kept = versions(&source, &prefix).await.unwrap();
        assert_eq!(kept.len(), 2);
        assert!(kept.iter().all(|(_, key)| key.wrap_id == new.id()));
        // Nothing the old wrapping key opens is left, and seal has what it had.
        assert_eq!(
            keyring(&store.config, Arc::clone(&new))
                .public_keys(&acme)
                .await
                .unwrap(),
            before
        );
        let again = rewrap(&source, &both, RewrapOptions::default())
            .await
            .unwrap();
        assert_eq!((again.rewrapped, again.left), (0, 2));
    }

    fn setting(name: &str) -> Option<String> {
        std::env::var(name).ok().filter(|value| !value.is_empty())
    }

    /// The real OVHcloud KMS service key the environment names, as
    /// `tests/real_kms.rs` reads it.
    fn real_ovh_kms() -> Option<Arc<dyn KeyWrap>> {
        use crate::{OvhKmsAuth, OvhKmsConfig, OvhKmsWrap};
        let file = |name: &str| {
            let path = setting(name)?;
            Some(std::fs::read_to_string(&path).unwrap_or_else(|_| panic!("cannot read {path}")))
        };
        let auth = match (
            file("SEAL_TEST_OVH_KMS_TOKEN_FILE"),
            file("SEAL_TEST_OVH_KMS_CERT"),
            file("SEAL_TEST_OVH_KMS_KEY"),
        ) {
            (Some(token), _, _) => OvhKmsAuth::Token(Zeroizing::new(token)),
            (None, Some(cert_pem), Some(key_pem)) => OvhKmsAuth::Certificate {
                cert_pem,
                key_pem: Zeroizing::new(key_pem),
            },
            _ => return None,
        };
        let wrap = OvhKmsWrap::new(&OvhKmsConfig {
            endpoint: setting("SEAL_TEST_OVH_KMS_ENDPOINT")?,
            okms_id: setting("SEAL_TEST_OVH_KMS_OKMS_ID")?,
            key_id: setting("SEAL_TEST_OVH_KMS_KEY_ID")?,
            auth,
            ca_pem: None,
            timeout: Duration::from_secs(10),
        })
        .expect("the OVHcloud KMS settings are valid");
        Some(Arc::new(wrap))
    }

    /// A real bucket, such as one in OVHcloud Object Storage, with credentials from the
    /// environment. Skips if they are not there.
    ///
    /// - `SEAL_TEST_S3_ENDPOINT`, such as `https://s3.gra.io.cloud.ovh.net`,
    ///   `SEAL_TEST_S3_REGION` and `SEAL_TEST_S3_BUCKET`. The bucket exists already.
    /// - `SEAL_TEST_S3_CREDENTIALS_FILE`: a shared credentials file that only its owner
    ///   can read, and optionally `SEAL_TEST_S3_PROFILE`.
    ///
    /// Everything is written under a prefix made for this run, `seal-test-<random>/`,
    /// and destroyed at the end. With the `SEAL_TEST_OVH_KMS_*` settings of
    /// `tests/real_kms.rs` as well, the keys are moved from a wrapping key file to that
    /// service key, as a deployment that starts with a file moves to the KMS.
    #[tokio::test(flavor = "multi_thread")]
    #[ignore = "needs a bucket in an S3-compatible object store"]
    async fn a_real_bucket_does_what_seal_needs() {
        let (Some(endpoint), Some(region), Some(bucket), Some(credentials_file)) = (
            setting("SEAL_TEST_S3_ENDPOINT"),
            setting("SEAL_TEST_S3_REGION"),
            setting("SEAL_TEST_S3_BUCKET"),
            setting("SEAL_TEST_S3_CREDENTIALS_FILE"),
        ) else {
            println!("skipped: SEAL_TEST_S3_* is not set");
            return;
        };
        let mut random = [0_u8; 6];
        ring::rand::SecureRandom::fill(&ring::rand::SystemRandom::new(), &mut random).unwrap();
        let run: String = random.iter().map(|byte| format!("{byte:02x}")).collect();
        let config = S3KeySourceConfig {
            endpoint,
            region,
            bucket,
            prefix: format!("seal-test-{run}/"),
            credentials_file: PathBuf::from(credentials_file),
            profile: setting("SEAL_TEST_S3_PROFILE").unwrap_or_else(|| "default".to_owned()),
            ca_pem: None,
            timeout: Duration::from_secs(20),
            max_keys: 16,
        };
        let old = file_wrap(7);
        let new = real_ovh_kms().unwrap_or_else(|| {
            println!("SEAL_TEST_OVH_KMS_* is not set: wrapping with files only");
            file_wrap(8)
        });
        println!(
            "under {} in {}, from {} to {}",
            config.prefix,
            config.bucket,
            old.id(),
            new.id()
        );
        a_store_does_what_seal_needs(&config, &old, &new).await;

        // Whether the bucket keeps versions, nothing of this run is left in it.
        let source = S3KeySource::new(&config).unwrap();
        match versions(&source, &config.prefix).await {
            Some(kept) => assert!(kept.is_empty(), "{} versions were left", kept.len()),
            None => println!("the store does not list versions"),
        }
    }
}
