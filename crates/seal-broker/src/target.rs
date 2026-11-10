//! The caller's target URL, parsed strictly.
//!
//! A policy matches on what a URL means, and a provider acts on how it is written.
//! So a URL that a parser would rewrite is refused rather than normalised: if the
//! two could differ, a request could match one path and reach another.

use std::net::IpAddr;

use seal_format::policy::{Destination, Scheme};

use crate::error::{BrokerError, ErrorCode};

/// A target URL that has been checked.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Target {
    /// The scheme.
    pub scheme: Scheme,
    /// The host, as written. An IPv6 literal keeps its brackets.
    pub host: String,
    /// The port, with the scheme's default applied.
    pub port: u16,
    /// The path, as written.
    pub path: String,
    /// The query, as written, without the `?`.
    pub query: Option<String>,
}

impl Target {
    /// Parses a target URL, refusing anything a parser would rewrite.
    ///
    /// # Errors
    ///
    /// Returns [`ErrorCode::BadRequest`] for a URL that is malformed, has
    /// credentials or a fragment, or would change when normalised. The error never
    /// includes the URL.
    pub fn parse(text: &str) -> Result<Self, BrokerError> {
        let bad = |detail| BrokerError::new(ErrorCode::BadRequest, detail);
        let parsed = url::Url::parse(text).map_err(|_| bad("URL is not valid"))?;
        let scheme = match parsed.scheme() {
            "https" => Scheme::Https,
            "http" => Scheme::Http,
            _ => return Err(bad("URL scheme is not http or https")),
        };
        if !parsed.username().is_empty() || parsed.password().is_some() {
            return Err(bad("URL has credentials"));
        }
        if parsed.fragment().is_some() || text.contains('#') {
            return Err(bad("URL has a fragment"));
        }
        let host = parsed.host_str().ok_or_else(|| bad("URL has no host"))?;
        if host.ends_with('.') {
            return Err(bad("URL host has a trailing dot"));
        }

        // Compare what follows the scheme with what the parser made of it.
        let rest = text
            .strip_prefix(parsed.scheme())
            .and_then(|rest| rest.strip_prefix("://"))
            .ok_or_else(|| bad("URL would change when normalised"))?;
        let (authority, after_authority) = rest
            .find(['/', '?'])
            .map_or((rest, ""), |index| rest.split_at(index));
        let (written_host, written_port) =
            split_authority(authority).ok_or_else(|| bad("URL would change when normalised"))?;
        if written_host != host {
            return Err(bad("URL host is not normalised"));
        }
        let default_port = match scheme {
            Scheme::Https => 443,
            Scheme::Http => 80,
        };
        let port = match written_port {
            None => default_port,
            Some(written) => written
                .parse::<u16>()
                .ok()
                .filter(|port| written == port.to_string() && *port != 0)
                .ok_or_else(|| bad("URL port is not valid"))?,
        };

        let mut normalised = parsed.path().to_owned();
        if let Some(query) = parsed.query() {
            normalised.push('?');
            normalised.push_str(query);
        }
        // A URL with no path means the root, and that alone is not a rewrite.
        let written = if after_authority.is_empty() {
            "/"
        } else {
            after_authority
        };
        if written != normalised {
            return Err(bad("URL path would change when normalised"));
        }
        Ok(Self {
            scheme,
            host: host.to_owned(),
            port,
            path: parsed.path().to_owned(),
            query: parsed.query().map(str::to_owned),
        })
    }

    /// Whether this target is within a destination: the same scheme, host and port,
    /// and within any path prefix.
    #[must_use]
    pub fn matches(&self, destination: &Destination) -> bool {
        let Destination::Http {
            scheme,
            host,
            path_prefix,
            ..
        } = destination
        else {
            return false;
        };
        *scheme == self.scheme
            && host.as_str() == self.host
            && destination.effective_port() == self.port
            && path_prefix
                .as_deref()
                .is_none_or(|prefix| self.path_is_within(prefix))
    }

    /// Whether the path is within a prefix, on a segment boundary.
    ///
    /// Under a prefix, an encoded dot or separator is refused, because a provider
    /// could decode it into a path outside the prefix. Without a prefix any path is
    /// allowed anyway, so object names containing `%2F` still work.
    fn path_is_within(&self, prefix: &str) -> bool {
        let lower = self.path.to_ascii_lowercase();
        if ["%2e", "%2f", "%5c"].iter().any(|e| lower.contains(e)) {
            return false;
        }
        if prefix.ends_with('/') {
            self.path.starts_with(prefix)
        } else {
            self.path == prefix
                || self
                    .path
                    .strip_prefix(prefix)
                    .is_some_and(|rest| rest.starts_with('/'))
        }
    }

    /// The host without an IPv6 literal's brackets, for resolving and for TLS.
    #[must_use]
    pub fn bare_host(&self) -> &str {
        self.host
            .strip_prefix('[')
            .and_then(|host| host.strip_suffix(']'))
            .unwrap_or(&self.host)
    }

    /// The host as an address, if it is an IP literal.
    #[must_use]
    pub fn ip_literal(&self) -> Option<IpAddr> {
        self.bare_host().parse().ok()
    }

    /// The `Host` header's value, leaving out the scheme's default port.
    #[must_use]
    pub fn authority(&self) -> String {
        let default_port = match self.scheme {
            Scheme::Https => 443,
            Scheme::Http => 80,
        };
        if self.port == default_port {
            self.host.clone()
        } else {
            format!("{}:{}", self.host, self.port)
        }
    }
}

/// Splits `host:port`, keeping an IPv6 literal's brackets with the host.
fn split_authority(authority: &str) -> Option<(&str, Option<&str>)> {
    if authority.starts_with('[') {
        let end = authority.find(']')?;
        let (host, rest) = authority.split_at(end + 1);
        return match rest.strip_prefix(':') {
            Some(port) => Some((host, Some(port))),
            None if rest.is_empty() => Some((host, None)),
            None => None,
        };
    }
    match authority.split_once(':') {
        Some((host, port)) => Some((host, Some(port))),
        None => Some((authority, None)),
    }
}

#[cfg(test)]
mod tests {
    use seal_format::policy::Host;

    use super::*;

    fn destination(
        scheme: Scheme,
        host: &str,
        port: Option<u16>,
        prefix: Option<&str>,
    ) -> Destination {
        Destination::Http {
            scheme,
            host: Host::new(host).unwrap(),
            port,
            path_prefix: prefix.map(str::to_owned),
        }
    }

    fn api(prefix: Option<&str>) -> Destination {
        destination(Scheme::Https, "api.example.com", None, prefix)
    }

    fn matches(url: &str, destination: &Destination) -> bool {
        Target::parse(url).is_ok_and(|target| target.matches(destination))
    }

    #[test]
    fn parses_the_parts_of_a_url() {
        let target = Target::parse("https://api.example.com:8443/v2/orders?a=1&b=%20").unwrap();
        assert_eq!(target.scheme, Scheme::Https);
        assert_eq!(target.host, "api.example.com");
        assert_eq!(target.port, 8443);
        assert_eq!(target.path, "/v2/orders");
        assert_eq!(target.query.as_deref(), Some("a=1&b=%20"));
        assert_eq!(target.authority(), "api.example.com:8443");
    }

    #[test]
    fn applies_default_ports_and_a_root_path() {
        let target = Target::parse("https://api.example.com").unwrap();
        assert_eq!(target.port, 443);
        assert_eq!(target.path, "/");
        assert_eq!(target.authority(), "api.example.com");
        assert_eq!(Target::parse("http://a.example.com").unwrap().port, 80);
        assert_eq!(
            Target::parse("https://a.example.com:443/")
                .unwrap()
                .authority(),
            "a.example.com"
        );
    }

    #[test]
    fn handles_ip_literals() {
        let target = Target::parse("https://[2001:db8::1]:8443/a").unwrap();
        assert_eq!(target.host, "[2001:db8::1]");
        assert_eq!(target.bare_host(), "2001:db8::1");
        assert_eq!(target.ip_literal(), Some("2001:db8::1".parse().unwrap()));
        assert_eq!(target.port, 8443);
        assert_eq!(target.authority(), "[2001:db8::1]:8443");
        let target = Target::parse("https://192.0.2.1/").unwrap();
        assert_eq!(target.ip_literal(), Some("192.0.2.1".parse().unwrap()));
        assert_eq!(
            Target::parse("https://a.example.com/")
                .unwrap()
                .ip_literal(),
            None
        );
    }

    /// Known URL bypass attempts: traversal, encoded separators, look-alike hosts.
    #[test]
    fn refuses_urls_that_a_parser_would_rewrite() {
        for url in [
            "https://api.example.com/v2/../admin",
            "https://api.example.com/v2/./orders",
            "https://api.example.com/v2/%2e%2e/admin",
            "https://api.example.com/v2/%2E./admin",
            "https://api.example.com/v2\\..\\admin",
            "https://API.example.com/v2/",
            "https://api.example.com./v2/",
            "https://api.example.com:443x/",
            "https://api.example.com:0/",
            "https://api.example.com:0443/",
            "https://api.example.com:99999/",
            "https://user@api.example.com/",
            "https://api.example.com@evil.example/",
            "https://user:pass@api.example.com/",
            "https://api.example.com/#fragment",
            "https://api.example.com/v2/#",
            "https://api.example.com/a b",
            "https://bücher.example/",
            "https://0x7f.0.0.1/",
            "https://127.1/",
            "https://[::FFFF:1.2.3.4]/",
            "https:/api.example.com/",
            "https:api.example.com/",
            "https:///api.example.com/",
            "HTTPS://api.example.com/",
            " https://api.example.com/",
            "https://api.example.com/\n",
            "ftp://api.example.com/",
            "file:///etc/passwd",
            "not a url",
            "",
        ] {
            assert!(Target::parse(url).is_err(), "{url:?}");
        }
    }

    #[test]
    fn errors_do_not_echo_the_url() {
        let error = Target::parse("https://user:SECRETVALUE@api.example.com/").unwrap_err();
        assert!(!error.to_string().contains("SECRETVALUE"));
        assert_eq!(error.code(), ErrorCode::BadRequest);
    }

    #[test]
    fn matching_is_exact_on_scheme_host_and_port() {
        let destination = api(None);
        assert!(matches("https://api.example.com/", &destination));
        assert!(matches(
            "https://api.example.com:443/any/path",
            &destination
        ));
        assert!(!matches("http://api.example.com/", &destination));
        assert!(!matches("https://api.example.com:8443/", &destination));
        assert!(!matches("https://evil.example.com/", &destination));
        assert!(!matches(
            "https://api.example.com.evil.example/",
            &destination
        ));
        assert!(!matches("https://evilapi.example.com/", &destination));
        assert!(!matches("https://sub.api.example.com/", &destination));
    }

    #[test]
    fn matching_uses_the_destination_port() {
        let custom = destination(Scheme::Https, "api.example.com", Some(8443), None);
        assert!(matches("https://api.example.com:8443/", &custom));
        assert!(!matches("https://api.example.com/", &custom));
        let explicit = destination(Scheme::Https, "api.example.com", Some(443), None);
        assert!(matches("https://api.example.com/", &explicit));
        let plain = destination(Scheme::Http, "api.example.com", None, None);
        assert!(matches("http://api.example.com:80/", &plain));
        assert!(!matches("https://api.example.com/", &plain));
    }

    #[test]
    fn matching_handles_ip_literals_exactly() {
        let v6 = destination(Scheme::Https, "[2001:db8::1]", None, None);
        assert!(matches("https://[2001:db8::1]/", &v6));
        assert!(!matches("https://[2001:db8::2]/", &v6));
    }

    #[test]
    fn a_prefix_ending_in_a_slash_matches_what_is_below_it() {
        let destination = api(Some("/v2/"));
        assert!(matches("https://api.example.com/v2/", &destination));
        assert!(matches("https://api.example.com/v2/orders", &destination));
        assert!(matches(
            "https://api.example.com/v2/orders?a=1",
            &destination
        ));
        assert!(!matches("https://api.example.com/v2", &destination));
        assert!(!matches("https://api.example.com/v3/", &destination));
        assert!(!matches("https://api.example.com/", &destination));
    }

    #[test]
    fn a_prefix_without_a_slash_matches_on_a_segment_boundary() {
        let destination = api(Some("/v2"));
        assert!(matches("https://api.example.com/v2", &destination));
        assert!(matches("https://api.example.com/v2/", &destination));
        assert!(matches("https://api.example.com/v2/orders", &destination));
        assert!(!matches("https://api.example.com/v2x", &destination));
        assert!(!matches("https://api.example.com/v2-admin/", &destination));
        assert!(!matches("https://api.example.com/v", &destination));
    }

    #[test]
    fn under_a_prefix_encoded_separators_are_refused() {
        let destination = api(Some("/v2/"));
        for url in [
            "https://api.example.com/v2/a%2f..%2fadmin",
            "https://api.example.com/v2/a%2F..%2Fadmin",
            "https://api.example.com/v2/%2e%2e%2fadmin",
            "https://api.example.com/v2/a%5c..%5cadmin",
        ] {
            assert!(!matches(url, &destination), "{url}");
        }
    }

    #[test]
    fn without_a_prefix_encoded_separators_are_allowed() {
        // Object names in S3 and Azure can contain them.
        assert!(matches("https://api.example.com/bucket/a%2Fb", &api(None)));
    }

    #[test]
    fn matching_is_case_sensitive_on_paths() {
        assert!(!matches("https://api.example.com/V2/", &api(Some("/v2/"))));
    }

    #[test]
    fn a_postgres_destination_never_matches_a_url() {
        let postgres = Destination::Postgres {
            host: Host::new("db.example.com").unwrap(),
            port: 443,
            databases: vec!["a".to_owned()],
            user: seal_format::policy::Part::Literal("u".to_owned()),
            tls: seal_format::policy::PgTls::VerifyFull,
            allow_replication: false,
        };
        assert!(!matches("https://db.example.com/", &postgres));
    }
}
