//! The service's configuration, in TOML. Unknown fields are errors, so a typo is
//! never silently ignored. `docs/operations.md` is the reference.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::str::FromStr;
use std::time::Duration;

use serde::Deserialize;
use serde::de::{self, Deserializer};

/// Why a configuration is not valid. Names the setting, never a secret.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConfigError(pub String);

impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "configuration: {}", self.0)
    }
}

impl std::error::Error for ConfigError {}

fn invalid(message: impl Into<String>) -> ConfigError {
    ConfigError(message.into())
}

/// A duration written like `100ms`, `60s`, `15m` or `8h`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Interval(pub Duration);

impl FromStr for Interval {
    type Err = ConfigError;

    fn from_str(text: &str) -> Result<Self, ConfigError> {
        let split = text
            .find(|c: char| !c.is_ascii_digit())
            .ok_or_else(|| invalid(format!("duration {text:?} needs a unit")))?;
        let (number, unit) = text.split_at(split);
        let number: u64 = number
            .parse()
            .map_err(|_| invalid(format!("duration {text:?} is not a number")))?;
        let seconds = |factor: u64| number.checked_mul(factor).map(Duration::from_secs);
        let duration = match unit {
            "ms" => Some(Duration::from_millis(number)),
            "s" => seconds(1),
            "m" => seconds(60),
            "h" => seconds(3600),
            _ => None,
        };
        duration
            .map(Self)
            .ok_or_else(|| invalid(format!("duration {text:?} has an unknown unit")))
    }
}

/// A size written like `65536`, `256KiB`, `1MiB` or `1GiB`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Size(pub u64);

impl FromStr for Size {
    type Err = ConfigError;

    fn from_str(text: &str) -> Result<Self, ConfigError> {
        let split = text
            .find(|c: char| !c.is_ascii_digit())
            .unwrap_or(text.len());
        let (number, unit) = text.split_at(split);
        let number: u64 = number
            .parse()
            .map_err(|_| invalid(format!("size {text:?} is not a number")))?;
        let factor = match unit {
            "" | "B" => 1,
            "KiB" => 1 << 10,
            "MiB" => 1 << 20,
            "GiB" => 1 << 30,
            _ => return Err(invalid(format!("size {text:?} has an unknown unit"))),
        };
        number
            .checked_mul(factor)
            .map(Self)
            .ok_or_else(|| invalid(format!("size {text:?} is too large")))
    }
}

/// A rate written like `1000/s` or `60/m`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Rate {
    /// How many.
    pub count: u32,
    /// Per how long.
    pub per: Duration,
}

impl FromStr for Rate {
    type Err = ConfigError;

    fn from_str(text: &str) -> Result<Self, ConfigError> {
        let (count, unit) = text
            .split_once('/')
            .ok_or_else(|| invalid(format!("rate {text:?} must look like 100/s")))?;
        let count: u32 = count
            .parse()
            .ok()
            .filter(|count| *count > 0)
            .ok_or_else(|| invalid(format!("rate {text:?} needs a positive count")))?;
        let per = match unit {
            "s" => Duration::from_secs(1),
            "m" => Duration::from_secs(60),
            "h" => Duration::from_secs(3600),
            _ => return Err(invalid(format!("rate {text:?} has an unknown unit"))),
        };
        Ok(Self { count, per })
    }
}

macro_rules! from_string {
    ($($type:ty),*) => {$(
        impl<'de> Deserialize<'de> for $type {
            fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
                let text = String::deserialize(deserializer)?;
                text.parse().map_err(|error: ConfigError| de::Error::custom(error.0))
            }
        }
    )*};
}

from_string!(Interval, Size, Rate);

/// The whole configuration.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// Where the service listens.
    pub listen: Listen,
    /// Who may call, and which keysets each may use.
    #[serde(default)]
    pub callers: Vec<CallerConfig>,
    /// Keys.
    pub keys: KeysConfig,
    /// Which addresses may be connected to.
    #[serde(default)]
    pub network: NetworkConfig,
    /// Connections toward providers.
    #[serde(default)]
    pub pools: PoolsConfig,
    /// Limits.
    #[serde(default)]
    pub limits: LimitsConfig,
    /// Audit records.
    #[serde(default)]
    pub audit: AuditConfig,
    /// Metrics and health.
    #[serde(default)]
    pub metrics: MetricsConfig,
}

/// Where the service listens: a Unix socket, or TCP with mutual TLS.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Listen {
    /// A Unix socket path. Callers are identified by their uid.
    pub unix: Option<PathBuf>,
    /// A TCP address. Callers are identified by their certificate's subject.
    pub tcp: Option<SocketAddr>,
    /// TLS for the TCP listener.
    pub tls: Option<TlsFiles>,
    /// How often certificate files are checked for changes.
    #[serde(default = "default_reload")]
    pub reload_interval: Interval,
}

fn default_reload() -> Interval {
    Interval(Duration::from_secs(10))
}

/// Certificate files, in PEM, reloaded when they change.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TlsFiles {
    /// The service's certificate chain.
    pub cert: PathBuf,
    /// The service's private key.
    pub key: PathBuf,
    /// The CA that issues callers' certificates.
    pub client_ca: PathBuf,
}

/// One caller.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CallerConfig {
    /// The name in audit records.
    pub name: String,
    /// The uid, for a Unix socket.
    pub unix_uid: Option<u32>,
    /// The certificate subject, for TLS, such as `CN=app,O=Example`.
    pub cert_subject: Option<String>,
    /// A subject alternative name of the certificate, for TLS: a URI such as
    /// `spiffe://example.org/app`, or a DNS name.
    pub cert_san: Option<String>,
    /// The keysets it may use. `*` means all.
    pub keysets: Vec<String>,
    /// Whether it may make and rotate keys.
    #[serde(default)]
    pub admin: bool,
    /// Whether it may destroy the keysets it may use, which cannot be undone. Separate
    /// from `admin`, so that a caller that makes keysets cannot also end them.
    #[serde(default)]
    pub destroy_keysets: bool,
}

/// Where wrapped keys come from and what unwraps them.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeysConfig {
    /// The key source.
    pub source: SourceConfig,
    /// The wrapping key.
    pub wrap: WrapConfig,
    /// See the keyring.
    #[serde(default = "defaults::idle_evict")]
    pub idle_evict: Interval,
    /// See the keyring.
    #[serde(default = "defaults::refresh_interval")]
    pub refresh_interval: Interval,
    /// See the keyring.
    #[serde(default = "defaults::max_stale")]
    pub max_stale: Interval,
    /// See the keyring.
    #[serde(default = "defaults::max_unwrap_age")]
    pub max_unwrap_age: Interval,
    /// See the keyring.
    #[serde(default = "defaults::max_loaded_keysets")]
    pub max_loaded_keysets: usize,
    /// See the keyring.
    #[serde(default = "defaults::max_keys_per_keyset")]
    pub max_keys_per_keyset: usize,
    /// See the keyring.
    #[serde(default = "defaults::max_live_keys")]
    pub max_live_keys: usize,
    /// See the keyring.
    #[serde(default = "defaults::max_tracked_keysets")]
    pub max_tracked_keysets: usize,
    /// Whether to lock the process's memory.
    #[serde(default)]
    pub lock_memory: LockMemory,
}

/// A key source.
#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum SourceConfig {
    /// A directory of `<keyset>/<kid>.json` files.
    Dir(PathBuf),
    /// A key service over HTTPS with a client certificate.
    Http {
        /// The base URL.
        url: String,
        /// The key service's CA, in PEM.
        ca: PathBuf,
        /// seal's client certificate, in PEM.
        cert: PathBuf,
        /// seal's client key, in PEM.
        key: PathBuf,
    },
}

/// A wrapping key.
#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum WrapConfig {
    /// 32 bytes in a file only seal's user can read.
    File(PathBuf),
}

/// Whether to lock memory, so that key pages are never swapped.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LockMemory {
    /// Do not try.
    Off,
    /// Try, and log once if it fails.
    #[default]
    BestEffort,
    /// Refuse to start if it fails.
    Required,
}

/// Which addresses may be connected to.
#[derive(Clone, Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NetworkConfig {
    /// Always refused.
    #[serde(default)]
    pub deny_cidrs: Vec<String>,
    /// Allowed whatever their class.
    #[serde(default)]
    pub allow_private_cidrs: Vec<String>,
    /// Whether a rule's `allow_private_destination` has any effect.
    #[serde(default)]
    pub honour_private_rules: bool,
    /// More CAs to trust toward providers, in PEM files.
    #[serde(default)]
    pub extra_ca_files: Vec<PathBuf>,
}

/// Connections toward providers.
#[derive(Clone, Copy, Debug, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct PoolsConfig {
    /// The most connections, active or idle.
    pub max_upstream_connections: usize,
    /// The most idle connections to one address.
    pub max_idle_per_host: usize,
    /// How long a connection may stay idle.
    pub idle_timeout: Interval,
    /// The most client-certificate identities.
    pub max_client_cert_identities: usize,
}

impl Default for PoolsConfig {
    fn default() -> Self {
        Self {
            max_upstream_connections: 1024,
            max_idle_per_host: 8,
            idle_timeout: Interval(Duration::from_secs(90)),
            max_client_cert_identities: 256,
        }
    }
}

/// Limits.
#[derive(Clone, Copy, Debug, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct LimitsConfig {
    /// The most `send` streams at once.
    pub max_concurrent_streams: usize,
    /// What one stream may buffer.
    pub per_stream_buffer: Size,
    /// The most capped buffers at once.
    pub max_concurrent_buffered: usize,
    /// The largest capped buffer.
    pub buffer_cap: Size,
    /// The largest request head, including envelopes.
    pub max_head: Size,
    /// The most caller connections at once.
    pub max_caller_connections: usize,
    /// How long a transfer may make no progress.
    pub idle_timeout: Interval,
    /// How long connecting may take.
    pub connect_timeout: Interval,
    /// How long the first response byte may take.
    pub first_byte_timeout: Interval,
    /// The total deadline for a request holding a capped buffer.
    pub buffered_total_timeout: Interval,
    /// An optional total deadline for streamed requests.
    pub max_stream_duration: Option<Interval>,
    /// The longest Postgres session.
    pub pg_max_session: Interval,
    /// Requests per caller.
    pub rate_per_caller: Rate,
    /// Requests per keyset.
    pub rate_per_keyset: Rate,
    /// Startup refuses if the computed memory ceiling exceeds this.
    pub memory_budget: Size,
}

impl Default for LimitsConfig {
    fn default() -> Self {
        Self {
            max_concurrent_streams: 512,
            per_stream_buffer: Size(256 * 1024),
            max_concurrent_buffered: 64,
            buffer_cap: Size(1 << 20),
            max_head: Size(256 * 1024),
            max_caller_connections: 256,
            idle_timeout: Interval(Duration::from_secs(60)),
            connect_timeout: Interval(Duration::from_secs(10)),
            first_byte_timeout: Interval(Duration::from_secs(60)),
            buffered_total_timeout: Interval(Duration::from_secs(60)),
            max_stream_duration: None,
            pg_max_session: Interval(Duration::from_secs(8 * 3600)),
            rate_per_caller: Rate {
                count: 1000,
                per: Duration::from_secs(1),
            },
            rate_per_keyset: Rate {
                count: 200,
                per: Duration::from_secs(1),
            },
            memory_budget: Size(2 << 30),
        }
    }
}

/// Where audit records go.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct AuditConfig {
    /// The sink.
    pub sink: AuditSinkConfig,
    /// What a write failure does.
    pub on_failure: AuditFailure,
}

impl Default for AuditConfig {
    fn default() -> Self {
        Self {
            sink: AuditSinkConfig::Stdout,
            on_failure: AuditFailure::FailClosed,
        }
    }
}

/// An audit sink.
#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum AuditSinkConfig {
    /// One JSON line per record on standard output.
    Stdout,
    /// One JSON line per record, appended to a file.
    File(PathBuf),
}

/// What a failure to write an audit record does.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditFailure {
    /// The request fails rather than go unaudited.
    #[default]
    FailClosed,
    /// The request goes on. For development only.
    BestEffort,
}

/// Metrics and health.
#[derive(Clone, Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MetricsConfig {
    /// Where `/metrics`, `/healthz` and `/readyz` are served, if anywhere.
    pub listen: Option<SocketAddr>,
    /// A file holding the bearer token every request to that address must present.
    /// Needed unless the address is a loopback one.
    pub token_file: Option<PathBuf>,
}

mod defaults {
    use std::time::Duration;

    use super::Interval;

    pub fn idle_evict() -> Interval {
        Interval(Duration::from_secs(15 * 60))
    }
    pub fn refresh_interval() -> Interval {
        Interval(Duration::from_secs(60))
    }
    pub fn max_stale() -> Interval {
        Interval(Duration::from_secs(5 * 60))
    }
    pub fn max_unwrap_age() -> Interval {
        Interval(Duration::from_secs(3600))
    }
    pub fn max_loaded_keysets() -> usize {
        1024
    }
    pub fn max_keys_per_keyset() -> usize {
        16
    }
    pub fn max_live_keys() -> usize {
        4096
    }
    pub fn max_tracked_keysets() -> usize {
        4096
    }
}

impl Config {
    /// Parses and checks a configuration.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError`] naming what is wrong.
    pub fn parse(text: &str) -> Result<Self, ConfigError> {
        let config: Self = toml::from_str(text).map_err(|error| invalid(error.message()))?;
        config.check()?;
        Ok(config)
    }

    /// Reads, parses and checks a configuration file.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError`] naming what is wrong.
    pub fn load(path: &std::path::Path) -> Result<Self, ConfigError> {
        check_not_writable_by_others(path)?;
        let text = std::fs::read_to_string(path)
            .map_err(|_| invalid(format!("cannot read {}", path.display())))?;
        Self::parse(&text)
    }

    fn check(&self) -> Result<(), ConfigError> {
        match (&self.listen.unix, &self.listen.tcp, &self.listen.tls) {
            (Some(_), None, None) | (None, Some(_), Some(_)) => {}
            (None, Some(_), None) => return Err(invalid("listen.tcp needs listen.tls")),
            _ => return Err(invalid("listen needs either unix, or tcp with tls")),
        }
        if self.callers.is_empty() {
            return Err(invalid("there are no callers"));
        }
        let mut names = std::collections::BTreeSet::new();
        let mut uids = std::collections::BTreeSet::new();
        let mut subjects = std::collections::BTreeSet::new();
        let mut sans = std::collections::BTreeSet::new();
        for caller in &self.callers {
            if !names.insert(&caller.name) {
                return Err(invalid(format!("caller {} appears twice", caller.name)));
            }
            let identities = usize::from(caller.unix_uid.is_some())
                + usize::from(caller.cert_subject.is_some())
                + usize::from(caller.cert_san.is_some());
            if identities != 1 {
                return Err(invalid(format!(
                    "caller {} needs exactly one of unix_uid, cert_subject and cert_san",
                    caller.name
                )));
            }
            if self.listen.unix.is_some() != caller.unix_uid.is_some() {
                return Err(invalid(format!(
                    "caller {} is identified in a way this listener cannot see",
                    caller.name
                )));
            }
            // Two callers with one identity would be one caller with the later one's
            // keysets, whatever the earlier one says.
            let is_new = match (&caller.unix_uid, &caller.cert_subject) {
                (Some(uid), _) => uids.insert(*uid),
                (None, Some(subject)) => {
                    let subject = crate::callers::normalise_subject(subject);
                    let is_written_out = subject.split(',').all(|part| {
                        part.split_once('=')
                            .is_some_and(|(name, value)| !name.is_empty() && !value.is_empty())
                    });
                    if !is_written_out {
                        return Err(invalid(format!(
                            "caller {} has a cert_subject that is not attributes like CN=app,O=Example",
                            caller.name
                        )));
                    }
                    subjects.insert(subject)
                }
                (None, None) => match &caller.cert_san {
                    Some(name) => {
                        let is_a_name =
                            !name.is_empty() && name.chars().all(|c| c.is_ascii_graphic());
                        if !is_a_name {
                            return Err(invalid(format!(
                                "caller {} has a cert_san that is not a URI or a DNS name",
                                caller.name
                            )));
                        }
                        sans.insert(crate::callers::Identity::san(name))
                    }
                    None => true,
                },
            };
            if !is_new {
                return Err(invalid(format!(
                    "caller {} has the identity of another caller",
                    caller.name
                )));
            }
            if caller.keysets.is_empty() && !caller.admin {
                return Err(invalid(format!("caller {} has no keysets", caller.name)));
            }
            for keyset in &caller.keysets {
                if keyset != "*" && seal_format::KeysetId::new(keyset.clone()).is_err() {
                    return Err(invalid(format!(
                        "caller {} lists a keyset that is not valid",
                        caller.name
                    )));
                }
            }
        }
        let limits = &self.limits;
        let positive = [
            limits.max_concurrent_streams,
            limits.max_concurrent_buffered,
            limits.max_caller_connections,
            self.pools.max_upstream_connections,
        ];
        if positive.contains(&0) || limits.buffer_cap.0 == 0 || limits.per_stream_buffer.0 == 0 {
            return Err(invalid("a limit is zero"));
        }
        if limits.per_stream_buffer.0 < 16 * 1024 || limits.per_stream_buffer.0 > (1 << 30) {
            return Err(invalid(
                "limits.per_stream_buffer must be between 16KiB and 1GiB",
            ));
        }
        if limits.max_head.0 < 64 * 1024 {
            return Err(invalid("limits.max_head must be at least 64KiB"));
        }
        for cidr in self
            .network
            .deny_cidrs
            .iter()
            .chain(&self.network.allow_private_cidrs)
        {
            cidr.parse::<seal_broker::address::Cidr>()
                .map_err(|_| invalid(format!("address range {cidr:?} is not valid")))?;
        }
        self.keyring()
            .validate()
            .map_err(|error| invalid(error.to_string()))?;
        match (self.metrics.listen, &self.metrics.token_file) {
            (Some(address), None) if !address.ip().is_loopback() => {
                return Err(invalid(
                    "metrics.listen is not a loopback address, so it needs metrics.token_file",
                ));
            }
            (None, Some(_)) => {
                return Err(invalid("metrics.token_file needs metrics.listen"));
            }
            _ => {}
        }
        Ok(())
    }

    /// The keyring's settings.
    #[must_use]
    pub fn keyring(&self) -> seal_keys::KeyringConfig {
        let keys = &self.keys;
        seal_keys::KeyringConfig {
            idle_evict: keys.idle_evict.0,
            refresh_interval: keys.refresh_interval.0,
            max_stale: keys.max_stale.0,
            max_unwrap_age: keys.max_unwrap_age.0,
            max_loaded_keysets: keys.max_loaded_keysets,
            max_keys_per_keyset: keys.max_keys_per_keyset,
            max_live_keys: keys.max_live_keys,
            max_tracked_keysets: keys.max_tracked_keysets,
            ..seal_keys::KeyringConfig::default()
        }
    }
}

/// Refuses a file that its group or others could change.
///
/// # Errors
///
/// Returns [`ConfigError`] if the file cannot be read or is writable by others.
pub fn check_not_writable_by_others(path: &std::path::Path) -> Result<(), ConfigError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let metadata = std::fs::metadata(path)
            .map_err(|_| invalid(format!("cannot read {}", path.display())))?;
        if metadata.permissions().mode() & 0o022 != 0 {
            return Err(invalid(format!(
                "{} is writable by its group or others",
                path.display()
            )));
        }
    }
    let _ = path;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const MINIMAL: &str = r#"
        [listen]
        unix = "/run/seal/seal.sock"

        [[callers]]
        name = "app"
        unix_uid = 990
        keysets = ["*"]

        [keys]
        source = { dir = "/var/lib/seal/keys" }
        wrap = { file = "/etc/seal/kek" }
    "#;

    #[test]
    fn a_minimal_configuration_gets_the_documented_defaults() {
        let config = Config::parse(MINIMAL).unwrap();
        assert_eq!(config.limits.buffer_cap, Size(1 << 20));
        assert_eq!(
            config.limits.idle_timeout,
            Interval(Duration::from_secs(60))
        );
        assert_eq!(config.keys.max_stale, Interval(Duration::from_secs(300)));
        assert_eq!(config.keys.lock_memory, LockMemory::BestEffort);
        assert_eq!(config.audit.on_failure, AuditFailure::FailClosed);
        assert!(!config.network.honour_private_rules);
        assert!(config.limits.max_stream_duration.is_none());
    }

    #[test]
    fn the_examples_in_deploy_parse() {
        for name in ["same-host.toml", "separate-machine.toml"] {
            let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../deploy/config")
                .join(name);
            let text = std::fs::read_to_string(&path).unwrap();
            Config::parse(&text).unwrap_or_else(|error| panic!("{name}: {error}"));
        }
    }

    #[test]
    fn unknown_fields_are_errors() {
        for (old, new) in [
            ("[listen]", "[listen]\ntypo = 1"),
            ("admin", "admin"),
            ("keysets = [\"*\"]", "keysets = [\"*\"]\nadmn = true"),
            ("wrap = { file", "wrap = { fil"),
        ] {
            let text = MINIMAL.replace(old, new);
            if text != MINIMAL {
                assert!(Config::parse(&text).is_err(), "{new}");
            }
        }
        assert!(Config::parse(&format!("{MINIMAL}\n[surprise]\na = 1")).is_err());
    }

    #[test]
    fn listeners_and_callers_must_fit_together() {
        let tcp_without_tls =
            MINIMAL.replace("unix = \"/run/seal/seal.sock\"", "tcp = \"127.0.0.1:1\"");
        assert!(Config::parse(&tcp_without_tls).is_err());
        let both = MINIMAL.replace("unix_uid = 990", "unix_uid = 990\ncert_subject = \"CN=a\"");
        assert!(Config::parse(&both).is_err());
        let cert_on_unix = MINIMAL.replace("unix_uid = 990", "cert_subject = \"CN=a\"");
        assert!(Config::parse(&cert_on_unix).is_err());
        let twice =
            format!("{MINIMAL}\n[[callers]]\nname = \"app\"\nunix_uid = 1\nkeysets = [\"*\"]");
        assert!(Config::parse(&twice).is_err());
        let same_uid =
            format!("{MINIMAL}\n[[callers]]\nname = \"other\"\nunix_uid = 990\nkeysets = [\"*\"]");
        assert!(
            Config::parse(&same_uid)
                .unwrap_err()
                .0
                .contains("identity of another caller")
        );
        let mtls = MINIMAL
            .replace(
                "unix = \"/run/seal/seal.sock\"",
                "tcp = \"127.0.0.1:1\"\ntls = { cert = \"c\", key = \"k\", client_ca = \"a\" }",
            )
            .replace("unix_uid = 990", "cert_subject = \"CN=app, O=Example\"");
        Config::parse(&mtls).unwrap();
        let same_subject = format!(
            "{mtls}\n[[callers]]\nname = \"other\"\ncert_subject = \"cn=app,O=Example\"\nkeysets = [\"*\"]"
        );
        assert!(
            Config::parse(&same_subject)
                .unwrap_err()
                .0
                .contains("identity of another caller")
        );
        let by_name = mtls.replace(
            "cert_subject = \"CN=app, O=Example\"",
            "cert_san = \"spiffe://example.org/app\"",
        );
        Config::parse(&by_name).unwrap();
        let same_name = format!(
            "{by_name}\n[[callers]]\nname = \"other\"\ncert_san = \"spiffe://example.org/app\"\nkeysets = [\"*\"]"
        );
        assert!(
            Config::parse(&same_name)
                .unwrap_err()
                .0
                .contains("identity of another caller")
        );
        let two_ways = by_name.replace("cert_san", "cert_subject = \"CN=app\"\ncert_san");
        assert!(Config::parse(&two_ways).is_err());
        for name in ["", "a b", "caf\u{e9}.example"] {
            let text = by_name.replace("spiffe://example.org/app", name);
            assert!(
                Config::parse(&text).unwrap_err().0.contains("cert_san"),
                "{name}"
            );
        }
        let name_on_unix = MINIMAL.replace("unix_uid = 990", "cert_san = \"app.example\"");
        assert!(Config::parse(&name_on_unix).is_err());
        for subject in ["app", "CN=", "CN=app,", "=app"] {
            let text = mtls.replace("CN=app, O=Example", subject);
            assert!(
                Config::parse(&text).unwrap_err().0.contains("cert_subject"),
                "{subject}"
            );
        }
        let bad_keyset = MINIMAL.replace("keysets = [\"*\"]", "keysets = [\"..\"]");
        assert!(Config::parse(&bad_keyset).is_err());
        let no_callers = MINIMAL.replace("[[callers]]\n        name = \"app\"\n        unix_uid = 990\n        keysets = [\"*\"]", "");
        assert!(Config::parse(&no_callers).is_err());
    }

    #[test]
    fn metrics_beyond_loopback_need_a_token() {
        let with = |metrics: &str| Config::parse(&format!("{MINIMAL}\n[metrics]\n{metrics}"));
        with("listen = \"127.0.0.1:9464\"").unwrap();
        with("listen = \"[::1]:9464\"").unwrap();
        for open in ["0.0.0.0:9464", "10.0.0.5:9464", "[::]:9464"] {
            let error = with(&format!("listen = \"{open}\"")).unwrap_err();
            assert!(error.0.contains("token_file"), "{open}");
            with(&format!(
                "listen = \"{open}\"\ntoken_file = \"/etc/seal/metrics-token\""
            ))
            .unwrap();
        }
        with("listen = \"127.0.0.1:9464\"\ntoken_file = \"/etc/seal/metrics-token\"").unwrap();
        assert!(with("token_file = \"/etc/seal/metrics-token\"").is_err());
    }

    #[test]
    fn the_keyring_relations_are_checked() {
        let text = MINIMAL.replace(
            "wrap = { file = \"/etc/seal/kek\" }",
            "wrap = { file = \"/etc/seal/kek\" }\nmax_stale = \"30s\"\nrefresh_interval = \"60s\"",
        );
        assert!(
            Config::parse(&text)
                .unwrap_err()
                .0
                .contains("refresh_interval")
        );
    }

    #[test]
    fn durations_sizes_and_rates_parse() {
        assert_eq!(
            "100ms".parse::<Interval>().unwrap().0,
            Duration::from_millis(100)
        );
        assert_eq!(
            "15m".parse::<Interval>().unwrap().0,
            Duration::from_secs(900)
        );
        assert_eq!(
            "8h".parse::<Interval>().unwrap().0,
            Duration::from_secs(28_800)
        );
        for bad in ["", "10", "s", "1d", "-1s", "1.5s"] {
            assert!(bad.parse::<Interval>().is_err(), "{bad}");
        }
        assert_eq!("256KiB".parse::<Size>().unwrap().0, 262_144);
        assert_eq!("1GiB".parse::<Size>().unwrap().0, 1 << 30);
        assert_eq!("4096".parse::<Size>().unwrap().0, 4096);
        for bad in ["1KB", "x", "1 MiB", "99999999999999GiB"] {
            assert!(bad.parse::<Size>().is_err(), "{bad}");
        }
        assert_eq!(
            "1000/s".parse::<Rate>().unwrap(),
            Rate {
                count: 1000,
                per: Duration::from_secs(1)
            }
        );
        for bad in ["1000", "0/s", "1/d", "x/s"] {
            assert!(bad.parse::<Rate>().is_err(), "{bad}");
        }
    }

    #[test]
    fn address_ranges_are_checked() {
        let text = format!("{MINIMAL}\n[network]\ndeny_cidrs = [\"10.0.0.0/33\"]");
        assert!(Config::parse(&text).is_err());
    }
}
