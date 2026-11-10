//! All network access toward providers goes through these two traits, so that tests
//! can prove what a refused request did and did not do.

use std::io;
use std::net::{IpAddr, SocketAddr};

use async_trait::async_trait;
use hickory_resolver::TokioResolver;
use tokio::net::TcpStream;

/// Turns a host name into addresses.
#[async_trait]
pub trait Resolve: Send + Sync {
    /// The host's addresses. Errors carry no detail, because resolver errors can
    /// include names and configuration.
    async fn resolve(&self, host: &str) -> Result<Vec<IpAddr>, ResolveFailed>;
}

/// A lookup failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ResolveFailed;

/// Opens a TCP connection to an address that has been checked.
#[async_trait]
pub trait Connect: Send + Sync {
    /// Connects. There is no host name here, so there can be no second lookup.
    async fn connect(&self, address: SocketAddr) -> io::Result<TcpStream>;
}

/// Resolves with the system's DNS configuration.
#[derive(Debug)]
pub struct DnsResolver {
    resolver: TokioResolver,
}

impl DnsResolver {
    /// Reads the system's DNS configuration.
    ///
    /// # Errors
    ///
    /// Returns [`ResolveFailed`] if it cannot be read.
    pub fn from_system() -> Result<Self, ResolveFailed> {
        let resolver = TokioResolver::builder_tokio()
            .map_err(|_| ResolveFailed)?
            .build()
            .map_err(|_| ResolveFailed)?;
        Ok(Self { resolver })
    }
}

#[async_trait]
impl Resolve for DnsResolver {
    async fn resolve(&self, host: &str) -> Result<Vec<IpAddr>, ResolveFailed> {
        let lookup = self
            .resolver
            .lookup_ip(host)
            .await
            .map_err(|_| ResolveFailed)?;
        Ok(lookup.iter().collect())
    }
}

/// Connects with Tokio.
#[derive(Clone, Copy, Debug, Default)]
pub struct TcpConnector;

#[async_trait]
impl Connect for TcpConnector {
    async fn connect(&self, address: SocketAddr) -> io::Result<TcpStream> {
        let stream = TcpStream::connect(address).await?;
        stream.set_nodelay(true)?;
        Ok(stream)
    }
}
