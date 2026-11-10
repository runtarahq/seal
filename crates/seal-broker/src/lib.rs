//! Policy matching, injection, signing, the HTTP client and the Postgres relay.

#![forbid(unsafe_code)]

pub mod address;
pub mod audit;
pub mod body;
pub mod broker;
pub mod claims;
pub mod client;
pub mod error;
pub mod identity;
pub mod inject;
mod json;
pub mod matcher;
pub mod net;
pub mod pg;
mod presign;
pub mod relay;
pub mod response_seal;
pub mod target;
pub mod verify;

pub use broker::{
    Broker, BrokerConfig, ConnectRequest, Environment, Limits, Presented, PresignRequest,
    SendRequest, SendResponse, VerifyRequest,
};
pub use error::{BrokerError, ErrorCode};
