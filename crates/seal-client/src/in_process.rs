//! seal as a library, in this process. The application can read every credential;
//! the only gain is that plaintext stays inside seal's code, so it does not leak into
//! logs, errors or responses by accident.

use std::sync::Once;
use zeroize::Zeroizing;

use async_trait::async_trait;
use http_body_util::BodyExt;
use seal_broker::{Broker, BrokerError};
use seal_format::KeysetId;
use seal_keys::Keyring;

use crate::{
    ConnectRequest, ErrorCode, Info, Mode, PgStream, PresignRequest, PublicKeyInfo, SealClient,
    SealError, SendRequest, SendResponse, VerifyRequest, WrappedKey,
};

/// seal in this process.
pub struct InProcessClient {
    broker: Broker,
    keyring: Option<Keyring>,
    buffer_cap: u64,
}

/// Wraps a broker. Logs once, at `warn`, that credentials are readable by this process.
#[must_use]
pub fn in_process(broker: Broker, keyring: Option<Keyring>, buffer_cap: u64) -> InProcessClient {
    static WARNED: Once = Once::new();
    WARNED.call_once(|| {
        tracing::warn!("credentials are readable by this process (seal in-process mode)");
    });
    InProcessClient {
        broker,
        keyring,
        buffer_cap,
    }
}

fn from_broker(error: &BrokerError) -> SealError {
    SealError::new(
        ErrorCode::from_name(error.code().as_str()).unwrap_or(ErrorCode::Internal),
        error.detail(),
    )
}

fn from_keys(error: seal_keys::KeyError) -> SealError {
    let code = match error {
        seal_keys::KeyError::UnknownKeyset => ErrorCode::KeysetUnknown,
        seal_keys::KeyError::AlreadyExists | seal_keys::KeyError::TooManyKeys => {
            ErrorCode::Conflict
        }
        seal_keys::KeyError::Invalid(_) => ErrorCode::BadRequest,
        _ => ErrorCode::KeysUnavailable,
    };
    SealError::new(code, error.to_string())
}

impl InProcessClient {
    fn keyring(&self) -> Result<&Keyring, SealError> {
        self.keyring
            .as_ref()
            .ok_or_else(|| SealError::new(ErrorCode::CallerDenied, "this client has no keyring"))
    }
}

#[async_trait]
impl SealClient for InProcessClient {
    fn mode(&self) -> Mode {
        Mode::InProcess
    }

    async fn send(&self, request: SendRequest) -> Result<SendResponse, SealError> {
        let SendRequest {
            keyset,
            item,
            sealed,
            plain,
            request,
        } = request;
        let (parts, body) = request.into_parts();
        let response = self
            .broker
            .send(seal_broker::SendRequest {
                caller: "in-process".to_owned(),
                keyset,
                item,
                sealed: sealed
                    .into_iter()
                    .map(|(name, value)| {
                        let presented = seal_broker::Presented {
                            envelope: value.envelope,
                            item: value.item,
                        };
                        (name, presented)
                    })
                    .collect(),
                plain,
                method: parts.method,
                url: parts.uri.to_string(),
                headers: parts.headers,
                body: body
                    .map_err(|_| {
                        BrokerError::new(
                            seal_broker::ErrorCode::BadRequest,
                            "the caller's body failed",
                        )
                    })
                    .boxed_unsync(),
            })
            .await
            .map_err(|error| from_broker(&error))?;
        let mut builder = http::Response::builder().status(response.status);
        if let Some(headers) = builder.headers_mut() {
            *headers = response.headers;
        }
        let body = response
            .body
            .map_err(|error| from_broker(&error))
            .boxed_unsync();
        Ok(SendResponse {
            response: builder.body(body).map_err(|_| {
                SealError::new(ErrorCode::Internal, "the response could not be formed")
            })?,
            sealed_fields: response.sealed_fields,
            claims: response.claims,
        })
    }

    async fn presign(&self, request: PresignRequest) -> Result<Zeroizing<String>, SealError> {
        self.broker
            .presign(seal_broker::PresignRequest {
                caller: "in-process".to_owned(),
                keyset: request.keyset,
                item: request.item,
                sealed: request
                    .sealed
                    .into_iter()
                    .map(|(name, value)| {
                        let presented = seal_broker::Presented {
                            envelope: value.envelope,
                            item: value.item,
                        };
                        (name, presented)
                    })
                    .collect(),
                plain: request.plain,
                method: request.method,
                url: request.url,
                expires_s: request.expires_s,
            })
            .await
            .map_err(|error| from_broker(&error))
    }

    async fn verify(&self, request: VerifyRequest) -> Result<bool, SealError> {
        self.broker
            .verify(seal_broker::VerifyRequest {
                caller: "in-process".to_owned(),
                keyset: request.keyset,
                item: request.item,
                field: request.field,
                value: seal_broker::Presented {
                    envelope: request.value.envelope,
                    item: request.value.item,
                },
                message: seal_broker::body::full_body(request.message),
                mac: request.mac,
            })
            .await
            .map_err(|error| from_broker(&error))
    }

    async fn connect_pg(&self, request: ConnectRequest) -> Result<PgStream, SealError> {
        let session = self
            .broker
            .open_session(seal_broker::ConnectRequest {
                caller: "in-process".to_owned(),
                keyset: request.keyset,
                item: request.item,
                sealed: request
                    .sealed
                    .into_iter()
                    .map(|(name, value)| {
                        let presented = seal_broker::Presented {
                            envelope: value.envelope,
                            item: value.item,
                        };
                        (name, presented)
                    })
                    .collect(),
                plain: request.plain,
                host: request.host,
                port: request.port,
            })
            .await
            .map_err(|error| from_broker(&error))?;
        let (application, seal_end) = tokio::io::duplex(crate::PG_BUFFER);
        tokio::spawn(async move {
            // A failure has been told to the application as a Postgres error, and
            // audited.
            let _ = session.run(seal_end).await;
        });
        Ok(PgStream::new(application))
    }

    async fn info(&self) -> Result<Info, SealError> {
        Ok(Info {
            mode: Mode::InProcess.as_str().to_owned(),
            version: env!("CARGO_PKG_VERSION").to_owned(),
            buffer_cap: self.buffer_cap,
        })
    }

    async fn generate_keyset(&self, keyset: &KeysetId) -> Result<WrappedKey, SealError> {
        self.keyring()?
            .generate(keyset)
            .await
            .map(convert)
            .map_err(from_keys)
    }

    async fn rotate(&self, keyset: &KeysetId) -> Result<WrappedKey, SealError> {
        self.keyring()?
            .rotate(keyset)
            .await
            .map(convert)
            .map_err(from_keys)
    }

    async fn public_keys(&self, keyset: &KeysetId) -> Result<Vec<PublicKeyInfo>, SealError> {
        let keys = self
            .keyring()?
            .public_keys(keyset)
            .await
            .map_err(from_keys)?;
        Ok(keys
            .into_iter()
            .map(|key| PublicKeyInfo {
                kid: key.kid.to_string(),
                public: key.public.to_base64url(),
                created: key.created,
            })
            .collect())
    }
}

fn convert(key: seal_keys::WrappedKey) -> WrappedKey {
    WrappedKey {
        keyset: key.keyset.to_string(),
        kid: key.kid.to_string(),
        public: key.public,
        created: key.created,
        wrap_id: key.wrap_id,
        wrapped: key.wrapped,
    }
}
