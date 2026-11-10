//! The relay framework for TCP protocols: after a protocol's own login step, bytes go
//! both ways unread, counted, with an idle timeout and a session limit. Postgres is
//! the first protocol; another adds only its login.

use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::task::{Context, Poll};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::time::Instant;

use crate::error::{BrokerError, ErrorCode};

/// What a relay moved, and how it ended.
#[derive(Debug)]
pub struct Relayed {
    /// Bytes from the caller to the server.
    pub caller_to_server: u64,
    /// Bytes from the server to the caller.
    pub server_to_caller: u64,
    /// `Ok` if either side closed, otherwise why it stopped.
    pub result: Result<(), BrokerError>,
}

/// The limits of a relay.
#[derive(Clone, Copy, Debug)]
pub struct RelayLimits {
    /// The longest nothing may move.
    pub idle: Duration,
    /// The longest a session may last.
    pub max_session: Duration,
    /// The buffer for each direction.
    pub buffer: usize,
}

/// Activity shared by both directions.
struct Activity {
    started: Instant,
    /// Milliseconds since `started` at the last byte.
    last: AtomicU64,
}

impl Activity {
    fn touch(&self) {
        let elapsed = u64::try_from(self.started.elapsed().as_millis()).unwrap_or(u64::MAX);
        self.last.store(elapsed, Ordering::Relaxed);
    }

    fn idle_for(&self) -> Duration {
        let last = Duration::from_millis(self.last.load(Ordering::Relaxed));
        self.started.elapsed().saturating_sub(last)
    }
}

/// A stream that counts what is read from it, and marks activity both ways.
struct Counted<S> {
    inner: S,
    read: Arc<AtomicU64>,
    activity: Arc<Activity>,
}

impl<S: AsyncRead + Unpin> AsyncRead for Counted<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        let before = buf.filled().len();
        let poll = Pin::new(&mut this.inner).poll_read(cx, buf);
        let read = buf.filled().len() - before;
        if read > 0 {
            this.read.fetch_add(read as u64, Ordering::Relaxed);
            this.activity.touch();
        }
        poll
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Counted<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let this = self.get_mut();
        let poll = Pin::new(&mut this.inner).poll_write(cx, buf);
        if matches!(poll, Poll::Ready(Ok(written)) if written > 0) {
            this.activity.touch();
        }
        poll
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

/// Relays until either side closes, the session goes idle, or it reaches its limit.
pub async fn relay<C, S>(caller: C, server: S, limits: RelayLimits) -> Relayed
where
    C: AsyncRead + AsyncWrite + Unpin,
    S: AsyncRead + AsyncWrite + Unpin,
{
    let activity = Arc::new(Activity {
        started: Instant::now(),
        last: AtomicU64::new(0),
    });
    let (from_caller, from_server) = (Arc::new(AtomicU64::new(0)), Arc::new(AtomicU64::new(0)));
    let mut caller = Counted {
        inner: caller,
        read: Arc::clone(&from_caller),
        activity: Arc::clone(&activity),
    };
    let mut server = Counted {
        inner: server,
        read: Arc::clone(&from_server),
        activity: Arc::clone(&activity),
    };
    let deadline = Instant::now() + limits.max_session;
    let check = limits
        .idle
        .min(Duration::from_secs(1))
        .max(Duration::from_millis(10));
    let result = {
        let copy = tokio::io::copy_bidirectional_with_sizes(
            &mut caller,
            &mut server,
            limits.buffer,
            limits.buffer,
        );
        tokio::pin!(copy);
        loop {
            tokio::select! {
                done = &mut copy => {
                    break match done {
                        Ok(_) => Ok(()),
                        // A peer that closes without TLS's close_notify has still closed.
                        Err(error) if error.kind() == std::io::ErrorKind::UnexpectedEof => Ok(()),
                        Err(_) => Err(BrokerError::new(
                            ErrorCode::UpstreamReset,
                            "the session's connection failed",
                        )),
                    };
                }
                () = tokio::time::sleep(check) => {
                    if Instant::now() >= deadline {
                        break Err(BrokerError::new(ErrorCode::UpstreamTimeout, "the session reached its limit"));
                    }
                    if activity.idle_for() >= limits.idle {
                        break Err(BrokerError::new(ErrorCode::UpstreamTimeout, "the session was idle too long"));
                    }
                }
            }
        }
    };
    Relayed {
        caller_to_server: from_caller.load(Ordering::Relaxed),
        server_to_caller: from_server.load(Ordering::Relaxed),
        result,
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use super::*;

    fn limits(idle: Duration, max_session: Duration) -> RelayLimits {
        RelayLimits {
            idle,
            max_session,
            buffer: 8192,
        }
    }

    #[tokio::test]
    async fn bytes_go_both_ways_and_are_counted() {
        let (caller, mut caller_end) = tokio::io::duplex(1024);
        let (server, mut server_end) = tokio::io::duplex(1024);
        let task = tokio::spawn(relay(
            caller,
            server,
            limits(Duration::from_secs(5), Duration::from_secs(5)),
        ));
        caller_end.write_all(b"query").await.unwrap();
        let mut buffer = [0; 5];
        server_end.read_exact(&mut buffer).await.unwrap();
        assert_eq!(&buffer, b"query");
        server_end.write_all(b"rows!!").await.unwrap();
        let mut buffer = [0; 6];
        caller_end.read_exact(&mut buffer).await.unwrap();
        drop(caller_end);
        drop(server_end);
        let relayed = task.await.unwrap();
        assert_eq!((relayed.caller_to_server, relayed.server_to_caller), (5, 6));
        assert!(relayed.result.is_ok());
    }

    #[tokio::test(start_paused = true)]
    async fn an_idle_session_ends() {
        let (caller, _caller_end) = tokio::io::duplex(1024);
        let (server, _server_end) = tokio::io::duplex(1024);
        let relayed = relay(
            caller,
            server,
            limits(Duration::from_secs(30), Duration::from_secs(3600)),
        )
        .await;
        assert_eq!(
            relayed.result.unwrap_err().code(),
            ErrorCode::UpstreamTimeout
        );
    }

    #[tokio::test(start_paused = true)]
    async fn a_busy_session_still_ends_at_its_limit() {
        let (caller, mut caller_end) = tokio::io::duplex(1 << 16);
        let (server, mut server_end) = tokio::io::duplex(1 << 16);
        let feeder = tokio::spawn(async move {
            loop {
                if caller_end.write_all(b"x").await.is_err() {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(500)).await;
            }
        });
        let drain = tokio::spawn(async move {
            let mut sink = [0; 64];
            while matches!(server_end.read(&mut sink).await, Ok(n) if n > 0) {}
        });
        let relayed = relay(
            caller,
            server,
            limits(Duration::from_secs(5), Duration::from_secs(20)),
        )
        .await;
        assert_eq!(
            relayed.result.unwrap_err().code(),
            ErrorCode::UpstreamTimeout
        );
        assert!(relayed.caller_to_server >= 30);
        feeder.abort();
        drain.abort();
    }
}
