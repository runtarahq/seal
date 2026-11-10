//! Bodies that stream, without ever growing a buffer, and that time out on progress.
//!
//! Frames pass through as they arrive, and a frame is only asked for when the other
//! side can take it, so a slow reader slows the provider rather than filling memory.
//! A transfer fails when no bytes move in either direction for the idle timeout, not
//! after a fixed total, so that long transfers complete.

use std::future::Future;
use std::pin::Pin;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, PoisonError};
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::Bytes;
use http_body::{Body, Frame, SizeHint};
use http_body_util::{BodyExt, Empty, Full};
use hyper::body::Incoming;
use tokio::sync::Notify;
use tokio::time::{Instant, Sleep, sleep_until};
use zeroize::Zeroizing;

use crate::audit::{AuditGuard, Outcome};
use crate::client::{Checkout, RequestBody, body_error};
use crate::error::{BrokerError, ErrorCode};

const NOT_DONE: u64 = u64::MAX;

/// What has happened so far on one request, shared by both directions.
pub(crate) struct Progress {
    base: Instant,
    connected: AtomicBool,
    connected_signal: Notify,
    last_ms: AtomicU64,
    request_done_ms: AtomicU64,
    bytes_in: AtomicU64,
    bytes_out: AtomicU64,
    failure: Mutex<Option<BrokerError>>,
}

impl Progress {
    pub(crate) fn new() -> Self {
        Self {
            base: Instant::now(),
            connected: AtomicBool::new(false),
            connected_signal: Notify::new(),
            last_ms: AtomicU64::new(0),
            request_done_ms: AtomicU64::new(NOT_DONE),
            bytes_in: AtomicU64::new(0),
            bytes_out: AtomicU64::new(0),
            failure: Mutex::new(None),
        }
    }

    fn now_ms(&self) -> u64 {
        u64::try_from(self.base.elapsed().as_millis()).unwrap_or(u64::MAX - 1)
    }

    fn touch(&self) {
        self.last_ms.store(self.now_ms(), Ordering::Relaxed);
    }

    pub(crate) fn mark_request_done(&self) {
        let now = self.now_ms();
        self.last_ms.store(now, Ordering::Relaxed);
        self.request_done_ms.store(now, Ordering::Relaxed);
    }

    fn at(&self, ms: u64) -> Instant {
        self.base + Duration::from_millis(ms)
    }

    /// A connection is ready, so the clocks that measure the provider can start.
    /// Connecting has its own timeout.
    pub(crate) fn mark_connected(&self) {
        let now = self.now_ms();
        self.last_ms.store(now, Ordering::Relaxed);
        if self.request_done_ms.load(Ordering::Relaxed) != NOT_DONE {
            // A request with no body is done as soon as it can be sent.
            self.request_done_ms.store(now, Ordering::Relaxed);
        }
        self.connected.store(true, Ordering::Relaxed);
        self.connected_signal.notify_one();
    }

    /// Waits for the signal from `mark_connected`.
    pub(crate) async fn connected_signal(&self) {
        self.connected_signal.notified().await;
    }

    /// When the request stops being allowed to wait for a response head: nothing
    /// until it is connected; while uploading, the idle timeout; once sent, the
    /// first-byte timeout.
    pub(crate) fn head_deadline(&self, idle: Duration, first_byte: Duration) -> Option<Instant> {
        if !self.connected.load(Ordering::Relaxed) {
            return None;
        }
        Some(match self.request_done_ms.load(Ordering::Relaxed) {
            NOT_DONE => self.idle_deadline(idle),
            done => self.at(done) + first_byte,
        })
    }

    fn idle_deadline(&self, idle: Duration) -> Instant {
        self.at(self.last_ms.load(Ordering::Relaxed)) + idle
    }

    pub(crate) fn bytes_in(&self) -> u64 {
        self.bytes_in.load(Ordering::Relaxed)
    }

    pub(crate) fn bytes_out(&self) -> u64 {
        self.bytes_out.load(Ordering::Relaxed)
    }

    /// Records the size of a message that was read whole, with no request to send.
    pub(crate) fn set_bytes_in(&self, bytes: u64) {
        self.bytes_in.store(bytes, Ordering::Relaxed);
    }

    /// Records the size of a response that was buffered rather than streamed.
    pub(crate) fn set_bytes_out(&self, bytes: u64) {
        self.bytes_out.store(bytes, Ordering::Relaxed);
    }

    /// Records why the transfer failed. The first reason wins.
    fn fail(&self, error: BrokerError) -> BrokerError {
        let mut failure = self.failure.lock().unwrap_or_else(PoisonError::into_inner);
        failure.get_or_insert(error).clone()
    }

    /// Why the transfer failed, if a wrapper recorded it.
    pub(crate) fn failure(&self) -> Option<BrokerError> {
        self.failure
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }
}

fn timed_out() -> BrokerError {
    BrokerError::new(
        ErrorCode::UpstreamTimeout,
        "no progress within the idle timeout",
    )
}

fn over_time() -> BrokerError {
    BrokerError::new(
        ErrorCode::UpstreamTimeout,
        "over the maximum stream duration",
    )
}

/// Polls the idle and total deadlines while the other side has nothing to give.
struct Watchdog {
    progress: Arc<Progress>,
    idle: Duration,
    idle_sleep: Pin<Box<Sleep>>,
    total_sleep: Option<Pin<Box<Sleep>>>,
}

impl Watchdog {
    fn new(progress: Arc<Progress>, idle: Duration, total_deadline: Option<Instant>) -> Self {
        let idle_sleep = Box::pin(sleep_until(progress.idle_deadline(idle)));
        Self {
            progress,
            idle,
            idle_sleep,
            total_sleep: total_deadline.map(|deadline| Box::pin(sleep_until(deadline))),
        }
    }

    /// `Some` if a deadline has passed. Otherwise, a timer will wake the task.
    fn expired(&mut self, cx: &mut Context<'_>) -> Option<BrokerError> {
        if let Some(total) = &mut self.total_sleep
            && total.as_mut().poll(cx).is_ready()
        {
            return Some(over_time());
        }
        loop {
            if self.idle_sleep.as_mut().poll(cx).is_pending() {
                return None;
            }
            // The timer fired, but progress may have moved the deadline since.
            let deadline = self.progress.idle_deadline(self.idle);
            if deadline <= Instant::now() {
                return Some(timed_out());
            }
            self.idle_sleep.as_mut().reset(deadline);
        }
    }
}

/// The request body, counted, watched for a caller that stalls, and held to the
/// `Content-Length` the request declares.
pub(crate) struct TrackedRequestBody {
    inner: RequestBody,
    watchdog: Watchdog,
    /// The request's `Content-Length`, if it has one. A body of another length would
    /// be cut short or leave the provider waiting, so it fails the request instead.
    declared: Option<u64>,
    seen: u64,
}

impl TrackedRequestBody {
    pub(crate) fn new(
        inner: RequestBody,
        progress: Arc<Progress>,
        idle: Duration,
        total_deadline: Option<Instant>,
        declared: Option<u64>,
    ) -> Self {
        if inner.is_end_stream() {
            progress.mark_request_done();
        }
        Self {
            inner,
            watchdog: Watchdog::new(progress, idle, total_deadline),
            declared,
            seen: 0,
        }
    }

    fn wrong_length(detail: &'static str) -> BrokerError {
        BrokerError::new(ErrorCode::BadRequest, detail)
    }
}

impl Body for TrackedRequestBody {
    type Data = Bytes;
    type Error = BrokerError;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, BrokerError>>> {
        let this = self.get_mut();
        let progress = Arc::clone(&this.watchdog.progress);
        match Pin::new(&mut this.inner).poll_frame(cx) {
            Poll::Ready(Some(Ok(frame))) => {
                if let Some(data) = frame.data_ref() {
                    this.seen = this.seen.saturating_add(data.len() as u64);
                    if this.declared.is_some_and(|declared| this.seen > declared) {
                        return Poll::Ready(Some(Err(progress.fail(Self::wrong_length(
                            "the body is longer than its Content-Length",
                        )))));
                    }
                    progress
                        .bytes_in
                        .fetch_add(data.len() as u64, Ordering::Relaxed);
                    progress.touch();
                }
                Poll::Ready(Some(Ok(frame)))
            }
            Poll::Ready(Some(Err(error))) => Poll::Ready(Some(Err(progress.fail(error)))),
            Poll::Ready(None) => {
                if this.declared.is_some_and(|declared| this.seen < declared) {
                    return Poll::Ready(Some(Err(progress.fail(Self::wrong_length(
                        "the body is shorter than its Content-Length",
                    )))));
                }
                progress.mark_request_done();
                Poll::Ready(None)
            }
            Poll::Pending => match this.watchdog.expired(cx) {
                Some(error) => Poll::Ready(Some(Err(progress.fail(error)))),
                None => Poll::Pending,
            },
        }
    }

    fn is_end_stream(&self) -> bool {
        // A body that ends short of its length still has an error to give.
        self.inner.is_end_stream() && self.declared.is_none_or(|declared| declared == self.seen)
    }

    fn size_hint(&self) -> SizeHint {
        self.inner.size_hint()
    }
}

/// What has to happen when a streamed response ends.
pub(crate) struct Finish {
    pub(crate) checkout: Checkout,
    pub(crate) audit: AuditGuard,
}

impl Finish {
    fn complete(self, error: Option<&BrokerError>) -> Result<(), BrokerError> {
        match error {
            None => {
                self.checkout.finish();
                self.audit.finish(Outcome::Ok, None).map_err(|_| {
                    BrokerError::new(ErrorCode::Internal, "could not write the audit record")
                })
            }
            Some(error) => {
                drop(self.checkout);
                // The request has already failed, and that is what the caller hears.
                let _ = self.audit.finish(Outcome::Failed, Some(error.code()));
                Ok(())
            }
        }
    }
}

/// Looks for the secrets seal put in a request in the response body that comes back,
/// across the boundaries of the pieces it arrives in. The end of a piece is held back
/// only while it is the start of a secret, so a response that repeats one gives the
/// caller none of it, and any other response is not delayed.
pub(crate) struct ReflectionScan {
    secrets: Vec<Zeroizing<Vec<u8>>>,
    /// The end of what has arrived, where it is the start of a secret.
    held: Zeroizing<Vec<u8>>,
}

impl ReflectionScan {
    /// A scan for these secrets, or `None` if none is long enough to look for.
    pub(crate) fn new(secrets: Vec<Zeroizing<Vec<u8>>>) -> Option<Self> {
        let secrets: Vec<_> = secrets
            .into_iter()
            .filter(|secret| secret.len() >= crate::inject::MIN_REFLECTED_SECRET)
            .collect();
        (!secrets.is_empty()).then(|| Self {
            secrets,
            held: Zeroizing::new(Vec::new()),
        })
    }

    /// How many bytes at the end of `bytes` are the start of a secret: the most that
    /// a secret arriving in pieces could have shown of itself so far.
    fn started(&self, bytes: &[u8]) -> usize {
        self.secrets
            .iter()
            .map(|secret| {
                let longest = (secret.len() - 1).min(bytes.len());
                (1..=longest)
                    .rev()
                    .find(|length| bytes.ends_with(&secret[..*length]))
                    .unwrap_or(0)
            })
            .max()
            .unwrap_or(0)
    }

    fn repeated() -> BrokerError {
        BrokerError::new(
            ErrorCode::ResponseUnparseable,
            "the response repeats a credential",
        )
    }

    /// Whether these bytes hold one of the secrets.
    pub(crate) fn finds(&self, bytes: &[u8]) -> bool {
        self.secrets.iter().any(|secret| {
            bytes
                .windows(secret.len())
                .any(|window| window == secret.as_slice())
        })
    }

    /// Takes the next piece of the body, and gives back what can be passed on.
    ///
    /// # Errors
    ///
    /// [`ErrorCode::ResponseUnparseable`] if the body so far holds a secret.
    pub(crate) fn push(&mut self, data: &[u8]) -> Result<Bytes, BrokerError> {
        let mut seen = Zeroizing::new(Vec::with_capacity(self.held.len() + data.len()));
        seen.extend_from_slice(&self.held);
        seen.extend_from_slice(data);
        if self.finds(&seen) {
            self.held.clear();
            return Err(Self::repeated());
        }
        let pass = seen.len() - self.started(&seen);
        self.held.clear();
        self.held.extend_from_slice(&seen[pass..]);
        Ok(Bytes::copy_from_slice(&seen[..pass]))
    }

    /// What was held back, once the body has ended: the start of a secret, and no more
    /// of it than that.
    pub(crate) fn finish(&mut self) -> Bytes {
        let rest = Bytes::copy_from_slice(&self.held);
        self.held.clear();
        rest
    }
}

/// A response body streaming from the provider.
pub(crate) struct ResponseStream {
    inner: Incoming,
    watchdog: Watchdog,
    finish: Option<Finish>,
    scan: Option<ReflectionScan>,
    /// A frame that follows what the scan held back, such as trailers.
    after_held: Option<Frame<Bytes>>,
    ended: bool,
}

impl ResponseStream {
    pub(crate) fn new(
        inner: Incoming,
        finish: Finish,
        progress: Arc<Progress>,
        idle: Duration,
        total_deadline: Option<Instant>,
        scan: Option<ReflectionScan>,
    ) -> Self {
        progress.touch();
        Self {
            inner,
            watchdog: Watchdog::new(progress, idle, total_deadline),
            finish: Some(finish),
            scan,
            after_held: None,
            ended: false,
        }
    }

    fn count(&self, data: &Bytes) {
        let progress = &self.watchdog.progress;
        progress
            .bytes_out
            .fetch_add(data.len() as u64, Ordering::Relaxed);
        progress.touch();
    }

    fn complete(&mut self) -> Poll<Option<Result<Frame<Bytes>, BrokerError>>> {
        match take_finish(&mut self.finish) {
            Some(finish) => match finish.complete(None) {
                Ok(()) => Poll::Ready(None),
                Err(error) => Poll::Ready(Some(Err(error))),
            },
            None => Poll::Ready(None),
        }
    }

    fn fail(&mut self, error: BrokerError) -> BrokerError {
        let error = self.watchdog.progress.fail(error);
        if let Some(finish) = take_finish(&mut self.finish) {
            let _ = finish.complete(Some(&error));
        }
        error
    }
}

fn take_finish(finish: &mut Option<Finish>) -> Option<Finish> {
    finish.take()
}

impl Body for ResponseStream {
    type Data = Bytes;
    type Error = BrokerError;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, BrokerError>>> {
        let this = self.get_mut();
        loop {
            if let Some(frame) = this.after_held.take() {
                return Poll::Ready(Some(Ok(frame)));
            }
            if this.ended {
                return this.complete();
            }
            match Pin::new(&mut this.inner).poll_frame(cx) {
                Poll::Ready(Some(Ok(frame))) => {
                    let Some(scan) = &mut this.scan else {
                        if let Some(data) = frame.data_ref() {
                            this.count(data);
                        }
                        return Poll::Ready(Some(Ok(frame)));
                    };
                    let passed = match frame.into_data() {
                        Ok(data) => match scan.push(&data) {
                            Ok(passed) => passed,
                            Err(error) => {
                                let error = this.fail(error);
                                return Poll::Ready(Some(Err(error)));
                            }
                        },
                        // Trailers end the data: what was held goes first.
                        Err(other) => {
                            this.after_held = Some(other);
                            scan.finish()
                        }
                    };
                    if passed.is_empty() {
                        continue;
                    }
                    this.count(&passed);
                    return Poll::Ready(Some(Ok(Frame::data(passed))));
                }
                Poll::Ready(Some(Err(error))) => {
                    let error = this.fail(body_error(&error));
                    return Poll::Ready(Some(Err(error)));
                }
                Poll::Ready(None) => {
                    this.ended = true;
                    let rest = this.scan.as_mut().map(ReflectionScan::finish);
                    if let Some(rest) = rest.filter(|rest| !rest.is_empty()) {
                        this.count(&rest);
                        return Poll::Ready(Some(Ok(Frame::data(rest))));
                    }
                }
                Poll::Pending => {
                    return match this.watchdog.expired(cx) {
                        Some(error) => {
                            let error = this.fail(error);
                            Poll::Ready(Some(Err(error)))
                        }
                        None => Poll::Pending,
                    };
                }
            }
        }
    }

    fn is_end_stream(&self) -> bool {
        false
    }

    fn size_hint(&self) -> SizeHint {
        self.inner.size_hint()
    }
}

/// A response's body, as a stream of frames.
pub struct ResponseBody(ResponseBodyInner);

enum ResponseBodyInner {
    Stream(Box<ResponseStream>),
    Buffered(Full<Bytes>),
}

impl ResponseBody {
    pub(crate) fn stream(stream: ResponseStream) -> Self {
        Self(ResponseBodyInner::Stream(Box::new(stream)))
    }

    pub(crate) fn buffered(bytes: Bytes) -> Self {
        Self(ResponseBodyInner::Buffered(Full::new(bytes)))
    }
}

impl Body for ResponseBody {
    type Data = Bytes;
    type Error = BrokerError;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, BrokerError>>> {
        match &mut self.get_mut().0 {
            ResponseBodyInner::Stream(stream) => Pin::new(stream.as_mut()).poll_frame(cx),
            ResponseBodyInner::Buffered(full) => Pin::new(full)
                .poll_frame(cx)
                .map(|frame| frame.map(|frame| frame.map_err(|never| match never {}))),
        }
    }

    fn is_end_stream(&self) -> bool {
        match &self.0 {
            ResponseBodyInner::Stream(stream) => stream.is_end_stream(),
            ResponseBodyInner::Buffered(full) => full.is_end_stream(),
        }
    }

    fn size_hint(&self) -> SizeHint {
        match &self.0 {
            ResponseBodyInner::Stream(stream) => stream.size_hint(),
            ResponseBodyInner::Buffered(full) => full.size_hint(),
        }
    }
}

/// A request body with nothing in it.
#[must_use]
pub fn empty_body() -> RequestBody {
    Empty::new()
        .map_err(|never: std::convert::Infallible| match never {})
        .boxed_unsync()
}

/// A request body holding these bytes.
#[must_use]
pub fn full_body(bytes: impl Into<Bytes>) -> RequestBody {
    Full::new(bytes.into())
        .map_err(|never: std::convert::Infallible| match never {})
        .boxed_unsync()
}

/// A body whose buffer is wiped when the last reference to it goes.
pub(crate) fn wiped_body(bytes: Zeroizing<Vec<u8>>) -> RequestBody {
    full_body(Bytes::from_owner(bytes))
}

/// Reads a body up to a cap into a buffer that is wiped, including as it grows.
///
/// # Errors
///
/// Returns `over_cap` if the body is larger, or the body's own error.
pub(crate) async fn read_capped<B>(
    mut body: B,
    cap: u64,
    over_cap: BrokerError,
    map_error: impl Fn(B::Error) -> BrokerError,
) -> Result<Zeroizing<Vec<u8>>, BrokerError>
where
    B: Body<Data = Bytes> + Unpin,
{
    if body.size_hint().lower() > cap {
        return Err(over_cap);
    }
    let mut buffer = Zeroizing::new(Vec::new());
    while let Some(frame) = body.frame().await {
        let frame = frame.map_err(&map_error)?;
        let Ok(data) = frame.into_data() else {
            continue;
        };
        let needed = buffer.len() + data.len();
        if needed as u64 > cap {
            return Err(over_cap);
        }
        if needed > buffer.capacity() {
            // Grown by hand, because a reallocating `Vec` leaves an unwiped copy.
            let mut grown = Zeroizing::new(Vec::with_capacity(needed.next_power_of_two()));
            grown.extend_from_slice(&buffer);
            buffer = grown;
        }
        buffer.extend_from_slice(&data);
    }
    Ok(buffer)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn over() -> BrokerError {
        BrokerError::new(ErrorCode::BodyTooLarge, "over")
    }

    #[tokio::test]
    async fn reading_stops_at_the_cap() {
        let read = |bytes: &'static [u8], cap| {
            read_capped(
                Full::new(Bytes::from(bytes)),
                cap,
                over(),
                |never: std::convert::Infallible| match never {},
            )
        };
        assert_eq!(&*read(b"abc", 3).await.unwrap(), b"abc");
        assert_eq!(
            read(b"abc", 2).await.unwrap_err().code(),
            ErrorCode::BodyTooLarge
        );
        assert_eq!(&*read(b"", 0).await.unwrap(), b"");
    }

    #[tokio::test]
    async fn a_body_that_lies_about_its_size_still_stops_at_the_cap() {
        use http_body_util::StreamBody;
        let chunks: Vec<Result<Frame<Bytes>, std::convert::Infallible>> = (0..100)
            .map(|_| Ok(Frame::data(Bytes::from_static(b"0123456789"))))
            .collect();
        let body = StreamBody::new(tokio_stream_from(chunks));
        let error = read_capped(body, 25, over(), |never| match never {})
            .await
            .unwrap_err();
        assert_eq!(error.code(), ErrorCode::BodyTooLarge);
    }

    fn tokio_stream_from<T: Unpin>(items: Vec<T>) -> Items<T> {
        Items(items.into_iter())
    }

    struct Items<T>(std::vec::IntoIter<T>);

    impl<T: Unpin> futures_core::Stream for Items<T> {
        type Item = T;
        fn poll_next(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Option<T>> {
            Poll::Ready(self.get_mut().0.next())
        }
    }

    #[tokio::test(start_paused = true)]
    async fn the_idle_deadline_moves_with_progress() {
        let progress = Progress::new();
        let idle = Duration::from_secs(10);
        let first = progress.idle_deadline(idle);
        tokio::time::advance(Duration::from_secs(4)).await;
        progress.touch();
        assert_eq!(progress.idle_deadline(idle), first + Duration::from_secs(4));
    }

    #[tokio::test(start_paused = true)]
    async fn the_head_deadline_starts_when_connected_and_depends_on_the_upload() {
        let progress = Progress::new();
        let (idle, first_byte) = (Duration::from_secs(10), Duration::from_secs(60));
        assert_eq!(progress.head_deadline(idle, first_byte), None);

        tokio::time::advance(Duration::from_secs(3)).await;
        progress.mark_connected();
        let connected = Instant::now();
        assert_eq!(
            progress.head_deadline(idle, first_byte),
            Some(connected + idle)
        );

        tokio::time::advance(Duration::from_secs(5)).await;
        progress.mark_request_done();
        assert_eq!(
            progress.head_deadline(idle, first_byte),
            Some(connected + Duration::from_secs(65))
        );
    }

    #[tokio::test(start_paused = true)]
    async fn a_request_with_no_body_starts_its_first_byte_clock_when_connected() {
        let progress = Progress::new();
        let (idle, first_byte) = (Duration::from_secs(10), Duration::from_secs(60));
        progress.mark_request_done();
        tokio::time::advance(Duration::from_secs(3)).await;
        progress.mark_connected();
        assert_eq!(
            progress.head_deadline(idle, first_byte),
            Some(Instant::now() + first_byte)
        );
    }

    #[tokio::test]
    async fn the_first_failure_is_the_one_kept() {
        let progress = Progress::new();
        progress.fail(timed_out());
        let kept = progress.fail(over());
        assert_eq!(kept.code(), ErrorCode::UpstreamTimeout);
        assert_eq!(
            progress.failure().unwrap().code(),
            ErrorCode::UpstreamTimeout
        );
    }

    fn scan(secrets: &[&[u8]]) -> Option<ReflectionScan> {
        ReflectionScan::new(
            secrets
                .iter()
                .map(|secret| Zeroizing::new(secret.to_vec()))
                .collect(),
        )
    }

    /// Feeds a body in pieces, and returns everything that was passed on.
    fn passed(scan: &mut ReflectionScan, pieces: &[&[u8]]) -> Result<Vec<u8>, BrokerError> {
        let mut out = Vec::new();
        for piece in pieces {
            out.extend_from_slice(&scan.push(piece)?);
        }
        out.extend_from_slice(&scan.finish());
        Ok(out)
    }

    #[test]
    fn a_body_without_the_secret_passes_whole_however_it_is_cut() {
        let body = b"{\"id\":42,\"note\":\"nothing to see, SECRET-canar is not it\"}";
        for size in 1..=body.len() {
            let mut scan = scan(&[b"SECRET-canary", b"another-secret-value"]).unwrap();
            let pieces: Vec<&[u8]> = body.chunks(size).collect();
            assert_eq!(
                passed(&mut scan, &pieces).unwrap(),
                body,
                "pieces of {size}"
            );
        }
    }

    #[test]
    fn a_secret_is_found_across_pieces_and_none_of_it_is_passed_on() {
        let body = b"<html>your key is SECRET-canary, keep it safe</html>";
        for size in 1..=body.len() {
            let mut scan = scan(&[b"another-secret-value", b"SECRET-canary"]).unwrap();
            let mut out = Vec::new();
            let mut refused = false;
            for piece in body.chunks(size) {
                match scan.push(piece) {
                    Ok(bytes) => out.extend_from_slice(&bytes),
                    Err(error) => {
                        assert_eq!(error.code(), ErrorCode::ResponseUnparseable);
                        refused = true;
                        break;
                    }
                }
            }
            assert!(refused, "pieces of {size}");
            // Not even its first byte, which is where the body stops.
            assert!(out.len() <= body.len() - b"SECRET-canary, keep it safe</html>".len());
            assert!(body.starts_with(&out));
            assert!(scan.finish().is_empty());
        }
    }

    #[test]
    fn only_the_start_of_a_secret_is_held_back() {
        let mut scan = scan(&[b"SECRET-canary"]).unwrap();
        // A streamed response is passed on as it arrives.
        assert_eq!(scan.push(b"data: one\n\n").unwrap(), &b"data: one\n\n"[..]);
        // Unless it ends as a secret begins, and then only that much waits.
        assert_eq!(scan.push(b"data: SECRET-c").unwrap(), &b"data: "[..]);
        assert_eq!(scan.push(b"anal\n").unwrap(), &b"SECRET-canal\n"[..]);
        assert_eq!(scan.push(b"SEC").unwrap(), &b""[..]);
        assert_eq!(scan.finish(), &b"SEC"[..]);
    }

    #[test]
    fn secrets_too_short_to_look_for_are_not_looked_for() {
        assert!(scan(&[]).is_none());
        assert!(scan(&[b"short"]).is_none());
        let mut scan = scan(&[b"short", b"long-enough"]).unwrap();
        assert_eq!(
            passed(&mut scan, &[b"a short story"]).unwrap(),
            b"a short story"
        );
    }
}
