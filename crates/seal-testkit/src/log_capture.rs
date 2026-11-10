//! Captures `tracing` output so that tests can scan it for canaries.

use std::io;
use std::sync::{Arc, Mutex, PoisonError};

use tracing::Dispatch;
use tracing::dispatcher::DefaultGuard;
use tracing_subscriber::fmt::MakeWriter;
use tracing_subscriber::fmt::format::FmtSpan;

/// Collects everything logged at any level, including span fields.
///
/// Capture applies to the current thread while the guard from
/// [`LogCapture::install`] is alive. Code on other threads needs
/// [`LogCapture::dispatch`] set as its default, or the capture misses it and a
/// scan would pass without having seen its output.
#[derive(Clone, Debug, Default)]
pub struct LogCapture {
    buffer: Arc<Mutex<Vec<u8>>>,
}

impl LogCapture {
    /// Creates an empty capture.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Makes this capture the current thread's subscriber until the guard is
    /// dropped.
    #[must_use = "capture stops when the guard is dropped"]
    pub fn install(&self) -> DefaultGuard {
        tracing::dispatcher::set_default(&self.dispatch())
    }

    /// A dispatcher writing to this capture, for use on other threads.
    #[must_use]
    pub fn dispatch(&self) -> Dispatch {
        let subscriber = tracing_subscriber::fmt()
            .with_max_level(tracing::Level::TRACE)
            .with_span_events(FmtSpan::FULL)
            .with_ansi(false)
            .with_writer(self.clone())
            .finish();
        Dispatch::new(subscriber)
    }

    /// Everything captured so far. Invalid UTF-8 is replaced.
    #[must_use]
    pub fn contents(&self) -> String {
        let buffer = self.buffer.lock().unwrap_or_else(PoisonError::into_inner);
        String::from_utf8_lossy(&buffer).into_owned()
    }
}

impl io::Write for LogCapture {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        // A panicking test may have poisoned the lock. Its logs are still valid.
        self.buffer
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl<'writer> MakeWriter<'writer> for LogCapture {
    type Writer = Self;

    fn make_writer(&'writer self) -> Self::Writer {
        self.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::canary::{Canary, CanaryRegistry, Encoding};

    #[test]
    fn captures_every_level() {
        let capture = LogCapture::new();
        let _guard = capture.install();
        tracing::error!("an error");
        tracing::warn!("a warning");
        tracing::info!("some info");
        tracing::debug!("some debug");
        tracing::trace!("a trace");

        let logs = capture.contents();
        for message in [
            "an error",
            "a warning",
            "some info",
            "some debug",
            "a trace",
        ] {
            assert!(logs.contains(message), "{message} missing");
        }
    }

    #[test]
    fn captures_event_and_span_fields() {
        let capture = LogCapture::new();
        let _guard = capture.install();
        let span = tracing::info_span!("request", span_field = "in-the-span");
        let _entered = span.enter();
        tracing::info!(event_field = "in-the-event", "message");

        let logs = capture.contents();
        assert!(logs.contains("in-the-span"));
        assert!(logs.contains("in-the-event"));
    }

    #[test]
    fn a_span_field_is_seen_even_with_no_event_inside_it() {
        let capture = LogCapture::new();
        let _guard = capture.install();
        drop(tracing::trace_span!("quiet", field = "only-in-the-span").entered());

        assert!(capture.contents().contains("only-in-the-span"));
    }

    #[test]
    fn stops_capturing_when_the_guard_is_dropped() {
        let capture = LogCapture::new();
        {
            let _guard = capture.install();
            tracing::info!("during");
        }
        tracing::info!("after");

        let logs = capture.contents();
        assert!(logs.contains("during"));
        assert!(!logs.contains("after"));
    }

    #[test]
    fn dispatch_captures_from_another_thread() {
        let capture = LogCapture::new();
        let dispatch = capture.dispatch();
        std::thread::spawn(move || {
            tracing::dispatcher::with_default(&dispatch, || tracing::info!("from a thread"));
        })
        .join()
        .unwrap();

        assert!(capture.contents().contains("from a thread"));
    }

    #[test]
    fn captures_survive_a_poisoned_lock() {
        let capture = LogCapture::new();
        let poisoner = capture.clone();
        let _ = std::thread::spawn(move || {
            let _held = poisoner.buffer.lock().unwrap();
            panic!("poison the lock");
        })
        .join();

        let _guard = capture.install();
        tracing::info!("after the panic");
        assert!(capture.contents().contains("after the panic"));
    }

    #[test]
    fn a_leaked_canary_is_found_in_the_captured_logs() {
        let canary = Canary::generate().unwrap();
        let mut registry = CanaryRegistry::new();
        registry.register(&canary);

        let capture = LogCapture::new();
        let _guard = capture.install();
        tracing::info!(token = canary.value(), "this must never happen");

        let hits = registry.scan("logs", &capture.contents());
        // `tracing` writes a string field through Debug, which escapes it, and
        // the scan still has to recognise it.
        assert!(
            hits.iter().any(|hit| hit.encoding == Encoding::Json),
            "{hits:?}"
        );
    }

    #[test]
    fn clean_logs_have_no_hits() {
        let canary = Canary::generate().unwrap();
        let mut registry = CanaryRegistry::new();
        registry.register(&canary);

        let capture = LogCapture::new();
        let _guard = capture.install();
        tracing::info!(keyset = "acme", "a normal message");

        assert!(registry.scan("logs", &capture.contents()).is_empty());
    }
}
