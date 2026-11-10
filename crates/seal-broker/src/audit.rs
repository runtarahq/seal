//! One record per `send`. Written by seal, so a compromised caller cannot hide its use.
//!
//! A record has a fixed schema of identifiers and counts: never headers, bodies or
//! query strings.

use std::sync::Arc;
use std::time::SystemTime;

use serde::Serialize;
use tokio::time::Instant;

use crate::body::Progress;
use crate::error::ErrorCode;

/// The audit record's fixed schema.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct AuditRecord {
    /// When the request started, in seconds since the Unix epoch.
    pub ts: u64,
    /// The operation.
    pub op: &'static str,
    /// The caller's identity.
    pub caller: String,
    /// The keyset.
    pub keyset: String,
    /// The item.
    pub item: String,
    /// The names of the sealed fields presented.
    pub fields: Vec<String>,
    /// Fields bound to another record, as `field=keyset/item`: shared values.
    pub shared: Vec<String>,
    /// The index of the matched rule for each field that matched, in field order.
    pub rules: Vec<usize>,
    /// The method.
    pub method: String,
    /// The destination host, if the URL was valid.
    pub host: Option<String>,
    /// The destination path without its query string, if the URL was valid.
    pub path: Option<String>,
    /// The response's status, if there was one.
    pub status: Option<u16>,
    /// Request body bytes sent.
    pub bytes_in: u64,
    /// Response body bytes returned.
    pub bytes_out: u64,
    /// How long it took.
    pub ms: u64,
    /// How it ended.
    pub outcome: Outcome,
    /// The error code, if it failed.
    pub code: Option<&'static str>,
    /// How a Postgres session logged in, such as `scram-sha-256-plus`.
    pub pg_auth: Option<&'static str>,
}

/// How a request ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    /// The response was returned in full.
    Ok,
    /// Refused before anything reached the provider.
    Refused,
    /// Failed after the provider may have received the request.
    Failed,
    /// The caller went away.
    Cancelled,
}

/// A record could not be written.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AuditFailed;

/// Where audit records go.
pub trait AuditSink: Send + Sync {
    /// Writes a record. A failure fails the request rather than leaving it unaudited.
    ///
    /// # Errors
    ///
    /// Returns [`AuditFailed`] if the record could not be written.
    fn record(&self, record: &AuditRecord) -> Result<(), AuditFailed>;
}

/// Where the time comes from.
pub trait Clock: Send + Sync {
    /// The current time.
    fn now(&self) -> SystemTime;
}

/// The system's clock.
#[derive(Clone, Copy, Debug, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> SystemTime {
        SystemTime::now()
    }
}

/// A record being filled in. If it is dropped unwritten, the caller went away, and it
/// writes itself as cancelled, so that every request leaves a record.
pub(crate) struct AuditGuard {
    sink: Arc<dyn AuditSink>,
    started: Instant,
    progress: Arc<Progress>,
    record: Option<AuditRecord>,
}

impl AuditGuard {
    pub(crate) fn new(
        sink: Arc<dyn AuditSink>,
        record: AuditRecord,
        progress: Arc<Progress>,
    ) -> Self {
        Self {
            sink,
            started: Instant::now(),
            progress,
            record: Some(record),
        }
    }

    pub(crate) fn update(&mut self, change: impl FnOnce(&mut AuditRecord)) {
        if let Some(record) = &mut self.record {
            change(record);
        }
    }

    /// Writes the record.
    pub(crate) fn finish(
        mut self,
        outcome: Outcome,
        code: Option<ErrorCode>,
    ) -> Result<(), AuditFailed> {
        self.write(outcome, code)
    }

    fn write(&mut self, outcome: Outcome, code: Option<ErrorCode>) -> Result<(), AuditFailed> {
        let Some(mut record) = self.record.take() else {
            return Ok(());
        };
        record.bytes_in = self.progress.bytes_in();
        record.bytes_out = self.progress.bytes_out();
        record.outcome = outcome;
        record.code = code.map(ErrorCode::as_str);
        record.ms = u64::try_from(self.started.elapsed().as_millis()).unwrap_or(u64::MAX);
        self.sink.record(&record)
    }
}

impl Drop for AuditGuard {
    fn drop(&mut self) {
        // Nothing can be returned to a caller that has gone.
        let _ = self.write(Outcome::Cancelled, None);
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use super::*;

    #[derive(Default)]
    struct Memory(Mutex<Vec<AuditRecord>>);

    impl AuditSink for Memory {
        fn record(&self, record: &AuditRecord) -> Result<(), AuditFailed> {
            self.0.lock().unwrap().push(record.clone());
            Ok(())
        }
    }

    fn record() -> AuditRecord {
        AuditRecord {
            ts: 1,
            op: "send",
            caller: "app".to_owned(),
            keyset: "acme".to_owned(),
            item: "c_1".to_owned(),
            fields: vec!["token".to_owned()],
            shared: vec![],
            rules: vec![0],
            method: "GET".to_owned(),
            host: Some("api.example.com".to_owned()),
            path: Some("/v2/orders".to_owned()),
            status: Some(200),
            bytes_in: 1,
            bytes_out: 2,
            ms: 0,
            outcome: Outcome::Ok,
            code: None,
            pg_auth: None,
        }
    }

    #[tokio::test]
    async fn the_schema_is_the_documented_one() {
        let json = serde_json::to_value(record()).unwrap();
        let keys: Vec<&str> = json
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        assert_eq!(
            keys,
            [
                "bytes_in",
                "bytes_out",
                "caller",
                "code",
                "fields",
                "host",
                "item",
                "keyset",
                "method",
                "ms",
                "op",
                "outcome",
                "path",
                "pg_auth",
                "rules",
                "shared",
                "status",
                "ts"
            ]
        );
        assert_eq!(json["outcome"], "ok");
    }

    #[tokio::test]
    async fn finishing_writes_once_with_the_outcome() {
        let memory = Arc::new(Memory::default());
        let guard = AuditGuard::new(memory.clone(), record(), Arc::new(Progress::new()));
        guard
            .finish(Outcome::Failed, Some(ErrorCode::UpstreamReset))
            .unwrap();
        let records = memory.0.lock().unwrap();
        assert_eq!(
            records.len(),
            1,
            "dropping after finishing writes nothing more"
        );
        assert_eq!(records[0].outcome, Outcome::Failed);
        assert_eq!(records[0].code, Some("UPSTREAM_RESET"));
    }

    #[tokio::test]
    async fn dropping_unwritten_records_a_cancellation() {
        let memory = Arc::new(Memory::default());
        drop(AuditGuard::new(
            memory.clone(),
            record(),
            Arc::new(Progress::new()),
        ));
        assert_eq!(memory.0.lock().unwrap()[0].outcome, Outcome::Cancelled);
    }

    #[tokio::test]
    async fn a_failing_sink_is_reported() {
        struct Failing;
        impl AuditSink for Failing {
            fn record(&self, _: &AuditRecord) -> Result<(), AuditFailed> {
                Err(AuditFailed)
            }
        }
        let guard = AuditGuard::new(Arc::new(Failing), record(), Arc::new(Progress::new()));
        assert_eq!(guard.finish(Outcome::Ok, None), Err(AuditFailed));
    }
}
