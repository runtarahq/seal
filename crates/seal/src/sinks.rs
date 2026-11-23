//! Audit sinks: one JSON line per record, written by seal so a compromised caller
//! cannot hide its use. A failed write fails the request, unless configured otherwise.

use std::collections::VecDeque;
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::Path;
use std::sync::{Mutex, PoisonError};

use seal_broker::audit::{AuditFailed, AuditRecord, AuditSink, Outcome};

use crate::config::AuditFailure;

/// Writes records to standard output.
#[derive(Debug, Default)]
pub struct StdoutSink;

impl AuditSink for StdoutSink {
    fn record(&self, record: &AuditRecord) -> Result<(), AuditFailed> {
        let line = line(record)?;
        let mut stdout = std::io::stdout().lock();
        stdout
            .write_all(&line)
            .and_then(|()| stdout.flush())
            .map_err(|_| AuditFailed)
    }
}

/// Appends records to a file.
#[derive(Debug)]
pub struct FileSink {
    file: Mutex<File>,
}

impl FileSink {
    /// Opens a file for appending, creating it readable only by seal's user.
    ///
    /// # Errors
    ///
    /// Returns an error if it cannot be opened, or if a file that was already there
    /// can be written by its group or reached by others: the mode above applies only
    /// to a file this creates.
    pub fn open(path: &Path) -> std::io::Result<Self> {
        let mut options = OpenOptions::new();
        options.append(true).create(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let file = options.open(path)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if file.metadata()?.permissions().mode() & 0o027 != 0 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    "the audit file is writable by its group or accessible to others",
                ));
            }
        }
        Ok(Self {
            file: Mutex::new(file),
        })
    }
}

impl AuditSink for FileSink {
    fn record(&self, record: &AuditRecord) -> Result<(), AuditFailed> {
        let line = line(record)?;
        let mut file = self.file.lock().unwrap_or_else(PoisonError::into_inner);
        // One write per record, so that records from concurrent requests never mix.
        file.write_all(&line)
            .and_then(|()| file.flush())
            .map_err(|_| AuditFailed)
    }
}

fn line(record: &AuditRecord) -> Result<Vec<u8>, AuditFailed> {
    let mut line = serde_json::to_vec(record).map_err(|_| AuditFailed)?;
    line.push(b'\n');
    Ok(line)
}

/// Applies the configured failure behaviour to another sink.
pub struct Policy<S> {
    inner: S,
    on_failure: AuditFailure,
    /// Records that could not be written, to write before anything else is used.
    missed: Mutex<VecDeque<AuditRecord>>,
}

/// The most unwritten records kept. Nothing new is used while one is unwritten, so
/// those that matter are of what was under way when the sink broke, and they arrive as
/// each ends, which may be hours later for a Postgres session.
const MAX_MISSED: usize = 1024;

/// How many of them may be refusals. Every request refused while the sink cannot
/// write would leave one, and a caller can make those as fast as its rate allows:
/// kept without a limit of their own, they would fill the room before the records of
/// what was really used arrived.
const MAX_MISSED_REFUSALS: usize = 64;

impl<S> Policy<S> {
    /// Wraps a sink.
    pub fn new(inner: S, on_failure: AuditFailure) -> Self {
        Self {
            inner,
            on_failure,
            missed: Mutex::new(VecDeque::new()),
        }
    }
}

impl<S: AuditSink> AuditSink for Policy<S> {
    fn record(&self, record: &AuditRecord) -> Result<(), AuditFailed> {
        match (self.inner.record(record), self.on_failure) {
            (Ok(()), _) => Ok(()),
            (Err(_), AuditFailure::BestEffort) => {
                metrics::counter!("seal_audit_failures_total").increment(1);
                Ok(())
            }
            (Err(error), AuditFailure::FailClosed) => {
                metrics::counter!("seal_audit_failures_total").increment(1);
                let mut missed = self.missed.lock().unwrap_or_else(PoisonError::into_inner);
                let room = if record.outcome == Outcome::Refused {
                    MAX_MISSED_REFUSALS
                } else {
                    MAX_MISSED
                };
                if missed.len() < room {
                    missed.push_back(record.clone());
                } else {
                    metrics::counter!("seal_audit_dropped_total").increment(1);
                }
                Err(error)
            }
        }
    }

    /// A record is written when its request ends, so the one that finds the sink
    /// broken has already used its credential. From then on nothing is used until the
    /// records that were missed have been written.
    fn ready(&self) -> Result<(), AuditFailed> {
        let mut missed = self.missed.lock().unwrap_or_else(PoisonError::into_inner);
        while let Some(record) = missed.front() {
            self.inner.record(record)?;
            missed.pop_front();
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(caller: &str) -> AuditRecord {
        AuditRecord {
            ts: 1,
            op: "send",
            caller: caller.to_owned(),
            keyset: "acme".to_owned(),
            item: "c".to_owned(),
            fields: vec![],
            shared: vec![],
            rules: vec![],
            method: "GET".to_owned(),
            host: None,
            path: None,
            status: None,
            bytes_in: 0,
            bytes_out: 0,
            ms: 0,
            outcome: Outcome::Ok,
            code: None,
            pg_auth: None,
            verified: None,
            expires_s: None,
            policies: Vec::new(),
        }
    }

    struct Failing;
    impl AuditSink for Failing {
        fn record(&self, _: &AuditRecord) -> Result<(), AuditFailed> {
            Err(AuditFailed)
        }
    }

    #[test]
    fn a_file_gets_one_json_line_per_record_and_is_private() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("audit.jsonl");
        let sink = FileSink::open(&path).unwrap();
        sink.record(&record("a")).unwrap();
        sink.record(&record("b")).unwrap();
        drop(sink);
        let sink = FileSink::open(&path).unwrap();
        sink.record(&record("c")).unwrap();
        let text = std::fs::read_to_string(&path).unwrap();
        let callers: Vec<String> = text
            .lines()
            .map(|line| {
                serde_json::from_str::<serde_json::Value>(line).unwrap()["caller"]
                    .as_str()
                    .unwrap()
                    .to_owned()
            })
            .collect();
        assert_eq!(callers, ["a", "b", "c"], "appends, never truncates");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn a_file_others_can_reach_is_refused() {
        use std::os::unix::fs::PermissionsExt;
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("audit.jsonl");
        std::fs::write(&path, b"").unwrap();
        for (mode, is_allowed) in [
            (0o600, true),
            (0o640, true),
            (0o644, false),
            (0o660, false),
            (0o602, false),
        ] {
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
            assert_eq!(FileSink::open(&path).is_ok(), is_allowed, "{mode:o}");
        }
    }

    /// Fails while told to, and keeps what it wrote.
    #[derive(Default)]
    struct Flaky {
        broken: Mutex<bool>,
        written: Mutex<Vec<String>>,
    }
    impl AuditSink for &Flaky {
        fn record(&self, record: &AuditRecord) -> Result<(), AuditFailed> {
            if *self.broken.lock().unwrap() {
                return Err(AuditFailed);
            }
            self.written.lock().unwrap().push(record.caller.clone());
            Ok(())
        }
    }

    #[test]
    fn after_a_record_is_missed_nothing_is_ready_until_it_is_written() {
        let sink = Flaky::default();
        let policy = Policy::new(&sink, AuditFailure::FailClosed);
        assert_eq!(policy.ready(), Ok(()));
        *sink.broken.lock().unwrap() = true;
        // A sink is only found broken by a write.
        assert_eq!(policy.ready(), Ok(()));
        assert_eq!(policy.record(&record("a")), Err(AuditFailed));
        assert_eq!(policy.record(&record("b")), Err(AuditFailed));
        assert_eq!(policy.ready(), Err(AuditFailed));
        *sink.broken.lock().unwrap() = false;
        assert_eq!(policy.ready(), Ok(()));
        assert_eq!(*sink.written.lock().unwrap(), ["a", "b"], "written late");
        assert_eq!(policy.ready(), Ok(()));
        assert_eq!(sink.written.lock().unwrap().len(), 2, "and once");

        // Best effort never holds anything up.
        let policy = Policy::new(&sink, AuditFailure::BestEffort);
        *sink.broken.lock().unwrap() = true;
        assert_eq!(policy.record(&record("c")), Ok(()));
        assert_eq!(policy.ready(), Ok(()));
    }

    #[test]
    fn refusals_made_while_the_sink_is_broken_do_not_crowd_out_what_was_used() {
        let sink = Flaky::default();
        let policy = Policy::new(&sink, AuditFailure::FailClosed);
        *sink.broken.lock().unwrap() = true;
        // A session under way when the sink broke ends, and finds it broken.
        assert_eq!(policy.record(&record("first")), Err(AuditFailed));
        // From then on every request is refused, and a caller can ask as fast as its
        // rate allows.
        for _ in 0..10 * MAX_MISSED {
            let mut refused = record("refused");
            refused.outcome = Outcome::Refused;
            assert_eq!(policy.record(&refused), Err(AuditFailed));
        }
        // What was also under way ends later still, and its record is kept.
        let mut session = record("session");
        session.outcome = Outcome::Cancelled;
        assert_eq!(policy.record(&session), Err(AuditFailed));

        *sink.broken.lock().unwrap() = false;
        assert_eq!(policy.ready(), Ok(()));
        let written = sink.written.lock().unwrap();
        assert_eq!(written.first().map(String::as_str), Some("first"));
        assert_eq!(written.last().map(String::as_str), Some("session"));
        assert_eq!(written.len(), MAX_MISSED_REFUSALS + 1);
    }

    #[test]
    fn failure_closes_by_default_and_only_best_effort_carries_on() {
        assert_eq!(
            Policy::new(Failing, AuditFailure::FailClosed).record(&record("a")),
            Err(AuditFailed)
        );
        assert_eq!(
            Policy::new(Failing, AuditFailure::BestEffort).record(&record("a")),
            Ok(())
        );
    }
}
