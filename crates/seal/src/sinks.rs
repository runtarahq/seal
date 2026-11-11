//! Audit sinks: one JSON line per record, written by seal so a compromised caller
//! cannot hide its use. A failed write fails the request, unless configured otherwise.

use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::Path;
use std::sync::{Mutex, PoisonError};

use seal_broker::audit::{AuditFailed, AuditRecord, AuditSink};

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
}

impl<S> Policy<S> {
    /// Wraps a sink.
    pub fn new(inner: S, on_failure: AuditFailure) -> Self {
        Self { inner, on_failure }
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
                Err(error)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use seal_broker::audit::Outcome;

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
            pg_tls: None,
            verified: None,
            expires_s: None,
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
