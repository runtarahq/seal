//! The types that hold plaintext secrets.
//!
//! Plaintext lives only in these types. They zeroize on drop and implement no
//! `Display`, `Serialize`, `Clone` or `PartialEq`, and `Debug` is redacted.
//! Reading one takes an explicit `expose` call, so every place that touches
//! plaintext can be found with grep.

use std::fmt;

use zeroize::Zeroize;

/// A plaintext secret.
pub struct Secret(Box<[u8]>);

impl Secret {
    /// Copies a secret from a slice. The caller still owns the original.
    #[must_use]
    pub fn new(bytes: &[u8]) -> Self {
        Self(Box::from(bytes))
    }

    /// Runs `read` with the plaintext. The plaintext must not outlive the call.
    pub fn expose<R>(&self, read: impl FnOnce(&[u8]) -> R) -> R {
        read(&self.0)
    }
}

impl Drop for Secret {
    fn drop(&mut self) {
        self.0.zeroize();
        #[cfg(test)]
        tests::observe_drop(&self.0);
    }
}

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Secret([REDACTED])")
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use std::cell::RefCell;

    use super::*;

    thread_local! {
        /// What each dropped secret's buffer held after wiping.
        static DROPPED: RefCell<Vec<Vec<u8>>> = const { RefCell::new(Vec::new()) };
    }

    pub(crate) fn observe_drop(buffer: &[u8]) {
        DROPPED.with(|dropped| dropped.borrow_mut().push(buffer.to_vec()));
    }

    pub(crate) fn take_dropped() -> Vec<Vec<u8>> {
        DROPPED.with(|dropped| dropped.take())
    }

    #[test]
    fn debug_is_redacted() {
        let secret = Secret::new(b"hunter2");
        assert_eq!(format!("{secret:?}"), "Secret([REDACTED])");
        assert_eq!(format!("{secret:#?}"), "Secret([REDACTED])");
    }

    #[test]
    fn expose_gives_the_plaintext() {
        let secret = Secret::new(b"hunter2");
        assert_eq!(secret.expose(<[u8]>::to_vec), b"hunter2");
    }

    #[test]
    fn expose_works_for_an_empty_secret() {
        assert!(Secret::new(b"").expose(<[u8]>::is_empty));
    }

    #[test]
    fn the_buffer_is_wiped_on_drop() {
        take_dropped();
        drop(Secret::new(b"hunter2"));
        assert_eq!(take_dropped(), [vec![0_u8; 7]]);
    }
}
