//! Process hardening at startup, through `nix`'s safe functions only.

use crate::config::LockMemory;

/// What hardening managed to do, for the startup log.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Hardened {
    /// Whether memory is locked, so key pages are never swapped.
    pub memory_locked: bool,
}

/// Refuses to run as root, turns off core dumps, and locks memory as configured.
///
/// # Errors
///
/// Returns a message if seal runs as root, core dumps cannot be turned off, or memory
/// locking is required and fails.
pub fn harden(lock_memory: LockMemory) -> Result<Hardened, String> {
    #[cfg(unix)]
    {
        if nix::unistd::geteuid().is_root() {
            return Err("seal refuses to run as root".to_owned());
        }
        nix::sys::resource::setrlimit(nix::sys::resource::Resource::RLIMIT_CORE, 0, 0)
            .map_err(|_| "could not turn off core dumps".to_owned())?;
    }
    #[cfg(target_os = "linux")]
    {
        nix::sys::prctl::set_dumpable(false)
            .map_err(|_| "could not mark the process undumpable".to_owned())?;
    }
    let memory_locked = match lock_memory {
        LockMemory::Off => false,
        LockMemory::BestEffort | LockMemory::Required => {
            let locked = lock_all();
            if !locked {
                if lock_memory == LockMemory::Required {
                    return Err(
                        "memory locking is required and failed; raise LimitMEMLOCK".to_owned()
                    );
                }
                tracing::warn!("memory is not locked, so key pages could reach swap");
            }
            locked
        }
    };
    Ok(Hardened { memory_locked })
}

fn lock_all() -> bool {
    #[cfg(target_os = "linux")]
    {
        use nix::sys::mman::{MlockAllFlags, mlockall};
        mlockall(MlockAllFlags::MCL_CURRENT | MlockAllFlags::MCL_FUTURE).is_ok()
    }
    #[cfg(not(target_os = "linux"))]
    {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hardening_succeeds_for_a_normal_user_without_locking() {
        if nix::unistd::geteuid().is_root() {
            assert!(harden(LockMemory::Off).is_err());
            return;
        }
        assert_eq!(
            harden(LockMemory::Off).unwrap(),
            Hardened {
                memory_locked: false
            }
        );
        let limit =
            nix::sys::resource::getrlimit(nix::sys::resource::Resource::RLIMIT_CORE).unwrap();
        assert_eq!(limit, (0, 0));
    }
}
