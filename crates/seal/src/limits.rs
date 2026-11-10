//! Rate limits per caller and per keyset, and the memory ceiling.

use std::collections::HashMap;
use std::hash::Hash;
use std::sync::{Mutex, PoisonError};

use tokio::time::Instant;

use crate::config::{Config, Rate};

/// Token buckets keyed by a name callers choose, so the table is bounded: past
/// `capacity`, the least recently used bucket is dropped, which only ever forgets a
/// limit, never invents one.
pub struct RateLimiter<K> {
    rate: Rate,
    capacity: usize,
    buckets: Mutex<HashMap<K, Bucket>>,
}

#[derive(Clone, Copy)]
struct Bucket {
    tokens: f64,
    updated: Instant,
}

impl<K: Eq + Hash + Clone> RateLimiter<K> {
    /// A limiter allowing `rate`, with bursts of up to one period's worth.
    #[must_use]
    pub fn new(rate: Rate, capacity: usize) -> Self {
        Self {
            rate,
            capacity: capacity.max(1),
            buckets: Mutex::new(HashMap::new()),
        }
    }

    /// Takes a token, if there is one.
    pub fn allow(&self, key: &K) -> bool {
        let now = Instant::now();
        let burst = f64::from(self.rate.count);
        let per_second = burst / self.rate.per.as_secs_f64();
        let mut buckets = self.buckets.lock().unwrap_or_else(PoisonError::into_inner);
        if !buckets.contains_key(key) && buckets.len() >= self.capacity {
            let oldest = buckets
                .iter()
                .min_by_key(|(_, bucket)| bucket.updated)
                .map(|(key, _)| key.clone());
            if let Some(oldest) = oldest {
                buckets.remove(&oldest);
            }
        }
        let bucket = buckets.entry(key.clone()).or_insert(Bucket {
            tokens: burst,
            updated: now,
        });
        let elapsed = now.duration_since(bucket.updated).as_secs_f64();
        bucket.tokens = (bucket.tokens + elapsed * per_second).min(burst);
        bucket.updated = now;
        if bucket.tokens >= 1.0 {
            bucket.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

/// Measured or estimated costs in bytes, per unit of each bounded resource. A memory
/// test re-measures those marked measured and fails if a constant is too low (6.8).
pub mod costs {
    /// Per stream, on top of its buffer: task, gRPC and HTTP/2 state. Measured at
    /// about 29 KiB, with its connection.
    pub const STREAM: u64 = 64 * 1024;
    /// How much larger parsed JSON is than its bytes. Estimated: the nightly test
    /// measures a full capped buffer, at about twice the cap, but not parsing.
    pub const PARSE_FACTOR: u64 = 4;
    /// The largest envelope, which a sealed response field can grow to.
    pub const MAX_ENVELOPE: u64 = 96 * 1024;
    /// Per caller connection: HTTP/2 buffers, and TLS records over TCP. Measured at
    /// about 23 KiB on a Unix socket.
    pub const CALLER_CONNECTION: u64 = 128 * 1024;
    /// Per provider connection: TLS records and HTTP/2 buffers. Measured at about
    /// 28 KiB idle, over plain HTTP.
    pub const UPSTREAM_CONNECTION: u64 = 128 * 1024;
    /// Per client-certificate TLS configuration. Estimated, not measured.
    pub const TLS_CONFIG: u64 = 32 * 1024;
    /// Per live key, including a keyset's overhead as if it were alone. Measured at
    /// about 2 KiB.
    pub const KEY: u64 = 4 * 1024;
    /// Per remembered unknown keyset or rate bucket. Measured at about 73 bytes.
    pub const TRACKED_KEYSET: u64 = 512;
    /// The process itself: runtime, TLS stacks, allocator. Measured at about 11 MiB idle.
    pub const FIXED_OVERHEAD: u64 = 64 * 1024 * 1024;
    /// Allocator fragmentation, as a percentage.
    pub const ALLOCATOR_MARGIN_PERCENT: u64 = 25;
}

/// One term of the ceiling, for `check-config` to print.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Term {
    /// What it counts.
    pub name: &'static str,
    /// Its bytes.
    pub bytes: u64,
}

/// The memory ceiling the configuration implies: every bounded resource times its
/// cost, plus fixed overhead and a margin.
#[must_use]
pub fn ceiling(config: &Config) -> (u64, Vec<Term>) {
    let limits = &config.limits;
    let as_u64 = |value: usize| u64::try_from(value).unwrap_or(u64::MAX);
    let terms = vec![
        Term {
            name: "streams",
            bytes: as_u64(limits.max_concurrent_streams).saturating_mul(
                limits.per_stream_buffer.0
                    + limits.max_head.0 * costs::PARSE_FACTOR
                    + costs::STREAM,
            ),
        },
        Term {
            name: "capped buffers",
            bytes: as_u64(limits.max_concurrent_buffered).saturating_mul(
                limits.buffer_cap.0 * costs::PARSE_FACTOR + 8 * costs::MAX_ENVELOPE,
            ),
        },
        Term {
            name: "caller connections",
            bytes: as_u64(limits.max_caller_connections).saturating_mul(costs::CALLER_CONNECTION),
        },
        Term {
            name: "provider connections",
            bytes: as_u64(config.pools.max_upstream_connections)
                .saturating_mul(costs::UPSTREAM_CONNECTION),
        },
        Term {
            name: "client-certificate identities",
            bytes: as_u64(config.pools.max_client_cert_identities)
                .saturating_mul(costs::TLS_CONFIG),
        },
        Term {
            name: "live keys",
            bytes: as_u64(config.keys.max_live_keys).saturating_mul(costs::KEY),
        },
        Term {
            name: "tracked keysets and rate buckets",
            // Unknown keysets, plus a rate bucket per keyset and per caller.
            bytes: as_u64(config.keys.max_tracked_keysets)
                .saturating_mul(2)
                .saturating_add(as_u64(config.callers.len()))
                .saturating_mul(costs::TRACKED_KEYSET),
        },
        Term {
            name: "fixed overhead",
            bytes: costs::FIXED_OVERHEAD,
        },
    ];
    let sum = terms
        .iter()
        .fold(0_u64, |sum, term| sum.saturating_add(term.bytes));
    let total = sum.saturating_add(sum / 100 * costs::ALLOCATOR_MARGIN_PERCENT);
    (total, terms)
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    #[tokio::test(start_paused = true)]
    async fn a_bucket_allows_its_rate_and_refills() {
        let limiter = RateLimiter::new(
            Rate {
                count: 3,
                per: Duration::from_secs(1),
            },
            10,
        );
        let key = "app".to_owned();
        assert!((0..3).all(|_| limiter.allow(&key)));
        assert!(!limiter.allow(&key));
        tokio::time::advance(Duration::from_millis(340)).await;
        assert!(limiter.allow(&key));
        assert!(!limiter.allow(&key));
        assert!(
            limiter.allow(&"other".to_owned()),
            "keys have their own buckets"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn the_table_is_bounded() {
        let limiter = RateLimiter::new(
            Rate {
                count: 1,
                per: Duration::from_secs(60),
            },
            2,
        );
        for key in ["a", "b", "c"] {
            assert!(limiter.allow(&key.to_owned()));
            tokio::time::advance(Duration::from_millis(1)).await;
        }
        assert_eq!(limiter.buckets.lock().unwrap().len(), 2);
    }

    #[test]
    fn the_ceiling_of_the_example_fits_its_budget_and_grows_with_limits() {
        let text = std::fs::read_to_string(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../deploy/config/same-host.toml"),
        )
        .unwrap();
        let mut config = Config::parse(&text).unwrap();
        let (total, terms) = ceiling(&config);
        assert!(total <= config.limits.memory_budget.0, "{total} > budget");
        assert_eq!(terms.len(), 8);

        config.limits.max_concurrent_streams *= 4;
        assert!(ceiling(&config).0 > total);
    }
}
