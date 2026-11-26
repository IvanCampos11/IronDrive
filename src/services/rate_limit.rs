use dashmap::DashMap;
use std::time::Instant;

use rocket::request::{FromRequest, Outcome, Request};

/// Prune expired entries once the map grows past this many keys, so a flood
/// of requests from many addresses can't grow memory without bound.
const PRUNE_THRESHOLD: usize = 10_000;

/// In-memory fixed-window rate limiter, keyed by an arbitrary string
/// (e.g. `"login:<ip>"`).
pub struct RateLimiter {
    /// key -> (attempts in window, window start, window length in seconds)
    attempts: DashMap<String, (u32, Instant, u64)>,
}

impl RateLimiter {
    pub fn new() -> Self {
        Self {
            attempts: DashMap::new(),
        }
    }

    /// Returns `true` if within limit, `false` if rate-limited.
    pub fn check(&self, key: &str, max_attempts: u32, window_secs: u64) -> bool {
        let now = Instant::now();

        // Must run before `entry()` below: DashMap's retain locks every shard.
        if self.attempts.len() > PRUNE_THRESHOLD {
            self.prune(now);
        }

        let mut entry = self
            .attempts
            .entry(key.to_string())
            .or_insert((0, now, window_secs));
        let (count, start, window) = entry.value_mut();

        if now.duration_since(*start).as_secs() > *window {
            *count = 1;
            *start = now;
            *window = window_secs;
            true
        } else if *count < max_attempts {
            *count += 1;
            true
        } else {
            false
        }
    }

    /// Drop every entry whose window has already ended.
    fn prune(&self, now: Instant) {
        self.attempts
            .retain(|_, (_, start, window)| now.duration_since(*start).as_secs() <= *window);
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.attempts.len()
    }
}

impl Default for RateLimiter {
    fn default() -> Self {
        Self::new()
    }
}

/// Request guard to extract the client IP address.
pub struct ClientIp(pub String);

#[rocket::async_trait]
impl<'r> FromRequest<'r> for ClientIp {
    type Error = ();

    async fn from_request(request: &'r Request<'_>) -> Outcome<Self, Self::Error> {
        let ip = request
            .client_ip()
            .map(|ip| ip.to_string())
            .unwrap_or_else(|| "unknown".to_string());
        Outcome::Success(ClientIp(ip))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allows_within_limit() {
        let rl = RateLimiter::new();
        for _ in 0..5 {
            assert!(rl.check("test", 5, 60));
        }
    }

    #[test]
    fn blocks_over_limit() {
        let rl = RateLimiter::new();
        for _ in 0..5 {
            rl.check("test", 5, 60);
        }
        assert!(!rl.check("test", 5, 60));
    }

    #[test]
    fn expired_entries_are_pruned() {
        let rl = RateLimiter::new();
        for i in 0..=PRUNE_THRESHOLD {
            rl.check(&format!("k{i}"), 5, 0);
        }
        std::thread::sleep(std::time::Duration::from_millis(1100));
        rl.check("trigger", 5, 60);
        assert!(rl.len() < 10, "expired entries should be pruned, got {}", rl.len());
    }

    #[test]
    fn separate_keys_independent() {
        let rl = RateLimiter::new();
        for _ in 0..5 {
            rl.check("a", 5, 60);
        }
        assert!(rl.check("b", 5, 60));
    }
}
