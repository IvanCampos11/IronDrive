use dashmap::DashMap;
use std::time::Instant;

use rocket::request::{FromRequest, Outcome, Request};

/// In-memory rate limiter using sliding window counters.
pub struct RateLimiter {
    attempts: DashMap<String, (u32, Instant)>,
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
        let mut entry = self.attempts.entry(key.to_string()).or_insert((0, now));
        let (count, start) = entry.value_mut();

        if now.duration_since(*start).as_secs() > window_secs {
            *count = 1;
            *start = now;
            true
        } else if *count < max_attempts {
            *count += 1;
            true
        } else {
            false
        }
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
    fn separate_keys_independent() {
        let rl = RateLimiter::new();
        for _ in 0..5 {
            rl.check("a", 5, 60);
        }
        assert!(rl.check("b", 5, 60));
    }
}
