use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Algorithm, Argon2, Params, Version,
};
use rand::Rng;
use std::time::Duration;

/// Argon2id hasher with pinned params (19 MiB, 2 iterations, 1 lane).
fn argon2_hasher() -> Argon2<'static> {
    let params = Params::new(
        19 * 1024, // 19 MiB = 19456 KiB
        2,         // iterations (time cost)
        1,         // parallelism lanes
        None,      // default output length (32 bytes)
    )
    .expect("hardcoded Argon2 params are valid");

    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
}

/// Hash a password with Argon2id. Returns the PHC-formatted hash string.
/// Call from `spawn_blocking`.
pub fn hash_password(password: &str) -> Result<String, String> {
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = argon2_hasher();

    let password_hash = argon2
        .hash_password(password.as_bytes(), &salt)
        .map_err(|e| format!("Failed to hash password: {e}"))?;

    Ok(password_hash.to_string())
}

/// Verify a password against a stored PHC hash string. Returns `Ok(true)` on
/// match, `Ok(false)` on mismatch, `Err` if the hash is malformed.
/// Call from `spawn_blocking`.
pub fn verify_password(password: &str, hash: &str) -> Result<bool, String> {
    let parsed_hash =
        PasswordHash::new(hash).map_err(|e| format!("Failed to parse password hash: {e}"))?;

    // PHC string carries the params used during hashing, so default is fine here.
    let argon2 = Argon2::default();

    match argon2.verify_password(password.as_bytes(), &parsed_hash) {
        Ok(()) => Ok(true),
        Err(argon2::password_hash::Error::Password) => Ok(false),
        Err(e) => Err(format!("Password verification failed: {e}")),
    }
}

/// Sleep for ~200 ms ± 50 ms jitter to mimic Argon2 verify latency.
/// Called on login when the username doesn't exist so the response time
/// looks the same as a wrong-password attempt.
pub async fn timing_safe_delay() {
    const BASE_MS: u64 = 200;
    const JITTER_MS: u64 = 50;

    let jitter = rand::thread_rng().gen_range(0..=(JITTER_MS * 2));
    let delay = Duration::from_millis(BASE_MS - JITTER_MS + jitter);
    tokio::time::sleep(delay).await;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_produces_argon2id_string() {
        let hash = hash_password("test-password").unwrap();
        assert!(
            hash.starts_with("$argon2id$"),
            "Expected argon2id hash prefix, got: {hash}"
        );
    }

    #[test]
    fn hash_embeds_correct_params() {
        let hash = hash_password("test-password").unwrap();
        // PHC format: $argon2id$v=19$m=19456,t=2,p=1$<salt>$<hash>
        assert!(
            hash.contains("m=19456,t=2,p=1"),
            "Expected m=19456,t=2,p=1 in hash, got: {hash}"
        );
    }

    #[test]
    fn hash_is_unique_per_call() {
        let h1 = hash_password("same-password").unwrap();
        let h2 = hash_password("same-password").unwrap();
        assert_ne!(
            h1, h2,
            "Two hashes of the same password should differ (random salt)"
        );
    }

    #[test]
    fn verify_correct_password() {
        let hash = hash_password("correct-horse-battery-staple").unwrap();
        assert!(verify_password("correct-horse-battery-staple", &hash).unwrap());
    }

    #[test]
    fn verify_wrong_password() {
        let hash = hash_password("correct-password").unwrap();
        assert!(!verify_password("wrong-password", &hash).unwrap());
    }

    #[test]
    fn verify_empty_password_against_nonempty_hash() {
        let hash = hash_password("not-empty").unwrap();
        assert!(!verify_password("", &hash).unwrap());
    }

    #[test]
    fn hash_empty_password() {
        // Allowed at the crypto layer; service layer enforces minimum length.
        let hash = hash_password("").unwrap();
        assert!(verify_password("", &hash).unwrap());
    }

    #[test]
    fn verify_rejects_malformed_hash() {
        let result = verify_password("test-credential", "not-a-valid-hash");
        assert!(result.is_err());
    }

    #[test]
    fn hash_and_verify_unicode_password() {
        let password = "пароль-🔐-密码";
        let hash = hash_password(password).unwrap();
        assert!(verify_password(password, &hash).unwrap());
        assert!(!verify_password("wrong", &hash).unwrap());
    }

    #[test]
    fn hash_and_verify_long_password() {
        let password = "a".repeat(1024);
        let hash = hash_password(&password).unwrap();
        assert!(verify_password(&password, &hash).unwrap());
    }

    #[tokio::test]
    async fn timing_safe_delay_completes_in_expected_range() {
        let start = std::time::Instant::now();
        timing_safe_delay().await;
        let elapsed = start.elapsed();
        assert!(
            elapsed >= Duration::from_millis(140) && elapsed <= Duration::from_millis(300),
            "Expected delay in ~150–250 ms range, got {:?}",
            elapsed,
        );
    }
}
