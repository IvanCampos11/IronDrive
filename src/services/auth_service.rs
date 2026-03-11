use chrono::{Duration, Utc};

use crate::config::AppConfig;
use crate::db::DbPool;
use crate::errors::AppError;
use crate::models::session::Session;
use crate::models::user::{CreateUserParams, User};
use crate::utils::crypto;

const USERNAME_MIN_LEN: usize = 3;
const USERNAME_MAX_LEN: usize = 32;
const PASSWORD_MIN_LEN: usize = 8;
const PASSWORD_MAX_LEN: usize = 1024;
const EMAIL_MAX_LEN: usize = 254;

pub struct RegisterResult {
    pub user: User,
}

pub struct LoginResult {
    pub token: String,
    pub setup_complete: bool,
    pub user: User,
}

/// Register a new user. First user is auto-promoted to admin.
pub async fn register(
    pool: &DbPool,
    config: &AppConfig,
    username: &str,
    email: &str,
    password: &str,
) -> Result<RegisterResult, AppError> {
    let username = normalize_username(username)?;
    let email = normalize_email(email)?;
    validate_password(password)?;

    let password_owned = password.to_string();
    let password_hash = tokio::task::spawn_blocking(move || crypto::hash_password(&password_owned))
        .await
        .map_err(|e| AppError::Internal(format!("Password hashing task failed: {e}")))?
        .map_err(AppError::Internal)?;

    let role = if is_first_user(pool).await? {
        "admin"
    } else {
        "user"
    };

    let user = User::create(
        pool,
        CreateUserParams {
            username: username.clone(),
            email: email.clone(),
            password_hash,
            role: role.to_string(),
            quota_bytes: config.default_quota_bytes as i64,
        },
    )
    .await?;

    tracing::info!(
        user_id = %user.id,
        username = %user.username,
        role = %user.role,
        "New user registered"
    );

    Ok(RegisterResult { user })
}

/// Authenticate with username + password, return a session token.
/// Timing-safe: sleeps on unknown username to prevent enumeration.
pub async fn login(
    pool: &DbPool,
    config: &AppConfig,
    username: &str,
    password: &str,
) -> Result<LoginResult, AppError> {
    let username = normalize_username(username)?;
    let lookup = User::get_password_hash(pool, &username).await?;

    let (user_id, stored_hash) = match lookup {
        Some(pair) => pair,
        None => {
            // Mimic Argon2 latency so "no such user" is indistinguishable from "wrong password".
            crypto::timing_safe_delay().await;

            tracing::debug!(username = %username, "Login attempt for nonexistent user");
            return Err(AppError::Unauthorized);
        }
    };

    let password_owned = password.to_string();
    let hash_owned = stored_hash;
    let is_valid =
        tokio::task::spawn_blocking(move || crypto::verify_password(&password_owned, &hash_owned))
            .await
            .map_err(|e| AppError::Internal(format!("Password verify task failed: {e}")))?
            .map_err(AppError::Internal)?;

    if !is_valid {
        tracing::info!(username = %username, "Failed login attempt — wrong password");
        return Err(AppError::Unauthorized);
    }

    let user = User::find_by_id(pool, &user_id)
        .await?
        .ok_or_else(|| AppError::Internal("User found by hash but not by ID".into()))?;

    if !user.is_active {
        tracing::info!(
            user_id = %user.id,
            username = %user.username,
            "Login rejected — account deactivated"
        );
        return Err(AppError::Unauthorized);
    }

    let raw_token = generate_session_token();
    let token_hash = crate::guards::auth_guard::hash_token(&raw_token);

    let expires_at = Utc::now().naive_utc() + Duration::hours(config.session_expiry_hours as i64);

    Session::create(pool, &user.id, &token_hash, expires_at).await?;

    tracing::info!(
        user_id = %user.id,
        username = %user.username,
        "User logged in"
    );

    Ok(LoginResult {
        token: raw_token,
        setup_complete: user.setup_complete,
        user,
    })
}

/// Destroy a single session by user ID + token hash.
pub async fn logout(
    pool: &DbPool,
    user_id: &str,
    session_token_hash: &str,
) -> Result<(), AppError> {
    let deleted = Session::delete_by_user_and_token(pool, user_id, session_token_hash).await?;

    if deleted {
        tracing::info!(user_id = %user_id, "User logged out");
    } else {
        tracing::warn!(
            user_id = %user_id,
            "Logout called but no matching session found — possibly already expired"
        );
    }

    Ok(())
}

/// Trim, validate length and charset, return normalized username.
fn normalize_username(username: &str) -> Result<String, AppError> {
    let trimmed = username.trim();

    if trimmed.len() < USERNAME_MIN_LEN {
        return Err(AppError::Validation(format!(
            "Username must be at least {USERNAME_MIN_LEN} characters."
        )));
    }
    if trimmed.len() > USERNAME_MAX_LEN {
        return Err(AppError::Validation(format!(
            "Username must be at most {USERNAME_MAX_LEN} characters."
        )));
    }

    if !trimmed
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        return Err(AppError::Validation(
            "Username may only contain letters, numbers, hyphens, and underscores.".into(),
        ));
    }

    if let Some(first) = trimmed.chars().next() {
        if !first.is_ascii_alphanumeric() {
            return Err(AppError::Validation(
                "Username must start with a letter or number.".into(),
            ));
        }
    }

    Ok(trimmed.to_string())
}

/// Trim, validate structure, lowercase the whole address.
fn normalize_email(email: &str) -> Result<String, AppError> {
    let trimmed = email.trim();

    if trimmed.is_empty() {
        return Err(AppError::Validation("Email is required.".into()));
    }
    if trimmed.len() > EMAIL_MAX_LEN {
        return Err(AppError::Validation(format!(
            "Email must be at most {EMAIL_MAX_LEN} characters."
        )));
    }

    let at_pos = trimmed.find('@');
    let (local, domain) = match at_pos {
        Some(pos) if pos > 0 && pos < trimmed.len() - 1 => (&trimmed[..pos], &trimmed[pos + 1..]),
        _ => {
            return Err(AppError::Validation(
                "Email must be a valid email address.".into(),
            ));
        }
    };

    if !domain.contains('.') {
        return Err(AppError::Validation(
            "Email must be a valid email address.".into(),
        ));
    }

    let normalized = format!(
        "{}@{}",
        local.to_ascii_lowercase(),
        domain.to_ascii_lowercase()
    );

    Ok(normalized)
}

fn validate_password(password: &str) -> Result<(), AppError> {
    if password.len() < PASSWORD_MIN_LEN {
        return Err(AppError::Validation(format!(
            "Password must be at least {PASSWORD_MIN_LEN} characters."
        )));
    }
    if password.len() > PASSWORD_MAX_LEN {
        return Err(AppError::Validation(format!(
            "Password must be at most {PASSWORD_MAX_LEN} characters."
        )));
    }

    Ok(())
}

/// Returns `true` if no users exist yet.
async fn is_first_user(pool: &DbPool) -> Result<bool, AppError> {
    let row: (bool,) = sqlx::query_as("SELECT NOT EXISTS (SELECT 1 FROM users)")
        .fetch_one(pool)
        .await?;

    Ok(row.0)
}

/// Random 256-bit session token as URL-safe base64 (no padding).
fn generate_session_token() -> String {
    use base64::Engine;
    use rand::RngCore;
    let mut bytes = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db;

    async fn test_pool() -> DbPool {
        let pool = db::init_pool("sqlite::memory:")
            .await
            .expect("Failed to create test pool");
        db::run_migrations(&pool)
            .await
            .expect("Failed to run migrations");
        pool
    }

    fn test_config() -> AppConfig {
        AppConfig {
            secret_key: "test-key-not-real".into(),
            data_dir: "/tmp/irondrive-test".into(),
            db_dir: "/tmp/irondrive-test-db".into(),
            default_quota_bytes: 5_368_709_120,
            max_upload_bytes: 5_368_709_120,
            session_expiry_hours: 168,
            chunk_size_bytes: 8_388_608,
            chunk_upload_expiry_hours: 24,
            max_parallel_chunks: 4,
            integrity_scan_enabled: false,
            integrity_scan_interval_hours: 168,
        }
    }

    // ── Registration Tests ───────────────────────────────────────────

    #[tokio::test]
    async fn register_first_user_becomes_admin() {
        let pool = test_pool().await;
        let config = test_config();

        let result = register(&pool, &config, "alice", "alice@example.com", "password123")
            .await
            .unwrap();

        assert_eq!(result.user.username, "alice");
        assert_eq!(result.user.role, "admin");
        assert!(!result.user.setup_complete);
    }

    #[tokio::test]
    async fn register_second_user_is_regular() {
        let pool = test_pool().await;
        let config = test_config();

        register(&pool, &config, "alice", "alice@example.com", "password123")
            .await
            .unwrap();

        let result = register(&pool, &config, "bob", "bob@example.com", "password456")
            .await
            .unwrap();

        assert_eq!(result.user.role, "user");
    }

    #[tokio::test]
    async fn register_duplicate_username_fails() {
        let pool = test_pool().await;
        let config = test_config();

        register(&pool, &config, "alice", "alice@example.com", "password123")
            .await
            .unwrap();

        let result = register(&pool, &config, "alice", "alice2@example.com", "password456").await;
        assert!(matches!(result, Err(AppError::Conflict(_))));
    }

    #[tokio::test]
    async fn register_duplicate_email_fails() {
        let pool = test_pool().await;
        let config = test_config();

        register(&pool, &config, "alice", "alice@example.com", "password123")
            .await
            .unwrap();

        let result = register(&pool, &config, "bob", "alice@example.com", "password456").await;
        assert!(matches!(result, Err(AppError::Conflict(_))));
    }

    #[tokio::test]
    async fn register_duplicate_email_different_case_fails() {
        let pool = test_pool().await;
        let config = test_config();

        register(&pool, &config, "alice", "alice@example.com", "password123")
            .await
            .unwrap();

        // Same email, different case — should be detected as duplicate.
        let result = register(&pool, &config, "bob", "Alice@Example.COM", "password456").await;
        assert!(matches!(result, Err(AppError::Conflict(_))));
    }

    #[tokio::test]
    async fn register_normalizes_email_to_lowercase() {
        let pool = test_pool().await;
        let config = test_config();

        let result = register(&pool, &config, "alice", "Alice@Example.COM", "password123")
            .await
            .unwrap();

        assert_eq!(result.user.email, "alice@example.com");
    }

    #[tokio::test]
    async fn register_trims_username_whitespace() {
        let pool = test_pool().await;
        let config = test_config();

        let result = register(
            &pool,
            &config,
            "  alice  ",
            "alice@example.com",
            "password123",
        )
        .await
        .unwrap();

        assert_eq!(result.user.username, "alice");
    }

    #[tokio::test]
    async fn register_trims_email_whitespace() {
        let pool = test_pool().await;
        let config = test_config();

        let result = register(
            &pool,
            &config,
            "alice",
            "  alice@example.com  ",
            "password123",
        )
        .await
        .unwrap();

        assert_eq!(result.user.email, "alice@example.com");
    }

    #[tokio::test]
    async fn register_short_username_fails() {
        let pool = test_pool().await;
        let config = test_config();

        let result = register(&pool, &config, "ab", "ab@example.com", "password123").await;
        assert!(matches!(result, Err(AppError::Validation(_))));
    }

    #[tokio::test]
    async fn register_long_username_fails() {
        let pool = test_pool().await;
        let config = test_config();

        let long_name = "a".repeat(USERNAME_MAX_LEN + 1);
        let result = register(
            &pool,
            &config,
            &long_name,
            "long@example.com",
            "password123",
        )
        .await;
        assert!(matches!(result, Err(AppError::Validation(_))));
    }

    #[tokio::test]
    async fn register_invalid_username_chars_fails() {
        let pool = test_pool().await;
        let config = test_config();

        let result = register(&pool, &config, "al ice", "a@example.com", "password123").await;
        assert!(matches!(result, Err(AppError::Validation(_))));

        let result = register(&pool, &config, "al@ice", "b@example.com", "password123").await;
        assert!(matches!(result, Err(AppError::Validation(_))));
    }

    #[tokio::test]
    async fn register_username_starting_with_symbol_fails() {
        let pool = test_pool().await;
        let config = test_config();

        let result = register(&pool, &config, "-alice", "a@example.com", "password123").await;
        assert!(matches!(result, Err(AppError::Validation(_))));

        let result = register(&pool, &config, "_alice", "b@example.com", "password123").await;
        assert!(matches!(result, Err(AppError::Validation(_))));
    }

    #[tokio::test]
    async fn register_valid_username_with_symbols() {
        let pool = test_pool().await;
        let config = test_config();

        let result = register(
            &pool,
            &config,
            "alice-bob_99",
            "alice@example.com",
            "password123",
        )
        .await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn register_short_password_fails() {
        let pool = test_pool().await;
        let config = test_config();

        let result = register(&pool, &config, "alice", "alice@example.com", "short").await;
        assert!(matches!(result, Err(AppError::Validation(_))));
    }

    #[tokio::test]
    async fn register_invalid_email_fails() {
        let pool = test_pool().await;
        let config = test_config();

        let result = register(&pool, &config, "alice", "not-an-email", "password123").await;
        assert!(matches!(result, Err(AppError::Validation(_))));

        let result = register(&pool, &config, "alice", "@example.com", "password123").await;
        assert!(matches!(result, Err(AppError::Validation(_))));

        let result = register(&pool, &config, "alice", "alice@", "password123").await;
        assert!(matches!(result, Err(AppError::Validation(_))));

        let result = register(&pool, &config, "alice", "", "password123").await;
        assert!(matches!(result, Err(AppError::Validation(_))));

        let result = register(&pool, &config, "alice", "alice@localhost", "password123").await;
        assert!(matches!(result, Err(AppError::Validation(_))));
    }

    // ── Login Tests ──────────────────────────────────────────────────

    #[tokio::test]
    async fn login_success() {
        let pool = test_pool().await;
        let config = test_config();

        register(&pool, &config, "alice", "alice@example.com", "password123")
            .await
            .unwrap();

        let result = login(&pool, &config, "alice", "password123").await.unwrap();

        assert!(!result.token.is_empty());
        assert!(!result.setup_complete);
        assert_eq!(result.user.username, "alice");
    }

    #[tokio::test]
    async fn login_trims_username_whitespace() {
        let pool = test_pool().await;
        let config = test_config();

        register(&pool, &config, "alice", "alice@example.com", "password123")
            .await
            .unwrap();

        let result = login(&pool, &config, "  alice  ", "password123")
            .await
            .unwrap();

        assert_eq!(result.user.username, "alice");
    }

    #[tokio::test]
    async fn login_wrong_password_fails() {
        let pool = test_pool().await;
        let config = test_config();

        register(&pool, &config, "alice", "alice@example.com", "password123")
            .await
            .unwrap();

        let result = login(&pool, &config, "alice", "wrong-password").await;
        assert!(matches!(result, Err(AppError::Unauthorized)));
    }

    #[tokio::test]
    async fn login_nonexistent_user_fails() {
        let pool = test_pool().await;
        let config = test_config();

        let result = login(&pool, &config, "nobody", "password123").await;
        assert!(matches!(result, Err(AppError::Unauthorized)));
    }

    #[tokio::test]
    async fn login_deactivated_user_fails() {
        let pool = test_pool().await;
        let config = test_config();

        let reg = register(&pool, &config, "alice", "alice@example.com", "password123")
            .await
            .unwrap();

        // Deactivate the user directly in the DB.
        sqlx::query("UPDATE users SET is_active = 0 WHERE id = ?")
            .bind(&reg.user.id)
            .execute(&pool)
            .await
            .unwrap();

        let result = login(&pool, &config, "alice", "password123").await;
        assert!(matches!(result, Err(AppError::Unauthorized)));
    }

    #[tokio::test]
    async fn login_creates_session_that_validates() {
        let pool = test_pool().await;
        let config = test_config();

        register(&pool, &config, "alice", "alice@example.com", "password123")
            .await
            .unwrap();

        let login_result = login(&pool, &config, "alice", "password123").await.unwrap();

        // The token should be usable to find a valid session.
        let token_hash = crate::guards::auth_guard::hash_token(&login_result.token);
        let session = Session::validate(&pool, &token_hash).await.unwrap();
        assert!(session.is_some());
    }

    #[tokio::test]
    async fn multiple_logins_create_separate_sessions() {
        let pool = test_pool().await;
        let config = test_config();

        register(&pool, &config, "alice", "alice@example.com", "password123")
            .await
            .unwrap();

        let r1 = login(&pool, &config, "alice", "password123").await.unwrap();
        let r2 = login(&pool, &config, "alice", "password123").await.unwrap();

        // Tokens should be different.
        assert_ne!(r1.token, r2.token);

        // Both sessions should be valid.
        let h1 = crate::guards::auth_guard::hash_token(&r1.token);
        let h2 = crate::guards::auth_guard::hash_token(&r2.token);
        assert!(Session::validate(&pool, &h1).await.unwrap().is_some());
        assert!(Session::validate(&pool, &h2).await.unwrap().is_some());
    }

    // ── Logout Tests ─────────────────────────────────────────────────

    #[tokio::test]
    async fn logout_destroys_session() {
        let pool = test_pool().await;
        let config = test_config();

        let reg = register(&pool, &config, "alice", "alice@example.com", "password123")
            .await
            .unwrap();

        let login_result = login(&pool, &config, "alice", "password123").await.unwrap();
        let token_hash = crate::guards::auth_guard::hash_token(&login_result.token);

        // Session should exist before logout.
        assert!(Session::validate(&pool, &token_hash)
            .await
            .unwrap()
            .is_some());

        logout(&pool, &reg.user.id, &token_hash).await.unwrap();

        // Session should be gone after logout.
        assert!(Session::validate(&pool, &token_hash)
            .await
            .unwrap()
            .is_none());
    }

    #[tokio::test]
    async fn logout_only_destroys_one_session() {
        let pool = test_pool().await;
        let config = test_config();

        let reg = register(&pool, &config, "alice", "alice@example.com", "password123")
            .await
            .unwrap();

        let r1 = login(&pool, &config, "alice", "password123").await.unwrap();
        let r2 = login(&pool, &config, "alice", "password123").await.unwrap();

        let h1 = crate::guards::auth_guard::hash_token(&r1.token);
        let h2 = crate::guards::auth_guard::hash_token(&r2.token);

        // Log out session 1.
        logout(&pool, &reg.user.id, &h1).await.unwrap();

        // Session 1 should be gone.
        assert!(Session::validate(&pool, &h1).await.unwrap().is_none());
        // Session 2 should still be valid.
        assert!(Session::validate(&pool, &h2).await.unwrap().is_some());
    }

    #[tokio::test]
    async fn logout_nonexistent_session_is_ok() {
        let pool = test_pool().await;
        let config = test_config();

        let reg = register(&pool, &config, "alice", "alice@example.com", "password123")
            .await
            .unwrap();

        // Logging out with a fake token hash should not error.
        let result = logout(&pool, &reg.user.id, "nonexistent-hash").await;
        assert!(result.is_ok());
    }

    // ── Validation Helpers ───────────────────────────────────────────

    #[test]
    fn normalize_username_accepts_valid() {
        assert_eq!(normalize_username("alice").unwrap(), "alice");
        assert_eq!(normalize_username("bob99").unwrap(), "bob99");
        assert_eq!(normalize_username("my-user").unwrap(), "my-user");
        assert_eq!(normalize_username("my_user").unwrap(), "my_user");
        assert_eq!(normalize_username("a1b").unwrap(), "a1b");
    }

    #[test]
    fn normalize_username_trims() {
        assert_eq!(normalize_username("  alice  ").unwrap(), "alice");
        assert_eq!(normalize_username("\talice\n").unwrap(), "alice");
    }

    #[test]
    fn normalize_username_rejects_invalid() {
        assert!(normalize_username("ab").is_err()); // too short
        assert!(normalize_username("").is_err()); // empty
        assert!(normalize_username("   ").is_err()); // whitespace only
        assert!(normalize_username("-abc").is_err()); // starts with symbol
        assert!(normalize_username("_abc").is_err()); // starts with symbol
        assert!(normalize_username("a b c").is_err()); // spaces
        assert!(normalize_username("abc!").is_err()); // special char
    }

    #[test]
    fn normalize_email_accepts_valid() {
        assert_eq!(normalize_email("a@b.com").unwrap(), "a@b.com");
        assert_eq!(
            normalize_email("user@example.org").unwrap(),
            "user@example.org"
        );
        assert_eq!(
            normalize_email("first.last@sub.domain.com").unwrap(),
            "first.last@sub.domain.com"
        );
    }

    #[test]
    fn normalize_email_lowercases() {
        assert_eq!(
            normalize_email("Alice@Example.COM").unwrap(),
            "alice@example.com"
        );
        assert_eq!(
            normalize_email("USER@DOMAIN.ORG").unwrap(),
            "user@domain.org"
        );
    }

    #[test]
    fn normalize_email_trims() {
        assert_eq!(
            normalize_email("  alice@example.com  ").unwrap(),
            "alice@example.com"
        );
    }

    #[test]
    fn normalize_email_rejects_invalid() {
        assert!(normalize_email("").is_err());
        assert!(normalize_email("noatsign").is_err());
        assert!(normalize_email("@domain.com").is_err());
        assert!(normalize_email("user@").is_err());
        assert!(normalize_email("user@localhost").is_err()); // no dot in domain
    }

    #[test]
    fn validate_password_accepts_valid() {
        assert!(validate_password("12345678").is_ok());
        assert!(validate_password("a very long password that is fine").is_ok());
    }

    #[test]
    fn validate_password_rejects_invalid() {
        assert!(validate_password("").is_err());
        assert!(validate_password("short").is_err());
        assert!(validate_password("1234567").is_err()); // 7 chars
        assert!(validate_password(&"x".repeat(PASSWORD_MAX_LEN + 1)).is_err());
    }

    #[test]
    fn generate_session_token_is_correct_length() {
        let token = generate_session_token();
        // 32 bytes → 43 base64url chars (no padding)
        assert_eq!(token.len(), 43);
    }

    #[test]
    fn generate_session_token_is_unique() {
        let t1 = generate_session_token();
        let t2 = generate_session_token();
        assert_ne!(t1, t2);
    }

    #[test]
    fn generate_session_token_is_url_safe() {
        for _ in 0..100 {
            let token = generate_session_token();
            assert!(
                token
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'),
                "Token contains non-URL-safe characters: {token}"
            );
        }
    }
}
