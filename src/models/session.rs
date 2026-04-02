use chrono::{NaiveDateTime, Utc};
use sqlx::SqlitePool;
use uuid::Uuid;

/// A row from the `sessions` table. Only the SHA-256 hash of the token is stored.
#[derive(Debug, Clone, sqlx::FromRow)]
#[allow(dead_code)]
pub struct Session {
    pub id: String,
    pub user_id: String,
    pub token_hash: String,
    pub expires_at: String,
    pub created_at: String,
}

impl Session {
    /// Insert a new session row and return it.
    pub async fn create(
        pool: &SqlitePool,
        user_id: &str,
        token_hash: &str,
        expires_at: NaiveDateTime,
    ) -> Result<Self, sqlx::Error> {
        let id = Uuid::new_v4().to_string();
        let expires_at_str = expires_at.format("%Y-%m-%d %H:%M:%S").to_string();

        sqlx::query_as::<_, Session>(
            r#"
            INSERT INTO sessions (id, user_id, token_hash, expires_at)
            VALUES (?, ?, ?, ?)
            RETURNING id, user_id, token_hash, expires_at, created_at
            "#,
        )
        .bind(&id)
        .bind(user_id)
        .bind(token_hash)
        .bind(&expires_at_str)
        .fetch_one(pool)
        .await
    }

    /// Look up a session by its token hash. Does not check expiry.
    pub async fn find_by_token_hash(
        pool: &SqlitePool,
        token_hash: &str,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as::<_, Session>(
            "SELECT id, user_id, token_hash, expires_at, created_at FROM sessions WHERE token_hash = ?",
        )
        .bind(token_hash)
        .fetch_optional(pool)
        .await
    }

    /// Find by token hash and check expiry. Returns `None` if missing or expired.
    /// Expired sessions are auto-deleted.
    pub async fn validate(
        pool: &SqlitePool,
        token_hash: &str,
    ) -> Result<Option<Self>, sqlx::Error> {
        let session = match Self::find_by_token_hash(pool, token_hash).await? {
            Some(s) => s,
            None => return Ok(None),
        };

        if session.is_expired() {
            // Best-effort cleanup — ignore errors.
            let _ = Self::delete(pool, &session.id).await;
            return Ok(None);
        }

        Ok(Some(session))
    }

    /// Delete a session by ID.
    pub async fn delete(pool: &SqlitePool, session_id: &str) -> Result<bool, sqlx::Error> {
        let result = sqlx::query("DELETE FROM sessions WHERE id = ?")
            .bind(session_id)
            .execute(pool)
            .await?;

        Ok(result.rows_affected() > 0)
    }

    /// Delete a session matching both user ID and token hash (used for logout).
    pub async fn delete_by_user_and_token(
        pool: &SqlitePool,
        user_id: &str,
        token_hash: &str,
    ) -> Result<bool, sqlx::Error> {
        let result = sqlx::query("DELETE FROM sessions WHERE user_id = ? AND token_hash = ?")
            .bind(user_id)
            .bind(token_hash)
            .execute(pool)
            .await?;

        Ok(result.rows_affected() > 0)
    }

    /// Delete all sessions for a user ("log out everywhere").
    #[cfg_attr(not(test), allow(dead_code))]
    pub async fn delete_all_for_user(pool: &SqlitePool, user_id: &str) -> Result<u64, sqlx::Error> {
        let result = sqlx::query("DELETE FROM sessions WHERE user_id = ?")
            .bind(user_id)
            .execute(pool)
            .await?;

        Ok(result.rows_affected())
    }

    /// Delete all expired sessions. Returns the number removed.
    #[cfg_attr(not(test), allow(dead_code))]
    pub async fn delete_expired(pool: &SqlitePool) -> Result<u64, sqlx::Error> {
        let now = Utc::now()
            .naive_utc()
            .format("%Y-%m-%d %H:%M:%S")
            .to_string();

        let result = sqlx::query("DELETE FROM sessions WHERE expires_at <= ?")
            .bind(&now)
            .execute(pool)
            .await?;

        Ok(result.rows_affected())
    }

    /// Returns `true` if `expires_at` is in the past.
    pub fn is_expired(&self) -> bool {
        let now = Utc::now().naive_utc();
        match NaiveDateTime::parse_from_str(&self.expires_at, "%Y-%m-%d %H:%M:%S") {
            Ok(exp) => now >= exp,
            // Unparseable timestamp → treat as expired (fail closed).
            Err(_) => true,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;

    /// In-memory SQLite with sessions and users tables for testing.
    async fn test_pool() -> SqlitePool {
        let pool = SqlitePool::connect("sqlite::memory:").await.unwrap();

        sqlx::query(
            "CREATE TABLE users (
                id              TEXT PRIMARY KEY,
                username        TEXT NOT NULL UNIQUE,
                email           TEXT NOT NULL UNIQUE,
                password_hash   TEXT NOT NULL,
                role            TEXT NOT NULL DEFAULT 'user',
                quota_bytes     INTEGER NOT NULL DEFAULT 5368709120,
                is_active       INTEGER NOT NULL DEFAULT 1,
                setup_complete  INTEGER NOT NULL DEFAULT 0,
                created_at      TEXT NOT NULL DEFAULT (datetime('now')),
                updated_at      TEXT NOT NULL DEFAULT (datetime('now'))
            )",
        )
        .execute(&pool)
        .await
        .unwrap();

        sqlx::query(
            "CREATE TABLE sessions (
                id         TEXT PRIMARY KEY,
                user_id    TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                token_hash TEXT NOT NULL UNIQUE,
                expires_at TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT (datetime('now'))
            )",
        )
        .execute(&pool)
        .await
        .unwrap();

        sqlx::query(
            "INSERT INTO users (id, username, email, password_hash) VALUES ('u1', 'alice', 'alice@example.com', 'hash')",
        )
        .execute(&pool)
        .await
        .unwrap();

        pool
    }

    #[tokio::test]
    async fn create_and_find_by_token_hash() {
        let pool = test_pool().await;
        let expires = Utc::now().naive_utc() + Duration::hours(1);

        let session = Session::create(&pool, "u1", "abc123hash", expires)
            .await
            .unwrap();

        assert_eq!(session.user_id, "u1");
        assert_eq!(session.token_hash, "abc123hash");

        let found = Session::find_by_token_hash(&pool, "abc123hash")
            .await
            .unwrap();
        assert!(found.is_some());
        assert_eq!(found.unwrap().id, session.id);
    }

    #[tokio::test]
    async fn find_by_token_hash_returns_none_for_missing() {
        let pool = test_pool().await;
        let found = Session::find_by_token_hash(&pool, "nonexistent")
            .await
            .unwrap();
        assert!(found.is_none());
    }

    #[tokio::test]
    async fn validate_returns_none_for_expired_session() {
        let pool = test_pool().await;

        let expired = Utc::now().naive_utc() - Duration::hours(1);
        Session::create(&pool, "u1", "expired_hash", expired)
            .await
            .unwrap();

        let result = Session::validate(&pool, "expired_hash").await.unwrap();
        assert!(result.is_none());

        let gone = Session::find_by_token_hash(&pool, "expired_hash")
            .await
            .unwrap();
        assert!(gone.is_none());
    }

    #[tokio::test]
    async fn validate_returns_session_when_valid() {
        let pool = test_pool().await;
        let expires = Utc::now().naive_utc() + Duration::hours(1);
        Session::create(&pool, "u1", "valid_hash", expires)
            .await
            .unwrap();

        let result = Session::validate(&pool, "valid_hash").await.unwrap();
        assert!(result.is_some());
    }

    #[tokio::test]
    async fn delete_single_session() {
        let pool = test_pool().await;
        let expires = Utc::now().naive_utc() + Duration::hours(1);
        let session = Session::create(&pool, "u1", "del_hash", expires)
            .await
            .unwrap();

        let deleted = Session::delete(&pool, &session.id).await.unwrap();
        assert!(deleted);

        let found = Session::find_by_token_hash(&pool, "del_hash")
            .await
            .unwrap();
        assert!(found.is_none());
    }

    #[tokio::test]
    async fn delete_returns_false_for_missing() {
        let pool = test_pool().await;
        let deleted = Session::delete(&pool, "nonexistent").await.unwrap();
        assert!(!deleted);
    }

    #[tokio::test]
    async fn delete_all_for_user() {
        let pool = test_pool().await;
        let expires = Utc::now().naive_utc() + Duration::hours(1);

        Session::create(&pool, "u1", "hash1", expires)
            .await
            .unwrap();
        Session::create(&pool, "u1", "hash2", expires)
            .await
            .unwrap();
        Session::create(&pool, "u1", "hash3", expires)
            .await
            .unwrap();

        let count = Session::delete_all_for_user(&pool, "u1").await.unwrap();
        assert_eq!(count, 3);

        let found = Session::find_by_token_hash(&pool, "hash1").await.unwrap();
        assert!(found.is_none());
    }

    #[tokio::test]
    async fn delete_expired_removes_only_expired() {
        let pool = test_pool().await;
        let future = Utc::now().naive_utc() + Duration::hours(1);
        let past = Utc::now().naive_utc() - Duration::hours(1);

        Session::create(&pool, "u1", "alive_hash", future)
            .await
            .unwrap();
        Session::create(&pool, "u1", "dead_hash", past)
            .await
            .unwrap();

        let removed = Session::delete_expired(&pool).await.unwrap();
        assert_eq!(removed, 1);

        assert!(Session::find_by_token_hash(&pool, "alive_hash")
            .await
            .unwrap()
            .is_some());
        assert!(Session::find_by_token_hash(&pool, "dead_hash")
            .await
            .unwrap()
            .is_none());
    }

    #[test]
    fn is_expired_returns_true_for_past() {
        let session = Session {
            id: "s1".into(),
            user_id: "u1".into(),
            token_hash: "h".into(),
            expires_at: "2000-01-01 00:00:00".into(),
            created_at: "2000-01-01 00:00:00".into(),
        };
        assert!(session.is_expired());
    }

    #[test]
    fn is_expired_returns_false_for_future() {
        let future = (Utc::now().naive_utc() + Duration::hours(1))
            .format("%Y-%m-%d %H:%M:%S")
            .to_string();
        let session = Session {
            id: "s1".into(),
            user_id: "u1".into(),
            token_hash: "h".into(),
            expires_at: future,
            created_at: "2024-01-01 00:00:00".into(),
        };
        assert!(!session.is_expired());
    }

    #[test]
    fn is_expired_returns_true_for_unparseable() {
        let session = Session {
            id: "s1".into(),
            user_id: "u1".into(),
            token_hash: "h".into(),
            expires_at: "not-a-date".into(),
            created_at: "2024-01-01 00:00:00".into(),
        };
        assert!(session.is_expired());
    }
}
