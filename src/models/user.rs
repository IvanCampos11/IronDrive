use serde::Serialize;
use sqlx::FromRow;
use uuid::Uuid;

use crate::db::DbPool;
use crate::errors::AppError;

/// A user account in the system.
///
/// Maps to the `users` table but deliberately excludes `password_hash`.
/// The hash never lives on a struct — it's queried and verified inside a
/// single function (`get_password_hash`) and then dropped.
#[derive(Debug, Clone, FromRow, Serialize)]
pub struct User {
    pub id: String,
    pub username: String,
    pub email: String,
    pub role: String,
    pub quota_bytes: i64,
    pub is_active: bool,
    pub setup_complete: bool,
    pub created_at: String,
    pub updated_at: String,
}

/// Parameters for creating a new user.
pub struct CreateUserParams {
    pub username: String,
    pub email: String,
    pub password_hash: String,
    pub role: String,
    pub quota_bytes: i64,
}

impl User {
    /// Insert a new user into the database and return the created record.
    ///
    /// The caller is responsible for hashing the password before calling this —
    /// `password_hash` must already be an Argon2 hash string.
    ///
    /// # Errors
    ///
    /// Returns `AppError::Conflict` if the username or email is already taken.
    /// Returns `AppError::Sqlx` for other database errors.
    pub async fn create(pool: &DbPool, params: CreateUserParams) -> Result<User, AppError> {
        let id = Uuid::new_v4().to_string();

        // Check for existing username
        if Self::find_by_username(pool, &params.username)
            .await?
            .is_some()
        {
            return Err(AppError::Conflict(
                "A user with that username already exists.".into(),
            ));
        }

        // Check for existing email
        if Self::find_by_email(pool, &params.email).await?.is_some() {
            return Err(AppError::Conflict(
                "A user with that email already exists.".into(),
            ));
        }

        sqlx::query(
            "INSERT INTO users (id, username, email, password_hash, role, quota_bytes)
             VALUES (?, ?, ?, ?, ?, ?)",
        )
        .bind(&id)
        .bind(&params.username)
        .bind(&params.email)
        .bind(&params.password_hash)
        .bind(&params.role)
        .bind(params.quota_bytes)
        .execute(pool)
        .await?;

        // Fetch the full row back so created_at / updated_at are populated by
        // the database defaults.
        Self::find_by_id(pool, &id).await?.ok_or_else(|| {
            AppError::Internal("User was inserted but could not be read back".into())
        })
    }

    /// Look up a user by their unique ID.
    pub async fn find_by_id(pool: &DbPool, id: &str) -> Result<Option<User>, AppError> {
        let user = sqlx::query_as::<_, User>(
            "SELECT id, username, email, role, quota_bytes, is_active, setup_complete, created_at, updated_at
             FROM users WHERE id = ?",
        )
            .bind(id)
            .fetch_optional(pool)
            .await?;

        Ok(user)
    }

    /// Look up a user by their unique username (case-sensitive).
    pub async fn find_by_username(pool: &DbPool, username: &str) -> Result<Option<User>, AppError> {
        let user = sqlx::query_as::<_, User>(
            "SELECT id, username, email, role, quota_bytes, is_active, setup_complete, created_at, updated_at
             FROM users WHERE username = ?",
        )
            .bind(username)
            .fetch_optional(pool)
            .await?;

        Ok(user)
    }

    /// Look up a user by their unique email address (case-sensitive).
    pub async fn find_by_email(pool: &DbPool, email: &str) -> Result<Option<User>, AppError> {
        let user = sqlx::query_as::<_, User>(
            "SELECT id, username, email, role, quota_bytes, is_active, setup_complete, created_at, updated_at
             FROM users WHERE email = ?",
        )
            .bind(email)
            .fetch_optional(pool)
            .await?;

        Ok(user)
    }

    /// Retrieve the password hash for a user identified by username.
    ///
    /// Returns `(user_id, password_hash)` so the caller can verify the
    /// password and then load the full `User` by ID on success. The hash
    /// lives only in a local variable — it never touches a struct and is
    /// dropped as soon as the calling function returns.
    ///
    /// Returns `None` if no user with that username exists.
    pub async fn get_password_hash(
        pool: &DbPool,
        username: &str,
    ) -> Result<Option<(String, String)>, AppError> {
        let row = sqlx::query_as::<_, (String, String)>(
            "SELECT id, password_hash FROM users WHERE username = ?",
        )
        .bind(username)
        .fetch_optional(pool)
        .await?;

        Ok(row)
    }

    /// Mark a user's setup as complete (called after the setup wizard finishes).
    pub async fn mark_setup_complete(pool: &DbPool, user_id: &str) -> Result<(), AppError> {
        let result = sqlx::query(
            "UPDATE users SET setup_complete = 1, updated_at = datetime('now') WHERE id = ?",
        )
        .bind(user_id)
        .execute(pool)
        .await?;

        if result.rows_affected() == 0 {
            return Err(AppError::NotFound);
        }

        Ok(())
    }

    /// Returns `true` if this user has the `admin` role.
    pub fn is_admin(&self) -> bool {
        self.role == "admin"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db;

    /// Create a fresh in-memory database with migrations applied.
    async fn test_pool() -> DbPool {
        let pool = db::init_pool("sqlite::memory:")
            .await
            .expect("Failed to create test pool");
        db::run_migrations(&pool)
            .await
            .expect("Failed to run migrations");
        pool
    }

    fn default_params() -> CreateUserParams {
        CreateUserParams {
            username: "alice".into(),
            email: "alice@example.com".into(),
            password_hash: "$argon2id$fake_hash_for_testing".into(),
            role: "user".into(),
            quota_bytes: 5_368_709_120,
        }
    }

    #[tokio::test]
    async fn create_and_find_by_id() {
        let pool = test_pool().await;
        let user = User::create(&pool, default_params()).await.unwrap();

        assert_eq!(user.username, "alice");
        assert_eq!(user.email, "alice@example.com");
        assert_eq!(user.role, "user");
        assert!(!user.setup_complete);
        assert!(user.is_active);

        let found = User::find_by_id(&pool, &user.id).await.unwrap();
        assert!(found.is_some());
        assert_eq!(found.unwrap().id, user.id);
    }

    #[tokio::test]
    async fn find_by_username() {
        let pool = test_pool().await;
        User::create(&pool, default_params()).await.unwrap();

        let found = User::find_by_username(&pool, "alice").await.unwrap();
        assert!(found.is_some());
        assert_eq!(found.unwrap().username, "alice");

        let not_found = User::find_by_username(&pool, "bob").await.unwrap();
        assert!(not_found.is_none());
    }

    #[tokio::test]
    async fn find_by_email() {
        let pool = test_pool().await;
        User::create(&pool, default_params()).await.unwrap();

        let found = User::find_by_email(&pool, "alice@example.com")
            .await
            .unwrap();
        assert!(found.is_some());
        assert_eq!(found.unwrap().email, "alice@example.com");

        let not_found = User::find_by_email(&pool, "bob@example.com").await.unwrap();
        assert!(not_found.is_none());
    }

    #[tokio::test]
    async fn duplicate_username_is_conflict() {
        let pool = test_pool().await;
        User::create(&pool, default_params()).await.unwrap();

        let result = User::create(
            &pool,
            CreateUserParams {
                username: "alice".into(),
                email: "alice2@example.com".into(),
                ..default_params()
            },
        )
        .await;

        assert!(matches!(result, Err(AppError::Conflict(_))));
    }

    #[tokio::test]
    async fn duplicate_email_is_conflict() {
        let pool = test_pool().await;
        User::create(&pool, default_params()).await.unwrap();

        let result = User::create(
            &pool,
            CreateUserParams {
                username: "bob".into(),
                email: "alice@example.com".into(),
                ..default_params()
            },
        )
        .await;

        assert!(matches!(result, Err(AppError::Conflict(_))));
    }

    #[tokio::test]
    async fn mark_setup_complete() {
        let pool = test_pool().await;
        let user = User::create(&pool, default_params()).await.unwrap();
        assert!(!user.setup_complete);

        User::mark_setup_complete(&pool, &user.id).await.unwrap();

        let updated = User::find_by_id(&pool, &user.id).await.unwrap().unwrap();
        assert!(updated.setup_complete);
    }

    #[tokio::test]
    async fn mark_setup_complete_nonexistent_user() {
        let pool = test_pool().await;
        let result = User::mark_setup_complete(&pool, "nonexistent-id").await;
        assert!(matches!(result, Err(AppError::NotFound)));
    }

    #[tokio::test]
    async fn is_admin() {
        let pool = test_pool().await;
        let regular = User::create(&pool, default_params()).await.unwrap();
        assert!(!regular.is_admin());

        let admin = User::create(
            &pool,
            CreateUserParams {
                username: "boss".into(),
                email: "boss@example.com".into(),
                role: "admin".into(),
                ..default_params()
            },
        )
        .await
        .unwrap();
        assert!(admin.is_admin());
    }

    #[tokio::test]
    async fn get_password_hash_returns_hash() {
        let pool = test_pool().await;
        User::create(&pool, default_params()).await.unwrap();

        let result = User::get_password_hash(&pool, "alice").await.unwrap();
        assert!(result.is_some());

        let (user_id, hash) = result.unwrap();
        assert!(!user_id.is_empty());
        assert_eq!(hash, "$argon2id$fake_hash_for_testing");
    }

    #[tokio::test]
    async fn get_password_hash_returns_none_for_missing() {
        let pool = test_pool().await;
        let result = User::get_password_hash(&pool, "nobody").await.unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn user_struct_has_no_password_hash() {
        let pool = test_pool().await;
        let user = User::create(&pool, default_params()).await.unwrap();

        // Serialize to JSON and confirm no trace of the hash anywhere.
        let json = serde_json::to_string(&user).unwrap();
        assert!(!json.contains("password_hash"));
        assert!(!json.contains("fake_hash"));
        assert!(!json.contains("argon2"));

        // Also confirm Debug output is clean.
        let debug = format!("{:?}", user);
        assert!(!debug.contains("password_hash"));
        assert!(!debug.contains("fake_hash"));
        assert!(!debug.contains("argon2"));
    }
}
