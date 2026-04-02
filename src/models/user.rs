use serde::Serialize;
use sqlx::FromRow;
use uuid::Uuid;

use crate::db::{is_unique_violation, DbPool};
use crate::errors::AppError;

/// A user row from the `users` table. Excludes `password_hash` by design.
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

pub struct CreateUserParams {
    pub username: String,
    pub email: String,
    pub password_hash: String,
    pub role: String,
    pub quota_bytes: i64,
}

impl User {
    /// Insert a new user. `password_hash` must already be hashed.
    /// Returns `Conflict` if username or email is taken.
    pub async fn create(pool: &DbPool, params: CreateUserParams) -> Result<User, AppError> {
        let id = Uuid::new_v4().to_string();

        // Pre-check for friendly error messages; DB constraints catch TOCTOU races.
        if Self::find_by_username(pool, &params.username)
            .await?
            .is_some()
        {
            return Err(AppError::Conflict(
                "A user with that username already exists.".into(),
            ));
        }

        if Self::find_by_email(pool, &params.email).await?.is_some() {
            return Err(AppError::Conflict(
                "A user with that email already exists.".into(),
            ));
        }

        let insert_result = sqlx::query(
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
        .await;

        match insert_result {
            Ok(_) => {}
            Err(e) if is_unique_violation(&e) => {
                tracing::warn!(
                    username = %params.username,
                    email = %params.email,
                    "UNIQUE constraint race during user creation"
                );
                return Err(AppError::Conflict(
                    "A user with that username or email already exists.".into(),
                ));
            }
            Err(e) => return Err(AppError::Sqlx(e)),
        }

        Self::find_by_id(pool, &id).await?.ok_or_else(|| {
            AppError::Internal("User was inserted but could not be read back".into())
        })
    }

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

    /// Returns `(user_id, password_hash)` for the given username, or `None`.
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

    #[cfg_attr(not(test), allow(dead_code))]
    pub fn is_admin(&self) -> bool {
        self.role == "admin"
    }
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

        let json = serde_json::to_string(&user).unwrap();
        assert!(!json.contains("password_hash"));
        assert!(!json.contains("fake_hash"));
        assert!(!json.contains("argon2"));

        let debug = format!("{:?}", user);
        assert!(!debug.contains("password_hash"));
        assert!(!debug.contains("fake_hash"));
        assert!(!debug.contains("argon2"));
    }
}
