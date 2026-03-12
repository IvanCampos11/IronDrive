use serde::Serialize;
use sqlx::FromRow;
use uuid::Uuid;

use crate::db::{is_unique_violation, DbPool};
use crate::errors::AppError;

/// A row from `personal_libraries`. One per user.
#[derive(Debug, Clone, FromRow, Serialize)]
pub struct PersonalLibrary {
    pub id: String,
    pub user_id: String,
    pub encryption_mode: String,
    #[serde(skip_serializing)]
    pub encrypted_data_key: Vec<u8>,
    #[serde(skip_serializing)]
    pub salt: Option<Vec<u8>>,
    #[serde(skip_serializing)]
    pub verify_blob: Option<Vec<u8>>,
    #[serde(skip_serializing)]
    pub recovery_blob: Option<Vec<u8>>,
    pub created_at: String,
}

pub struct CreateLibraryParams {
    pub user_id: String,
    pub encryption_mode: String,
    pub encrypted_data_key: Vec<u8>,
    pub salt: Option<Vec<u8>>,
    pub verify_blob: Option<Vec<u8>>,
    pub recovery_blob: Option<Vec<u8>>,
}

impl PersonalLibrary {
    /// Insert a new library row. Returns `Conflict` if one already exists for this user.
    pub async fn create(
        pool: &DbPool,
        params: CreateLibraryParams,
    ) -> Result<PersonalLibrary, AppError> {
        let id = Uuid::new_v4().to_string();

        // Pre-check for a friendly error message; the DB UNIQUE constraint catches races.
        if Self::find_by_user(pool, &params.user_id).await?.is_some() {
            return Err(AppError::Conflict(
                "This user already has a personal library.".into(),
            ));
        }

        let insert_result = sqlx::query(
            "INSERT INTO personal_libraries (id, user_id, encryption_mode, encrypted_data_key, salt, verify_blob, recovery_blob)
             VALUES (?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(&id)
        .bind(&params.user_id)
        .bind(&params.encryption_mode)
        .bind(&params.encrypted_data_key)
        .bind(&params.salt)
        .bind(&params.verify_blob)
        .bind(&params.recovery_blob)
        .execute(pool)
        .await;

        match insert_result {
            Ok(_) => {}
            Err(e) if is_unique_violation(&e) => {
                tracing::warn!(
                    user_id = %params.user_id,
                    "UNIQUE constraint race during library creation"
                );
                return Err(AppError::Conflict(
                    "This user already has a personal library.".into(),
                ));
            }
            Err(e) => return Err(AppError::Sqlx(e)),
        }

        Self::find_by_id(pool, &id).await?.ok_or_else(|| {
            AppError::Internal("Library was inserted but could not be read back".into())
        })
    }

    pub async fn find_by_id(pool: &DbPool, id: &str) -> Result<Option<PersonalLibrary>, AppError> {
        let library = sqlx::query_as::<_, PersonalLibrary>(
            "SELECT id, user_id, encryption_mode, encrypted_data_key, salt, verify_blob, recovery_blob, created_at
             FROM personal_libraries WHERE id = ?",
        )
        .bind(id)
        .fetch_optional(pool)
        .await?;

        Ok(library)
    }

    /// Delete a library row by ID. Used for rollback if disk operations fail after insert.
    pub async fn delete_by_id(pool: &DbPool, id: &str) -> Result<(), AppError> {
        sqlx::query("DELETE FROM personal_libraries WHERE id = ?")
            .bind(id)
            .execute(pool)
            .await?;
        Ok(())
    }

    pub async fn find_by_user(
        pool: &DbPool,
        user_id: &str,
    ) -> Result<Option<PersonalLibrary>, AppError> {
        let library = sqlx::query_as::<_, PersonalLibrary>(
            "SELECT id, user_id, encryption_mode, encrypted_data_key, salt, verify_blob, recovery_blob, created_at
             FROM personal_libraries WHERE user_id = ?",
        )
        .bind(user_id)
        .fetch_optional(pool)
        .await?;

        Ok(library)
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

    /// Insert a test user and return its ID.
    async fn seed_user(pool: &DbPool, username: &str) -> String {
        let id = Uuid::new_v4().to_string();
        sqlx::query("INSERT INTO users (id, username, email, password_hash) VALUES (?, ?, ?, ?)")
            .bind(&id)
            .bind(username)
            .bind(format!("{username}@example.com"))
            .bind("$argon2id$fake_hash_for_testing")
            .execute(pool)
            .await
            .expect("Failed to seed test user");
        id
    }

    fn default_params(user_id: &str) -> CreateLibraryParams {
        CreateLibraryParams {
            user_id: user_id.to_owned(),
            encryption_mode: "server".into(),
            encrypted_data_key: vec![0xDE, 0xAD, 0xBE, 0xEF],
            salt: None,
            verify_blob: None,
            recovery_blob: None,
        }
    }

    #[tokio::test]
    async fn create_and_find_by_id() {
        let pool = test_pool().await;
        let user_id = seed_user(&pool, "alice").await;

        let lib = PersonalLibrary::create(&pool, default_params(&user_id))
            .await
            .unwrap();

        assert_eq!(lib.user_id, user_id);
        assert_eq!(lib.encryption_mode, "server");
        assert_eq!(lib.encrypted_data_key, vec![0xDE, 0xAD, 0xBE, 0xEF]);
        assert!(lib.salt.is_none());
        assert!(lib.verify_blob.is_none());
        assert!(lib.recovery_blob.is_none());

        let found = PersonalLibrary::find_by_id(&pool, &lib.id).await.unwrap();
        assert!(found.is_some());
        assert_eq!(found.unwrap().id, lib.id);
    }

    #[tokio::test]
    async fn find_by_user() {
        let pool = test_pool().await;
        let user_id = seed_user(&pool, "alice").await;

        PersonalLibrary::create(&pool, default_params(&user_id))
            .await
            .unwrap();

        let found = PersonalLibrary::find_by_user(&pool, &user_id)
            .await
            .unwrap();
        assert!(found.is_some());
        assert_eq!(found.unwrap().user_id, user_id);
    }

    #[tokio::test]
    async fn find_by_user_returns_none_when_no_library() {
        let pool = test_pool().await;
        let user_id = seed_user(&pool, "alice").await;

        let found = PersonalLibrary::find_by_user(&pool, &user_id)
            .await
            .unwrap();
        assert!(found.is_none());
    }

    #[tokio::test]
    async fn find_by_id_returns_none_for_missing() {
        let pool = test_pool().await;

        let found = PersonalLibrary::find_by_id(&pool, "nonexistent")
            .await
            .unwrap();
        assert!(found.is_none());
    }

    #[tokio::test]
    async fn duplicate_library_for_same_user_is_conflict() {
        let pool = test_pool().await;
        let user_id = seed_user(&pool, "alice").await;

        PersonalLibrary::create(&pool, default_params(&user_id))
            .await
            .unwrap();

        let result = PersonalLibrary::create(&pool, default_params(&user_id)).await;
        assert!(matches!(result, Err(AppError::Conflict(_))));
    }

    #[tokio::test]
    async fn different_users_can_each_have_a_library() {
        let pool = test_pool().await;
        let alice_id = seed_user(&pool, "alice").await;
        let bob_id = seed_user(&pool, "bob").await;

        let lib_a = PersonalLibrary::create(&pool, default_params(&alice_id))
            .await
            .unwrap();
        let lib_b = PersonalLibrary::create(&pool, default_params(&bob_id))
            .await
            .unwrap();

        assert_ne!(lib_a.id, lib_b.id);
        assert_eq!(lib_a.user_id, alice_id);
        assert_eq!(lib_b.user_id, bob_id);
    }

    #[tokio::test]
    async fn create_with_optional_fields_populated() {
        let pool = test_pool().await;
        let user_id = seed_user(&pool, "alice").await;

        let params = CreateLibraryParams {
            user_id: user_id.clone(),
            encryption_mode: "failsafe_user".into(),
            encrypted_data_key: vec![0x01, 0x02, 0x03],
            salt: Some(vec![0xAA, 0xBB]),
            verify_blob: Some(vec![0xCC, 0xDD]),
            recovery_blob: Some(vec![0xEE, 0xFF]),
        };

        let lib = PersonalLibrary::create(&pool, params).await.unwrap();

        assert_eq!(lib.encryption_mode, "failsafe_user");
        assert_eq!(lib.encrypted_data_key, vec![0x01, 0x02, 0x03]);
        assert_eq!(lib.salt, Some(vec![0xAA, 0xBB]));
        assert_eq!(lib.verify_blob, Some(vec![0xCC, 0xDD]));
        assert_eq!(lib.recovery_blob, Some(vec![0xEE, 0xFF]));
    }

    #[tokio::test]
    async fn serialized_json_excludes_sensitive_fields() {
        let pool = test_pool().await;
        let user_id = seed_user(&pool, "alice").await;

        let lib = PersonalLibrary::create(&pool, default_params(&user_id))
            .await
            .unwrap();

        let json = serde_json::to_string(&lib).unwrap();
        assert!(!json.contains("encrypted_data_key"));
        assert!(!json.contains("salt"));
        assert!(!json.contains("verify_blob"));
        assert!(!json.contains("recovery_blob"));
        assert!(json.contains("encryption_mode"));
        assert!(json.contains(&lib.id));
    }
}
