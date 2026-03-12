use std::path::Path;

use tokio::fs;

use crate::config::AppConfig;
use crate::db::DbPool;
use crate::errors::AppError;
use crate::models::library::{CreateLibraryParams, PersonalLibrary};
use crate::models::user::User;
use crate::services::crypto_service::{
    generate_data_key, unwrap_data_key, wrap_data_key, MasterKey,
};
use crate::services::unlock_state::UnlockState;

const META_FILENAME: &str = ".irondrive.meta";

#[derive(Debug, Clone)]
pub struct SetupLibraryResult {
    pub library: PersonalLibrary,
}

/// Create a server-mode personal library for the given user.
///
/// Steps: generate data key → wrap with master key → insert DB row →
/// create library dir on disk → load key into UnlockState → mark setup complete.
///
/// If disk operations fail after the DB insert, the DB row is rolled back
/// on a best-effort basis to avoid orphaned state.
pub async fn setup_library(
    pool: &DbPool,
    config: &AppConfig,
    master_key: &MasterKey,
    unlock_state: &UnlockState,
    user_id: &str,
) -> Result<SetupLibraryResult, AppError> {
    let user = User::find_by_id(pool, user_id)
        .await?
        .ok_or(AppError::NotFound)?;

    if user.setup_complete {
        return Err(AppError::Conflict(
            "Setup has already been completed for this user.".into(),
        ));
    }

    // Defensive: check for orphaned library row even if setup_complete is false.
    if PersonalLibrary::find_by_user(pool, user_id)
        .await?
        .is_some()
    {
        return Err(AppError::Conflict(
            "This user already has a personal library.".into(),
        ));
    }

    let data_key = generate_data_key();
    let encrypted_data_key = wrap_data_key(master_key, &data_key)?;

    let library = PersonalLibrary::create(
        pool,
        CreateLibraryParams {
            user_id: user_id.to_owned(),
            encryption_mode: "server".into(),
            encrypted_data_key,
            salt: None,
            verify_blob: None,
            recovery_blob: None,
        },
    )
    .await?;

    // Create library dir on disk. If this fails, roll back the DB row.
    let lib_dir = library_dir(config, &library.id);
    if let Err(e) = create_library_directory(&lib_dir, &library.id).await {
        tracing::error!(
            library_id = %library.id,
            path = %lib_dir,
            error = %e,
            "Failed to create library directory — rolling back DB row"
        );
        if let Err(del_err) = PersonalLibrary::delete_by_id(pool, &library.id).await {
            tracing::error!(
                library_id = %library.id,
                error = %del_err,
                "Failed to roll back library DB row after disk failure"
            );
        }
        return Err(e);
    }

    unlock_state.insert_library_key(&library.id, &data_key);
    User::mark_setup_complete(pool, user_id).await?;

    tracing::info!(
        library_id = %library.id,
        user_id = %user_id,
        "Personal library created (server mode)"
    );

    Ok(SetupLibraryResult { library })
}

/// Re-load all server-mode library data keys into `UnlockState` on boot.
pub async fn load_server_mode_keys(
    pool: &DbPool,
    master_key: &MasterKey,
    unlock_state: &UnlockState,
) -> Result<usize, AppError> {
    let rows = sqlx::query_as::<_, PersonalLibrary>(
        "SELECT id, user_id, encryption_mode, encrypted_data_key, salt, verify_blob, recovery_blob, created_at
         FROM personal_libraries
         WHERE encryption_mode = 'server'",
    )
    .fetch_all(pool)
    .await?;

    let mut loaded = 0usize;

    for lib in &rows {
        match unwrap_data_key(master_key, &lib.encrypted_data_key) {
            Ok(data_key) => {
                unlock_state.insert_library_key(&lib.id, &data_key);
                loaded += 1;
            }
            Err(e) => {
                tracing::error!(
                    library_id = %lib.id,
                    user_id = %lib.user_id,
                    error = %e,
                    "Failed to unwrap data key for server-mode library — skipping"
                );
            }
        }
    }

    if loaded < rows.len() {
        tracing::warn!(
            total = rows.len(),
            loaded,
            skipped = rows.len() - loaded,
            "Some server-mode library keys could not be unwrapped"
        );
    }

    Ok(loaded)
}

fn library_dir(config: &AppConfig, library_id: &str) -> String {
    format!("{}/libraries/{}", config.data_dir, library_id)
}

async fn create_library_directory(lib_dir: &str, library_id: &str) -> Result<(), AppError> {
    let path = Path::new(lib_dir);

    fs::create_dir_all(path).await.map_err(|e| {
        AppError::Internal(format!(
            "Failed to create library directory '{}': {}",
            lib_dir, e
        ))
    })?;

    let meta_path = path.join(META_FILENAME);
    let meta_content = format!(
        "type = \"library\"\nid = \"{}\"\ncreated_by = \"irondrive\"\n",
        library_id
    );

    fs::write(&meta_path, meta_content.as_bytes())
        .await
        .map_err(|e| {
            AppError::Internal(format!(
                "Failed to write meta file '{}': {}",
                meta_path.display(),
                e
            ))
        })?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db;
    use crate::services::crypto_service::bootstrap_master_key;

    async fn test_pool() -> DbPool {
        let pool = db::init_pool("sqlite::memory:")
            .await
            .expect("Failed to create test pool");
        db::run_migrations(&pool)
            .await
            .expect("Failed to run migrations");
        pool
    }

    fn test_config(data_dir: &str) -> AppConfig {
        AppConfig {
            secret_key: base64_test_key(),
            data_dir: data_dir.to_owned(),
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

    /// A valid base64-encoded 32-byte key for tests.
    fn base64_test_key() -> String {
        use base64::Engine;
        base64::engine::general_purpose::STANDARD.encode([0xABu8; 32])
    }

    /// Insert a test user and return its ID.
    async fn seed_user(pool: &DbPool, username: &str) -> String {
        let id = uuid::Uuid::new_v4().to_string();
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

    #[tokio::test]
    async fn setup_creates_library_and_directory() {
        let tmp = tempfile::tempdir().unwrap();
        let data_dir = tmp.path().to_str().unwrap();
        let pool = test_pool().await;
        let config = test_config(data_dir);
        let master_key = bootstrap_master_key(&pool, &config.secret_key)
            .await
            .unwrap();
        let unlock_state = UnlockState::new();
        let user_id = seed_user(&pool, "alice").await;

        let result = setup_library(&pool, &config, &master_key, &unlock_state, &user_id)
            .await
            .unwrap();

        // Library row was created.
        assert_eq!(result.library.user_id, user_id);
        assert_eq!(result.library.encryption_mode, "server");
        assert!(!result.library.encrypted_data_key.is_empty());
        assert!(result.library.salt.is_none());
        assert!(result.library.verify_blob.is_none());
        assert!(result.library.recovery_blob.is_none());

        // Library can be looked up by user.
        let found = PersonalLibrary::find_by_user(&pool, &user_id)
            .await
            .unwrap()
            .expect("Library should exist");
        assert_eq!(found.id, result.library.id);

        // Data key is in unlock state.
        assert!(unlock_state.is_library_unlocked(&result.library.id));

        // User is marked as setup complete.
        let user = User::find_by_id(&pool, &user_id).await.unwrap().unwrap();
        assert!(user.setup_complete);

        // Directory was created on disk.
        let lib_dir = format!("{}/libraries/{}", data_dir, result.library.id);
        assert!(Path::new(&lib_dir).is_dir());

        // Meta file exists and has expected content.
        let meta_path = format!("{}/.irondrive.meta", lib_dir);
        let meta = tokio::fs::read_to_string(&meta_path).await.unwrap();
        assert!(meta.contains("type = \"library\""));
        assert!(meta.contains(&result.library.id));
    }

    #[tokio::test]
    async fn setup_fails_if_user_already_completed() {
        let tmp = tempfile::tempdir().unwrap();
        let data_dir = tmp.path().to_str().unwrap();
        let pool = test_pool().await;
        let config = test_config(data_dir);
        let master_key = bootstrap_master_key(&pool, &config.secret_key)
            .await
            .unwrap();
        let unlock_state = UnlockState::new();
        let user_id = seed_user(&pool, "alice").await;

        // First setup succeeds.
        setup_library(&pool, &config, &master_key, &unlock_state, &user_id)
            .await
            .unwrap();

        // Second setup should fail with Conflict.
        let result = setup_library(&pool, &config, &master_key, &unlock_state, &user_id).await;
        assert!(matches!(result, Err(AppError::Conflict(_))));
    }

    #[tokio::test]
    async fn setup_fails_if_user_not_found() {
        let tmp = tempfile::tempdir().unwrap();
        let data_dir = tmp.path().to_str().unwrap();
        let pool = test_pool().await;
        let config = test_config(data_dir);
        let master_key = bootstrap_master_key(&pool, &config.secret_key)
            .await
            .unwrap();
        let unlock_state = UnlockState::new();

        let result = setup_library(&pool, &config, &master_key, &unlock_state, "nonexistent").await;
        assert!(matches!(result, Err(AppError::NotFound)));
    }

    #[tokio::test]
    async fn data_key_can_be_unwrapped_after_setup() {
        let tmp = tempfile::tempdir().unwrap();
        let data_dir = tmp.path().to_str().unwrap();
        let pool = test_pool().await;
        let config = test_config(data_dir);
        let master_key = bootstrap_master_key(&pool, &config.secret_key)
            .await
            .unwrap();
        let unlock_state = UnlockState::new();
        let user_id = seed_user(&pool, "alice").await;

        let result = setup_library(&pool, &config, &master_key, &unlock_state, &user_id)
            .await
            .unwrap();

        // The encrypted_data_key stored in the DB can be unwrapped with the master key.
        let lib = PersonalLibrary::find_by_id(&pool, &result.library.id)
            .await
            .unwrap()
            .unwrap();

        let unwrapped = unwrap_data_key(&master_key, &lib.encrypted_data_key).unwrap();

        // It should match the key in unlock state.
        let from_state = unlock_state
            .get_library_key(&lib.id)
            .expect("Key should be in unlock state");

        assert_eq!(*unwrapped.as_bytes(), *from_state.as_bytes());
    }

    #[tokio::test]
    async fn two_users_get_different_data_keys() {
        let tmp = tempfile::tempdir().unwrap();
        let data_dir = tmp.path().to_str().unwrap();
        let pool = test_pool().await;
        let config = test_config(data_dir);
        let master_key = bootstrap_master_key(&pool, &config.secret_key)
            .await
            .unwrap();
        let unlock_state = UnlockState::new();

        let alice_id = seed_user(&pool, "alice").await;
        let bob_id = seed_user(&pool, "bob").await;

        let alice_lib = setup_library(&pool, &config, &master_key, &unlock_state, &alice_id)
            .await
            .unwrap();
        let bob_lib = setup_library(&pool, &config, &master_key, &unlock_state, &bob_id)
            .await
            .unwrap();

        let alice_key = unlock_state.get_library_key(&alice_lib.library.id).unwrap();
        let bob_key = unlock_state.get_library_key(&bob_lib.library.id).unwrap();

        // Each user gets a unique data key.
        assert_ne!(*alice_key.as_bytes(), *bob_key.as_bytes());

        // Each user gets a unique library ID and directory.
        assert_ne!(alice_lib.library.id, bob_lib.library.id);

        let alice_dir = format!("{}/libraries/{}", data_dir, alice_lib.library.id);
        let bob_dir = format!("{}/libraries/{}", data_dir, bob_lib.library.id);
        assert!(Path::new(&alice_dir).is_dir());
        assert!(Path::new(&bob_dir).is_dir());
    }

    #[tokio::test]
    async fn load_server_mode_keys_restores_unlock_state() {
        let tmp = tempfile::tempdir().unwrap();
        let data_dir = tmp.path().to_str().unwrap();
        let pool = test_pool().await;
        let config = test_config(data_dir);
        let master_key = bootstrap_master_key(&pool, &config.secret_key)
            .await
            .unwrap();
        let unlock_state = UnlockState::new();

        let alice_id = seed_user(&pool, "alice").await;
        let bob_id = seed_user(&pool, "bob").await;

        let alice_lib = setup_library(&pool, &config, &master_key, &unlock_state, &alice_id)
            .await
            .unwrap();
        let bob_lib = setup_library(&pool, &config, &master_key, &unlock_state, &bob_id)
            .await
            .unwrap();

        // Capture the keys before clearing.
        let alice_key_before = unlock_state.get_library_key(&alice_lib.library.id).unwrap();
        let bob_key_before = unlock_state.get_library_key(&bob_lib.library.id).unwrap();

        // Simulate a server restart: clear all keys.
        unlock_state.clear_all();
        assert_eq!(unlock_state.unlocked_library_count(), 0);

        // Reload keys from the database.
        let loaded = load_server_mode_keys(&pool, &master_key, &unlock_state)
            .await
            .unwrap();
        assert_eq!(loaded, 2);
        assert_eq!(unlock_state.unlocked_library_count(), 2);

        // Keys match what was originally generated.
        let alice_key_after = unlock_state.get_library_key(&alice_lib.library.id).unwrap();
        let bob_key_after = unlock_state.get_library_key(&bob_lib.library.id).unwrap();

        assert_eq!(*alice_key_before.as_bytes(), *alice_key_after.as_bytes());
        assert_eq!(*bob_key_before.as_bytes(), *bob_key_after.as_bytes());
    }

    #[tokio::test]
    async fn load_server_mode_keys_with_no_libraries() {
        let pool = test_pool().await;
        let config = test_config("/tmp/irondrive-empty");
        let master_key = bootstrap_master_key(&pool, &config.secret_key)
            .await
            .unwrap();
        let unlock_state = UnlockState::new();

        let loaded = load_server_mode_keys(&pool, &master_key, &unlock_state)
            .await
            .unwrap();
        assert_eq!(loaded, 0);
        assert_eq!(unlock_state.unlocked_library_count(), 0);
    }

    #[tokio::test]
    async fn create_library_directory_writes_meta() {
        let tmp = tempfile::tempdir().unwrap();
        let lib_dir = tmp.path().join("test-lib");
        let lib_dir_str = lib_dir.to_str().unwrap();

        create_library_directory(lib_dir_str, "lib-123")
            .await
            .unwrap();

        assert!(lib_dir.is_dir());

        let meta = tokio::fs::read_to_string(lib_dir.join(META_FILENAME))
            .await
            .unwrap();
        assert!(meta.contains("type = \"library\""));
        assert!(meta.contains("id = \"lib-123\""));
        assert!(meta.contains("created_by = \"irondrive\""));
    }
}
