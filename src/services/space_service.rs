use std::path::Path;

use tokio::fs;

use crate::config::AppConfig;
use crate::db::DbPool;
use crate::errors::AppError;
use crate::models::group::Group;
use crate::models::space::{
    CreateSpaceParams, Space, SpaceAccess, SpaceAccessDetail, SpaceWithMeta, UpdateSpaceParams,
};
use crate::models::user::User;
use crate::services::crypto_service::{
    generate_data_key, unwrap_data_key, wrap_data_key, MasterKey,
};
use crate::services::unlock_state::UnlockState;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const META_FILENAME: &str = ".irondrive.meta";
const NAME_MIN_LEN: usize = 1;
const NAME_MAX_LEN: usize = 100;
const PERM_READ: &str = "read";
const PERM_WRITE: &str = "write";
const PERM_ADMIN: &str = "admin";

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Create a new space owned by a user.
///
/// Steps: generate data key → wrap with master key → insert DB row →
/// create space dir on disk → load key into UnlockState.
///
/// If disk operations fail after the DB insert, the DB row is rolled back
/// on a best-effort basis to avoid orphaned state.
pub async fn create_space(
    pool: &DbPool,
    config: &AppConfig,
    master_key: &MasterKey,
    unlock_state: &UnlockState,
    owner_id: &str,
    name: &str,
) -> Result<SpaceWithMeta, AppError> {
    let name = validate_name(name)?;

    let data_key = generate_data_key();
    let encrypted_data_key = wrap_data_key(master_key, &data_key)?;

    let space = Space::create(
        pool,
        CreateSpaceParams {
            name,
            owner_type: "user".into(),
            owner_id: owner_id.to_owned(),
            encryption_mode: "server".into(),
            encrypted_data_key,
        },
    )
    .await?;

    // Create space dir on disk. If this fails, roll back the DB row.
    let dir = space_dir(config, &space.id);
    if let Err(e) = create_space_directory(&dir, &space.id).await {
        tracing::error!(
            space_id = %space.id,
            path = %dir,
            error = %e,
            "Failed to create space directory — rolling back DB row"
        );
        if let Err(del_err) = Space::delete_by_id(pool, &space.id).await {
            tracing::error!(
                space_id = %space.id,
                error = %del_err,
                "Failed to roll back space DB row after disk failure"
            );
        }
        return Err(e);
    }

    unlock_state.insert_space_key(&space.id, &data_key);

    tracing::info!(
        space_id = %space.id,
        owner_id = %owner_id,
        "Space created (server mode)"
    );

    Ok(SpaceWithMeta {
        space,
        grantee_count: 0,
        user_permission: PERM_ADMIN.to_string(),
    })
}

/// Create a new space owned by a group.
pub async fn create_group_space(
    pool: &DbPool,
    config: &AppConfig,
    master_key: &MasterKey,
    unlock_state: &UnlockState,
    group_id: &str,
    name: &str,
) -> Result<SpaceWithMeta, AppError> {
    let name = validate_name(name)?;

    // Verify the group exists before creating a space for it.
    Group::find_by_id(pool, group_id)
        .await?
        .ok_or(AppError::NotFound)?;

    let data_key = generate_data_key();
    let encrypted_data_key = wrap_data_key(master_key, &data_key)?;

    let space = Space::create(
        pool,
        CreateSpaceParams {
            name,
            owner_type: "group".into(),
            owner_id: group_id.to_owned(),
            encryption_mode: "server".into(),
            encrypted_data_key,
        },
    )
    .await?;

    let dir = space_dir(config, &space.id);
    if let Err(e) = create_space_directory(&dir, &space.id).await {
        tracing::error!(
            space_id = %space.id,
            path = %dir,
            error = %e,
            "Failed to create space directory — rolling back DB row"
        );
        if let Err(del_err) = Space::delete_by_id(pool, &space.id).await {
            tracing::error!(
                space_id = %space.id,
                error = %del_err,
                "Failed to roll back space DB row after disk failure"
            );
        }
        return Err(e);
    }

    unlock_state.insert_space_key(&space.id, &data_key);

    tracing::info!(
        space_id = %space.id,
        group_id = %group_id,
        "Group space created (server mode)"
    );

    Ok(SpaceWithMeta {
        space,
        grantee_count: 0,
        user_permission: PERM_ADMIN.to_string(),
    })
}

/// Get a single space with meta. Returns `NotFound` if the user has no access.
pub async fn get_space(
    pool: &DbPool,
    user_id: &str,
    space_id: &str,
) -> Result<SpaceWithMeta, AppError> {
    Space::find_for_user(pool, user_id, space_id)
        .await?
        .ok_or(AppError::NotFound)
}

/// List all spaces the user can access.
pub async fn list_user_spaces(
    pool: &DbPool,
    user_id: &str,
) -> Result<Vec<SpaceWithMeta>, AppError> {
    Space::find_all_for_user(pool, user_id).await
}

/// Rename a space. Requires admin permission.
pub async fn update_space(
    pool: &DbPool,
    user_id: &str,
    space_id: &str,
    name: &str,
) -> Result<Space, AppError> {
    require_permission(pool, user_id, space_id, PERM_ADMIN).await?;

    let name = validate_name(name)?;
    let space = Space::update(pool, space_id, UpdateSpaceParams { name }).await?;

    tracing::info!(
        space_id = %space_id,
        user_id = %user_id,
        "Space updated"
    );

    Ok(space)
}

/// Delete a space. Requires admin permission.
/// Removes the DB row (cascade deletes access rows), the on-disk directory,
/// and the key from UnlockState.
pub async fn delete_space(
    pool: &DbPool,
    config: &AppConfig,
    unlock_state: &UnlockState,
    user_id: &str,
    space_id: &str,
) -> Result<(), AppError> {
    require_permission(pool, user_id, space_id, PERM_ADMIN).await?;

    Space::delete_by_id(pool, space_id).await?;

    // Remove the key from memory.
    unlock_state.remove_space_key(space_id);

    // Remove the directory from disk (best-effort).
    let dir = space_dir(config, space_id);
    if let Err(e) = fs::remove_dir_all(&dir).await {
        tracing::warn!(
            space_id = %space_id,
            path = %dir,
            error = %e,
            "Failed to remove space directory from disk after deletion"
        );
    }

    tracing::info!(
        space_id = %space_id,
        user_id = %user_id,
        "Space deleted"
    );

    Ok(())
}

// ---------------------------------------------------------------------------
// Access management
// ---------------------------------------------------------------------------

/// Grant access to a user on a space. Requires admin permission.
pub async fn grant_user_access(
    pool: &DbPool,
    actor_id: &str,
    space_id: &str,
    target_username: &str,
    permission: &str,
) -> Result<SpaceAccess, AppError> {
    require_permission(pool, actor_id, space_id, PERM_ADMIN).await?;
    validate_permission(permission)?;

    let target = User::find_by_username(pool, target_username)
        .await?
        .ok_or(AppError::NotFound)?;

    let access = SpaceAccess::grant(pool, space_id, "user", &target.id, permission).await?;

    tracing::info!(
        space_id = %space_id,
        actor_id = %actor_id,
        target_user = %target_username,
        permission = %permission,
        "User access granted"
    );

    Ok(access)
}

/// Grant access to a group on a space. Requires admin permission.
pub async fn grant_group_access(
    pool: &DbPool,
    actor_id: &str,
    space_id: &str,
    group_id: &str,
    permission: &str,
) -> Result<SpaceAccess, AppError> {
    require_permission(pool, actor_id, space_id, PERM_ADMIN).await?;
    validate_permission(permission)?;

    // Verify the group exists before granting it access.
    Group::find_by_id(pool, group_id)
        .await?
        .ok_or(AppError::NotFound)?;

    let access = SpaceAccess::grant(pool, space_id, "group", group_id, permission).await?;

    tracing::info!(
        space_id = %space_id,
        actor_id = %actor_id,
        group_id = %group_id,
        permission = %permission,
        "Group access granted"
    );

    Ok(access)
}

/// Revoke a specific access grant. Requires admin permission.
pub async fn revoke_access(
    pool: &DbPool,
    actor_id: &str,
    space_id: &str,
    grantee_type: &str,
    grantee_id: &str,
) -> Result<(), AppError> {
    require_permission(pool, actor_id, space_id, PERM_ADMIN).await?;

    SpaceAccess::revoke(pool, space_id, grantee_type, grantee_id).await?;

    tracing::info!(
        space_id = %space_id,
        actor_id = %actor_id,
        grantee_type = %grantee_type,
        grantee_id = %grantee_id,
        "Access revoked"
    );

    Ok(())
}

/// Update permission level for an existing access grant. Requires admin permission.
pub async fn update_access_permission(
    pool: &DbPool,
    actor_id: &str,
    space_id: &str,
    grantee_type: &str,
    grantee_id: &str,
    permission: &str,
) -> Result<SpaceAccess, AppError> {
    require_permission(pool, actor_id, space_id, PERM_ADMIN).await?;
    validate_permission(permission)?;

    let access =
        SpaceAccess::update_permission(pool, space_id, grantee_type, grantee_id, permission)
            .await?;

    tracing::info!(
        space_id = %space_id,
        actor_id = %actor_id,
        grantee_type = %grantee_type,
        grantee_id = %grantee_id,
        permission = %permission,
        "Access permission updated"
    );

    Ok(access)
}

/// List all access entries for a space. Requires at least read permission.
pub async fn list_access(
    pool: &DbPool,
    user_id: &str,
    space_id: &str,
) -> Result<Vec<SpaceAccessDetail>, AppError> {
    require_permission(pool, user_id, space_id, PERM_READ).await?;
    SpaceAccess::list_with_details(pool, space_id).await
}

/// Resolve the effective permission a user has on a space.
/// Returns `None` if the user has no access.
pub async fn resolve_permission(
    pool: &DbPool,
    user_id: &str,
    space_id: &str,
) -> Result<Option<String>, AppError> {
    SpaceAccess::resolve_user_permission(pool, user_id, space_id).await
}

// ---------------------------------------------------------------------------
// Boot: load server-mode space keys
// ---------------------------------------------------------------------------

/// Load all server-mode space data keys into `UnlockState` at startup.
pub async fn load_server_mode_keys(
    pool: &DbPool,
    master_key: &MasterKey,
    unlock_state: &UnlockState,
) -> Result<usize, AppError> {
    let spaces = Space::find_all_server_mode(pool).await?;
    let total = spaces.len();
    let mut loaded = 0usize;

    for space in &spaces {
        match unwrap_data_key(master_key, &space.encrypted_data_key) {
            Ok(data_key) => {
                unlock_state.insert_space_key(&space.id, &data_key);
                loaded += 1;
            }
            Err(e) => {
                tracing::error!(
                    space_id = %space.id,
                    error = %e,
                    "Failed to unwrap data key for server-mode space — skipping"
                );
            }
        }
    }

    if loaded < total {
        tracing::warn!(
            total,
            loaded,
            skipped = total - loaded,
            "Some server-mode space keys could not be unwrapped"
        );
    }

    Ok(loaded)
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

fn space_dir(config: &AppConfig, space_id: &str) -> String {
    format!("{}/spaces/{}", config.data_dir, space_id)
}

async fn create_space_directory(dir: &str, space_id: &str) -> Result<(), AppError> {
    let path = Path::new(dir);

    fs::create_dir_all(path).await.map_err(|e| {
        AppError::Internal(format!("Failed to create space directory '{}': {}", dir, e))
    })?;

    let meta_path = path.join(META_FILENAME);
    let meta_content = format!(
        "type = \"space\"\nid = \"{}\"\ncreated_by = \"irondrive\"\n",
        space_id
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

/// Check that the user has at least the required permission level.
async fn require_permission(
    pool: &DbPool,
    user_id: &str,
    space_id: &str,
    required: &str,
) -> Result<(), AppError> {
    let perm = SpaceAccess::resolve_user_permission(pool, user_id, space_id)
        .await?
        .ok_or(AppError::NotFound)?;

    let level = permission_level(&perm);
    let required_level = permission_level(required);

    if level < required_level {
        return Err(AppError::Forbidden);
    }

    Ok(())
}

fn permission_level(perm: &str) -> u8 {
    match perm {
        PERM_READ => 1,
        PERM_WRITE => 2,
        PERM_ADMIN => 3,
        _ => 0,
    }
}

fn validate_name(name: &str) -> Result<String, AppError> {
    let name = name.trim().to_string();
    if name.len() < NAME_MIN_LEN || name.len() > NAME_MAX_LEN {
        return Err(AppError::Validation(format!(
            "Space name must be between {NAME_MIN_LEN} and {NAME_MAX_LEN} characters."
        )));
    }
    Ok(name)
}

fn validate_permission(perm: &str) -> Result<(), AppError> {
    match perm {
        PERM_READ | PERM_WRITE | PERM_ADMIN => Ok(()),
        _ => Err(AppError::Validation(format!(
            "Invalid permission '{perm}'. Must be one of: {PERM_READ}, {PERM_WRITE}, {PERM_ADMIN}."
        ))),
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db;
    use crate::models::group::{CreateGroupParams, Group, GroupMember};
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

    fn base64_test_key() -> String {
        use base64::Engine;
        base64::engine::general_purpose::STANDARD.encode([0xABu8; 32])
    }

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

    // -----------------------------------------------------------------------
    // Create space
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn create_space_success() {
        let tmp = tempfile::tempdir().unwrap();
        let data_dir = tmp.path().to_str().unwrap();
        let pool = test_pool().await;
        let config = test_config(data_dir);
        let master_key = bootstrap_master_key(&pool, &config.secret_key)
            .await
            .unwrap();
        let unlock_state = UnlockState::new();
        let owner_id = seed_user(&pool, "alice").await;

        let result =
            create_space(&pool, &config, &master_key, &unlock_state, &owner_id, "Project X")
                .await
                .unwrap();

        assert_eq!(result.space.name, "Project X");
        assert_eq!(result.space.owner_type, "user");
        assert_eq!(result.space.owner_id, owner_id);
        assert_eq!(result.space.encryption_mode, "server");
        assert_eq!(result.user_permission, "admin");
        assert_eq!(result.grantee_count, 0);

        // Key should be loaded.
        assert!(unlock_state.is_space_unlocked(&result.space.id));

        // Directory should exist.
        let dir = format!("{}/spaces/{}", data_dir, result.space.id);
        assert!(Path::new(&dir).exists());
        assert!(Path::new(&dir).join(META_FILENAME).exists());
    }

    #[tokio::test]
    async fn create_space_empty_name_rejected() {
        let tmp = tempfile::tempdir().unwrap();
        let data_dir = tmp.path().to_str().unwrap();
        let pool = test_pool().await;
        let config = test_config(data_dir);
        let master_key = bootstrap_master_key(&pool, &config.secret_key)
            .await
            .unwrap();
        let unlock_state = UnlockState::new();
        let owner_id = seed_user(&pool, "alice").await;

        let err = create_space(&pool, &config, &master_key, &unlock_state, &owner_id, "  ")
            .await
            .unwrap_err();
        assert!(matches!(err, AppError::Validation(_)));
    }

    // -----------------------------------------------------------------------
    // Create group space
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn create_group_space_success() {
        let tmp = tempfile::tempdir().unwrap();
        let data_dir = tmp.path().to_str().unwrap();
        let pool = test_pool().await;
        let config = test_config(data_dir);
        let master_key = bootstrap_master_key(&pool, &config.secret_key)
            .await
            .unwrap();
        let unlock_state = UnlockState::new();
        let alice_id = seed_user(&pool, "alice").await;

        let group = Group::create(
            &pool,
            CreateGroupParams {
                name: "Team".into(),
                description: None,
                created_by: alice_id.clone(),
            },
        )
        .await
        .unwrap();
        GroupMember::add(&pool, &group.id, &alice_id, "owner")
            .await
            .unwrap();

        let result = create_group_space(
            &pool,
            &config,
            &master_key,
            &unlock_state,
            &group.id,
            "Team Space",
        )
        .await
        .unwrap();

        assert_eq!(result.space.name, "Team Space");
        assert_eq!(result.space.owner_type, "group");
        assert_eq!(result.space.owner_id, group.id);
        assert!(unlock_state.is_space_unlocked(&result.space.id));
    }

    // -----------------------------------------------------------------------
    // Get / List spaces
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn get_space_with_access() {
        let pool = test_pool().await;
        let tmp = tempfile::tempdir().unwrap();
        let data_dir = tmp.path().to_str().unwrap();
        let config = test_config(data_dir);
        let master_key = bootstrap_master_key(&pool, &config.secret_key)
            .await
            .unwrap();
        let unlock_state = UnlockState::new();
        let alice_id = seed_user(&pool, "alice").await;

        let created =
            create_space(&pool, &config, &master_key, &unlock_state, &alice_id, "My Space")
                .await
                .unwrap();

        let fetched = get_space(&pool, &alice_id, &created.space.id).await.unwrap();
        assert_eq!(fetched.space.name, "My Space");
        assert_eq!(fetched.user_permission, "admin");
    }

    #[tokio::test]
    async fn get_space_without_access_returns_not_found() {
        let pool = test_pool().await;
        let tmp = tempfile::tempdir().unwrap();
        let data_dir = tmp.path().to_str().unwrap();
        let config = test_config(data_dir);
        let master_key = bootstrap_master_key(&pool, &config.secret_key)
            .await
            .unwrap();
        let unlock_state = UnlockState::new();
        let alice_id = seed_user(&pool, "alice").await;
        let bob_id = seed_user(&pool, "bob").await;

        let created =
            create_space(&pool, &config, &master_key, &unlock_state, &alice_id, "Private")
                .await
                .unwrap();

        let err = get_space(&pool, &bob_id, &created.space.id)
            .await
            .unwrap_err();
        assert!(matches!(err, AppError::NotFound));
    }

    #[tokio::test]
    async fn list_user_spaces_only_accessible() {
        let pool = test_pool().await;
        let tmp = tempfile::tempdir().unwrap();
        let data_dir = tmp.path().to_str().unwrap();
        let config = test_config(data_dir);
        let master_key = bootstrap_master_key(&pool, &config.secret_key)
            .await
            .unwrap();
        let unlock_state = UnlockState::new();
        let alice_id = seed_user(&pool, "alice").await;
        let bob_id = seed_user(&pool, "bob").await;

        // Alice creates two spaces.
        create_space(&pool, &config, &master_key, &unlock_state, &alice_id, "A1")
            .await
            .unwrap();
        create_space(&pool, &config, &master_key, &unlock_state, &alice_id, "A2")
            .await
            .unwrap();
        // Bob creates one space.
        create_space(&pool, &config, &master_key, &unlock_state, &bob_id, "B1")
            .await
            .unwrap();

        let alice_spaces = list_user_spaces(&pool, &alice_id).await.unwrap();
        assert_eq!(alice_spaces.len(), 2);

        let bob_spaces = list_user_spaces(&pool, &bob_id).await.unwrap();
        assert_eq!(bob_spaces.len(), 1);
    }

    // -----------------------------------------------------------------------
    // Update space
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn update_space_as_admin() {
        let pool = test_pool().await;
        let tmp = tempfile::tempdir().unwrap();
        let data_dir = tmp.path().to_str().unwrap();
        let config = test_config(data_dir);
        let master_key = bootstrap_master_key(&pool, &config.secret_key)
            .await
            .unwrap();
        let unlock_state = UnlockState::new();
        let alice_id = seed_user(&pool, "alice").await;

        let created =
            create_space(&pool, &config, &master_key, &unlock_state, &alice_id, "Old")
                .await
                .unwrap();

        let updated =
            update_space(&pool, &alice_id, &created.space.id, "New").await.unwrap();
        assert_eq!(updated.name, "New");
    }

    #[tokio::test]
    async fn update_space_as_reader_forbidden() {
        let pool = test_pool().await;
        let tmp = tempfile::tempdir().unwrap();
        let data_dir = tmp.path().to_str().unwrap();
        let config = test_config(data_dir);
        let master_key = bootstrap_master_key(&pool, &config.secret_key)
            .await
            .unwrap();
        let unlock_state = UnlockState::new();
        let alice_id = seed_user(&pool, "alice").await;
        let bob_id = seed_user(&pool, "bob").await;

        let created =
            create_space(&pool, &config, &master_key, &unlock_state, &alice_id, "S")
                .await
                .unwrap();

        // Grant bob read-only.
        SpaceAccess::grant(&pool, &created.space.id, "user", &bob_id, "read")
            .await
            .unwrap();

        let err = update_space(&pool, &bob_id, &created.space.id, "Hacked")
            .await
            .unwrap_err();
        assert!(matches!(err, AppError::Forbidden));
    }

    // -----------------------------------------------------------------------
    // Delete space
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn delete_space_success() {
        let pool = test_pool().await;
        let tmp = tempfile::tempdir().unwrap();
        let data_dir = tmp.path().to_str().unwrap();
        let config = test_config(data_dir);
        let master_key = bootstrap_master_key(&pool, &config.secret_key)
            .await
            .unwrap();
        let unlock_state = UnlockState::new();
        let alice_id = seed_user(&pool, "alice").await;

        let created =
            create_space(&pool, &config, &master_key, &unlock_state, &alice_id, "Doomed")
                .await
                .unwrap();
        let space_id = created.space.id.clone();

        delete_space(&pool, &config, &unlock_state, &alice_id, &space_id)
            .await
            .unwrap();

        // DB row gone.
        assert!(Space::find_by_id(&pool, &space_id).await.unwrap().is_none());
        // Key removed.
        assert!(!unlock_state.is_space_unlocked(&space_id));
        // Directory removed.
        let dir = format!("{}/spaces/{}", data_dir, space_id);
        assert!(!Path::new(&dir).exists());
    }

    #[tokio::test]
    async fn delete_space_without_admin_forbidden() {
        let pool = test_pool().await;
        let tmp = tempfile::tempdir().unwrap();
        let data_dir = tmp.path().to_str().unwrap();
        let config = test_config(data_dir);
        let master_key = bootstrap_master_key(&pool, &config.secret_key)
            .await
            .unwrap();
        let unlock_state = UnlockState::new();
        let alice_id = seed_user(&pool, "alice").await;
        let bob_id = seed_user(&pool, "bob").await;

        let created =
            create_space(&pool, &config, &master_key, &unlock_state, &alice_id, "S")
                .await
                .unwrap();

        SpaceAccess::grant(&pool, &created.space.id, "user", &bob_id, "write")
            .await
            .unwrap();

        let err = delete_space(&pool, &config, &unlock_state, &bob_id, &created.space.id)
            .await
            .unwrap_err();
        assert!(matches!(err, AppError::Forbidden));
    }

    // -----------------------------------------------------------------------
    // Access management
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn grant_and_revoke_user_access() {
        let pool = test_pool().await;
        let tmp = tempfile::tempdir().unwrap();
        let data_dir = tmp.path().to_str().unwrap();
        let config = test_config(data_dir);
        let master_key = bootstrap_master_key(&pool, &config.secret_key)
            .await
            .unwrap();
        let unlock_state = UnlockState::new();
        let alice_id = seed_user(&pool, "alice").await;
        let _bob_id = seed_user(&pool, "bob").await;

        let created =
            create_space(&pool, &config, &master_key, &unlock_state, &alice_id, "S")
                .await
                .unwrap();

        // Grant bob write.
        let access =
            grant_user_access(&pool, &alice_id, &created.space.id, "bob", "write")
                .await
                .unwrap();
        assert_eq!(access.permission, "write");
        assert_eq!(access.grantee_type, "user");

        // Revoke.
        revoke_access(&pool, &alice_id, &created.space.id, "user", &access.grantee_id)
            .await
            .unwrap();

        // Bob should no longer have access.
        let perm =
            resolve_permission(&pool, &access.grantee_id, &created.space.id)
                .await
                .unwrap();
        assert!(perm.is_none());
    }

    #[tokio::test]
    async fn grant_access_nonexistent_user_returns_not_found() {
        let pool = test_pool().await;
        let tmp = tempfile::tempdir().unwrap();
        let data_dir = tmp.path().to_str().unwrap();
        let config = test_config(data_dir);
        let master_key = bootstrap_master_key(&pool, &config.secret_key)
            .await
            .unwrap();
        let unlock_state = UnlockState::new();
        let alice_id = seed_user(&pool, "alice").await;

        let created =
            create_space(&pool, &config, &master_key, &unlock_state, &alice_id, "S")
                .await
                .unwrap();

        let err =
            grant_user_access(&pool, &alice_id, &created.space.id, "ghost", "read")
                .await
                .unwrap_err();
        assert!(matches!(err, AppError::NotFound));
    }

    #[tokio::test]
    async fn grant_invalid_permission_rejected() {
        let pool = test_pool().await;
        let tmp = tempfile::tempdir().unwrap();
        let data_dir = tmp.path().to_str().unwrap();
        let config = test_config(data_dir);
        let master_key = bootstrap_master_key(&pool, &config.secret_key)
            .await
            .unwrap();
        let unlock_state = UnlockState::new();
        let alice_id = seed_user(&pool, "alice").await;
        let _bob_id = seed_user(&pool, "bob").await;

        let created =
            create_space(&pool, &config, &master_key, &unlock_state, &alice_id, "S")
                .await
                .unwrap();

        let err =
            grant_user_access(&pool, &alice_id, &created.space.id, "bob", "superadmin")
                .await
                .unwrap_err();
        assert!(matches!(err, AppError::Validation(_)));
    }

    #[tokio::test]
    async fn non_admin_cannot_grant_access() {
        let pool = test_pool().await;
        let tmp = tempfile::tempdir().unwrap();
        let data_dir = tmp.path().to_str().unwrap();
        let config = test_config(data_dir);
        let master_key = bootstrap_master_key(&pool, &config.secret_key)
            .await
            .unwrap();
        let unlock_state = UnlockState::new();
        let alice_id = seed_user(&pool, "alice").await;
        let bob_id = seed_user(&pool, "bob").await;
        let _charlie_id = seed_user(&pool, "charlie").await;

        let created =
            create_space(&pool, &config, &master_key, &unlock_state, &alice_id, "S")
                .await
                .unwrap();

        // Grant bob write.
        SpaceAccess::grant(&pool, &created.space.id, "user", &bob_id, "write")
            .await
            .unwrap();

        // Bob (write) tries to grant charlie — should fail.
        let err =
            grant_user_access(&pool, &bob_id, &created.space.id, "charlie", "read")
                .await
                .unwrap_err();
        assert!(matches!(err, AppError::Forbidden));
    }

    #[tokio::test]
    async fn update_access_permission_success() {
        let pool = test_pool().await;
        let tmp = tempfile::tempdir().unwrap();
        let data_dir = tmp.path().to_str().unwrap();
        let config = test_config(data_dir);
        let master_key = bootstrap_master_key(&pool, &config.secret_key)
            .await
            .unwrap();
        let unlock_state = UnlockState::new();
        let alice_id = seed_user(&pool, "alice").await;
        let bob_id = seed_user(&pool, "bob").await;

        let created =
            create_space(&pool, &config, &master_key, &unlock_state, &alice_id, "S")
                .await
                .unwrap();

        SpaceAccess::grant(&pool, &created.space.id, "user", &bob_id, "read")
            .await
            .unwrap();

        let updated = update_access_permission(
            &pool,
            &alice_id,
            &created.space.id,
            "user",
            &bob_id,
            "admin",
        )
        .await
        .unwrap();
        assert_eq!(updated.permission, "admin");
    }

    #[tokio::test]
    async fn list_access_requires_read() {
        let pool = test_pool().await;
        let tmp = tempfile::tempdir().unwrap();
        let data_dir = tmp.path().to_str().unwrap();
        let config = test_config(data_dir);
        let master_key = bootstrap_master_key(&pool, &config.secret_key)
            .await
            .unwrap();
        let unlock_state = UnlockState::new();
        let alice_id = seed_user(&pool, "alice").await;
        let bob_id = seed_user(&pool, "bob").await;

        let created =
            create_space(&pool, &config, &master_key, &unlock_state, &alice_id, "S")
                .await
                .unwrap();

        // Bob has no access — should get NotFound.
        let err = list_access(&pool, &bob_id, &created.space.id)
            .await
            .unwrap_err();
        assert!(matches!(err, AppError::NotFound));

        // Grant bob read — should work.
        SpaceAccess::grant(&pool, &created.space.id, "user", &bob_id, "read")
            .await
            .unwrap();
        let entries = list_access(&pool, &bob_id, &created.space.id)
            .await
            .unwrap();
        assert_eq!(entries.len(), 1);
    }

    // -----------------------------------------------------------------------
    // Permission resolution
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn writer_cannot_delete_or_update() {
        let pool = test_pool().await;
        let tmp = tempfile::tempdir().unwrap();
        let data_dir = tmp.path().to_str().unwrap();
        let config = test_config(data_dir);
        let master_key = bootstrap_master_key(&pool, &config.secret_key)
            .await
            .unwrap();
        let unlock_state = UnlockState::new();
        let alice_id = seed_user(&pool, "alice").await;
        let bob_id = seed_user(&pool, "bob").await;

        let created =
            create_space(&pool, &config, &master_key, &unlock_state, &alice_id, "S")
                .await
                .unwrap();

        SpaceAccess::grant(&pool, &created.space.id, "user", &bob_id, "write")
            .await
            .unwrap();

        // Writer cannot rename.
        let err = update_space(&pool, &bob_id, &created.space.id, "New")
            .await
            .unwrap_err();
        assert!(matches!(err, AppError::Forbidden));

        // Writer cannot delete.
        let err = delete_space(&pool, &config, &unlock_state, &bob_id, &created.space.id)
            .await
            .unwrap_err();
        assert!(matches!(err, AppError::Forbidden));
    }

    // -----------------------------------------------------------------------
    // Boot: load server-mode keys
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn load_server_mode_keys_restores_unlock_state() {
        let pool = test_pool().await;
        let tmp = tempfile::tempdir().unwrap();
        let data_dir = tmp.path().to_str().unwrap();
        let config = test_config(data_dir);
        let master_key = bootstrap_master_key(&pool, &config.secret_key)
            .await
            .unwrap();
        let unlock_state = UnlockState::new();
        let alice_id = seed_user(&pool, "alice").await;

        // Create two spaces.
        let s1 =
            create_space(&pool, &config, &master_key, &unlock_state, &alice_id, "S1")
                .await
                .unwrap();
        let s2 =
            create_space(&pool, &config, &master_key, &unlock_state, &alice_id, "S2")
                .await
                .unwrap();

        // Simulate reboot: fresh UnlockState.
        let fresh_state = UnlockState::new();
        assert!(!fresh_state.is_space_unlocked(&s1.space.id));
        assert!(!fresh_state.is_space_unlocked(&s2.space.id));

        let loaded = load_server_mode_keys(&pool, &master_key, &fresh_state)
            .await
            .unwrap();
        assert_eq!(loaded, 2);
        assert!(fresh_state.is_space_unlocked(&s1.space.id));
        assert!(fresh_state.is_space_unlocked(&s2.space.id));
    }

    #[tokio::test]
    async fn load_server_mode_keys_with_no_spaces() {
        let pool = test_pool().await;
        let master_key = bootstrap_master_key(&pool, &base64_test_key())
            .await
            .unwrap();
        let unlock_state = UnlockState::new();

        let loaded = load_server_mode_keys(&pool, &master_key, &unlock_state)
            .await
            .unwrap();
        assert_eq!(loaded, 0);
    }

    // -----------------------------------------------------------------------
    // Group existence hardening
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn create_group_space_nonexistent_group_returns_not_found() {
        let tmp = tempfile::tempdir().unwrap();
        let data_dir = tmp.path().to_str().unwrap();
        let pool = test_pool().await;
        let config = test_config(data_dir);
        let master_key = bootstrap_master_key(&pool, &config.secret_key)
            .await
            .unwrap();
        let unlock_state = UnlockState::new();

        let err = create_group_space(
            &pool,
            &config,
            &master_key,
            &unlock_state,
            "nonexistent-group-id",
            "Ghost Space",
        )
        .await
        .unwrap_err();
        assert!(matches!(err, AppError::NotFound));

        // Verify no space was created.
        let all = Space::find_all_server_mode(&pool).await.unwrap();
        assert!(all.is_empty());
    }

    #[tokio::test]
    async fn grant_group_access_nonexistent_group_returns_not_found() {
        let tmp = tempfile::tempdir().unwrap();
        let data_dir = tmp.path().to_str().unwrap();
        let pool = test_pool().await;
        let config = test_config(data_dir);
        let master_key = bootstrap_master_key(&pool, &config.secret_key)
            .await
            .unwrap();
        let unlock_state = UnlockState::new();
        let alice_id = seed_user(&pool, "alice").await;

        let created =
            create_space(&pool, &config, &master_key, &unlock_state, &alice_id, "S")
                .await
                .unwrap();

        let err = grant_group_access(
            &pool,
            &alice_id,
            &created.space.id,
            "nonexistent-group-id",
            "read",
        )
        .await
        .unwrap_err();
        assert!(matches!(err, AppError::NotFound));

        // Verify no access row was created.
        let entries = SpaceAccess::list_with_details(&pool, &created.space.id)
            .await
            .unwrap();
        assert!(entries.is_empty());
    }
}
