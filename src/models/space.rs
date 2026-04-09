//! Database models and queries for spaces and space access grants.
//!
//! Tables: `spaces` (metadata + encrypted key), `space_access` (permission grants).
//! Permission resolution uses CTEs that check ownership (user/group),
//! direct user grants, and group-membership grants, then picks the highest.

use serde::Serialize;
use sqlx::FromRow;
use uuid::Uuid;

use crate::db::{is_unique_violation, DbPool};
use crate::errors::AppError;

// ---------------------------------------------------------------------------
// Structs
// ---------------------------------------------------------------------------

/// A row from the `spaces` table.
#[derive(Debug, Clone, FromRow, Serialize)]
pub struct Space {
    pub id: String,
    pub name: String,
    pub owner_type: String,
    pub owner_id: String,
    pub encryption_mode: String,
    pub encrypted_data_key: Vec<u8>,
    pub salt: Option<Vec<u8>>,
    pub verify_blob: Option<Vec<u8>>,
    pub recovery_blob: Option<Vec<u8>>,
    pub created_at: String,
}

pub struct CreateSpaceParams {
    pub name: String,
    pub owner_type: String,
    pub owner_id: String,
    pub encryption_mode: String,
    pub encrypted_data_key: Vec<u8>,
}

pub struct UpdateSpaceParams {
    pub name: String,
}

/// A row from the `space_access` table.
#[derive(Debug, Clone, FromRow, Serialize)]
pub struct SpaceAccess {
    pub space_id: String,
    pub grantee_type: String,
    pub grantee_id: String,
    pub permission: String,
    pub granted_at: String,
}

/// A space access entry joined with the grantee name for display.
/// For `grantee_type = 'user'` this is the username; for `'group'` the group name.
#[derive(Debug, Clone, FromRow, Serialize)]
pub struct SpaceAccessDetail {
    pub space_id: String,
    pub grantee_type: String,
    pub grantee_id: String,
    pub permission: String,
    pub granted_at: String,
    pub grantee_name: String,
}

/// A space with the requesting user's effective permission and the grantee count.
#[derive(Debug, Clone, Serialize)]
pub struct SpaceWithMeta {
    #[serde(flatten)]
    pub space: Space,
    pub grantee_count: i64,
    pub user_permission: String,
}

// ---------------------------------------------------------------------------
// Space queries
// ---------------------------------------------------------------------------

impl Space {
    /// Insert a new space. The caller is responsible for creating the
    /// corresponding directory on disk and loading the data key.
    pub async fn create(pool: &DbPool, params: CreateSpaceParams) -> Result<Space, AppError> {
        let id = Uuid::new_v4().to_string();

        sqlx::query(
            "INSERT INTO spaces (id, name, owner_type, owner_id, encryption_mode, encrypted_data_key)
             VALUES (?, ?, ?, ?, ?, ?)",
        )
        .bind(&id)
        .bind(&params.name)
        .bind(&params.owner_type)
        .bind(&params.owner_id)
        .bind(&params.encryption_mode)
        .bind(&params.encrypted_data_key)
        .execute(pool)
        .await
        .map_err(AppError::Sqlx)?;

        Self::find_by_id(pool, &id).await?.ok_or_else(|| {
            AppError::Internal("Space was inserted but could not be read back".into())
        })
    }

    pub async fn find_by_id(pool: &DbPool, id: &str) -> Result<Option<Space>, AppError> {
        let space = sqlx::query_as::<_, Space>(
            "SELECT id, name, owner_type, owner_id, encryption_mode,
                    encrypted_data_key, salt, verify_blob, recovery_blob, created_at
             FROM spaces WHERE id = ?",
        )
        .bind(id)
        .fetch_optional(pool)
        .await?;

        Ok(space)
    }

    /// All spaces that a user can access — via ownership (user or group)
    /// or via explicit grants (direct user or group membership).
    /// Returns each space with grantee count and the user's effective permission.
    ///
    /// The query uses three CTEs:
    /// 1. `user_groups` — group IDs the user belongs to
    /// 2. `accessible_spaces` — union of all ownership/grant paths
    /// 3. `best_perm` — collapse multiple grants into the highest permission
    pub async fn find_all_for_user(
        pool: &DbPool,
        user_id: &str,
    ) -> Result<Vec<SpaceWithMeta>, AppError> {
        // Build the set of group IDs this user belongs to, then query spaces
        // where the user is the owner, in the owner group, has a direct grant,
        // or is in a group that has a grant. We use a CTE for clarity.
        let rows = sqlx::query_as::<_, (String, String, String, String, String, Vec<u8>, Option<Vec<u8>>, Option<Vec<u8>>, Option<Vec<u8>>, String, i64, String)>(
            "WITH user_groups AS (
                SELECT group_id FROM group_members WHERE user_id = ?1
            ),
            accessible_spaces AS (
                -- User directly owns the space
                SELECT s.id, 'admin' AS perm FROM spaces s
                WHERE s.owner_type = 'user' AND s.owner_id = ?1
                UNION
                -- User is in the owner group
                SELECT s.id, 'admin' AS perm FROM spaces s
                WHERE s.owner_type = 'group' AND s.owner_id IN (SELECT group_id FROM user_groups)
                UNION
                -- Direct user grant
                SELECT sa.space_id, sa.permission FROM space_access sa
                WHERE sa.grantee_type = 'user' AND sa.grantee_id = ?1
                UNION
                -- Group grant (user is member of grantee group)
                SELECT sa.space_id, sa.permission FROM space_access sa
                WHERE sa.grantee_type = 'group' AND sa.grantee_id IN (SELECT group_id FROM user_groups)
            ),
            best_perm AS (
                SELECT id AS space_id,
                       MAX(CASE perm
                           WHEN 'admin' THEN 3
                           WHEN 'write' THEN 2
                           WHEN 'read'  THEN 1
                           ELSE 0
                       END) AS perm_rank,
                       -- pick the label matching the max rank
                       CASE MAX(CASE perm
                           WHEN 'admin' THEN 3
                           WHEN 'write' THEN 2
                           WHEN 'read'  THEN 1
                           ELSE 0
                       END)
                           WHEN 3 THEN 'admin'
                           WHEN 2 THEN 'write'
                           WHEN 1 THEN 'read'
                           ELSE 'none'
                       END AS perm
                FROM accessible_spaces
                GROUP BY id
            )
            SELECT s.id, s.name, s.owner_type, s.owner_id, s.encryption_mode,
                   s.encrypted_data_key, s.salt, s.verify_blob, s.recovery_blob, s.created_at,
                   (SELECT COUNT(*) FROM space_access WHERE space_id = s.id) AS grantee_count,
                   bp.perm AS user_permission
            FROM spaces s
            INNER JOIN best_perm bp ON bp.space_id = s.id
            ORDER BY s.name ASC",
        )
        .bind(user_id)
        .fetch_all(pool)
        .await?;

        let spaces = rows
            .into_iter()
            .map(
                |(id, name, owner_type, owner_id, encryption_mode, encrypted_data_key, salt, verify_blob, recovery_blob, created_at, grantee_count, user_permission)| {
                    SpaceWithMeta {
                        space: Space {
                            id,
                            name,
                            owner_type,
                            owner_id,
                            encryption_mode,
                            encrypted_data_key,
                            salt,
                            verify_blob,
                            recovery_blob,
                            created_at,
                        },
                        grantee_count,
                        user_permission,
                    }
                },
            )
            .collect();

        Ok(spaces)
    }

    /// Single space with meta for a specific user. Returns `None` if the user
    /// has no access.
    pub async fn find_for_user(
        pool: &DbPool,
        user_id: &str,
        space_id: &str,
    ) -> Result<Option<SpaceWithMeta>, AppError> {
        let row = sqlx::query_as::<_, (String, String, String, String, String, Vec<u8>, Option<Vec<u8>>, Option<Vec<u8>>, Option<Vec<u8>>, String, i64, String)>(
            "WITH user_groups AS (
                SELECT group_id FROM group_members WHERE user_id = ?1
            ),
            accessible AS (
                SELECT 'admin' AS perm
                FROM spaces WHERE id = ?2 AND owner_type = 'user' AND owner_id = ?1
                UNION
                SELECT 'admin' AS perm
                FROM spaces WHERE id = ?2 AND owner_type = 'group'
                    AND owner_id IN (SELECT group_id FROM user_groups)
                UNION
                SELECT sa.permission FROM space_access sa
                WHERE sa.space_id = ?2 AND sa.grantee_type = 'user' AND sa.grantee_id = ?1
                UNION
                SELECT sa.permission FROM space_access sa
                WHERE sa.space_id = ?2 AND sa.grantee_type = 'group'
                    AND sa.grantee_id IN (SELECT group_id FROM user_groups)
            ),
            best AS (
                SELECT CASE MAX(CASE perm
                           WHEN 'admin' THEN 3
                           WHEN 'write' THEN 2
                           WHEN 'read'  THEN 1
                           ELSE 0
                       END)
                           WHEN 3 THEN 'admin'
                           WHEN 2 THEN 'write'
                           WHEN 1 THEN 'read'
                           ELSE 'none'
                       END AS perm
                FROM accessible
            )
            SELECT s.id, s.name, s.owner_type, s.owner_id, s.encryption_mode,
                   s.encrypted_data_key, s.salt, s.verify_blob, s.recovery_blob, s.created_at,
                   (SELECT COUNT(*) FROM space_access WHERE space_id = s.id) AS grantee_count,
                   b.perm AS user_permission
            FROM spaces s, best b
            WHERE s.id = ?2 AND b.perm != 'none'",
        )
        .bind(user_id)
        .bind(space_id)
        .fetch_optional(pool)
        .await?;

        Ok(row.map(
            |(id, name, owner_type, owner_id, encryption_mode, encrypted_data_key, salt, verify_blob, recovery_blob, created_at, grantee_count, user_permission)| {
                SpaceWithMeta {
                    space: Space {
                        id,
                        name,
                        owner_type,
                        owner_id,
                        encryption_mode,
                        encrypted_data_key,
                        salt,
                        verify_blob,
                        recovery_blob,
                        created_at,
                    },
                    grantee_count,
                    user_permission,
                }
            },
        ))
    }

    /// Update space name. Returns `NotFound` if space doesn't exist.
    pub async fn update(
        pool: &DbPool,
        id: &str,
        params: UpdateSpaceParams,
    ) -> Result<Space, AppError> {
        let result = sqlx::query("UPDATE spaces SET name = ? WHERE id = ?")
            .bind(&params.name)
            .bind(id)
            .execute(pool)
            .await?;

        if result.rows_affected() == 0 {
            return Err(AppError::NotFound);
        }

        Self::find_by_id(pool, id).await?.ok_or(AppError::NotFound)
    }

    /// Delete a space. Access rows are cascade-deleted by the DB.
    /// The caller is responsible for removing the directory from disk.
    pub async fn delete_by_id(pool: &DbPool, id: &str) -> Result<(), AppError> {
        let result = sqlx::query("DELETE FROM spaces WHERE id = ?")
            .bind(id)
            .execute(pool)
            .await?;

        if result.rows_affected() == 0 {
            return Err(AppError::NotFound);
        }

        Ok(())
    }

    /// Return all spaces with `encryption_mode = 'server'`. Used at boot to
    /// load data keys into `UnlockState`.
    pub async fn find_all_server_mode(pool: &DbPool) -> Result<Vec<Space>, AppError> {
        let spaces = sqlx::query_as::<_, Space>(
            "SELECT id, name, owner_type, owner_id, encryption_mode,
                    encrypted_data_key, salt, verify_blob, recovery_blob, created_at
             FROM spaces WHERE encryption_mode = 'server'",
        )
        .fetch_all(pool)
        .await?;

        Ok(spaces)
    }
}

// ---------------------------------------------------------------------------
// SpaceAccess queries
// ---------------------------------------------------------------------------

impl SpaceAccess {
    /// Grant access to a user or group. Returns `Conflict` if the grant
    /// already exists.
    pub async fn grant(
        pool: &DbPool,
        space_id: &str,
        grantee_type: &str,
        grantee_id: &str,
        permission: &str,
    ) -> Result<SpaceAccess, AppError> {
        let insert_result = sqlx::query(
            "INSERT INTO space_access (space_id, grantee_type, grantee_id, permission)
             VALUES (?, ?, ?, ?)",
        )
        .bind(space_id)
        .bind(grantee_type)
        .bind(grantee_id)
        .bind(permission)
        .execute(pool)
        .await;

        match insert_result {
            Ok(_) => {}
            Err(e) if is_unique_violation(&e) => {
                return Err(AppError::Conflict(
                    "Access already granted to this user or group.".into(),
                ));
            }
            Err(e) => return Err(AppError::Sqlx(e)),
        }

        Self::find(pool, space_id, grantee_type, grantee_id)
            .await?
            .ok_or_else(|| {
                AppError::Internal("Access grant was inserted but could not be read back".into())
            })
    }

    /// Revoke a specific access grant.
    pub async fn revoke(
        pool: &DbPool,
        space_id: &str,
        grantee_type: &str,
        grantee_id: &str,
    ) -> Result<(), AppError> {
        let result = sqlx::query(
            "DELETE FROM space_access
             WHERE space_id = ? AND grantee_type = ? AND grantee_id = ?",
        )
        .bind(space_id)
        .bind(grantee_type)
        .bind(grantee_id)
        .execute(pool)
        .await?;

        if result.rows_affected() == 0 {
            return Err(AppError::NotFound);
        }

        Ok(())
    }

    /// Look up a single access grant.
    pub async fn find(
        pool: &DbPool,
        space_id: &str,
        grantee_type: &str,
        grantee_id: &str,
    ) -> Result<Option<SpaceAccess>, AppError> {
        let access = sqlx::query_as::<_, SpaceAccess>(
            "SELECT space_id, grantee_type, grantee_id, permission, granted_at
             FROM space_access
             WHERE space_id = ? AND grantee_type = ? AND grantee_id = ?",
        )
        .bind(space_id)
        .bind(grantee_type)
        .bind(grantee_id)
        .fetch_optional(pool)
        .await?;

        Ok(access)
    }

    /// Update the permission level of an existing grant.
    pub async fn update_permission(
        pool: &DbPool,
        space_id: &str,
        grantee_type: &str,
        grantee_id: &str,
        permission: &str,
    ) -> Result<SpaceAccess, AppError> {
        let result = sqlx::query(
            "UPDATE space_access SET permission = ?
             WHERE space_id = ? AND grantee_type = ? AND grantee_id = ?",
        )
        .bind(permission)
        .bind(space_id)
        .bind(grantee_type)
        .bind(grantee_id)
        .execute(pool)
        .await?;

        if result.rows_affected() == 0 {
            return Err(AppError::NotFound);
        }

        Self::find(pool, space_id, grantee_type, grantee_id)
            .await?
            .ok_or(AppError::NotFound)
    }

    /// All access entries for a space, joined with grantee names.
    /// For user grantees → username from `users`.
    /// For group grantees → name from `groups`.
    /// Ordered: admin first, then write, then read; alphabetical within tiers.
    pub async fn list_with_details(
        pool: &DbPool,
        space_id: &str,
    ) -> Result<Vec<SpaceAccessDetail>, AppError> {
        let details = sqlx::query_as::<_, SpaceAccessDetail>(
            "SELECT sa.space_id, sa.grantee_type, sa.grantee_id,
                    sa.permission, sa.granted_at,
                    CASE sa.grantee_type
                        WHEN 'user'  THEN COALESCE(u.username, '[deleted user]')
                        WHEN 'group' THEN COALESCE(g.name, '[deleted group]')
                        ELSE '[unknown]'
                    END AS grantee_name
             FROM space_access sa
             LEFT JOIN users u  ON sa.grantee_type = 'user'  AND u.id = sa.grantee_id
             LEFT JOIN groups g ON sa.grantee_type = 'group' AND g.id = sa.grantee_id
             WHERE sa.space_id = ?
             ORDER BY CASE sa.permission
                          WHEN 'admin' THEN 0
                          WHEN 'write' THEN 1
                          WHEN 'read'  THEN 2
                          ELSE 3
                      END,
                      grantee_name ASC",
        )
        .bind(space_id)
        .fetch_all(pool)
        .await?;

        Ok(details)
    }

    /// Resolve a user's effective permission on a space. Checks ownership
    /// (user or group) and all access grants (direct user or group membership).
    /// Returns the highest permission found, or `None` if no access.
    pub async fn resolve_user_permission(
        pool: &DbPool,
        user_id: &str,
        space_id: &str,
    ) -> Result<Option<String>, AppError> {
        let row: Option<(String,)> = sqlx::query_as(
            "WITH user_groups AS (
                SELECT group_id FROM group_members WHERE user_id = ?1
            ),
            perms AS (
                -- Owner (user)
                SELECT 'admin' AS perm FROM spaces
                WHERE id = ?2 AND owner_type = 'user' AND owner_id = ?1
                UNION ALL
                -- Owner (group member)
                SELECT 'admin' AS perm FROM spaces
                WHERE id = ?2 AND owner_type = 'group'
                    AND owner_id IN (SELECT group_id FROM user_groups)
                UNION ALL
                -- Direct user grant
                SELECT permission AS perm FROM space_access
                WHERE space_id = ?2 AND grantee_type = 'user' AND grantee_id = ?1
                UNION ALL
                -- Group grant
                SELECT permission AS perm FROM space_access
                WHERE space_id = ?2 AND grantee_type = 'group'
                    AND grantee_id IN (SELECT group_id FROM user_groups)
            )
            SELECT CASE MAX(CASE perm
                       WHEN 'admin' THEN 3
                       WHEN 'write' THEN 2
                       WHEN 'read'  THEN 1
                       ELSE 0
                   END)
                       WHEN 3 THEN 'admin'
                       WHEN 2 THEN 'write'
                       WHEN 1 THEN 'read'
                       ELSE 'none'
                   END AS best
            FROM perms
            HAVING COUNT(*) > 0",
        )
        .bind(user_id)
        .bind(space_id)
        .fetch_optional(pool)
        .await?;

        Ok(row.map(|(p,)| p))
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
    use crate::models::user::{CreateUserParams, User};

    async fn test_pool() -> DbPool {
        let pool = db::init_pool("sqlite::memory:")
            .await
            .expect("Failed to create test pool");
        db::run_migrations(&pool)
            .await
            .expect("Failed to run migrations");
        pool
    }

    async fn create_test_user(pool: &DbPool, username: &str) -> User {
        User::create(
            pool,
            CreateUserParams {
                username: username.into(),
                email: format!("{username}@example.com"),
                password_hash: "$argon2id$fake_hash".into(),
                role: "user".into(),
                quota_bytes: 5_368_709_120,
            },
        )
        .await
        .unwrap()
    }

    fn dummy_key() -> Vec<u8> {
        vec![0u8; 64]
    }

    async fn create_user_space(pool: &DbPool, name: &str, owner_id: &str) -> Space {
        Space::create(
            pool,
            CreateSpaceParams {
                name: name.into(),
                owner_type: "user".into(),
                owner_id: owner_id.into(),
                encryption_mode: "server".into(),
                encrypted_data_key: dummy_key(),
            },
        )
        .await
        .unwrap()
    }

    // -----------------------------------------------------------------------
    // Space CRUD
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn create_and_find_space() {
        let pool = test_pool().await;
        let user = create_test_user(&pool, "alice").await;

        let space = create_user_space(&pool, "Project X", &user.id).await;

        assert_eq!(space.name, "Project X");
        assert_eq!(space.owner_type, "user");
        assert_eq!(space.owner_id, user.id);
        assert_eq!(space.encryption_mode, "server");

        let found = Space::find_by_id(&pool, &space.id).await.unwrap();
        assert!(found.is_some());
        assert_eq!(found.unwrap().id, space.id);
    }

    #[tokio::test]
    async fn update_space_name() {
        let pool = test_pool().await;
        let user = create_test_user(&pool, "alice").await;
        let space = create_user_space(&pool, "Old Name", &user.id).await;

        let updated = Space::update(
            &pool,
            &space.id,
            UpdateSpaceParams {
                name: "New Name".into(),
            },
        )
        .await
        .unwrap();

        assert_eq!(updated.name, "New Name");
    }

    #[tokio::test]
    async fn delete_space_cascades_access() {
        let pool = test_pool().await;
        let alice = create_test_user(&pool, "alice").await;
        let bob = create_test_user(&pool, "bob").await;

        let space = create_user_space(&pool, "Doomed", &alice.id).await;
        SpaceAccess::grant(&pool, &space.id, "user", &bob.id, "read")
            .await
            .unwrap();

        // Verify the grant exists
        let found = SpaceAccess::find(&pool, &space.id, "user", &bob.id)
            .await
            .unwrap();
        assert!(found.is_some());

        // Delete the space — cascade should remove access
        Space::delete_by_id(&pool, &space.id).await.unwrap();
        assert!(Space::find_by_id(&pool, &space.id).await.unwrap().is_none());

        let after = SpaceAccess::find(&pool, &space.id, "user", &bob.id)
            .await
            .unwrap();
        assert!(after.is_none());
    }

    #[tokio::test]
    async fn delete_nonexistent_space_returns_not_found() {
        let pool = test_pool().await;
        let err = Space::delete_by_id(&pool, "nonexistent").await.unwrap_err();
        assert!(matches!(err, AppError::NotFound));
    }

    #[tokio::test]
    async fn find_all_server_mode() {
        let pool = test_pool().await;
        let user = create_test_user(&pool, "alice").await;

        create_user_space(&pool, "Server Space", &user.id).await;

        let server_spaces = Space::find_all_server_mode(&pool).await.unwrap();
        assert_eq!(server_spaces.len(), 1);
        assert_eq!(server_spaces[0].name, "Server Space");
    }

    // -----------------------------------------------------------------------
    // Access grants
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn grant_and_revoke_access() {
        let pool = test_pool().await;
        let alice = create_test_user(&pool, "alice").await;
        let bob = create_test_user(&pool, "bob").await;

        let space = create_user_space(&pool, "Shared", &alice.id).await;

        let access = SpaceAccess::grant(&pool, &space.id, "user", &bob.id, "write")
            .await
            .unwrap();
        assert_eq!(access.permission, "write");
        assert_eq!(access.grantee_type, "user");

        SpaceAccess::revoke(&pool, &space.id, "user", &bob.id)
            .await
            .unwrap();

        let after = SpaceAccess::find(&pool, &space.id, "user", &bob.id)
            .await
            .unwrap();
        assert!(after.is_none());
    }

    #[tokio::test]
    async fn duplicate_grant_returns_conflict() {
        let pool = test_pool().await;
        let alice = create_test_user(&pool, "alice").await;
        let bob = create_test_user(&pool, "bob").await;

        let space = create_user_space(&pool, "S", &alice.id).await;

        SpaceAccess::grant(&pool, &space.id, "user", &bob.id, "read")
            .await
            .unwrap();

        let err = SpaceAccess::grant(&pool, &space.id, "user", &bob.id, "write")
            .await
            .unwrap_err();
        assert!(matches!(err, AppError::Conflict(_)));
    }

    #[tokio::test]
    async fn update_access_permission() {
        let pool = test_pool().await;
        let alice = create_test_user(&pool, "alice").await;
        let bob = create_test_user(&pool, "bob").await;

        let space = create_user_space(&pool, "S", &alice.id).await;
        SpaceAccess::grant(&pool, &space.id, "user", &bob.id, "read")
            .await
            .unwrap();

        let updated =
            SpaceAccess::update_permission(&pool, &space.id, "user", &bob.id, "admin")
                .await
                .unwrap();
        assert_eq!(updated.permission, "admin");
    }

    #[tokio::test]
    async fn list_access_with_details() {
        let pool = test_pool().await;
        let alice = create_test_user(&pool, "alice").await;
        let bob = create_test_user(&pool, "bob").await;

        let space = create_user_space(&pool, "S", &alice.id).await;
        SpaceAccess::grant(&pool, &space.id, "user", &alice.id, "admin")
            .await
            .unwrap();
        SpaceAccess::grant(&pool, &space.id, "user", &bob.id, "read")
            .await
            .unwrap();

        let details = SpaceAccess::list_with_details(&pool, &space.id)
            .await
            .unwrap();
        assert_eq!(details.len(), 2);

        // admin first, then read
        assert_eq!(details[0].grantee_name, "alice");
        assert_eq!(details[0].permission, "admin");
        assert_eq!(details[1].grantee_name, "bob");
        assert_eq!(details[1].permission, "read");
    }

    // -----------------------------------------------------------------------
    // Permission resolution
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn owner_has_implicit_admin() {
        let pool = test_pool().await;
        let alice = create_test_user(&pool, "alice").await;

        let space = create_user_space(&pool, "Mine", &alice.id).await;

        // No explicit grant — ownership alone gives admin
        let perm = SpaceAccess::resolve_user_permission(&pool, &alice.id, &space.id)
            .await
            .unwrap();
        assert_eq!(perm.as_deref(), Some("admin"));
    }

    #[tokio::test]
    async fn group_owner_members_have_admin() {
        let pool = test_pool().await;
        let alice = create_test_user(&pool, "alice").await;
        let bob = create_test_user(&pool, "bob").await;

        // Create a group with alice as owner and bob as member
        let group = Group::create(
            &pool,
            CreateGroupParams {
                name: "Team".into(),
                description: None,
                created_by: alice.id.clone(),
            },
        )
        .await
        .unwrap();
        GroupMember::add(&pool, &group.id, &alice.id, "owner").await.unwrap();
        GroupMember::add(&pool, &group.id, &bob.id, "member").await.unwrap();

        // Create a group-owned space
        let space = Space::create(
            &pool,
            CreateSpaceParams {
                name: "Team Space".into(),
                owner_type: "group".into(),
                owner_id: group.id.clone(),
                encryption_mode: "server".into(),
                encrypted_data_key: dummy_key(),
            },
        )
        .await
        .unwrap();

        // Both group members get admin through group ownership
        let alice_perm =
            SpaceAccess::resolve_user_permission(&pool, &alice.id, &space.id)
                .await
                .unwrap();
        assert_eq!(alice_perm.as_deref(), Some("admin"));

        let bob_perm =
            SpaceAccess::resolve_user_permission(&pool, &bob.id, &space.id)
                .await
                .unwrap();
        assert_eq!(bob_perm.as_deref(), Some("admin"));
    }

    #[tokio::test]
    async fn direct_grant_permission() {
        let pool = test_pool().await;
        let alice = create_test_user(&pool, "alice").await;
        let bob = create_test_user(&pool, "bob").await;

        let space = create_user_space(&pool, "S", &alice.id).await;

        // Bob has no access yet
        let none = SpaceAccess::resolve_user_permission(&pool, &bob.id, &space.id)
            .await
            .unwrap();
        assert!(none.is_none());

        // Grant bob read
        SpaceAccess::grant(&pool, &space.id, "user", &bob.id, "read")
            .await
            .unwrap();

        let perm = SpaceAccess::resolve_user_permission(&pool, &bob.id, &space.id)
            .await
            .unwrap();
        assert_eq!(perm.as_deref(), Some("read"));
    }

    #[tokio::test]
    async fn group_grant_permission() {
        let pool = test_pool().await;
        let alice = create_test_user(&pool, "alice").await;
        let bob = create_test_user(&pool, "bob").await;
        let charlie = create_test_user(&pool, "charlie").await;

        // Create a group with bob in it
        let group = Group::create(
            &pool,
            CreateGroupParams {
                name: "Reviewers".into(),
                description: None,
                created_by: alice.id.clone(),
            },
        )
        .await
        .unwrap();
        GroupMember::add(&pool, &group.id, &bob.id, "member").await.unwrap();

        let space = create_user_space(&pool, "S", &alice.id).await;

        // Grant the group write access
        SpaceAccess::grant(&pool, &space.id, "group", &group.id, "write")
            .await
            .unwrap();

        // Bob gets write through group membership
        let bob_perm =
            SpaceAccess::resolve_user_permission(&pool, &bob.id, &space.id)
                .await
                .unwrap();
        assert_eq!(bob_perm.as_deref(), Some("write"));

        // Charlie is not in the group — no access
        let charlie_perm =
            SpaceAccess::resolve_user_permission(&pool, &charlie.id, &space.id)
                .await
                .unwrap();
        assert!(charlie_perm.is_none());
    }

    #[tokio::test]
    async fn highest_permission_wins() {
        let pool = test_pool().await;
        let alice = create_test_user(&pool, "alice").await;
        let bob = create_test_user(&pool, "bob").await;

        // Bob is in a group
        let group = Group::create(
            &pool,
            CreateGroupParams {
                name: "Editors".into(),
                description: None,
                created_by: alice.id.clone(),
            },
        )
        .await
        .unwrap();
        GroupMember::add(&pool, &group.id, &bob.id, "member").await.unwrap();

        let space = create_user_space(&pool, "S", &alice.id).await;

        // Direct grant: read
        SpaceAccess::grant(&pool, &space.id, "user", &bob.id, "read")
            .await
            .unwrap();
        // Group grant: write
        SpaceAccess::grant(&pool, &space.id, "group", &group.id, "write")
            .await
            .unwrap();

        // Should resolve to write (highest)
        let perm = SpaceAccess::resolve_user_permission(&pool, &bob.id, &space.id)
            .await
            .unwrap();
        assert_eq!(perm.as_deref(), Some("write"));
    }

    #[tokio::test]
    async fn find_all_for_user_includes_all_access_paths() {
        let pool = test_pool().await;
        let alice = create_test_user(&pool, "alice").await;
        let bob = create_test_user(&pool, "bob").await;

        // Space 1: alice owns directly
        let _s1 = create_user_space(&pool, "Alice Owned", &alice.id).await;

        // Space 2: bob owns, alice has a direct grant
        let s2 = create_user_space(&pool, "Bob Owned", &bob.id).await;
        SpaceAccess::grant(&pool, &s2.id, "user", &alice.id, "read")
            .await
            .unwrap();

        // Space 3: bob owns, no access for alice
        let _s3 = create_user_space(&pool, "Private", &bob.id).await;

        let alice_spaces = Space::find_all_for_user(&pool, &alice.id).await.unwrap();
        assert_eq!(alice_spaces.len(), 2);

        // Sorted by name
        assert_eq!(alice_spaces[0].space.name, "Alice Owned");
        assert_eq!(alice_spaces[0].user_permission, "admin");
        assert_eq!(alice_spaces[1].space.name, "Bob Owned");
        assert_eq!(alice_spaces[1].user_permission, "read");
    }

    #[tokio::test]
    async fn find_for_user_returns_none_without_access() {
        let pool = test_pool().await;
        let alice = create_test_user(&pool, "alice").await;
        let bob = create_test_user(&pool, "bob").await;

        let space = create_user_space(&pool, "Private", &alice.id).await;

        let result = Space::find_for_user(&pool, &bob.id, &space.id)
            .await
            .unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn revoke_nonexistent_returns_not_found() {
        let pool = test_pool().await;
        let alice = create_test_user(&pool, "alice").await;
        let space = create_user_space(&pool, "S", &alice.id).await;

        let err = SpaceAccess::revoke(&pool, &space.id, "user", "nonexistent")
            .await
            .unwrap_err();
        assert!(matches!(err, AppError::NotFound));
    }
}
