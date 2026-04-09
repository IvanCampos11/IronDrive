use serde::Serialize;
use sqlx::FromRow;
use uuid::Uuid;

use crate::db::{is_unique_violation, DbPool};
use crate::errors::AppError;

// ---------------------------------------------------------------------------
// Structs
// ---------------------------------------------------------------------------

/// A row from the `groups` table.
#[derive(Debug, Clone, FromRow, Serialize)]
pub struct Group {
    pub id: String,
    pub name: String,
    pub description: Option<String>,
    pub created_by: String,
    pub created_at: String,
}

pub struct CreateGroupParams {
    pub name: String,
    pub description: Option<String>,
    pub created_by: String,
}

pub struct UpdateGroupParams {
    pub name: String,
    pub description: Option<String>,
}

/// A row from the `group_members` table.
#[derive(Debug, Clone, FromRow, Serialize)]
pub struct GroupMember {
    pub group_id: String,
    pub user_id: String,
    pub role: String,
    pub joined_at: String,
}

/// A group member joined with user info for display.
#[derive(Debug, Clone, FromRow, Serialize)]
pub struct GroupMemberDetail {
    pub group_id: String,
    pub user_id: String,
    pub role: String,
    pub joined_at: String,
    pub username: String,
    pub email: String,
}

/// A group with the requesting user's role and the member count.
#[derive(Debug, Clone, Serialize)]
pub struct GroupWithMeta {
    #[serde(flatten)]
    pub group: Group,
    pub member_count: i64,
    pub user_role: String,
}

// ---------------------------------------------------------------------------
// Group queries
// ---------------------------------------------------------------------------

impl Group {
    /// Insert a new group. Returns `Conflict` if the name is taken.
    pub async fn create(pool: &DbPool, params: CreateGroupParams) -> Result<Group, AppError> {
        let id = Uuid::new_v4().to_string();

        if Self::find_by_name(pool, &params.name).await?.is_some() {
            return Err(AppError::Conflict(
                "A group with that name already exists.".into(),
            ));
        }

        let insert_result = sqlx::query(
            "INSERT INTO groups (id, name, description, created_by) VALUES (?, ?, ?, ?)",
        )
        .bind(&id)
        .bind(&params.name)
        .bind(&params.description)
        .bind(&params.created_by)
        .execute(pool)
        .await;

        match insert_result {
            Ok(_) => {}
            Err(e) if is_unique_violation(&e) => {
                tracing::warn!(
                    name = %params.name,
                    "UNIQUE constraint race during group creation"
                );
                return Err(AppError::Conflict(
                    "A group with that name already exists.".into(),
                ));
            }
            Err(e) => return Err(AppError::Sqlx(e)),
        }

        Self::find_by_id(pool, &id).await?.ok_or_else(|| {
            AppError::Internal("Group was inserted but could not be read back".into())
        })
    }

    pub async fn find_by_id(pool: &DbPool, id: &str) -> Result<Option<Group>, AppError> {
        let group = sqlx::query_as::<_, Group>(
            "SELECT id, name, description, created_by, created_at FROM groups WHERE id = ?",
        )
        .bind(id)
        .fetch_optional(pool)
        .await?;

        Ok(group)
    }

    pub async fn find_by_name(pool: &DbPool, name: &str) -> Result<Option<Group>, AppError> {
        let group = sqlx::query_as::<_, Group>(
            "SELECT id, name, description, created_by, created_at FROM groups WHERE name = ?",
        )
        .bind(name)
        .fetch_optional(pool)
        .await?;

        Ok(group)
    }

    /// Search groups whose name starts with `prefix`. Returns at most `limit` results.
    pub async fn search_by_name_prefix(pool: &DbPool, prefix: &str, limit: i64) -> Result<Vec<Group>, AppError> {
        let pattern = format!("{}%", prefix);
        let groups = sqlx::query_as::<_, Group>(
            "SELECT id, name, description, created_by, created_at FROM groups WHERE name LIKE ? ORDER BY name ASC LIMIT ?",
        )
        .bind(&pattern)
        .bind(limit)
        .fetch_all(pool)
        .await?;

        Ok(groups)
    }

    /// Single group with meta for a specific user. Returns `None` if the user
    /// is not a member. Preferred over `find_all_for_user` + filter when you
    /// only need one group.
    pub async fn find_for_user(
        pool: &DbPool,
        user_id: &str,
        group_id: &str,
    ) -> Result<Option<GroupWithMeta>, AppError> {
        let row = sqlx::query_as::<_, (String, String, Option<String>, String, String, i64, String)>(
            "SELECT g.id, g.name, g.description, g.created_by, g.created_at,
                    (SELECT COUNT(*) FROM group_members WHERE group_id = g.id) AS member_count,
                    gm.role
             FROM groups g
             INNER JOIN group_members gm ON gm.group_id = g.id AND gm.user_id = ?
             WHERE g.id = ?",
        )
        .bind(user_id)
        .bind(group_id)
        .fetch_optional(pool)
        .await?;

        Ok(row.map(|(id, name, description, created_by, created_at, member_count, user_role)| {
            GroupWithMeta {
                group: Group { id, name, description, created_by, created_at },
                member_count,
                user_role,
            }
        }))
    }

    /// All groups that a user belongs to (via `group_members`), with member count and user role.
    pub async fn find_all_for_user(
        pool: &DbPool,
        user_id: &str,
    ) -> Result<Vec<GroupWithMeta>, AppError> {
        let rows = sqlx::query_as::<_, (String, String, Option<String>, String, String, i64, String)>(
            "SELECT g.id, g.name, g.description, g.created_by, g.created_at,
                    (SELECT COUNT(*) FROM group_members WHERE group_id = g.id) AS member_count,
                    gm.role
             FROM groups g
             INNER JOIN group_members gm ON gm.group_id = g.id AND gm.user_id = ?
             ORDER BY g.name ASC",
        )
        .bind(user_id)
        .fetch_all(pool)
        .await?;

        let groups = rows
            .into_iter()
            .map(|(id, name, description, created_by, created_at, member_count, user_role)| {
                GroupWithMeta {
                    group: Group {
                        id,
                        name,
                        description,
                        created_by,
                        created_at,
                    },
                    member_count,
                    user_role,
                }
            })
            .collect();

        Ok(groups)
    }

    /// Update group name and description. Returns `NotFound` if group doesn't exist,
    /// `Conflict` if the new name is already taken by another group.
    pub async fn update(
        pool: &DbPool,
        id: &str,
        params: UpdateGroupParams,
    ) -> Result<Group, AppError> {
        // Check name uniqueness against other groups
        if let Some(existing) = Self::find_by_name(pool, &params.name).await? {
            if existing.id != id {
                return Err(AppError::Conflict(
                    "A group with that name already exists.".into(),
                ));
            }
        }

        let result = sqlx::query(
            "UPDATE groups SET name = ?, description = ? WHERE id = ?",
        )
        .bind(&params.name)
        .bind(&params.description)
        .bind(id)
        .execute(pool)
        .await;

        match result {
            Ok(r) if r.rows_affected() == 0 => Err(AppError::NotFound),
            Ok(_) => Self::find_by_id(pool, id).await?.ok_or(AppError::NotFound),
            Err(e) if is_unique_violation(&e) => Err(AppError::Conflict(
                "A group with that name already exists.".into(),
            )),
            Err(e) => Err(AppError::Sqlx(e)),
        }
    }

    /// Delete a group. Members are cascade-deleted by the DB.
    pub async fn delete_by_id(pool: &DbPool, id: &str) -> Result<(), AppError> {
        let result = sqlx::query("DELETE FROM groups WHERE id = ?")
            .bind(id)
            .execute(pool)
            .await?;

        if result.rows_affected() == 0 {
            return Err(AppError::NotFound);
        }

        Ok(())
    }
}

// ---------------------------------------------------------------------------
// GroupMember queries
// ---------------------------------------------------------------------------

impl GroupMember {
    /// Add a member to a group.
    pub async fn add(
        pool: &DbPool,
        group_id: &str,
        user_id: &str,
        role: &str,
    ) -> Result<GroupMember, AppError> {
        let insert_result = sqlx::query(
            "INSERT INTO group_members (group_id, user_id, role) VALUES (?, ?, ?)",
        )
        .bind(group_id)
        .bind(user_id)
        .bind(role)
        .execute(pool)
        .await;

        match insert_result {
            Ok(_) => {}
            Err(e) if is_unique_violation(&e) => {
                return Err(AppError::Conflict(
                    "This user is already a member of the group.".into(),
                ));
            }
            Err(e) => return Err(AppError::Sqlx(e)),
        }

        Self::find(pool, group_id, user_id)
            .await?
            .ok_or_else(|| {
                AppError::Internal("Member was inserted but could not be read back".into())
            })
    }

    /// Remove a member from a group.
    pub async fn remove(
        pool: &DbPool,
        group_id: &str,
        user_id: &str,
    ) -> Result<(), AppError> {
        let result =
            sqlx::query("DELETE FROM group_members WHERE group_id = ? AND user_id = ?")
                .bind(group_id)
                .bind(user_id)
                .execute(pool)
                .await?;

        if result.rows_affected() == 0 {
            return Err(AppError::NotFound);
        }

        Ok(())
    }

    /// Look up a single membership.
    pub async fn find(
        pool: &DbPool,
        group_id: &str,
        user_id: &str,
    ) -> Result<Option<GroupMember>, AppError> {
        let member = sqlx::query_as::<_, GroupMember>(
            "SELECT group_id, user_id, role, joined_at
             FROM group_members WHERE group_id = ? AND user_id = ?",
        )
        .bind(group_id)
        .bind(user_id)
        .fetch_optional(pool)
        .await?;

        Ok(member)
    }

    /// Check whether a user is a member of a group.
    pub async fn is_member(
        pool: &DbPool,
        group_id: &str,
        user_id: &str,
    ) -> Result<bool, AppError> {
        let count: (i32,) = sqlx::query_as(
            "SELECT COUNT(1) FROM group_members WHERE group_id = ? AND user_id = ?",
        )
        .bind(group_id)
        .bind(user_id)
        .fetch_one(pool)
        .await?;

        Ok(count.0 > 0)
    }

    /// All members of a group, joined with user info.
    pub async fn list_with_details(
        pool: &DbPool,
        group_id: &str,
    ) -> Result<Vec<GroupMemberDetail>, AppError> {
        let members = sqlx::query_as::<_, GroupMemberDetail>(
            "SELECT gm.group_id, gm.user_id, gm.role, gm.joined_at,
                    u.username, u.email
             FROM group_members gm
             INNER JOIN users u ON u.id = gm.user_id
             WHERE gm.group_id = ?
             ORDER BY CASE gm.role WHEN 'owner' THEN 0 WHEN 'manager' THEN 1 ELSE 2 END,
                      u.username ASC",
        )
        .bind(group_id)
        .fetch_all(pool)
        .await?;

        Ok(members)
    }

    /// Update a member's role.
    pub async fn update_role(
        pool: &DbPool,
        group_id: &str,
        user_id: &str,
        new_role: &str,
    ) -> Result<GroupMember, AppError> {
        let result = sqlx::query(
            "UPDATE group_members SET role = ? WHERE group_id = ? AND user_id = ?",
        )
        .bind(new_role)
        .bind(group_id)
        .bind(user_id)
        .execute(pool)
        .await?;

        if result.rows_affected() == 0 {
            return Err(AppError::NotFound);
        }

        Self::find(pool, group_id, user_id)
            .await?
            .ok_or(AppError::NotFound)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db;
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

    #[tokio::test]
    async fn create_and_find_group() {
        let pool = test_pool().await;
        let user = create_test_user(&pool, "alice").await;

        let group = Group::create(
            &pool,
            CreateGroupParams {
                name: "Team Alpha".into(),
                description: Some("First team".into()),
                created_by: user.id.clone(),
            },
        )
        .await
        .unwrap();

        assert_eq!(group.name, "Team Alpha");
        assert_eq!(group.description.as_deref(), Some("First team"));
        assert_eq!(group.created_by, user.id);

        let found = Group::find_by_id(&pool, &group.id).await.unwrap();
        assert!(found.is_some());
        assert_eq!(found.unwrap().id, group.id);
    }

    #[tokio::test]
    async fn duplicate_group_name_returns_conflict() {
        let pool = test_pool().await;
        let user = create_test_user(&pool, "alice").await;

        Group::create(
            &pool,
            CreateGroupParams {
                name: "Unique Name".into(),
                description: None,
                created_by: user.id.clone(),
            },
        )
        .await
        .unwrap();

        let err = Group::create(
            &pool,
            CreateGroupParams {
                name: "Unique Name".into(),
                description: None,
                created_by: user.id.clone(),
            },
        )
        .await
        .unwrap_err();

        assert!(matches!(err, AppError::Conflict(_)));
    }

    #[tokio::test]
    async fn update_group() {
        let pool = test_pool().await;
        let user = create_test_user(&pool, "alice").await;

        let group = Group::create(
            &pool,
            CreateGroupParams {
                name: "Old Name".into(),
                description: None,
                created_by: user.id.clone(),
            },
        )
        .await
        .unwrap();

        let updated = Group::update(
            &pool,
            &group.id,
            UpdateGroupParams {
                name: "New Name".into(),
                description: Some("Now with a description".into()),
            },
        )
        .await
        .unwrap();

        assert_eq!(updated.name, "New Name");
        assert_eq!(updated.description.as_deref(), Some("Now with a description"));
    }

    #[tokio::test]
    async fn delete_group_cascades_members() {
        let pool = test_pool().await;
        let user = create_test_user(&pool, "alice").await;

        let group = Group::create(
            &pool,
            CreateGroupParams {
                name: "Doomed".into(),
                description: None,
                created_by: user.id.clone(),
            },
        )
        .await
        .unwrap();

        GroupMember::add(&pool, &group.id, &user.id, "owner").await.unwrap();
        assert!(GroupMember::is_member(&pool, &group.id, &user.id).await.unwrap());

        Group::delete_by_id(&pool, &group.id).await.unwrap();

        assert!(Group::find_by_id(&pool, &group.id).await.unwrap().is_none());
        assert!(!GroupMember::is_member(&pool, &group.id, &user.id).await.unwrap());
    }

    #[tokio::test]
    async fn find_all_for_user() {
        let pool = test_pool().await;
        let alice = create_test_user(&pool, "alice").await;
        let bob = create_test_user(&pool, "bob").await;

        let g1 = Group::create(
            &pool,
            CreateGroupParams {
                name: "Alpha".into(),
                description: None,
                created_by: alice.id.clone(),
            },
        )
        .await
        .unwrap();
        let g2 = Group::create(
            &pool,
            CreateGroupParams {
                name: "Beta".into(),
                description: None,
                created_by: bob.id.clone(),
            },
        )
        .await
        .unwrap();

        GroupMember::add(&pool, &g1.id, &alice.id, "owner").await.unwrap();
        GroupMember::add(&pool, &g2.id, &bob.id, "owner").await.unwrap();
        GroupMember::add(&pool, &g2.id, &alice.id, "member").await.unwrap();

        let alice_groups = Group::find_all_for_user(&pool, &alice.id).await.unwrap();
        assert_eq!(alice_groups.len(), 2);
        assert_eq!(alice_groups[0].group.name, "Alpha");
        assert_eq!(alice_groups[0].user_role, "owner");
        assert_eq!(alice_groups[1].group.name, "Beta");
        assert_eq!(alice_groups[1].user_role, "member");
        assert_eq!(alice_groups[1].member_count, 2);

        let bob_groups = Group::find_all_for_user(&pool, &bob.id).await.unwrap();
        assert_eq!(bob_groups.len(), 1);
    }

    #[tokio::test]
    async fn add_and_remove_member() {
        let pool = test_pool().await;
        let alice = create_test_user(&pool, "alice").await;
        let bob = create_test_user(&pool, "bob").await;

        let group = Group::create(
            &pool,
            CreateGroupParams {
                name: "Test Group".into(),
                description: None,
                created_by: alice.id.clone(),
            },
        )
        .await
        .unwrap();

        let member = GroupMember::add(&pool, &group.id, &bob.id, "member").await.unwrap();
        assert_eq!(member.role, "member");
        assert!(GroupMember::is_member(&pool, &group.id, &bob.id).await.unwrap());

        GroupMember::remove(&pool, &group.id, &bob.id).await.unwrap();
        assert!(!GroupMember::is_member(&pool, &group.id, &bob.id).await.unwrap());
    }

    #[tokio::test]
    async fn duplicate_member_returns_conflict() {
        let pool = test_pool().await;
        let alice = create_test_user(&pool, "alice").await;

        let group = Group::create(
            &pool,
            CreateGroupParams {
                name: "G".into(),
                description: None,
                created_by: alice.id.clone(),
            },
        )
        .await
        .unwrap();

        GroupMember::add(&pool, &group.id, &alice.id, "owner").await.unwrap();

        let err = GroupMember::add(&pool, &group.id, &alice.id, "member")
            .await
            .unwrap_err();
        assert!(matches!(err, AppError::Conflict(_)));
    }

    #[tokio::test]
    async fn list_members_with_details() {
        let pool = test_pool().await;
        let alice = create_test_user(&pool, "alice").await;
        let bob = create_test_user(&pool, "bob").await;

        let group = Group::create(
            &pool,
            CreateGroupParams {
                name: "Detail Group".into(),
                description: None,
                created_by: alice.id.clone(),
            },
        )
        .await
        .unwrap();

        GroupMember::add(&pool, &group.id, &alice.id, "owner").await.unwrap();
        GroupMember::add(&pool, &group.id, &bob.id, "member").await.unwrap();

        let members = GroupMember::list_with_details(&pool, &group.id).await.unwrap();
        assert_eq!(members.len(), 2);

        // Sorted: owner first, then by username ASC
        assert_eq!(members[0].username, "alice");
        assert_eq!(members[0].role, "owner");
        assert_eq!(members[1].username, "bob");
        assert_eq!(members[1].role, "member");
    }

    #[tokio::test]
    async fn update_member_role() {
        let pool = test_pool().await;
        let alice = create_test_user(&pool, "alice").await;

        let group = Group::create(
            &pool,
            CreateGroupParams {
                name: "Role Group".into(),
                description: None,
                created_by: alice.id.clone(),
            },
        )
        .await
        .unwrap();

        GroupMember::add(&pool, &group.id, &alice.id, "member").await.unwrap();

        let updated = GroupMember::update_role(&pool, &group.id, &alice.id, "manager")
            .await
            .unwrap();
        assert_eq!(updated.role, "manager");
    }

    #[tokio::test]
    async fn remove_nonexistent_member_returns_not_found() {
        let pool = test_pool().await;
        let alice = create_test_user(&pool, "alice").await;

        let group = Group::create(
            &pool,
            CreateGroupParams {
                name: "Empty Group".into(),
                description: None,
                created_by: alice.id.clone(),
            },
        )
        .await
        .unwrap();

        let err = GroupMember::remove(&pool, &group.id, "nonexistent-id")
            .await
            .unwrap_err();
        assert!(matches!(err, AppError::NotFound));
    }
}
