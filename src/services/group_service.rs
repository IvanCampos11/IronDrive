use crate::db::DbPool;
use crate::errors::AppError;
use crate::models::group::{
    CreateGroupParams, Group, GroupMember, GroupMemberDetail, GroupWithMeta, UpdateGroupParams,
};
use crate::models::user::User;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const NAME_MIN_LEN: usize = 1;
const NAME_MAX_LEN: usize = 100;
const DESCRIPTION_MAX_LEN: usize = 500;

const ROLE_OWNER: &str = "owner";
const ROLE_MANAGER: &str = "manager";
const ROLE_MEMBER: &str = "member";

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Create a group and add the creator as its owner.
pub async fn create_group(
    pool: &DbPool,
    user_id: &str,
    name: &str,
    description: Option<&str>,
) -> Result<GroupWithMeta, AppError> {
    let name = validate_name(name)?;
    let description = validate_description(description)?;

    let group = Group::create(
        pool,
        CreateGroupParams {
            name,
            description: description.clone(),
            created_by: user_id.to_string(),
        },
    )
    .await?;

    // Creator is automatically the owner.
    GroupMember::add(pool, &group.id, user_id, ROLE_OWNER).await?;

    tracing::info!(
        group_id = %group.id,
        user_id = %user_id,
        group_name = %group.name,
        "Group created"
    );

    Ok(GroupWithMeta {
        group,
        member_count: 1,
        user_role: ROLE_OWNER.to_string(),
    })
}

/// Get a single group. The caller must be a member.
pub async fn get_group(
    pool: &DbPool,
    user_id: &str,
    group_id: &str,
) -> Result<GroupWithMeta, AppError> {
    let groups = Group::find_all_for_user(pool, user_id).await?;

    groups
        .into_iter()
        .find(|g| g.group.id == group_id)
        .ok_or(AppError::NotFound)
}

/// List all groups the user belongs to.
pub async fn list_user_groups(
    pool: &DbPool,
    user_id: &str,
) -> Result<Vec<GroupWithMeta>, AppError> {
    Group::find_all_for_user(pool, user_id).await
}

/// Update a group's name and/or description. Requires owner or manager role.
pub async fn update_group(
    pool: &DbPool,
    user_id: &str,
    group_id: &str,
    name: &str,
    description: Option<&str>,
) -> Result<Group, AppError> {
    require_manager_or_owner(pool, group_id, user_id).await?;

    let name = validate_name(name)?;
    let description = validate_description(description)?;

    let group = Group::update(pool, group_id, UpdateGroupParams { name, description }).await?;

    tracing::info!(
        group_id = %group_id,
        user_id = %user_id,
        "Group updated"
    );

    Ok(group)
}

/// Delete a group. Only the creator (owner) can delete.
pub async fn delete_group(
    pool: &DbPool,
    user_id: &str,
    group_id: &str,
) -> Result<(), AppError> {
    let group = Group::find_by_id(pool, group_id)
        .await?
        .ok_or(AppError::NotFound)?;

    if group.created_by != user_id {
        tracing::warn!(
            group_id = %group_id,
            user_id = %user_id,
            "Non-creator attempted to delete group"
        );
        return Err(AppError::Forbidden);
    }

    Group::delete_by_id(pool, group_id).await?;

    tracing::info!(
        group_id = %group_id,
        user_id = %user_id,
        "Group deleted"
    );

    Ok(())
}

/// List members of a group (with user details). Caller must be a member.
pub async fn list_members(
    pool: &DbPool,
    user_id: &str,
    group_id: &str,
) -> Result<Vec<GroupMemberDetail>, AppError> {
    require_member(pool, group_id, user_id).await?;
    GroupMember::list_with_details(pool, group_id).await
}

/// Add a member to a group by username. Requires owner or manager role.
pub async fn add_member(
    pool: &DbPool,
    actor_id: &str,
    group_id: &str,
    username: &str,
    role: &str,
) -> Result<GroupMember, AppError> {
    require_manager_or_owner(pool, group_id, actor_id).await?;
    validate_role(role)?;

    // Cannot add someone as owner — there's only one owner (the creator).
    if role == ROLE_OWNER {
        return Err(AppError::Validation(
            "Cannot assign the owner role. There can only be one owner.".into(),
        ));
    }

    let target_user = User::find_by_username(pool, username)
        .await?
        .ok_or_else(|| AppError::NotFound)?;

    let member = GroupMember::add(pool, group_id, &target_user.id, role).await?;

    tracing::info!(
        group_id = %group_id,
        actor_id = %actor_id,
        target_user_id = %target_user.id,
        role = %role,
        "Member added to group"
    );

    Ok(member)
}

/// Remove a member from a group. Owner/manager can remove others; any member
/// can remove themselves (leave). The group owner cannot be removed.
pub async fn remove_member(
    pool: &DbPool,
    actor_id: &str,
    group_id: &str,
    target_user_id: &str,
) -> Result<(), AppError> {
    let group = Group::find_by_id(pool, group_id)
        .await?
        .ok_or(AppError::NotFound)?;

    // Owner cannot be removed.
    if target_user_id == group.created_by {
        return Err(AppError::Validation(
            "The group owner cannot be removed.".into(),
        ));
    }

    let is_self = actor_id == target_user_id;

    if !is_self {
        // Must be owner or manager to remove others.
        require_manager_or_owner(pool, group_id, actor_id).await?;
    } else {
        // Must at least be a member to leave.
        require_member(pool, group_id, actor_id).await?;
    }

    GroupMember::remove(pool, group_id, target_user_id).await?;

    tracing::info!(
        group_id = %group_id,
        actor_id = %actor_id,
        target_user_id = %target_user_id,
        self_remove = %is_self,
        "Member removed from group"
    );

    Ok(())
}

/// Update a member's role. Only the owner can change roles.
/// Cannot change the owner's own role.
pub async fn update_member_role(
    pool: &DbPool,
    actor_id: &str,
    group_id: &str,
    target_user_id: &str,
    new_role: &str,
) -> Result<GroupMember, AppError> {
    let group = Group::find_by_id(pool, group_id)
        .await?
        .ok_or(AppError::NotFound)?;

    // Only the owner can change roles.
    if group.created_by != actor_id {
        return Err(AppError::Forbidden);
    }

    // Cannot change the owner's role.
    if target_user_id == group.created_by {
        return Err(AppError::Validation(
            "Cannot change the owner's role.".into(),
        ));
    }

    validate_role(new_role)?;
    if new_role == ROLE_OWNER {
        return Err(AppError::Validation(
            "Cannot assign the owner role.".into(),
        ));
    }

    // Target must be a current member.
    require_member(pool, group_id, target_user_id).await?;

    let updated = GroupMember::update_role(pool, group_id, target_user_id, new_role).await?;

    tracing::info!(
        group_id = %group_id,
        actor_id = %actor_id,
        target_user_id = %target_user_id,
        new_role = %new_role,
        "Member role updated"
    );

    Ok(updated)
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Verify the user is a member of the group; return `NotFound` otherwise.
async fn require_member(pool: &DbPool, group_id: &str, user_id: &str) -> Result<(), AppError> {
    if !GroupMember::is_member(pool, group_id, user_id).await? {
        return Err(AppError::NotFound);
    }
    Ok(())
}

/// Verify the user is an owner or manager; return `Forbidden` otherwise.
async fn require_manager_or_owner(
    pool: &DbPool,
    group_id: &str,
    user_id: &str,
) -> Result<(), AppError> {
    let member = GroupMember::find(pool, group_id, user_id)
        .await?
        .ok_or(AppError::NotFound)?;

    if member.role != ROLE_OWNER && member.role != ROLE_MANAGER {
        return Err(AppError::Forbidden);
    }
    Ok(())
}

fn validate_name(name: &str) -> Result<String, AppError> {
    let name = name.trim().to_string();
    if name.len() < NAME_MIN_LEN || name.len() > NAME_MAX_LEN {
        return Err(AppError::Validation(format!(
            "Group name must be between {NAME_MIN_LEN} and {NAME_MAX_LEN} characters."
        )));
    }
    Ok(name)
}

fn validate_description(description: Option<&str>) -> Result<Option<String>, AppError> {
    match description {
        Some(d) => {
            let d = d.trim().to_string();
            if d.is_empty() {
                return Ok(None);
            }
            if d.len() > DESCRIPTION_MAX_LEN {
                return Err(AppError::Validation(format!(
                    "Description must be at most {DESCRIPTION_MAX_LEN} characters."
                )));
            }
            Ok(Some(d))
        }
        None => Ok(None),
    }
}

fn validate_role(role: &str) -> Result<(), AppError> {
    match role {
        ROLE_OWNER | ROLE_MANAGER | ROLE_MEMBER => Ok(()),
        _ => Err(AppError::Validation(format!(
            "Invalid role '{role}'. Must be one of: {ROLE_MEMBER}, {ROLE_MANAGER}."
        ))),
    }
}
