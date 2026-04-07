use rocket::serde::json::Json;
use rocket::Route;
use rocket::State;
use serde::{Deserialize, Serialize};

use crate::db::DbPool;
use crate::errors::AppError;
use crate::guards::setup_guard::SetupComplete;
use crate::services::group_service;

// ---------------------------------------------------------------------------
// Request / Response DTOs
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct CreateGroupRequest {
    pub name: String,
    pub description: Option<String>,
}

#[derive(Deserialize)]
pub struct UpdateGroupRequest {
    pub name: String,
    pub description: Option<String>,
}

#[derive(Deserialize)]
pub struct AddMemberRequest {
    pub username: String,
    #[serde(default = "default_member_role")]
    pub role: String,
}

fn default_member_role() -> String {
    "member".into()
}

#[derive(Deserialize)]
pub struct UpdateRoleRequest {
    pub role: String,
}

#[derive(Serialize)]
pub struct GroupResponse {
    pub id: String,
    pub name: String,
    pub description: Option<String>,
    pub created_by: String,
    pub created_at: String,
    pub member_count: i64,
    pub user_role: String,
}

#[derive(Serialize)]
pub struct GroupListResponse {
    pub groups: Vec<GroupResponse>,
}

#[derive(Serialize)]
pub struct MemberResponse {
    pub user_id: String,
    pub username: String,
    pub email: String,
    pub role: String,
    pub joined_at: String,
}

#[derive(Serialize)]
pub struct MemberListResponse {
    pub members: Vec<MemberResponse>,
}

#[derive(Serialize)]
pub struct MessageResponse {
    pub message: String,
}

// ---------------------------------------------------------------------------
// Routes
// ---------------------------------------------------------------------------

/// POST /api/v1/groups — Create a new group.
#[post("/api/v1/groups", format = "json", data = "<body>")]
pub async fn create_group(
    pool: &State<DbPool>,
    user: SetupComplete,
    body: Json<CreateGroupRequest>,
) -> Result<Json<GroupResponse>, AppError> {
    let result = group_service::create_group(
        pool.inner(),
        &user.0.id,
        &body.name,
        body.description.as_deref(),
    )
    .await?;

    Ok(Json(GroupResponse {
        id: result.group.id,
        name: result.group.name,
        description: result.group.description,
        created_by: result.group.created_by,
        created_at: result.group.created_at,
        member_count: result.member_count,
        user_role: result.user_role,
    }))
}

/// GET /api/v1/groups — List groups the user belongs to.
#[get("/api/v1/groups")]
pub async fn list_groups(
    pool: &State<DbPool>,
    user: SetupComplete,
) -> Result<Json<GroupListResponse>, AppError> {
    let groups = group_service::list_user_groups(pool.inner(), &user.0.id).await?;

    let groups = groups
        .into_iter()
        .map(|g| GroupResponse {
            id: g.group.id,
            name: g.group.name,
            description: g.group.description,
            created_by: g.group.created_by,
            created_at: g.group.created_at,
            member_count: g.member_count,
            user_role: g.user_role,
        })
        .collect();

    Ok(Json(GroupListResponse { groups }))
}

/// GET /api/v1/groups/<id> — Get a single group.
#[get("/api/v1/groups/<id>")]
pub async fn get_group(
    pool: &State<DbPool>,
    user: SetupComplete,
    id: &str,
) -> Result<Json<GroupResponse>, AppError> {
    let g = group_service::get_group(pool.inner(), &user.0.id, id).await?;

    Ok(Json(GroupResponse {
        id: g.group.id,
        name: g.group.name,
        description: g.group.description,
        created_by: g.group.created_by,
        created_at: g.group.created_at,
        member_count: g.member_count,
        user_role: g.user_role,
    }))
}

/// PUT /api/v1/groups/<id> — Update group name / description.
#[put("/api/v1/groups/<id>", format = "json", data = "<body>")]
pub async fn update_group(
    pool: &State<DbPool>,
    user: SetupComplete,
    id: &str,
    body: Json<UpdateGroupRequest>,
) -> Result<Json<GroupResponse>, AppError> {
    let group = group_service::update_group(
        pool.inner(),
        &user.0.id,
        id,
        &body.name,
        body.description.as_deref(),
    )
    .await?;

    // Re-fetch with meta for response.
    let g = group_service::get_group(pool.inner(), &user.0.id, &group.id).await?;

    Ok(Json(GroupResponse {
        id: g.group.id,
        name: g.group.name,
        description: g.group.description,
        created_by: g.group.created_by,
        created_at: g.group.created_at,
        member_count: g.member_count,
        user_role: g.user_role,
    }))
}

/// DELETE /api/v1/groups/<id> — Delete a group. Owner only.
#[delete("/api/v1/groups/<id>")]
pub async fn delete_group(
    pool: &State<DbPool>,
    user: SetupComplete,
    id: &str,
) -> Result<Json<MessageResponse>, AppError> {
    group_service::delete_group(pool.inner(), &user.0.id, id).await?;

    Ok(Json(MessageResponse {
        message: "Group deleted successfully.".into(),
    }))
}

/// GET /api/v1/groups/<id>/members — List group members.
#[get("/api/v1/groups/<id>/members")]
pub async fn list_members(
    pool: &State<DbPool>,
    user: SetupComplete,
    id: &str,
) -> Result<Json<MemberListResponse>, AppError> {
    let members = group_service::list_members(pool.inner(), &user.0.id, id).await?;

    let members = members
        .into_iter()
        .map(|m| MemberResponse {
            user_id: m.user_id,
            username: m.username,
            email: m.email,
            role: m.role,
            joined_at: m.joined_at,
        })
        .collect();

    Ok(Json(MemberListResponse { members }))
}

/// POST /api/v1/groups/<id>/members — Add a member by username.
#[post("/api/v1/groups/<id>/members", format = "json", data = "<body>")]
pub async fn add_member(
    pool: &State<DbPool>,
    user: SetupComplete,
    id: &str,
    body: Json<AddMemberRequest>,
) -> Result<Json<MemberResponse>, AppError> {
    let member =
        group_service::add_member(pool.inner(), &user.0.id, id, &body.username, &body.role)
            .await?;

    // Fetch full details for response (the service returns GroupMember without user info).
    let members = group_service::list_members(pool.inner(), &user.0.id, id).await?;
    let detail = members
        .into_iter()
        .find(|m| m.user_id == member.user_id)
        .ok_or_else(|| AppError::Internal("Added member not found in list".into()))?;

    Ok(Json(MemberResponse {
        user_id: detail.user_id,
        username: detail.username,
        email: detail.email,
        role: detail.role,
        joined_at: detail.joined_at,
    }))
}

/// DELETE /api/v1/groups/<id>/members/<user_id> — Remove a member.
#[delete("/api/v1/groups/<id>/members/<user_id>")]
pub async fn remove_member(
    pool: &State<DbPool>,
    user: SetupComplete,
    id: &str,
    user_id: &str,
) -> Result<Json<MessageResponse>, AppError> {
    group_service::remove_member(pool.inner(), &user.0.id, id, user_id).await?;

    Ok(Json(MessageResponse {
        message: "Member removed successfully.".into(),
    }))
}

/// PUT /api/v1/groups/<id>/members/<user_id> — Update a member's role.
#[put("/api/v1/groups/<id>/members/<user_id>", format = "json", data = "<body>")]
pub async fn update_member_role(
    pool: &State<DbPool>,
    user: SetupComplete,
    id: &str,
    user_id: &str,
    body: Json<UpdateRoleRequest>,
) -> Result<Json<MemberResponse>, AppError> {
    group_service::update_member_role(pool.inner(), &user.0.id, id, user_id, &body.role).await?;

    // Fetch full details for response.
    let members = group_service::list_members(pool.inner(), &user.0.id, id).await?;
    let detail = members
        .into_iter()
        .find(|m| m.user_id == user_id)
        .ok_or_else(|| AppError::Internal("Updated member not found in list".into()))?;

    Ok(Json(MemberResponse {
        user_id: detail.user_id,
        username: detail.username,
        email: detail.email,
        role: detail.role,
        joined_at: detail.joined_at,
    }))
}

// ---------------------------------------------------------------------------
// Mount
// ---------------------------------------------------------------------------

pub fn routes() -> Vec<Route> {
    routes![
        create_group,
        list_groups,
        get_group,
        update_group,
        delete_group,
        list_members,
        add_member,
        remove_member,
        update_member_role,
    ]
}
