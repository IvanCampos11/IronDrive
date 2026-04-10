//! API routes for spaces, access control, and space file operations.

use rocket::data::{Data, ToByteUnit};
use rocket::http::{ContentType, Header};
use rocket::response::{self, Responder, Response};
use rocket::serde::json::Json;
use rocket::Request;
use rocket::Route;
use rocket::State;
use serde::{Deserialize, Serialize};

use crate::config::AppConfig;
use crate::db::DbPool;
use crate::errors::AppError;
use crate::guards::setup_guard::SetupComplete;
use crate::guards::space_guard::{SpaceAdmin, SpaceReader, SpaceWriter};
use crate::services::crypto_service::MasterKey;
use crate::services::fs_service::{self, FsEntry};
use crate::services::space_service;
use crate::services::unlock_state::UnlockState;
use crate::utils::format_bytes;

// Request and response DTOs.

#[derive(Deserialize)]
pub struct CreateSpaceRequest {
    pub name: String,
    /// `"user"` (default) or `"group"`.
    #[serde(default = "default_owner_type")]
    pub owner_type: String,
    /// Required when `owner_type` is `"group"` — the group ID.
    pub group_id: Option<String>,
}

fn default_owner_type() -> String {
    "user".into()
}

#[derive(Deserialize)]
pub struct UpdateSpaceRequest {
    pub name: String,
}

#[derive(Serialize)]
pub struct SpaceResponse {
    pub id: String,
    pub name: String,
    pub owner_type: String,
    pub owner_id: String,
    pub encryption_mode: String,
    pub created_at: String,
    pub grantee_count: i64,
    pub user_permission: String,
}

#[derive(Serialize)]
pub struct SpaceListResponse {
    pub spaces: Vec<SpaceResponse>,
}

#[derive(Serialize)]
pub struct MessageResponse {
    pub message: String,
}

// --- Access DTOs ---

#[derive(Deserialize)]
pub struct GrantUserAccessRequest {
    pub username: String,
    pub permission: String,
}

#[derive(Deserialize)]
pub struct GrantGroupAccessRequest {
    pub group_id: String,
    pub permission: String,
}

#[derive(Deserialize)]
pub struct UpdateAccessRequest {
    pub permission: String,
}

#[derive(Serialize)]
pub struct AccessResponse {
    pub space_id: String,
    pub grantee_type: String,
    pub grantee_id: String,
    pub permission: String,
    pub granted_at: String,
}

#[derive(Serialize)]
pub struct AccessDetailResponse {
    pub space_id: String,
    pub grantee_type: String,
    pub grantee_id: String,
    pub permission: String,
    pub granted_at: String,
    pub grantee_name: String,
}

#[derive(Serialize)]
pub struct AccessListResponse {
    pub access: Vec<AccessDetailResponse>,
}

// --- Filesystem DTOs ---

#[derive(Deserialize)]
pub struct MkdirRequest {
    pub path: String,
}

#[derive(Serialize)]
pub struct MkdirResponse {
    pub path: String,
    pub message: String,
}

#[derive(Deserialize)]
pub struct RenameRequest {
    pub old_path: String,
    pub new_path: String,
}

#[derive(Serialize)]
pub struct RenameResponse {
    pub old_path: String,
    pub new_path: String,
    pub message: String,
}

#[derive(Serialize)]
pub struct DeleteResponse {
    pub message: String,
}

#[derive(Serialize)]
pub struct ListResponse {
    pub path: String,
    pub entries: Vec<FsEntry>,
}

#[derive(Serialize)]
pub struct UploadResponse {
    pub path: String,
    pub size: u64,
    pub disk_size: u64,
    pub checksum_sha256: String,
    pub mime_type: Option<String>,
    pub message: String,
}

#[derive(Serialize)]
pub struct InfoResponse {
    #[serde(flatten)]
    pub entry: FsEntry,
}

#[derive(Serialize)]
pub struct UsageResponse {
    pub disk_bytes: u64,
    pub file_count: u64,
    pub dir_count: u64,
}

/// Custom responder for file downloads from a space.
pub struct FileDownload {
    pub data: Vec<u8>,
    pub filename: String,
    pub content_type: ContentType,
    pub checksum_sha256: String,
}

impl<'r> Responder<'r, 'static> for FileDownload {
    fn respond_to(self, _request: &'r Request<'_>) -> response::Result<'static> {
        let len = self.data.len();

        Response::build()
            .header(self.content_type)
            .header(Header::new("X-IronDrive-Integrity", self.checksum_sha256))
            .header(Header::new(
                "Content-Disposition",
                format!(
                    "attachment; filename=\"{}\"",
                    self.filename.replace('\"', "\\\"")
                ),
            ))
            .sized_body(len, std::io::Cursor::new(self.data))
            .ok()
    }
}

// Helpers.

fn parse_content_type(mime: Option<&str>) -> ContentType {
    mime.and_then(|m| {
        let parts: Vec<&str> = m.splitn(2, '/').collect();
        if parts.len() == 2 {
            Some(ContentType::new(parts[0].to_string(), parts[1].to_string()))
        } else {
            None
        }
    })
    .unwrap_or(ContentType::Binary)
}

fn space_response(
    s: &crate::models::space::SpaceWithMeta,
) -> SpaceResponse {
    SpaceResponse {
        id: s.space.id.clone(),
        name: s.space.name.clone(),
        owner_type: s.space.owner_type.clone(),
        owner_id: s.space.owner_id.clone(),
        encryption_mode: s.space.encryption_mode.clone(),
        created_at: s.space.created_at.clone(),
        grantee_count: s.grantee_count,
        user_permission: s.user_permission.clone(),
    }
}

// CRUD routes.

/// POST /api/v1/spaces — Create a new space.
#[post("/api/v1/spaces", format = "json", data = "<body>")]
pub async fn create_space(
    pool: &State<DbPool>,
    config: &State<AppConfig>,
    master_key: &State<MasterKey>,
    unlock_state: &State<UnlockState>,
    user: SetupComplete,
    body: Json<CreateSpaceRequest>,
) -> Result<Json<SpaceResponse>, AppError> {
    let result = match body.owner_type.as_str() {
        "group" => {
            let group_id = body.group_id.as_deref().ok_or_else(|| {
                AppError::Validation("group_id is required when owner_type is 'group'.".into())
            })?;
            space_service::create_group_space(
                pool.inner(),
                config.inner(),
                master_key.inner(),
                unlock_state.inner(),
                group_id,
                &body.name,
            )
            .await?
        }
        "user" | "" => {
            space_service::create_space(
                pool.inner(),
                config.inner(),
                master_key.inner(),
                unlock_state.inner(),
                &user.0.id,
                &body.name,
            )
            .await?
        }
        other => {
            return Err(AppError::Validation(format!(
                "Invalid owner_type '{other}'. Must be 'user' or 'group'."
            )));
        }
    };

    Ok(Json(space_response(&result)))
}

/// GET /api/v1/spaces — List all spaces the user can access.
#[get("/api/v1/spaces")]
pub async fn list_spaces(
    pool: &State<DbPool>,
    user: SetupComplete,
) -> Result<Json<SpaceListResponse>, AppError> {
    let spaces = space_service::list_user_spaces(pool.inner(), &user.0.id).await?;

    let spaces = spaces.iter().map(space_response).collect();

    Ok(Json(SpaceListResponse { spaces }))
}

/// GET /api/v1/spaces/<_id> — Get a single space.
#[get("/api/v1/spaces/<_id>")]
pub async fn get_space(
    _id: &str,
    reader: SpaceReader,
) -> Result<Json<SpaceResponse>, AppError> {
    Ok(Json(space_response(&reader.space)))
}

/// PUT /api/v1/spaces/<_id> — Update space name.
#[put("/api/v1/spaces/<_id>", format = "json", data = "<body>")]
pub async fn update_space(
    pool: &State<DbPool>,
    _id: &str,
    admin: SpaceAdmin,
    body: Json<UpdateSpaceRequest>,
) -> Result<Json<SpaceResponse>, AppError> {
    space_service::update_space(
        pool.inner(),
        &admin.user.id,
        &admin.space.space.id,
        &body.name,
    )
    .await?;

    // Re-fetch with meta for the response.
    let refreshed =
        space_service::get_space(pool.inner(), &admin.user.id, &admin.space.space.id).await?;

    Ok(Json(space_response(&refreshed)))
}

/// DELETE /api/v1/spaces/<_id> — Delete a space.
#[delete("/api/v1/spaces/<_id>")]
pub async fn delete_space(
    pool: &State<DbPool>,
    config: &State<AppConfig>,
    unlock_state: &State<UnlockState>,
    _id: &str,
    admin: SpaceAdmin,
) -> Result<Json<MessageResponse>, AppError> {
    space_service::delete_space(
        pool.inner(),
        config.inner(),
        unlock_state.inner(),
        &admin.user.id,
        &admin.space.space.id,
    )
    .await?;

    Ok(Json(MessageResponse {
        message: "Space deleted successfully.".into(),
    }))
}

// Access management routes.

/// GET /api/v1/spaces/<_id>/access — List all access entries.
#[get("/api/v1/spaces/<_id>/access")]
pub async fn list_access(
    pool: &State<DbPool>,
    _id: &str,
    reader: SpaceReader,
) -> Result<Json<AccessListResponse>, AppError> {
    let entries =
        space_service::list_access(pool.inner(), &reader.user.id, &reader.space.space.id).await?;

    let access = entries
        .into_iter()
        .map(|a| AccessDetailResponse {
            space_id: a.space_id,
            grantee_type: a.grantee_type,
            grantee_id: a.grantee_id,
            permission: a.permission,
            granted_at: a.granted_at,
            grantee_name: a.grantee_name,
        })
        .collect();

    Ok(Json(AccessListResponse { access }))
}

/// POST /api/v1/spaces/<_id>/access/user — Grant user access.
#[post("/api/v1/spaces/<_id>/access/user", format = "json", data = "<body>")]
pub async fn grant_user_access(
    pool: &State<DbPool>,
    _id: &str,
    admin: SpaceAdmin,
    body: Json<GrantUserAccessRequest>,
) -> Result<Json<AccessResponse>, AppError> {
    let access = space_service::grant_user_access(
        pool.inner(),
        &admin.user.id,
        &admin.space.space.id,
        &body.username,
        &body.permission,
    )
    .await?;

    Ok(Json(AccessResponse {
        space_id: access.space_id,
        grantee_type: access.grantee_type,
        grantee_id: access.grantee_id,
        permission: access.permission,
        granted_at: access.granted_at,
    }))
}

/// POST /api/v1/spaces/<_id>/access/group — Grant group access.
#[post("/api/v1/spaces/<_id>/access/group", format = "json", data = "<body>")]
pub async fn grant_group_access(
    pool: &State<DbPool>,
    _id: &str,
    admin: SpaceAdmin,
    body: Json<GrantGroupAccessRequest>,
) -> Result<Json<AccessResponse>, AppError> {
    let access = space_service::grant_group_access(
        pool.inner(),
        &admin.user.id,
        &admin.space.space.id,
        &body.group_id,
        &body.permission,
    )
    .await?;

    Ok(Json(AccessResponse {
        space_id: access.space_id,
        grantee_type: access.grantee_type,
        grantee_id: access.grantee_id,
        permission: access.permission,
        granted_at: access.granted_at,
    }))
}

/// PUT /api/v1/spaces/<_id>/access/<grantee_type>/<grantee_id> — Update permission.
#[put(
    "/api/v1/spaces/<_id>/access/<grantee_type>/<grantee_id>",
    format = "json",
    data = "<body>"
)]
pub async fn update_access(
    pool: &State<DbPool>,
    _id: &str,
    grantee_type: &str,
    grantee_id: &str,
    admin: SpaceAdmin,
    body: Json<UpdateAccessRequest>,
) -> Result<Json<AccessResponse>, AppError> {
    let access = space_service::update_access_permission(
        pool.inner(),
        &admin.user.id,
        &admin.space.space.id,
        grantee_type,
        grantee_id,
        &body.permission,
    )
    .await?;

    Ok(Json(AccessResponse {
        space_id: access.space_id,
        grantee_type: access.grantee_type,
        grantee_id: access.grantee_id,
        permission: access.permission,
        granted_at: access.granted_at,
    }))
}

/// DELETE /api/v1/spaces/<_id>/access/<grantee_type>/<grantee_id> — Revoke access.
#[delete("/api/v1/spaces/<_id>/access/<grantee_type>/<grantee_id>")]
pub async fn revoke_access(
    pool: &State<DbPool>,
    _id: &str,
    grantee_type: &str,
    grantee_id: &str,
    admin: SpaceAdmin,
) -> Result<Json<MessageResponse>, AppError> {
    space_service::revoke_access(
        pool.inner(),
        &admin.user.id,
        &admin.space.space.id,
        grantee_type,
        grantee_id,
    )
    .await?;

    Ok(Json(MessageResponse {
        message: "Access revoked successfully.".into(),
    }))
}

// Filesystem routes.

/// GET /api/v1/spaces/<_id>/files/list?path=<path>&integrity=<bool>
#[get("/api/v1/spaces/<_id>/files/list?<path>&<integrity>")]
pub async fn list_files(
    config: &State<AppConfig>,
    unlock_state: &State<UnlockState>,
    _id: &str,
    reader: SpaceReader,
    path: Option<String>,
    integrity: Option<bool>,
) -> Result<Json<ListResponse>, AppError> {
    let user_path = path.as_deref().unwrap_or("");
    let check_integrity = integrity.unwrap_or(false);

    let entries = fs_service::list_space_directory(
        config.inner(),
        unlock_state.inner(),
        &reader.space.space.id,
        user_path,
        check_integrity,
    )
    .await?;

    Ok(Json(ListResponse {
        path: user_path.to_string(),
        entries,
    }))
}

/// POST /api/v1/spaces/<_id>/files/mkdir
#[post("/api/v1/spaces/<_id>/files/mkdir", format = "json", data = "<body>")]
pub async fn mkdir(
    config: &State<AppConfig>,
    _id: &str,
    writer: SpaceWriter,
    body: Json<MkdirRequest>,
) -> Result<Json<MkdirResponse>, AppError> {
    let path =
        fs_service::create_space_directory(config.inner(), &writer.space.space.id, &body.path)
            .await?;

    Ok(Json(MkdirResponse {
        path,
        message: "Directory created successfully.".into(),
    }))
}

/// POST /api/v1/spaces/<_id>/files/upload?path=<path>&verify=<bool>
#[post("/api/v1/spaces/<_id>/files/upload?<path>&<verify>", data = "<data>")]
pub async fn upload(
    config: &State<AppConfig>,
    unlock_state: &State<UnlockState>,
    _id: &str,
    writer: SpaceWriter,
    path: String,
    verify: Option<bool>,
    data: Data<'_>,
) -> Result<Json<UploadResponse>, AppError> {
    let write_verify = verify.unwrap_or(false);

    let max_bytes = config.max_upload_bytes;
    let hard_cap_bytes: u64 = 50 * 1024 * 1024;
    let allowed_bytes = std::cmp::min(max_bytes.bytes(), hard_cap_bytes.bytes());
    let stream = data
        .open(allowed_bytes)
        .into_bytes()
        .await
        .map_err(|e| AppError::Internal(format!("Failed to read upload data: {e}")))?;

    if !stream.is_complete() {
        return Err(AppError::Validation(format!(
            "Upload exceeds the maximum allowed size of {}.",
            format_bytes(allowed_bytes.into())
        )));
    }

    let bytes = stream.into_inner();

    let result = fs_service::upload_space_file(
        config.inner(),
        unlock_state.inner(),
        &writer.space.space.id,
        &path,
        &bytes,
        write_verify,
    )
    .await?;

    Ok(Json(UploadResponse {
        path: result.path,
        size: result.size,
        disk_size: result.disk_size,
        checksum_sha256: result.checksum_sha256,
        mime_type: result.mime_type,
        message: "File uploaded successfully.".into(),
    }))
}

/// GET /api/v1/spaces/<_id>/files/download?path=<path>
#[get("/api/v1/spaces/<_id>/files/download?<path>")]
pub async fn download(
    config: &State<AppConfig>,
    unlock_state: &State<UnlockState>,
    _id: &str,
    reader: SpaceReader,
    path: String,
) -> Result<FileDownload, AppError> {
    let result = fs_service::download_space_file(
        config.inner(),
        unlock_state.inner(),
        &reader.space.space.id,
        &path,
    )
    .await?;

    let content_type = parse_content_type(result.mime_type.as_deref());

    Ok(FileDownload {
        data: result.data,
        filename: result.filename,
        content_type,
        checksum_sha256: result.checksum_sha256,
    })
}

/// DELETE /api/v1/spaces/<_id>/files/delete?path=<path>
#[delete("/api/v1/spaces/<_id>/files/delete?<path>")]
pub async fn delete_file(
    config: &State<AppConfig>,
    _id: &str,
    writer: SpaceWriter,
    path: String,
) -> Result<Json<DeleteResponse>, AppError> {
    fs_service::delete_space_entry(config.inner(), &writer.space.space.id, &path).await?;

    Ok(Json(DeleteResponse {
        message: "Entry deleted successfully.".into(),
    }))
}

/// POST /api/v1/spaces/<_id>/files/rename
#[post("/api/v1/spaces/<_id>/files/rename", format = "json", data = "<body>")]
pub async fn rename_file(
    config: &State<AppConfig>,
    _id: &str,
    writer: SpaceWriter,
    body: Json<RenameRequest>,
) -> Result<Json<RenameResponse>, AppError> {
    let result = fs_service::rename_space_entry(
        config.inner(),
        &writer.space.space.id,
        &body.old_path,
        &body.new_path,
    )
    .await?;

    Ok(Json(RenameResponse {
        old_path: result.old_path,
        new_path: result.new_path,
        message: "Entry renamed successfully.".into(),
    }))
}

/// GET /api/v1/spaces/<_id>/files/info?path=<path>&integrity=<bool>
#[get("/api/v1/spaces/<_id>/files/info?<path>&<integrity>")]
pub async fn file_info(
    config: &State<AppConfig>,
    unlock_state: &State<UnlockState>,
    _id: &str,
    reader: SpaceReader,
    path: Option<String>,
    integrity: Option<bool>,
) -> Result<Json<InfoResponse>, AppError> {
    let user_path = path.as_deref().unwrap_or("");
    let check_integrity = integrity.unwrap_or(false);

    let entry = fs_service::get_space_entry_info(
        config.inner(),
        unlock_state.inner(),
        &reader.space.space.id,
        user_path,
        check_integrity,
    )
    .await?;

    Ok(Json(InfoResponse { entry }))
}

/// GET /api/v1/spaces/<_id>/files/usage?path=<path>
#[get("/api/v1/spaces/<_id>/files/usage?<path>")]
pub async fn file_usage(
    config: &State<AppConfig>,
    _id: &str,
    reader: SpaceReader,
    path: Option<String>,
) -> Result<Json<UsageResponse>, AppError> {
    let user_path = path.as_deref().unwrap_or("");

    let result =
        fs_service::calculate_space_usage(config.inner(), &reader.space.space.id, user_path)
            .await?;

    Ok(Json(UsageResponse {
        disk_bytes: result.disk_bytes,
        file_count: result.file_count,
        dir_count: result.dir_count,
    }))
}

// Route collection.

pub fn routes() -> Vec<Route> {
    routes![
        // CRUD
        create_space,
        list_spaces,
        get_space,
        update_space,
        delete_space,
        // Access management
        list_access,
        grant_user_access,
        grant_group_access,
        update_access,
        revoke_access,
        // Filesystem
        list_files,
        mkdir,
        upload,
        download,
        delete_file,
        rename_file,
        file_info,
        file_usage,
    ]
}
