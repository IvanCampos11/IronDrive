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
use crate::guards::SetupComplete;
use crate::models::library::PersonalLibrary;
use crate::services::chunk_service;
use crate::utils::format_bytes;
use crate::services::fs_service::{self, FsEntry};
use crate::services::unlock_state::UnlockState;

// ---------------------------------------------------------------------------
// Request / Response types
// ---------------------------------------------------------------------------

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
    /// Plaintext SHA-256 hex digest. Computed on the fly for single-shot uploads;
    /// empty for chunked uploads.
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

#[derive(Deserialize)]
pub struct InitChunkUploadRequest {
    pub path: String,
    pub total_chunks: u32,
    pub total_bytes: u64,
    /// Advisory only — format-validated but not enforced server-side.
    pub checksum_sha256: Option<String>,
}

#[derive(Serialize)]
pub struct InitChunkUploadResponse {
    pub upload_id: String,
    pub chunk_size_bytes: u64,
    pub total_chunks: u32,
    pub total_bytes: u64,
    pub expires_at: String,
    pub message: String,
}

#[derive(Serialize)]
pub struct ChunkUploadResponse {
    pub upload_id: String,
    pub chunk_index: u32,
    pub received_chunks: u32,
    pub total_chunks: u32,
    pub message: String,
}

#[derive(Deserialize)]
pub struct CompleteChunkUploadRequest {
    pub upload_id: String,
    pub verify: Option<bool>,
}

#[derive(Serialize)]
pub struct CancelChunkUploadResponse {
    pub upload_id: String,
    pub message: String,
}

#[derive(Serialize)]
pub struct InitChunkDownloadResponse {
    pub token: String,
    pub filename: String,
    pub mime_type: Option<String>,
    pub chunk_size_bytes: u64,
    pub total_chunks: u32,
    pub total_bytes: u64,
    pub expires_at: String,
}

pub struct FileChunkDownload {
    pub data: Vec<u8>,
    pub content_type: ContentType,
    /// Plaintext SHA-256 hex digest for the `X-IronDrive-Integrity` header.
    pub checksum_sha256: String,
    pub chunk_index: u32,
    pub total_chunks: u32,
    pub total_bytes: u64,
}

impl<'r> Responder<'r, 'static> for FileChunkDownload {
    fn respond_to(self, _request: &'r Request<'_>) -> response::Result<'static> {
        let len = self.data.len();

        Response::build()
            .header(self.content_type)
            .header(Header::new("X-IronDrive-Integrity", self.checksum_sha256))
            .header(Header::new(
                "X-IronDrive-Chunk-Index",
                self.chunk_index.to_string(),
            ))
            .header(Header::new(
                "X-IronDrive-Chunk-Total",
                self.total_chunks.to_string(),
            ))
            .header(Header::new(
                "X-IronDrive-Total-Bytes",
                self.total_bytes.to_string(),
            ))
            .sized_body(len, std::io::Cursor::new(self.data))
            .ok()
    }
}

/// Custom responder for file downloads. Sends the decrypted body with
/// `X-IronDrive-Integrity` (plaintext SHA-256, computed on the fly).
pub struct FileDownload {
    pub data: Vec<u8>,
    pub filename: String,
    pub content_type: ContentType,
    /// Plaintext SHA-256 hex digest for the `X-IronDrive-Integrity` header.
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

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Look up the user's personal library, returning 404 if they haven't set one up.
async fn require_library(pool: &DbPool, user_id: &str) -> Result<PersonalLibrary, AppError> {
    PersonalLibrary::find_by_user(pool, user_id)
        .await?
        .ok_or(AppError::NotFound)
}

/// Parse a MIME string into a Rocket `ContentType`, falling back to
/// `application/octet-stream`.
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

// ---------------------------------------------------------------------------
// Routes
// ---------------------------------------------------------------------------

/// GET /api/v1/library/list?path=<path>&integrity=<bool>
///
/// List the contents of a directory in the user's personal library.
/// `path` defaults to `""` (library root). `integrity` defaults to `false`.
#[get("/api/v1/library/list?<path>&<integrity>")]
pub async fn list(
    pool: &State<DbPool>,
    config: &State<AppConfig>,
    unlock_state: &State<UnlockState>,
    user: SetupComplete,
    path: Option<String>,
    integrity: Option<bool>,
) -> Result<Json<ListResponse>, AppError> {
    let lib = require_library(pool.inner(), &user.0.id).await?;
    let user_path = path.as_deref().unwrap_or("");
    let check_integrity = integrity.unwrap_or(false);

    let entries = fs_service::list_directory(
        config.inner(),
        unlock_state.inner(),
        &lib.id,
        user_path,
        check_integrity,
    )
    .await?;

    Ok(Json(ListResponse {
        path: user_path.to_string(),
        entries,
    }))
}

/// POST /api/v1/library/mkdir
///
/// Create a directory (with parents) in the user's personal library.
#[post("/api/v1/library/mkdir", format = "json", data = "<body>")]
pub async fn mkdir(
    pool: &State<DbPool>,
    config: &State<AppConfig>,
    user: SetupComplete,
    body: Json<MkdirRequest>,
) -> Result<Json<MkdirResponse>, AppError> {
    let lib = require_library(pool.inner(), &user.0.id).await?;

    let path = fs_service::create_directory(config.inner(), &lib.id, &body.path).await?;

    Ok(Json(MkdirResponse {
        path,
        message: "Directory created successfully.".into(),
    }))
}

/// POST /api/v1/library/upload?path=<path>&verify=<bool>
///
/// Upload a file to the user's personal library. The request body is the raw
/// file content (not multipart). The `path` query parameter specifies where
/// to write the file (relative to library root, including filename).
/// `verify` enables write-verify (read-back after write); defaults to `false`.
#[post("/api/v1/library/upload?<path>&<verify>", data = "<data>")]
pub async fn upload(
    pool: &State<DbPool>,
    config: &State<AppConfig>,
    unlock_state: &State<UnlockState>,
    user: SetupComplete,
    path: String,
    verify: Option<bool>,
    data: Data<'_>,
) -> Result<Json<UploadResponse>, AppError> {
    let lib = require_library(pool.inner(), &user.0.id).await?;
    let write_verify = verify.unwrap_or(false);

    // Read the body up to the configured max upload size, but enforce a smaller
    // hard cap for this non-chunked endpoint to avoid excessive RAM usage.
    let max_bytes = config.max_upload_bytes;
    let hard_cap_bytes: u64 = 50 * 1024 * 1024; // 50 MiB hard in-memory limit.
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

    let result = fs_service::upload_file(
        config.inner(),
        unlock_state.inner(),
        &lib.id,
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

/// GET /api/v1/library/download?path=<path>
///
/// Download a file from the user's personal library. Returns the decrypted
/// file content with an `X-IronDrive-Integrity` header containing the
/// SHA-256 hex digest of the plaintext.
#[get("/api/v1/library/download?<path>")]
pub async fn download(
    pool: &State<DbPool>,
    config: &State<AppConfig>,
    unlock_state: &State<UnlockState>,
    user: SetupComplete,
    path: String,
) -> Result<FileDownload, AppError> {
    let lib = require_library(pool.inner(), &user.0.id).await?;

    let result =
        fs_service::download_file(config.inner(), unlock_state.inner(), &lib.id, &path).await?;

    let content_type = parse_content_type(result.mime_type.as_deref());

    Ok(FileDownload {
        data: result.data,
        filename: result.filename,
        content_type,
        checksum_sha256: result.checksum_sha256,
    })
}

/// DELETE /api/v1/library/delete?path=<path>
///
/// Delete a file or directory (recursively) from the user's personal library.
#[delete("/api/v1/library/delete?<path>")]
pub async fn delete(
    pool: &State<DbPool>,
    config: &State<AppConfig>,
    user: SetupComplete,
    path: String,
) -> Result<Json<DeleteResponse>, AppError> {
    let lib = require_library(pool.inner(), &user.0.id).await?;

    fs_service::delete_entry(config.inner(), &lib.id, &path).await?;

    Ok(Json(DeleteResponse {
        message: "Entry deleted successfully.".into(),
    }))
}

/// POST /api/v1/library/rename
///
/// Rename or move an entry within the user's personal library.
#[post("/api/v1/library/rename", format = "json", data = "<body>")]
pub async fn rename(
    pool: &State<DbPool>,
    config: &State<AppConfig>,
    user: SetupComplete,
    body: Json<RenameRequest>,
) -> Result<Json<RenameResponse>, AppError> {
    let lib = require_library(pool.inner(), &user.0.id).await?;

    let result =
        fs_service::rename_entry(config.inner(), &lib.id, &body.old_path, &body.new_path).await?;

    Ok(Json(RenameResponse {
        old_path: result.old_path,
        new_path: result.new_path,
        message: "Entry renamed successfully.".into(),
    }))
}

/// GET /api/v1/library/info?path=<path>&integrity=<bool>
///
/// Get metadata for a single file or directory. `path` defaults to `""`
/// (library root). `integrity` defaults to `false`.
#[get("/api/v1/library/info?<path>&<integrity>")]
pub async fn info(
    pool: &State<DbPool>,
    config: &State<AppConfig>,
    unlock_state: &State<UnlockState>,
    user: SetupComplete,
    path: Option<String>,
    integrity: Option<bool>,
) -> Result<Json<InfoResponse>, AppError> {
    let lib = require_library(pool.inner(), &user.0.id).await?;
    let user_path = path.as_deref().unwrap_or("");
    let check_integrity = integrity.unwrap_or(false);

    let entry = fs_service::get_entry_info(
        config.inner(),
        unlock_state.inner(),
        &lib.id,
        user_path,
        check_integrity,
    )
    .await?;

    Ok(Json(InfoResponse { entry }))
}

/// GET /api/v1/library/usage?path=<path>
///
/// Calculate disk usage for the user's library or a subtree. `path` defaults
/// to `""` (entire library).
#[get("/api/v1/library/usage?<path>")]
pub async fn usage(
    pool: &State<DbPool>,
    config: &State<AppConfig>,
    user: SetupComplete,
    path: Option<String>,
) -> Result<Json<UsageResponse>, AppError> {
    let lib = require_library(pool.inner(), &user.0.id).await?;
    let user_path = path.as_deref().unwrap_or("");

    let result = fs_service::calculate_usage(config.inner(), &lib.id, user_path).await?;

    Ok(Json(UsageResponse {
        disk_bytes: result.disk_bytes,
        file_count: result.file_count,
        dir_count: result.dir_count,
    }))
}

/// POST /api/v1/library/chunked/init
///
/// Start a chunked upload session for a large file.
#[post("/api/v1/library/chunked/init", format = "json", data = "<body>")]
pub async fn chunked_init_upload(
    pool: &State<DbPool>,
    config: &State<AppConfig>,
    user: SetupComplete,
    body: Json<InitChunkUploadRequest>,
) -> Result<Json<InitChunkUploadResponse>, AppError> {
    let lib = require_library(pool.inner(), &user.0.id).await?;

    let result = chunk_service::init_upload(
        pool.inner(),
        config.inner(),
        chunk_service::InitUploadParams {
            user_id: user.0.id.clone(),
            target_id: lib.id,
            target_type: "library".to_string(),
            target_path: body.path.clone(),
            total_chunks: body.total_chunks,
            total_bytes: body.total_bytes,
            checksum_sha256: body.checksum_sha256.clone(),
        },
    )
    .await?;

    Ok(Json(InitChunkUploadResponse {
        upload_id: result.upload_id,
        chunk_size_bytes: result.chunk_size_bytes,
        total_chunks: result.total_chunks,
        total_bytes: result.total_bytes,
        expires_at: result.expires_at,
        message: "Chunked upload initialized.".into(),
    }))
}

/// PUT /api/v1/library/chunked/upload/<upload_id>/<chunk_index>
///
/// Receive one chunk for an in-progress upload session.
#[put(
    "/api/v1/library/chunked/upload/<upload_id>/<chunk_index>",
    data = "<data>"
)]
pub async fn chunked_receive_chunk(
    pool: &State<DbPool>,
    config: &State<AppConfig>,
    user: SetupComplete,
    upload_id: &str,
    chunk_index: u32,
    data: Data<'_>,
) -> Result<Json<ChunkUploadResponse>, AppError> {
    let lib = require_library(pool.inner(), &user.0.id).await?;

    let allowed_bytes = (config.chunk_size_bytes + 1).bytes();
    let stream = data
        .open(allowed_bytes)
        .into_bytes()
        .await
        .map_err(|e| AppError::Internal(format!("Failed to read chunk data: {e}")))?;

    if !stream.is_complete() {
        return Err(AppError::Validation(format!(
            "Chunk exceeds the maximum chunk size of {} bytes.",
            config.chunk_size_bytes
        )));
    }

    let result = chunk_service::receive_chunk(
        pool.inner(),
        config.inner(),
        &user.0.id,
        &lib.id,
        "library",
        upload_id,
        chunk_index,
        &stream.into_inner(),
    )
    .await?;

    Ok(Json(ChunkUploadResponse {
        upload_id: result.upload_id,
        chunk_index: result.chunk_index,
        received_chunks: result.received_chunks,
        total_chunks: result.total_chunks,
        message: "Chunk received.".into(),
    }))
}

/// POST /api/v1/library/chunked/complete
///
/// Assemble all uploaded chunks and persist the final encrypted file.
#[post("/api/v1/library/chunked/complete", format = "json", data = "<body>")]
pub async fn chunked_complete_upload(
    pool: &State<DbPool>,
    config: &State<AppConfig>,
    unlock_state: &State<UnlockState>,
    user: SetupComplete,
    body: Json<CompleteChunkUploadRequest>,
) -> Result<Json<UploadResponse>, AppError> {
    let lib = require_library(pool.inner(), &user.0.id).await?;
    let write_verify = body.verify.unwrap_or(false);

    let result = chunk_service::complete_upload(
        pool.inner(),
        config.inner(),
        unlock_state.inner(),
        &user.0.id,
        &lib.id,
        "library",
        &body.upload_id,
        write_verify,
    )
    .await?;

    Ok(Json(UploadResponse {
        path: result.path,
        size: result.size,
        disk_size: result.disk_size,
        checksum_sha256: result.checksum_sha256,
        mime_type: result.mime_type,
        message: "Chunked upload completed successfully.".into(),
    }))
}

/// DELETE /api/v1/library/chunked/cancel?upload_id=<upload_id>
///
/// Cancel a chunked upload and remove all staging artifacts.
#[delete("/api/v1/library/chunked/cancel?<upload_id>")]
pub async fn chunked_cancel_upload(
    pool: &State<DbPool>,
    config: &State<AppConfig>,
    user: SetupComplete,
    upload_id: String,
) -> Result<Json<CancelChunkUploadResponse>, AppError> {
    let lib = require_library(pool.inner(), &user.0.id).await?;

    chunk_service::cancel_upload(
        pool.inner(),
        config.inner(),
        &user.0.id,
        &lib.id,
        "library",
        &upload_id,
    )
    .await?;

    Ok(Json(CancelChunkUploadResponse {
        upload_id,
        message: "Chunked upload canceled and cleaned up.".into(),
    }))
}

/// GET /api/v1/library/chunked/download/init?path=<path>
///
/// Initialize a chunked download and return a short-lived token.
#[get("/api/v1/library/chunked/download/init?<path>")]
pub async fn chunked_init_download(
    pool: &State<DbPool>,
    config: &State<AppConfig>,
    unlock_state: &State<UnlockState>,
    user: SetupComplete,
    path: String,
) -> Result<Json<InitChunkDownloadResponse>, AppError> {
    let lib = require_library(pool.inner(), &user.0.id).await?;

    let result = chunk_service::init_download(
        config.inner(),
        unlock_state.inner(),
        &user.0.id,
        &lib.id,
        "library",
        &path,
    )
    .await?;

    Ok(Json(InitChunkDownloadResponse {
        token: result.token,
        filename: result.filename,
        mime_type: result.mime_type,
        chunk_size_bytes: result.chunk_size_bytes,
        total_chunks: result.total_chunks,
        total_bytes: result.total_bytes,
        expires_at: result.expires_at,
    }))
}

/// GET /api/v1/library/chunked/download/chunk?token=<token>&index=<n>
///
/// Download one plaintext chunk from a token-authorized file.
#[get("/api/v1/library/chunked/download/chunk?<token>&<index>")]
pub async fn chunked_download_chunk(
    config: &State<AppConfig>,
    unlock_state: &State<UnlockState>,
    user: SetupComplete,
    token: String,
    index: u32,
) -> Result<FileChunkDownload, AppError> {
    let result = chunk_service::serve_chunk(
        config.inner(),
        unlock_state.inner(),
        &user.0.id,
        &token,
        index,
    )
    .await?;

    let content_type = parse_content_type(result.mime_type.as_deref());

    Ok(FileChunkDownload {
        data: result.data,
        content_type,
        checksum_sha256: result.checksum_sha256,
        chunk_index: result.chunk_index,
        total_chunks: result.total_chunks,
        total_bytes: result.total_bytes,
    })
}

// ---------------------------------------------------------------------------
// Route collection
// ---------------------------------------------------------------------------

pub fn routes() -> Vec<Route> {
    routes![
        list,
        mkdir,
        upload,
        download,
        delete,
        rename,
        info,
        usage,
        chunked_init_upload,
        chunked_receive_chunk,
        chunked_complete_upload,
        chunked_cancel_upload,
        chunked_init_download,
        chunked_download_chunk,
    ]
}
