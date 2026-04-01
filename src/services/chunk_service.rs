use std::path::{Path, PathBuf};

use base64::Engine;
use chrono::{Duration, Utc};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use tokio::io::AsyncWriteExt;
use tracing;
use uuid::Uuid;

use crate::config::AppConfig;
use crate::db::DbPool;
use crate::errors::AppError;
use crate::services::fs_service::{self, DownloadResult, UploadResult};
use crate::services::unlock_state::UnlockState;
use crate::utils::format_bytes;

const DOWNLOAD_TOKEN_VERSION: &str = "v1";
const DOWNLOAD_TOKEN_TTL_MINUTES: i64 = 10;
type HmacSha256 = Hmac<Sha256>;

#[derive(Debug, Clone)]
pub struct InitUploadParams {
    pub user_id: String,
    pub library_id: String,
    pub target_path: String,
    pub total_chunks: u32,
    pub total_bytes: u64,
    pub checksum_sha256: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct InitUploadResult {
    pub upload_id: String,
    pub chunk_size_bytes: u64,
    pub total_chunks: u32,
    pub total_bytes: u64,
    pub expires_at: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct ReceiveChunkResult {
    pub upload_id: String,
    pub chunk_index: u32,
    pub received_chunks: u32,
    pub total_chunks: u32,
}

#[derive(Debug, Clone, Serialize)]
pub struct InitDownloadResult {
    pub token: String,
    pub filename: String,
    pub mime_type: Option<String>,
    pub chunk_size_bytes: u64,
    pub total_chunks: u32,
    pub total_bytes: u64,
    pub expires_at: String,
}

#[derive(Debug)]
pub struct ChunkDownloadResult {
    pub data: Vec<u8>,
    pub mime_type: Option<String>,
    pub checksum_sha256: String,
    pub chunk_index: u32,
    pub total_chunks: u32,
    pub total_bytes: u64,
}

#[derive(Debug, Clone)]
struct ChunkedUploadRow {
    user_id: String,
    target_id: String,
    target_path: String,
    total_chunks: i64,
    total_bytes: i64,
    checksum: Option<String>,
    expires_at: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct DownloadTokenPayload {
    v: String,
    uid: String,
    lib: String,
    path: String,
    exp: i64,
    nonce: String,
}

/// Validate that an upload_id is a well-formed UUID.  Defence-in-depth:
/// even though we always query the DB first, rejecting non-UUID strings
/// here prevents any filesystem path-traversal via crafted upload IDs.
fn validate_upload_id(upload_id: &str) -> Result<(), AppError> {
    Uuid::parse_str(upload_id).map_err(|_| AppError::NotFound)?;
    Ok(())
}

fn staging_dir(config: &AppConfig, upload_id: &str) -> PathBuf {
    PathBuf::from(config.chunks_dir()).join(upload_id)
}

fn chunk_path(config: &AppConfig, upload_id: &str, chunk_index: u32) -> PathBuf {
    staging_dir(config, upload_id).join(format!("{chunk_index:08}.chunk"))
}

fn expected_total_chunks(total_bytes: u64, chunk_size_bytes: u64) -> u32 {
    if total_bytes == 0 {
        return 1;
    }
    ((total_bytes + chunk_size_bytes - 1) / chunk_size_bytes) as u32
}

fn expected_chunk_len(
    total_bytes: u64,
    chunk_size_bytes: u64,
    total_chunks: u32,
    index: u32,
) -> u64 {
    if index + 1 < total_chunks {
        return chunk_size_bytes;
    }

    let prior = chunk_size_bytes.saturating_mul((total_chunks.saturating_sub(1)) as u64);
    total_bytes.saturating_sub(prior)
}

fn normalize_hex(s: &str) -> String {
    s.trim().to_ascii_lowercase()
}

fn is_valid_sha256_hex(s: &str) -> bool {
    let normalized = normalize_hex(s);
    normalized.len() == 64 && normalized.chars().all(|c| c.is_ascii_hexdigit())
}

async fn load_upload_row(
    pool: &DbPool,
    upload_id: &str,
) -> Result<Option<ChunkedUploadRow>, AppError> {
    let row = sqlx::query_as::<_, (String, String, String, String, i64, i64, i64, Option<String>, String)>(
        "SELECT id, user_id, target_id, target_path, total_chunks, received_chunks, total_bytes, checksum, expires_at
         FROM chunked_uploads
         WHERE id = ? AND target_type = 'library'",
    )
    .bind(upload_id)
    .fetch_optional(pool)
    .await?;

    Ok(row.map(|r| ChunkedUploadRow {
        user_id: r.1,
        target_id: r.2,
        target_path: r.3,
        total_chunks: r.4,
        total_bytes: r.6,
        checksum: r.7,
        expires_at: r.8,
    }))
}

async fn count_uploaded_chunks(config: &AppConfig, upload_id: &str) -> Result<u32, AppError> {
    let dir = staging_dir(config, upload_id);
    let mut count = 0u32;

    if !tokio::fs::try_exists(&dir).await.unwrap_or(false) {
        return Ok(0);
    }

    let mut rd = tokio::fs::read_dir(&dir)
        .await
        .map_err(|e| AppError::Internal(format!("Failed to list staging dir: {e}")))?;

    while let Some(entry) = rd
        .next_entry()
        .await
        .map_err(|e| AppError::Internal(format!("Failed to read staging dir entry: {e}")))?
    {
        let name = entry.file_name().to_string_lossy().to_string();
        if name.ends_with(".chunk") {
            count = count.saturating_add(1);
        }
    }

    Ok(count)
}

fn is_expired(expires_at: &str) -> bool {
    chrono::NaiveDateTime::parse_from_str(expires_at, "%Y-%m-%d %H:%M:%S")
        .map(|dt| Utc::now().naive_utc() >= dt)
        .unwrap_or(true)
}

fn sign_payload(secret_key: &str, payload_b64: &str) -> Result<String, AppError> {
    let mut mac = HmacSha256::new_from_slice(secret_key.as_bytes())
        .map_err(|e| AppError::Internal(format!("Failed to initialize HMAC signer: {e}")))?;
    mac.update(payload_b64.as_bytes());
    Ok(hex::encode(mac.finalize().into_bytes()))
}

fn build_download_token(
    secret_key: &str,
    user_id: &str,
    library_id: &str,
    path: &str,
) -> Result<(String, String), AppError> {
    let expires_at = Utc::now() + Duration::minutes(DOWNLOAD_TOKEN_TTL_MINUTES);

    let payload = DownloadTokenPayload {
        v: DOWNLOAD_TOKEN_VERSION.to_string(),
        uid: user_id.to_string(),
        lib: library_id.to_string(),
        path: path.to_string(),
        exp: expires_at.timestamp(),
        nonce: Uuid::new_v4().to_string(),
    };

    let payload_json = serde_json::to_vec(&payload)
        .map_err(|e| AppError::Internal(format!("Failed to serialize token payload: {e}")))?;
    let payload_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(payload_json);
    let sig = sign_payload(secret_key, &payload_b64)?;

    Ok((
        format!("{payload_b64}.{sig}"),
        expires_at.format("%Y-%m-%d %H:%M:%S").to_string(),
    ))
}

fn verify_download_token(secret_key: &str, token: &str) -> Result<DownloadTokenPayload, AppError> {
    let mut parts = token.splitn(2, '.');
    let payload_b64 = parts
        .next()
        .ok_or_else(|| AppError::Validation("Invalid download token.".into()))?;
    let sig = parts
        .next()
        .ok_or_else(|| AppError::Validation("Invalid download token.".into()))?;

    let provided_sig = hex::decode(normalize_hex(sig))
        .map_err(|_| AppError::Validation("Invalid download token signature.".into()))?;

    let mut mac = HmacSha256::new_from_slice(secret_key.as_bytes())
        .map_err(|e| AppError::Internal(format!("Failed to initialize HMAC verifier: {e}")))?;
    mac.update(payload_b64.as_bytes());
    mac.verify_slice(&provided_sig)
        .map_err(|_| AppError::Validation("Invalid download token signature.".into()))?;

    let payload_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(payload_b64)
        .map_err(|_| AppError::Validation("Invalid download token payload.".into()))?;

    let payload: DownloadTokenPayload = serde_json::from_slice(&payload_bytes)
        .map_err(|_| AppError::Validation("Invalid download token payload.".into()))?;

    if payload.v != DOWNLOAD_TOKEN_VERSION {
        return Err(AppError::Validation(
            "Unsupported download token version.".into(),
        ));
    }

    if Utc::now().timestamp() >= payload.exp {
        return Err(AppError::Validation("Download token expired.".into()));
    }

    Ok(payload)
}

fn filename_from_target_path(path: &str) -> String {
    Path::new(path)
        .file_name()
        .and_then(|s| s.to_str())
        .map(|s| s.to_string())
        .unwrap_or_else(|| "file.bin".to_string())
}

pub async fn init_upload(
    pool: &DbPool,
    config: &AppConfig,
    params: InitUploadParams,
) -> Result<InitUploadResult, AppError> {
    if params.target_path.trim().is_empty() {
        return Err(AppError::Validation(
            "Target path must not be empty.".into(),
        ));
    }
    if params.target_path.ends_with('/') {
        return Err(AppError::Validation(
            "Target path must include a filename, not a directory.".into(),
        ));
    }
    if params.total_chunks == 0 {
        return Err(AppError::Validation(
            "total_chunks must be greater than zero.".into(),
        ));
    }
    if params.total_bytes <= config.chunk_size_bytes {
        return Err(AppError::Validation(
            "File is small enough for single-request upload; use /api/v1/library/upload instead."
                .into(),
        ));
    }
    if params.total_bytes > config.max_upload_bytes {
        return Err(AppError::Validation(format!(
            "File exceeds maximum allowed upload size of {}.",
            format_bytes(config.max_upload_bytes)
        )));
    }
    if let Some(ref checksum) = params.checksum_sha256 {
        if !is_valid_sha256_hex(checksum) {
            return Err(AppError::Validation(
                "checksum_sha256 must be a 64-character SHA-256 hex string.".into(),
            ));
        }
    }

    let expected_chunks = expected_total_chunks(params.total_bytes, config.chunk_size_bytes);
    if params.total_chunks != expected_chunks {
        return Err(AppError::Validation(format!(
            "total_chunks mismatch: expected {}, got {}.",
            expected_chunks, params.total_chunks
        )));
    }

    let upload_id = Uuid::new_v4().to_string();
    let expires_at = Utc::now() + Duration::hours(config.chunk_upload_expiry_hours as i64);
    let expires_at_str = expires_at.format("%Y-%m-%d %H:%M:%S").to_string();
    let filename = filename_from_target_path(&params.target_path);

    tokio::fs::create_dir_all(staging_dir(config, &upload_id))
        .await
        .map_err(|e| AppError::Internal(format!("Failed to create staging directory: {e}")))?;

    sqlx::query(
        "INSERT INTO chunked_uploads
         (id, user_id, target_type, target_id, target_path, filename, total_chunks, received_chunks, total_bytes, checksum, expires_at)
         VALUES (?, ?, 'library', ?, ?, ?, ?, 0, ?, ?, ?)",
    )
    .bind(&upload_id)
    .bind(&params.user_id)
    .bind(&params.library_id)
    .bind(&params.target_path)
    .bind(&filename)
    .bind(params.total_chunks as i64)
    .bind(params.total_bytes as i64)
    .bind(params.checksum_sha256.map(|s| normalize_hex(&s)))
    .bind(&expires_at_str)
    .execute(pool)
    .await?;

    Ok(InitUploadResult {
        upload_id,
        chunk_size_bytes: config.chunk_size_bytes,
        total_chunks: params.total_chunks,
        total_bytes: params.total_bytes,
        expires_at: expires_at_str,
    })
}

pub async fn receive_chunk(
    pool: &DbPool,
    config: &AppConfig,
    user_id: &str,
    library_id: &str,
    upload_id: &str,
    chunk_index: u32,
    data: &[u8],
) -> Result<ReceiveChunkResult, AppError> {
    validate_upload_id(upload_id)?;
    let row = load_upload_row(pool, upload_id)
        .await?
        .ok_or(AppError::NotFound)?;

    if row.user_id != user_id || row.target_id != library_id {
        return Err(AppError::NotFound);
    }
    if is_expired(&row.expires_at) {
        return Err(AppError::Validation("Upload session has expired.".into()));
    }

    let total_chunks = row.total_chunks as u32;
    if chunk_index >= total_chunks {
        return Err(AppError::Validation("chunk_index out of range.".into()));
    }

    let expected_len = expected_chunk_len(
        row.total_bytes as u64,
        config.chunk_size_bytes,
        total_chunks,
        chunk_index,
    );
    if data.len() as u64 != expected_len {
        return Err(AppError::Validation(format!(
            "Chunk size mismatch for index {}: expected {} bytes, got {} bytes.",
            chunk_index,
            expected_len,
            data.len()
        )));
    }

    tokio::fs::create_dir_all(staging_dir(config, upload_id))
        .await
        .map_err(|e| AppError::Internal(format!("Failed to ensure staging directory: {e}")))?;

    let path = chunk_path(config, upload_id, chunk_index);
    let mut file = match tokio::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&path)
        .await
    {
        Ok(file) => file,
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            return Err(AppError::Conflict("Chunk already uploaded.".into()))
        }
        Err(e) => {
            return Err(AppError::Internal(format!(
                "Failed to create chunk file: {e}"
            )))
        }
    };

    file.write_all(data)
        .await
        .map_err(|e| AppError::Internal(format!("Failed to write chunk: {e}")))?;
    file.flush()
        .await
        .map_err(|e| AppError::Internal(format!("Failed to flush chunk: {e}")))?;
    file.sync_data()
        .await
        .map_err(|e| AppError::Internal(format!("Failed to sync chunk to disk: {e}")))?;

    let received_chunks = count_uploaded_chunks(config, upload_id).await?;
    sqlx::query("UPDATE chunked_uploads SET received_chunks = ? WHERE id = ?")
        .bind(received_chunks as i64)
        .bind(upload_id)
        .execute(pool)
        .await?;

    Ok(ReceiveChunkResult {
        upload_id: upload_id.to_string(),
        chunk_index,
        received_chunks,
        total_chunks,
    })
}

pub async fn complete_upload(
    pool: &DbPool,
    config: &AppConfig,
    unlock_state: &UnlockState,
    user_id: &str,
    library_id: &str,
    upload_id: &str,
    write_verify: bool,
) -> Result<UploadResult, AppError> {
    validate_upload_id(upload_id)?;
    let row = load_upload_row(pool, upload_id)
        .await?
        .ok_or(AppError::NotFound)?;

    if row.user_id != user_id || row.target_id != library_id {
        return Err(AppError::NotFound);
    }
    if is_expired(&row.expires_at) {
        return Err(AppError::Validation("Upload session has expired.".into()));
    }

    let total_chunks = row.total_chunks as u32;
    let total_bytes = row.total_bytes as u64;

    // Build ordered list of chunk paths — do NOT read them into memory.
    let chunk_paths: Vec<PathBuf> = (0..total_chunks)
        .map(|idx| chunk_path(config, upload_id, idx))
        .collect();

    // Verify every chunk file is present before we start writing.
    for (idx, path) in chunk_paths.iter().enumerate() {
        if !tokio::fs::try_exists(path).await.unwrap_or(false) {
            return Err(AppError::Validation(format!("Missing chunk {}.", idx)));
        }
    }

    // Streaming encrypt: reads each chunk file, encrypts segment-by-segment,
    // and writes the STREAM format. RAM stays bounded to one chunk.
    let upload = fs_service::upload_file_streaming(
        config,
        unlock_state,
        library_id,
        &row.target_path,
        &chunk_paths,
        total_bytes,
        write_verify,
    )
    .await?;

    let _ = tokio::fs::remove_dir_all(staging_dir(config, upload_id)).await;
    let _ = sqlx::query("DELETE FROM chunked_uploads WHERE id = ?")
        .bind(upload_id)
        .execute(pool)
        .await;

    Ok(upload)
}

pub async fn cancel_upload(
    pool: &DbPool,
    config: &AppConfig,
    user_id: &str,
    library_id: &str,
    upload_id: &str,
) -> Result<(), AppError> {
    validate_upload_id(upload_id)?;
    let row = load_upload_row(pool, upload_id)
        .await?
        .ok_or(AppError::NotFound)?;

    if row.user_id != user_id || row.target_id != library_id {
        return Err(AppError::NotFound);
    }

    let _ = tokio::fs::remove_dir_all(staging_dir(config, upload_id)).await;
    sqlx::query("DELETE FROM chunked_uploads WHERE id = ?")
        .bind(upload_id)
        .execute(pool)
        .await?;

    Ok(())
}

pub async fn init_download(
    config: &AppConfig,
    unlock_state: &UnlockState,
    user_id: &str,
    library_id: &str,
    path: &str,
) -> Result<InitDownloadResult, AppError> {
    let download = fs_service::download_file(config, unlock_state, library_id, path).await?;
    let total_bytes = download.data.len() as u64;
    let total_chunks = expected_total_chunks(total_bytes.max(1), config.chunk_size_bytes);
    let (token, expires_at) = build_download_token(&config.secret_key, user_id, library_id, path)?;

    Ok(InitDownloadResult {
        token,
        filename: download.filename,
        mime_type: download.mime_type,
        chunk_size_bytes: config.chunk_size_bytes,
        total_chunks,
        total_bytes,
        expires_at,
    })
}

pub async fn serve_chunk(
    config: &AppConfig,
    unlock_state: &UnlockState,
    user_id: &str,
    token: &str,
    chunk_index: u32,
) -> Result<ChunkDownloadResult, AppError> {
    let payload = verify_download_token(&config.secret_key, token)?;
    if payload.uid != user_id {
        return Err(AppError::Forbidden);
    }

    let DownloadResult {
        data,
        checksum_sha256,
        mime_type,
        filename: _,
    } = fs_service::download_file(config, unlock_state, &payload.lib, &payload.path).await?;

    let total_bytes = data.len() as u64;
    let total_chunks = expected_total_chunks(total_bytes.max(1), config.chunk_size_bytes);

    if chunk_index >= total_chunks {
        return Err(AppError::Validation("chunk_index out of range.".into()));
    }

    let start = (chunk_index as u64).saturating_mul(config.chunk_size_bytes) as usize;
    let end = std::cmp::min(start + config.chunk_size_bytes as usize, data.len());
    let chunk = if start >= data.len() {
        Vec::new()
    } else {
        data[start..end].to_vec()
    };

    Ok(ChunkDownloadResult {
        data: chunk,
        mime_type,
        checksum_sha256,
        chunk_index,
        total_chunks,
        total_bytes,
    })
}

/// Remove expired chunked upload sessions and their staging directories.
///
/// Call this during server startup and periodically to reclaim disk space
/// from abandoned uploads.
pub async fn cleanup_expired_uploads(pool: &DbPool, config: &AppConfig) -> Result<u64, AppError> {
    let now = Utc::now().format("%Y-%m-%d %H:%M:%S").to_string();

    let rows: Vec<(String,)> =
        sqlx::query_as("SELECT id FROM chunked_uploads WHERE expires_at < ?")
            .bind(&now)
            .fetch_all(pool)
            .await?;

    let mut cleaned = 0u64;
    for (upload_id,) in &rows {
        let dir = staging_dir(config, upload_id);
        if tokio::fs::try_exists(&dir).await.unwrap_or(false) {
            let _ = tokio::fs::remove_dir_all(&dir).await;
        }
        let _ = sqlx::query("DELETE FROM chunked_uploads WHERE id = ?")
            .bind(upload_id)
            .execute(pool)
            .await;
        cleaned += 1;
    }

    if cleaned > 0 {
        tracing::info!(count = cleaned, "Cleaned up expired chunked upload sessions");
    }

    Ok(cleaned)
}
