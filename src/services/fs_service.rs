use std::path::{Path, PathBuf};

use serde::Serialize;
use tokio::fs;

use crate::config::AppConfig;
use crate::errors::AppError;
use crate::services::crypto_service::{
    self, encrypt_and_write_file_owned, read_and_decrypt_file, stream_encrypt_chunks_to_file,
    verify_file_integrity_async, DataKey, IntegrityStatus,
};
use crate::services::unlock_state::UnlockState;
use crate::utils::mime::mime_from_filename;
use crate::utils::path_safety::safe_join;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Files written by IronDrive into library root directories. We skip these
/// when listing directory contents so they never appear to the user.
const INTERNAL_META_FILENAME: &str = ".irondrive.meta";

// ---------------------------------------------------------------------------
// Response types
// ---------------------------------------------------------------------------

/// A single filesystem entry as returned by list/info operations.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct FsEntry {
    pub name: String,
    pub path: String,
    pub is_dir: bool,
    /// Size in bytes of the *plaintext* content. `None` for directories.
    pub size: Option<u64>,
    /// Size in bytes of the *encrypted* file on disk. `None` for directories.
    pub disk_size: Option<u64>,
    /// MIME type inferred from extension. `None` for directories or unknown.
    pub mime_type: Option<String>,
    /// ISO-8601 modified timestamp (from filesystem metadata).
    pub modified: Option<String>,
    /// Integrity status. Only populated when explicitly requested.
    pub integrity: Option<String>,
}

/// Result of [`upload_file`].
#[derive(Debug, Clone, Serialize)]
pub struct UploadResult {
    pub path: String,
    pub size: u64,
    pub disk_size: u64,
    /// Plaintext SHA-256 hex digest, computed on the fly for API responses.
    /// Empty for streaming uploads (computing it would defeat the point).
    pub checksum_sha256: String,
    pub mime_type: Option<String>,
}

/// Result of [`download_file`].
#[derive(Debug)]
pub struct DownloadResult {
    /// Decrypted plaintext bytes.
    pub data: Vec<u8>,
    /// SHA-256 hex digest of the plaintext (for `X-IronDrive-Integrity` header).
    pub checksum_sha256: String,
    pub mime_type: Option<String>,
    pub filename: String,
}

/// Result of [`calculate_usage`].
#[derive(Debug, Clone, Serialize)]
pub struct UsageResult {
    /// Total plaintext size is not available without decryption, so we
    /// report the on-disk (encrypted) size which is what matters for quotas.
    pub disk_bytes: u64,
    pub file_count: u64,
    pub dir_count: u64,
}

/// Result of [`rename_entry`].
#[derive(Debug, Clone, Serialize)]
pub struct RenameResult {
    pub old_path: String,
    pub new_path: String,
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Resolve the on-disk root directory for a library.
fn library_root(config: &AppConfig, library_id: &str) -> PathBuf {
    PathBuf::from(&config.data_dir)
        .join("libraries")
        .join(library_id)
}

/// Retrieve the data key for a library from [`UnlockState`], returning
/// [`AppError::Locked`] if it's not available.
fn require_data_key(unlock_state: &UnlockState, library_id: &str) -> Result<DataKey, AppError> {
    unlock_state
        .get_library_key(library_id)
        .ok_or(AppError::Locked)
}

/// Like `require_data_key` but returns `None` instead of erroring when
/// the library is locked. Used for integrity checks that can fall back
/// to key-free mode.
fn try_data_key(unlock_state: &UnlockState, library_id: &str) -> Option<DataKey> {
    unlock_state.get_library_key(library_id)
}

/// Turn a canonical on-disk path back into a user-facing relative path
/// (relative to `root`). Returns `""` if the path equals root.
fn relative_display_path(root: &Path, full: &Path) -> String {
    full.strip_prefix(root)
        .unwrap_or(full)
        .to_string_lossy()
        .replace('\\', "/")
}

/// Format a [`std::time::SystemTime`] as an RFC-3339 / ISO-8601 string.
fn format_system_time(t: std::time::SystemTime) -> String {
    let duration = t.duration_since(std::time::UNIX_EPOCH).unwrap_or_default();
    let secs = duration.as_secs();

    // Simple UTC timestamp without pulling in chrono for this one use.
    // Format: "2024-01-15T12:30:45Z"
    let days_since_epoch = secs / 86400;
    let time_of_day = secs % 86400;
    let hours = time_of_day / 3600;
    let minutes = (time_of_day % 3600) / 60;
    let seconds = time_of_day % 60;

    // Convert days since epoch to year-month-day (Gregorian).
    let (year, month, day) = days_to_ymd(days_since_epoch);

    format!("{year:04}-{month:02}-{day:02}T{hours:02}:{minutes:02}:{seconds:02}Z")
}

/// Convert days since Unix epoch to (year, month, day).
fn days_to_ymd(days: u64) -> (u64, u64, u64) {
    // Algorithm from Howard Hinnant's `civil_from_days`.
    let z = days as i64 + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = (z - era * 146097) as u64; // day of era [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365; // year of era [0, 399]
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // day of year [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let d = doy - (153 * mp + 2) / 5 + 1; // [1, 31]
    let m = if mp < 10 { mp + 3 } else { mp - 9 }; // [1, 12]
    let y = if m <= 2 { y + 1 } else { y };
    (y.max(0) as u64, m, d)
}

/// Check whether a filename is an internal IronDrive metadata file that
/// should be hidden from user-facing listings.
fn is_internal_file(name: &str) -> bool {
    name == INTERNAL_META_FILENAME
}

/// Compute the plaintext size from an encrypted single-shot blob length.
/// Format: SINGLE_MAGIC(3) + nonce(12) + ciphertext+tag(N+16) + file_hash(32) = N + 63
/// So plaintext = encrypted_len - 63, clamped to 0 for safety.
const ENCRYPTION_OVERHEAD: u64 = 3 + 12 + 16 + 32; // 63 bytes

fn plaintext_size_from_disk(disk_size: u64) -> u64 {
    disk_size.saturating_sub(ENCRYPTION_OVERHEAD)
}

/// Async wrapper for [`safe_join`] — moves the blocking path validation
/// (which calls `std::fs::canonicalize` and `std::fs::symlink_metadata`)
/// onto a blocking thread pool.
async fn safe_join_async(root: PathBuf, user_path: String) -> Result<PathBuf, AppError> {
    tokio::task::spawn_blocking(move || safe_join(&root, &user_path))
        .await
        .map_err(|e| AppError::Internal(format!("Path validation task failed: {e}")))?
}

/// Async wrapper for [`std::fs::canonicalize`].
async fn canonicalize_async(path: PathBuf) -> Result<PathBuf, AppError> {
    tokio::task::spawn_blocking(move || {
        std::fs::canonicalize(&path)
            .map_err(|e| AppError::Internal(format!("Cannot resolve path: {e}")))
    })
    .await
    .map_err(|e| AppError::Internal(format!("Canonicalize task failed: {e}")))?
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// List the contents of a directory inside a library.
///
/// `user_path` is relative to the library root (e.g. `""` or `"docs/reports"`).
/// An empty string lists the library root.
pub async fn list_directory(
    config: &AppConfig,
    unlock_state: &UnlockState,
    library_id: &str,
    user_path: &str,
    check_integrity: bool,
) -> Result<Vec<FsEntry>, AppError> {
    // Try to get the data key. If locked, integrity checks fall back to
    // key-free file hash only (instead of erroring).
    let data_key = if check_integrity {
        try_data_key(unlock_state, library_id)
    } else {
        None
    };

    let root = library_root(config, library_id);

    let canonical_root = canonicalize_async(root.clone()).await?;
    let target = if user_path.is_empty() {
        canonical_root.clone()
    } else {
        safe_join_async(root, user_path.to_string()).await?
    };

    // Verify target is a directory.
    let meta = fs::metadata(&target).await.map_err(|e| {
        if e.kind() == std::io::ErrorKind::NotFound {
            AppError::NotFound
        } else {
            AppError::Internal(format!("Cannot read directory metadata: {e}"))
        }
    })?;

    if !meta.is_dir() {
        return Err(AppError::Validation(
            "The specified path is not a directory.".into(),
        ));
    }

    let mut entries = Vec::new();
    let mut read_dir = fs::read_dir(&target)
        .await
        .map_err(|e| AppError::Internal(format!("Cannot read directory: {e}")))?;

    while let Some(dir_entry) = read_dir
        .next_entry()
        .await
        .map_err(|e| AppError::Internal(format!("Error reading directory entry: {e}")))?
    {
        let file_name = dir_entry.file_name();
        let name = file_name.to_string_lossy().to_string();

        // Skip internal files.
        if is_internal_file(&name) {
            continue;
        }

        // Skip dot-prefixed files (they shouldn't exist, but be defensive).
        if name.starts_with('.') {
            continue;
        }

        let entry_meta = dir_entry
            .metadata()
            .await
            .map_err(|e| AppError::Internal(format!("Cannot read metadata for '{name}': {e}")))?;

        let is_dir = entry_meta.is_dir();
        let disk_size = if is_dir { None } else { Some(entry_meta.len()) };
        let size = if is_dir {
            None
        } else {
            Some(plaintext_size_from_disk(entry_meta.len()))
        };

        let mime_type = if is_dir {
            None
        } else {
            mime_from_filename(&name)
        };

        let modified = entry_meta.modified().ok().map(format_system_time);

        let entry_path = dir_entry.path();
        let rel_path = relative_display_path(&canonical_root, &entry_path);

        let integrity = if check_integrity && !is_dir {
            let status = verify_file_integrity_async(data_key.as_ref(), &entry_path).await;
            Some(format_integrity_status(&status))
        } else {
            None
        };

        entries.push(FsEntry {
            name,
            path: rel_path,
            is_dir,
            size,
            disk_size,
            mime_type,
            modified,
            integrity,
        });
    }

    // Sort: directories first, then alphabetically by name (case-insensitive).
    entries.sort_by_cached_key(|e| (!e.is_dir, e.name.to_lowercase()));

    Ok(entries)
}

/// Create a directory (with parents) inside a library.
///
/// `user_path` is relative to the library root (e.g. `"photos/2024"`).
pub async fn create_directory(
    config: &AppConfig,
    library_id: &str,
    user_path: &str,
) -> Result<String, AppError> {
    if user_path.is_empty() {
        return Err(AppError::Validation(
            "Directory path must not be empty.".into(),
        ));
    }

    let root = library_root(config, library_id);
    let target = safe_join_async(root, user_path.to_string()).await?;

    // Attempt to create. If it already exists as a dir, that's fine.
    // If a file exists at this path, create_dir_all will fail.
    match fs::create_dir_all(&target).await {
        Ok(()) => {}
        Err(e) => {
            // Check if a file (not a directory) exists at the target path.
            if let Ok(meta) = fs::metadata(&target).await {
                if !meta.is_dir() {
                    return Err(AppError::Conflict(
                        "A file already exists at this path.".into(),
                    ));
                }
                // It's a directory — idempotent success (race: someone else created it).
            } else {
                return Err(AppError::Internal(format!(
                    "Failed to create directory: {e}"
                )));
            }
        }
    }

    Ok(user_path.to_string())
}

/// Upload (encrypt and write) a file into a library.
///
/// `user_path` is relative to the library root and should include the
/// filename (e.g. `"docs/report.pdf"`).
///
/// The `data` is the plaintext file content. It will be encrypted with
/// the library's data key and written to disk, followed by an optional
/// write-verify pass.
pub async fn upload_file(
    config: &AppConfig,
    unlock_state: &UnlockState,
    library_id: &str,
    user_path: &str,
    data: &[u8],
    write_verify: bool,
) -> Result<UploadResult, AppError> {
    upload_file_owned(
        config,
        unlock_state,
        library_id,
        user_path,
        data.to_vec(),
        write_verify,
    )
    .await
}

/// Upload (encrypt and write) a file into a library using owned plaintext.
///
/// This variant allows callers which already own large buffers (e.g. chunked
/// upload assembly) to avoid creating an additional full-size copy.
pub async fn upload_file_owned(
    config: &AppConfig,
    unlock_state: &UnlockState,
    library_id: &str,
    user_path: &str,
    data: Vec<u8>,
    write_verify: bool,
) -> Result<UploadResult, AppError> {
    if user_path.is_empty() {
        return Err(AppError::Validation("File path must not be empty.".into()));
    }

    let data_key = require_data_key(unlock_state, library_id)?;
    let root = library_root(config, library_id);
    let target = safe_join_async(root, user_path.to_string()).await?;

    // Ensure parent directory exists.
    if let Some(parent) = target.parent() {
        fs::create_dir_all(parent)
            .await
            .map_err(|e| AppError::Internal(format!("Failed to create parent directories: {e}")))?;
    }

    // Compute plaintext SHA-256 for the API response (not stored on disk).
    let checksum = crypto_service::sha256_bytes(&data);
    let checksum_hex = hex::encode(checksum);
    let plaintext_size = data.len() as u64;

    // Encrypt and write. If target is a directory, tokio::fs::write will fail
    // with an appropriate error.
    match encrypt_and_write_file_owned(&data_key, data, &target, write_verify).await {
        Ok(()) => {}
        Err(e) => {
            // Check if the target is a directory — that's a user-facing conflict.
            if let Ok(meta) = fs::metadata(&target).await {
                if meta.is_dir() {
                    return Err(AppError::Conflict(
                        "A directory already exists at this path.".into(),
                    ));
                }
            }
            return Err(e);
        }
    }

    // Read back the disk size.
    let disk_meta = fs::metadata(&target)
        .await
        .map_err(|e| AppError::Internal(format!("Failed to stat written file: {e}")))?;

    let filename = target
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_default();

    Ok(UploadResult {
        path: user_path.to_string(),
        size: plaintext_size,
        disk_size: disk_meta.len(),
        checksum_sha256: checksum_hex,
        mime_type: mime_from_filename(&filename),
    })
}

/// Upload (encrypt and write) a file into a library directly from chunk staging files.
///
/// Streaming path for large chunked uploads: chunk files are read, encrypted,
/// and written segment-by-segment without assembling the full plaintext into
/// memory. RAM usage is bounded to O(chunk_size).
pub async fn upload_file_streaming(
    config: &AppConfig,
    unlock_state: &UnlockState,
    library_id: &str,
    user_path: &str,
    chunk_paths: &[std::path::PathBuf],
    total_plaintext_bytes: u64,
    write_verify: bool,
) -> Result<UploadResult, AppError> {
    if user_path.is_empty() {
        return Err(AppError::Validation("File path must not be empty.".into()));
    }

    let data_key = require_data_key(unlock_state, library_id)?;
    let root = library_root(config, library_id);
    let target = safe_join_async(root, user_path.to_string()).await?;

    // Ensure parent directory exists.
    if let Some(parent) = target.parent() {
        fs::create_dir_all(parent)
            .await
            .map_err(|e| AppError::Internal(format!("Failed to create parent directories: {e}")))?;
    }

    stream_encrypt_chunks_to_file(
        &data_key,
        chunk_paths,
        total_plaintext_bytes,
        &target,
        write_verify,
    )
    .await?;

    let disk_meta = fs::metadata(&target)
        .await
        .map_err(|e| AppError::Internal(format!("Failed to stat written file: {e}")))?;

    let filename = target
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_default();

    Ok(UploadResult {
        path: user_path.to_string(),
        size: total_plaintext_bytes,
        disk_size: disk_meta.len(),
        checksum_sha256: String::new(),
        mime_type: mime_from_filename(&filename),
    })
}

/// Download (read and decrypt) a file from a library.
///
/// Returns the decrypted plaintext along with integrity metadata.
pub async fn download_file(
    config: &AppConfig,
    unlock_state: &UnlockState,
    library_id: &str,
    user_path: &str,
) -> Result<DownloadResult, AppError> {
    if user_path.is_empty() {
        return Err(AppError::Validation("File path must not be empty.".into()));
    }

    let data_key = require_data_key(unlock_state, library_id)?;
    let root = library_root(config, library_id);
    let target = safe_join_async(root, user_path.to_string()).await?;

    // Ensure it exists and is a file.
    let meta = fs::metadata(&target).await.map_err(|e| {
        if e.kind() == std::io::ErrorKind::NotFound {
            AppError::NotFound
        } else {
            AppError::Internal(format!("Cannot read file metadata: {e}"))
        }
    })?;

    if meta.is_dir() {
        return Err(AppError::Validation(
            "The specified path is a directory, not a file.".into(),
        ));
    }

    let plaintext = read_and_decrypt_file(&data_key, &target).await?;

    let checksum = crypto_service::sha256_bytes(&plaintext);
    let checksum_hex = hex::encode(checksum);

    let filename = target
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_default();

    Ok(DownloadResult {
        data: plaintext,
        checksum_sha256: checksum_hex,
        mime_type: mime_from_filename(&filename),
        filename,
    })
}

/// Delete a file or directory (recursively) from a library.
///
/// Refuses to delete the library root itself.
pub async fn delete_entry(
    config: &AppConfig,
    library_id: &str,
    user_path: &str,
) -> Result<(), AppError> {
    if user_path.is_empty() {
        return Err(AppError::Validation(
            "Cannot delete the library root.".into(),
        ));
    }

    let root = library_root(config, library_id);
    let target = safe_join_async(root.clone(), user_path.to_string()).await?;

    // Check existence first — this gives a clean NotFound before we try
    // to canonicalize (which would fail on a nonexistent path).
    let meta = fs::metadata(&target).await.map_err(|e| {
        if e.kind() == std::io::ErrorKind::NotFound {
            AppError::NotFound
        } else {
            AppError::Internal(format!("Cannot read entry metadata: {e}"))
        }
    })?;

    // Belt-and-suspenders: verify the resolved path is strictly inside the
    // library root. safe_join already checks this, but a bug there would be
    // catastrophic for delete_entry.
    let canonical_root = canonicalize_async(root).await?;
    let canonical_target = canonicalize_async(target.clone()).await?;
    if !canonical_target.starts_with(&canonical_root) || canonical_target == canonical_root {
        return Err(AppError::Validation(
            "Path escapes the library root.".into(),
        ));
    }

    tracing::info!(
        library_id = library_id,
        path = user_path,
        is_dir = meta.is_dir(),
        "Deleting entry"
    );

    if meta.is_dir() {
        fs::remove_dir_all(&target)
            .await
            .map_err(|e| AppError::Internal(format!("Failed to remove directory: {e}")))?;
    } else {
        fs::remove_file(&target)
            .await
            .map_err(|e| AppError::Internal(format!("Failed to remove file: {e}")))?;
    }

    Ok(())
}

/// Rename or move an entry within the same library.
///
/// Both `old_path` and `new_path` are relative to the library root.
pub async fn rename_entry(
    config: &AppConfig,
    library_id: &str,
    old_path: &str,
    new_path: &str,
) -> Result<RenameResult, AppError> {
    if old_path.is_empty() {
        return Err(AppError::Validation(
            "Cannot rename the library root.".into(),
        ));
    }
    if new_path.is_empty() {
        return Err(AppError::Validation("New path must not be empty.".into()));
    }

    let root = library_root(config, library_id);
    let source = safe_join_async(root.clone(), old_path.to_string()).await?;
    let dest = safe_join_async(root, new_path.to_string()).await?;

    // Pre-flight checks. Note: there is a small TOCTOU window between these
    // checks and the rename below. On Linux, rename(2) atomically replaces
    // the destination, so the worst case is an unexpected overwrite — not a
    // security issue since both paths are validated by safe_join.

    // Source must exist.
    if !fs::try_exists(&source).await.unwrap_or(false) {
        return Err(AppError::NotFound);
    }

    // Destination must not already exist.
    if fs::try_exists(&dest).await.unwrap_or(false) {
        return Err(AppError::Conflict(
            "An entry already exists at the destination path.".into(),
        ));
    }

    // Ensure destination parent exists.
    if let Some(parent) = dest.parent() {
        fs::create_dir_all(parent).await.map_err(|e| {
            AppError::Internal(format!(
                "Failed to create destination parent directories: {e}"
            ))
        })?;
    }

    fs::rename(&source, &dest)
        .await
        .map_err(|e| AppError::Internal(format!("Failed to rename entry: {e}")))?;

    Ok(RenameResult {
        old_path: old_path.to_string(),
        new_path: new_path.to_string(),
    })
}

/// Get info about a single file or directory, optionally checking integrity.
pub async fn get_entry_info(
    config: &AppConfig,
    unlock_state: &UnlockState,
    library_id: &str,
    user_path: &str,
    check_integrity: bool,
) -> Result<FsEntry, AppError> {
    let root = library_root(config, library_id);

    let canonical_root = canonicalize_async(root.clone()).await?;
    let target = if user_path.is_empty() {
        canonical_root.clone()
    } else {
        safe_join_async(root, user_path.to_string()).await?
    };

    let meta = fs::metadata(&target).await.map_err(|e| {
        if e.kind() == std::io::ErrorKind::NotFound {
            AppError::NotFound
        } else {
            AppError::Internal(format!("Cannot read entry metadata: {e}"))
        }
    })?;

    let is_dir = meta.is_dir();
    let disk_size = if is_dir { None } else { Some(meta.len()) };
    let size = if is_dir {
        None
    } else {
        Some(plaintext_size_from_disk(meta.len()))
    };

    let name = target
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_default();

    let mime_type = if is_dir {
        None
    } else {
        mime_from_filename(&name)
    };

    let modified = meta.modified().ok().map(format_system_time);

    let rel_path = relative_display_path(&canonical_root, &target);

    let integrity = if check_integrity && !is_dir {
        let dk = try_data_key(unlock_state, library_id);
        let status = verify_file_integrity_async(dk.as_ref(), &target).await;
        Some(format_integrity_status(&status))
    } else {
        None
    };

    Ok(FsEntry {
        name,
        path: rel_path,
        is_dir,
        size,
        disk_size,
        mime_type,
        modified,
        integrity,
    })
}

/// Walk a directory tree and sum up disk usage.
///
/// If `user_path` is empty, walks the entire library root.
///
/// **Note:** Internal metadata files (`.irondrive.meta`) and dot-prefixed
/// entries are excluded from the count. Reported `disk_bytes` reflects the
/// encrypted on-disk size of user-visible files only.
pub async fn calculate_usage(
    config: &AppConfig,
    library_id: &str,
    user_path: &str,
) -> Result<UsageResult, AppError> {
    let root = library_root(config, library_id);

    let target = if user_path.is_empty() {
        canonicalize_async(root.clone()).await?
    } else {
        safe_join_async(root, user_path.to_string()).await?
    };

    let meta = fs::metadata(&target).await.map_err(|e| {
        if e.kind() == std::io::ErrorKind::NotFound {
            AppError::NotFound
        } else {
            AppError::Internal(format!("Cannot read entry metadata: {e}"))
        }
    })?;

    if !meta.is_dir() {
        // Single file — return its size.
        return Ok(UsageResult {
            disk_bytes: meta.len(),
            file_count: 1,
            dir_count: 0,
        });
    }

    // Iterative tree walk using a stack (avoids recursion depth limits).
    let mut stack = vec![target];
    let mut disk_bytes: u64 = 0;
    let mut file_count: u64 = 0;
    let mut dir_count: u64 = 0;

    while let Some(dir) = stack.pop() {
        let mut read_dir = match fs::read_dir(&dir).await {
            Ok(rd) => rd,
            Err(e) => {
                tracing::warn!(
                    path = %dir.display(),
                    error = %e,
                    "Skipping unreadable directory during usage calculation"
                );
                continue;
            }
        };

        while let Ok(Some(entry)) = read_dir.next_entry().await {
            let name = entry.file_name();
            let name_str = name.to_string_lossy();

            // Skip internal/hidden files.
            if is_internal_file(&name_str) || name_str.starts_with('.') {
                continue;
            }

            let entry_meta = match entry.metadata().await {
                Ok(m) => m,
                Err(e) => {
                    tracing::warn!(
                        path = %entry.path().display(),
                        error = %e,
                        "Skipping unreadable entry during usage calculation"
                    );
                    continue;
                }
            };

            if entry_meta.is_dir() {
                dir_count = dir_count.saturating_add(1);
                stack.push(entry.path());
            } else if entry_meta.is_file() {
                file_count = file_count.saturating_add(1);
                disk_bytes = disk_bytes.saturating_add(entry_meta.len());
            }
            // Symlinks and other types are silently skipped.
        }
    }

    Ok(UsageResult {
        disk_bytes,
        file_count,
        dir_count,
    })
}

// ---------------------------------------------------------------------------
// Integrity formatting
// ---------------------------------------------------------------------------

fn format_integrity_status(status: &IntegrityStatus) -> String {
    match status {
        IntegrityStatus::Ok => "ok".to_string(),
        IntegrityStatus::FileHashMismatch => "file_hash_mismatch".to_string(),
        IntegrityStatus::DecryptionFailed(msg) => format!("decryption_failed: {msg}"),
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::services::crypto_service::{encrypt_file_bytes, generate_data_key};
    use crate::services::unlock_state::UnlockState;
    use tempfile::TempDir;

    /// Build a minimal AppConfig pointing at a temp directory.
    fn test_config(tmp: &TempDir) -> AppConfig {
        AppConfig {
            secret_key: "dGVzdC1rZXktZm9yLXVuaXQtdGVzdHM=".into(),
            data_dir: tmp.path().to_string_lossy().to_string(),
            db_dir: tmp.path().join("db").to_string_lossy().to_string(),
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

    /// Create the library directory structure on disk and return its ID.
    async fn setup_library(tmp: &TempDir) -> String {
        let lib_id = "test-library-001";
        let lib_dir = tmp.path().join("libraries").join(lib_id);
        fs::create_dir_all(&lib_dir).await.unwrap();
        lib_id.to_string()
    }

    /// Create an UnlockState with a test data key inserted for the given library.
    fn setup_unlock_state(library_id: &str) -> (UnlockState, DataKey) {
        let state = UnlockState::new();
        let key = generate_data_key();
        state.insert_library_key(library_id, &key);

        // We need a second copy since insert consumed the reference.
        let key2 = state.get_library_key(library_id).unwrap();
        (state, key2)
    }

    /// Write a plaintext-encrypted file directly to disk for test setup.
    #[allow(dead_code)]
    async fn write_test_file(data_key: &DataKey, path: &Path, plaintext: &[u8]) {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).await.unwrap();
        }
        let blob = encrypt_file_bytes(data_key, plaintext).unwrap();
        fs::write(path, &blob).await.unwrap();
    }

    // ─── format_system_time ────────────────────────────────────────────

    #[test]
    fn format_epoch_zero() {
        let t = std::time::UNIX_EPOCH;
        assert_eq!(format_system_time(t), "1970-01-01T00:00:00Z");
    }

    #[test]
    fn format_known_timestamp() {
        // 2024-06-15 14:30:00 UTC = 1718458200
        let t = std::time::UNIX_EPOCH + std::time::Duration::from_secs(1718458200);
        let s = format_system_time(t);
        assert!(s.starts_with("2024-06-15"), "got: {s}");
        assert!(s.ends_with('Z'));
    }

    // ─── plaintext_size_from_disk ──────────────────────────────────────

    #[test]
    fn plaintext_size_normal() {
        assert_eq!(plaintext_size_from_disk(163), 100);
        assert_eq!(plaintext_size_from_disk(63), 0); // minimum encrypted file (empty plaintext)
    }

    #[test]
    fn plaintext_size_underflow_clamped() {
        assert_eq!(plaintext_size_from_disk(10), 0);
        assert_eq!(plaintext_size_from_disk(0), 0);
    }

    // ─── is_internal_file ──────────────────────────────────────────────

    #[test]
    fn internal_meta_detected() {
        assert!(is_internal_file(".irondrive.meta"));
    }

    #[test]
    fn regular_file_not_internal() {
        assert!(!is_internal_file("report.pdf"));
        assert!(!is_internal_file("photos"));
    }

    // ─── relative_display_path ─────────────────────────────────────────

    #[test]
    fn relative_path_basic() {
        let root = Path::new("/data/libraries/lib1");
        let full = Path::new("/data/libraries/lib1/docs/file.txt");
        assert_eq!(relative_display_path(root, full), "docs/file.txt");
    }

    #[test]
    fn relative_path_at_root() {
        let root = Path::new("/data/libraries/lib1");
        assert_eq!(relative_display_path(root, root), "");
    }

    // ─── create_directory ──────────────────────────────────────────────

    #[tokio::test]
    async fn create_directory_simple() {
        let tmp = TempDir::new().unwrap();
        let config = test_config(&tmp);
        let lib_id = setup_library(&tmp).await;

        let result = create_directory(&config, &lib_id, "photos").await;
        assert!(result.is_ok(), "got: {result:?}");
        assert_eq!(result.unwrap(), "photos");

        let dir = tmp.path().join("libraries").join(&lib_id).join("photos");
        assert!(dir.exists());
        assert!(dir.is_dir());
    }

    #[tokio::test]
    async fn create_directory_nested() {
        let tmp = TempDir::new().unwrap();
        let config = test_config(&tmp);
        let lib_id = setup_library(&tmp).await;

        let result = create_directory(&config, &lib_id, "a/b/c").await;
        assert!(result.is_ok());

        let dir = tmp.path().join("libraries").join(&lib_id).join("a/b/c");
        assert!(dir.exists());
    }

    #[tokio::test]
    async fn create_directory_idempotent() {
        let tmp = TempDir::new().unwrap();
        let config = test_config(&tmp);
        let lib_id = setup_library(&tmp).await;

        create_directory(&config, &lib_id, "photos").await.unwrap();
        let result = create_directory(&config, &lib_id, "photos").await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn create_directory_rejects_empty() {
        let tmp = TempDir::new().unwrap();
        let config = test_config(&tmp);
        let _ = setup_library(&tmp).await;

        let result = create_directory(&config, "test-library-001", "").await;
        assert!(matches!(result, Err(AppError::Validation(_))));
    }

    #[tokio::test]
    async fn create_directory_rejects_traversal() {
        let tmp = TempDir::new().unwrap();
        let config = test_config(&tmp);
        let lib_id = setup_library(&tmp).await;

        let result = create_directory(&config, &lib_id, "../escape").await;
        assert!(matches!(result, Err(AppError::Validation(_))));
    }

    // ─── upload_file / download_file roundtrip ─────────────────────────

    #[tokio::test]
    async fn upload_and_download_roundtrip() {
        let tmp = TempDir::new().unwrap();
        let config = test_config(&tmp);
        let lib_id = setup_library(&tmp).await;
        let (unlock_state, _dk) = setup_unlock_state(&lib_id);

        let plaintext = b"Hello, IronDrive!";
        let upload = upload_file(
            &config,
            &unlock_state,
            &lib_id,
            "hello.txt",
            plaintext,
            true,
        )
        .await
        .unwrap();

        assert_eq!(upload.path, "hello.txt");
        assert_eq!(upload.size, plaintext.len() as u64);
        assert!(upload.disk_size > upload.size); // encryption overhead
        assert_eq!(upload.mime_type, Some("text/plain".into()));
        assert!(!upload.checksum_sha256.is_empty());

        let download = download_file(&config, &unlock_state, &lib_id, "hello.txt")
            .await
            .unwrap();

        assert_eq!(download.data, plaintext);
        assert_eq!(download.checksum_sha256, upload.checksum_sha256);
        assert_eq!(download.filename, "hello.txt");
        assert_eq!(download.mime_type, Some("text/plain".into()));
    }

    #[tokio::test]
    async fn upload_creates_parent_dirs() {
        let tmp = TempDir::new().unwrap();
        let config = test_config(&tmp);
        let lib_id = setup_library(&tmp).await;
        let (unlock_state, _dk) = setup_unlock_state(&lib_id);

        let result = upload_file(
            &config,
            &unlock_state,
            &lib_id,
            "a/b/c/file.txt",
            b"nested",
            false,
        )
        .await;

        assert!(result.is_ok());
        let parent = tmp.path().join("libraries").join(&lib_id).join("a/b/c");
        assert!(parent.exists());
    }

    #[tokio::test]
    async fn upload_empty_file() {
        let tmp = TempDir::new().unwrap();
        let config = test_config(&tmp);
        let lib_id = setup_library(&tmp).await;
        let (unlock_state, _dk) = setup_unlock_state(&lib_id);

        let upload = upload_file(&config, &unlock_state, &lib_id, "empty.bin", b"", false)
            .await
            .unwrap();

        assert_eq!(upload.size, 0);
        assert!(upload.disk_size > 0); // magic + nonce + tag + file_hash

        let download = download_file(&config, &unlock_state, &lib_id, "empty.bin")
            .await
            .unwrap();
        assert!(download.data.is_empty());
    }

    #[tokio::test]
    async fn upload_overwrites_existing_file() {
        let tmp = TempDir::new().unwrap();
        let config = test_config(&tmp);
        let lib_id = setup_library(&tmp).await;
        let (unlock_state, _dk) = setup_unlock_state(&lib_id);

        upload_file(
            &config,
            &unlock_state,
            &lib_id,
            "file.txt",
            b"version 1",
            false,
        )
        .await
        .unwrap();

        upload_file(
            &config,
            &unlock_state,
            &lib_id,
            "file.txt",
            b"version 2",
            false,
        )
        .await
        .unwrap();

        let download = download_file(&config, &unlock_state, &lib_id, "file.txt")
            .await
            .unwrap();
        assert_eq!(download.data, b"version 2");
    }

    #[tokio::test]
    async fn upload_rejects_empty_path() {
        let tmp = TempDir::new().unwrap();
        let config = test_config(&tmp);
        let lib_id = setup_library(&tmp).await;
        let (unlock_state, _dk) = setup_unlock_state(&lib_id);

        let result = upload_file(&config, &unlock_state, &lib_id, "", b"data", false).await;
        assert!(matches!(result, Err(AppError::Validation(_))));
    }

    #[tokio::test]
    async fn upload_rejects_locked_library() {
        let tmp = TempDir::new().unwrap();
        let config = test_config(&tmp);
        let lib_id = setup_library(&tmp).await;
        let unlock_state = UnlockState::new(); // no keys loaded

        let result = upload_file(&config, &unlock_state, &lib_id, "file.txt", b"data", false).await;
        assert!(matches!(result, Err(AppError::Locked)));
    }

    #[tokio::test]
    async fn download_rejects_locked_library() {
        let tmp = TempDir::new().unwrap();
        let config = test_config(&tmp);
        let lib_id = setup_library(&tmp).await;
        let unlock_state = UnlockState::new();

        let result = download_file(&config, &unlock_state, &lib_id, "file.txt").await;
        assert!(matches!(result, Err(AppError::Locked)));
    }

    #[tokio::test]
    async fn download_nonexistent_file() {
        let tmp = TempDir::new().unwrap();
        let config = test_config(&tmp);
        let lib_id = setup_library(&tmp).await;
        let (unlock_state, _dk) = setup_unlock_state(&lib_id);

        let result = download_file(&config, &unlock_state, &lib_id, "no-such-file.txt").await;
        assert!(matches!(result, Err(AppError::NotFound)));
    }

    #[tokio::test]
    async fn download_directory_fails() {
        let tmp = TempDir::new().unwrap();
        let config = test_config(&tmp);
        let lib_id = setup_library(&tmp).await;
        let (unlock_state, _dk) = setup_unlock_state(&lib_id);

        create_directory(&config, &lib_id, "somedir").await.unwrap();

        let result = download_file(&config, &unlock_state, &lib_id, "somedir").await;
        assert!(matches!(result, Err(AppError::Validation(_))));
    }

    // ─── delete_entry ──────────────────────────────────────────────────

    #[tokio::test]
    async fn delete_file() {
        let tmp = TempDir::new().unwrap();
        let config = test_config(&tmp);
        let lib_id = setup_library(&tmp).await;
        let (unlock_state, _dk) = setup_unlock_state(&lib_id);

        upload_file(
            &config,
            &unlock_state,
            &lib_id,
            "to-delete.txt",
            b"bye",
            false,
        )
        .await
        .unwrap();

        delete_entry(&config, &lib_id, "to-delete.txt")
            .await
            .unwrap();

        let target = tmp
            .path()
            .join("libraries")
            .join(&lib_id)
            .join("to-delete.txt");
        assert!(!target.exists());
    }

    #[tokio::test]
    async fn delete_directory_recursive() {
        let tmp = TempDir::new().unwrap();
        let config = test_config(&tmp);
        let lib_id = setup_library(&tmp).await;
        let (unlock_state, _dk) = setup_unlock_state(&lib_id);

        upload_file(
            &config,
            &unlock_state,
            &lib_id,
            "dir/sub/file.txt",
            b"deep",
            false,
        )
        .await
        .unwrap();

        delete_entry(&config, &lib_id, "dir").await.unwrap();

        let target = tmp.path().join("libraries").join(&lib_id).join("dir");
        assert!(!target.exists());
    }

    #[tokio::test]
    async fn delete_nonexistent_returns_not_found() {
        let tmp = TempDir::new().unwrap();
        let config = test_config(&tmp);
        let lib_id = setup_library(&tmp).await;

        let result = delete_entry(&config, &lib_id, "ghost.txt").await;
        assert!(matches!(result, Err(AppError::NotFound)));
    }

    #[tokio::test]
    async fn delete_root_rejected() {
        let tmp = TempDir::new().unwrap();
        let config = test_config(&tmp);
        let lib_id = setup_library(&tmp).await;

        let result = delete_entry(&config, &lib_id, "").await;
        assert!(matches!(result, Err(AppError::Validation(_))));
    }

    // ─── rename_entry ──────────────────────────────────────────────────

    #[tokio::test]
    async fn rename_file() {
        let tmp = TempDir::new().unwrap();
        let config = test_config(&tmp);
        let lib_id = setup_library(&tmp).await;
        let (unlock_state, _dk) = setup_unlock_state(&lib_id);

        upload_file(
            &config,
            &unlock_state,
            &lib_id,
            "old-name.txt",
            b"content",
            false,
        )
        .await
        .unwrap();

        let result = rename_entry(&config, &lib_id, "old-name.txt", "new-name.txt")
            .await
            .unwrap();

        assert_eq!(result.old_path, "old-name.txt");
        assert_eq!(result.new_path, "new-name.txt");

        // Old gone, new exists.
        let old = tmp
            .path()
            .join("libraries")
            .join(&lib_id)
            .join("old-name.txt");
        let new = tmp
            .path()
            .join("libraries")
            .join(&lib_id)
            .join("new-name.txt");
        assert!(!old.exists());
        assert!(new.exists());

        // Download via new name still works.
        let dl = download_file(&config, &unlock_state, &lib_id, "new-name.txt")
            .await
            .unwrap();
        assert_eq!(dl.data, b"content");
    }

    #[tokio::test]
    async fn rename_move_to_subdirectory() {
        let tmp = TempDir::new().unwrap();
        let config = test_config(&tmp);
        let lib_id = setup_library(&tmp).await;
        let (unlock_state, _dk) = setup_unlock_state(&lib_id);

        upload_file(
            &config,
            &unlock_state,
            &lib_id,
            "file.txt",
            b"moving",
            false,
        )
        .await
        .unwrap();

        rename_entry(&config, &lib_id, "file.txt", "subdir/file.txt")
            .await
            .unwrap();

        let target = tmp
            .path()
            .join("libraries")
            .join(&lib_id)
            .join("subdir/file.txt");
        assert!(target.exists());
    }

    #[tokio::test]
    async fn rename_source_not_found() {
        let tmp = TempDir::new().unwrap();
        let config = test_config(&tmp);
        let lib_id = setup_library(&tmp).await;

        let result = rename_entry(&config, &lib_id, "ghost.txt", "new.txt").await;
        assert!(matches!(result, Err(AppError::NotFound)));
    }

    #[tokio::test]
    async fn rename_destination_exists_conflict() {
        let tmp = TempDir::new().unwrap();
        let config = test_config(&tmp);
        let lib_id = setup_library(&tmp).await;
        let (unlock_state, _dk) = setup_unlock_state(&lib_id);

        upload_file(&config, &unlock_state, &lib_id, "a.txt", b"aaa", false)
            .await
            .unwrap();
        upload_file(&config, &unlock_state, &lib_id, "b.txt", b"bbb", false)
            .await
            .unwrap();

        let result = rename_entry(&config, &lib_id, "a.txt", "b.txt").await;
        assert!(matches!(result, Err(AppError::Conflict(_))));
    }

    #[tokio::test]
    async fn rename_rejects_empty_old_path() {
        let tmp = TempDir::new().unwrap();
        let config = test_config(&tmp);
        let lib_id = setup_library(&tmp).await;

        let result = rename_entry(&config, &lib_id, "", "new.txt").await;
        assert!(matches!(result, Err(AppError::Validation(_))));
    }

    #[tokio::test]
    async fn rename_rejects_empty_new_path() {
        let tmp = TempDir::new().unwrap();
        let config = test_config(&tmp);
        let lib_id = setup_library(&tmp).await;

        let result = rename_entry(&config, &lib_id, "file.txt", "").await;
        assert!(matches!(result, Err(AppError::Validation(_))));
    }

    // ─── list_directory ────────────────────────────────────────────────

    #[tokio::test]
    async fn list_empty_directory() {
        let tmp = TempDir::new().unwrap();
        let config = test_config(&tmp);
        let lib_id = setup_library(&tmp).await;
        let unlock_state = UnlockState::new();

        let entries = list_directory(&config, &unlock_state, &lib_id, "", false)
            .await
            .unwrap();

        assert!(entries.is_empty());
    }

    #[tokio::test]
    async fn list_directory_with_files_and_dirs() {
        let tmp = TempDir::new().unwrap();
        let config = test_config(&tmp);
        let lib_id = setup_library(&tmp).await;
        let (unlock_state, _dk) = setup_unlock_state(&lib_id);

        upload_file(
            &config,
            &unlock_state,
            &lib_id,
            "readme.txt",
            b"hello",
            false,
        )
        .await
        .unwrap();

        create_directory(&config, &lib_id, "photos").await.unwrap();

        upload_file(
            &config,
            &unlock_state,
            &lib_id,
            "report.pdf",
            b"pdf-data",
            false,
        )
        .await
        .unwrap();

        let entries = list_directory(&config, &unlock_state, &lib_id, "", false)
            .await
            .unwrap();

        assert_eq!(entries.len(), 3);

        // Directories come first.
        assert!(entries[0].is_dir);
        assert_eq!(entries[0].name, "photos");

        // Files sorted alphabetically.
        assert!(!entries[1].is_dir);
        assert_eq!(entries[1].name, "readme.txt");

        assert!(!entries[2].is_dir);
        assert_eq!(entries[2].name, "report.pdf");
    }

    #[tokio::test]
    async fn list_hides_internal_meta_file() {
        let tmp = TempDir::new().unwrap();
        let config = test_config(&tmp);
        let lib_id = setup_library(&tmp).await;
        let unlock_state = UnlockState::new();

        // Write a .irondrive.meta file (like library_service does).
        let meta_path = tmp
            .path()
            .join("libraries")
            .join(&lib_id)
            .join(".irondrive.meta");
        fs::write(&meta_path, b"type = \"library\"").await.unwrap();

        let entries = list_directory(&config, &unlock_state, &lib_id, "", false)
            .await
            .unwrap();

        // Meta file should be hidden.
        assert!(entries.is_empty());
    }

    #[tokio::test]
    async fn list_subdirectory() {
        let tmp = TempDir::new().unwrap();
        let config = test_config(&tmp);
        let lib_id = setup_library(&tmp).await;
        let (unlock_state, _dk) = setup_unlock_state(&lib_id);

        upload_file(&config, &unlock_state, &lib_id, "docs/a.txt", b"aaa", false)
            .await
            .unwrap();

        upload_file(&config, &unlock_state, &lib_id, "docs/b.txt", b"bbb", false)
            .await
            .unwrap();

        let entries = list_directory(&config, &unlock_state, &lib_id, "docs", false)
            .await
            .unwrap();

        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].name, "a.txt");
        assert_eq!(entries[1].name, "b.txt");
    }

    #[tokio::test]
    async fn list_nonexistent_directory() {
        let tmp = TempDir::new().unwrap();
        let config = test_config(&tmp);
        let lib_id = setup_library(&tmp).await;
        let unlock_state = UnlockState::new();

        let result = list_directory(&config, &unlock_state, &lib_id, "nonexistent", false).await;
        assert!(matches!(result, Err(AppError::NotFound)));
    }

    #[tokio::test]
    async fn list_file_as_directory_fails() {
        let tmp = TempDir::new().unwrap();
        let config = test_config(&tmp);
        let lib_id = setup_library(&tmp).await;
        let (unlock_state, _dk) = setup_unlock_state(&lib_id);

        upload_file(&config, &unlock_state, &lib_id, "file.txt", b"data", false)
            .await
            .unwrap();

        let result = list_directory(&config, &unlock_state, &lib_id, "file.txt", false).await;
        assert!(matches!(result, Err(AppError::Validation(_))));
    }

    // ─── list_directory with integrity checking ────────────────────────

    #[tokio::test]
    async fn list_with_integrity_check() {
        let tmp = TempDir::new().unwrap();
        let config = test_config(&tmp);
        let lib_id = setup_library(&tmp).await;
        let (unlock_state, _dk) = setup_unlock_state(&lib_id);

        upload_file(
            &config,
            &unlock_state,
            &lib_id,
            "good.txt",
            b"intact",
            false,
        )
        .await
        .unwrap();

        let entries = list_directory(&config, &unlock_state, &lib_id, "", true)
            .await
            .unwrap();

        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].integrity, Some("ok".into()));
    }

    // ─── get_entry_info ────────────────────────────────────────────────

    #[tokio::test]
    async fn info_for_file() {
        let tmp = TempDir::new().unwrap();
        let config = test_config(&tmp);
        let lib_id = setup_library(&tmp).await;
        let (unlock_state, _dk) = setup_unlock_state(&lib_id);

        upload_file(
            &config,
            &unlock_state,
            &lib_id,
            "info-test.txt",
            b"some data here",
            false,
        )
        .await
        .unwrap();

        let info = get_entry_info(&config, &unlock_state, &lib_id, "info-test.txt", false)
            .await
            .unwrap();

        assert_eq!(info.name, "info-test.txt");
        assert!(!info.is_dir);
        assert_eq!(info.size, Some(14)); // "some data here".len()
        assert!(info.disk_size.unwrap() > 14);
        assert_eq!(info.mime_type, Some("text/plain".into()));
        assert!(info.modified.is_some());
        assert!(info.integrity.is_none());
    }

    #[tokio::test]
    async fn info_for_directory() {
        let tmp = TempDir::new().unwrap();
        let config = test_config(&tmp);
        let lib_id = setup_library(&tmp).await;
        let unlock_state = UnlockState::new();

        create_directory(&config, &lib_id, "my-dir").await.unwrap();

        let info = get_entry_info(&config, &unlock_state, &lib_id, "my-dir", false)
            .await
            .unwrap();

        assert_eq!(info.name, "my-dir");
        assert!(info.is_dir);
        assert!(info.size.is_none());
        assert!(info.disk_size.is_none());
        assert!(info.mime_type.is_none());
    }

    #[tokio::test]
    async fn info_for_root() {
        let tmp = TempDir::new().unwrap();
        let config = test_config(&tmp);
        let lib_id = setup_library(&tmp).await;
        let unlock_state = UnlockState::new();

        let info = get_entry_info(&config, &unlock_state, &lib_id, "", false)
            .await
            .unwrap();

        assert!(info.is_dir);
    }

    #[tokio::test]
    async fn info_not_found() {
        let tmp = TempDir::new().unwrap();
        let config = test_config(&tmp);
        let lib_id = setup_library(&tmp).await;
        let unlock_state = UnlockState::new();

        let result = get_entry_info(&config, &unlock_state, &lib_id, "nope.txt", false).await;
        assert!(matches!(result, Err(AppError::NotFound)));
    }

    #[tokio::test]
    async fn info_with_integrity_check() {
        let tmp = TempDir::new().unwrap();
        let config = test_config(&tmp);
        let lib_id = setup_library(&tmp).await;
        let (unlock_state, _dk) = setup_unlock_state(&lib_id);

        upload_file(
            &config,
            &unlock_state,
            &lib_id,
            "checked.txt",
            b"verify me",
            false,
        )
        .await
        .unwrap();

        let info = get_entry_info(&config, &unlock_state, &lib_id, "checked.txt", true)
            .await
            .unwrap();

        assert_eq!(info.integrity, Some("ok".into()));
    }

    #[tokio::test]
    async fn info_integrity_detects_tampered_file() {
        let tmp = TempDir::new().unwrap();
        let config = test_config(&tmp);
        let lib_id = setup_library(&tmp).await;
        let (unlock_state, _dk) = setup_unlock_state(&lib_id);

        upload_file(
            &config,
            &unlock_state,
            &lib_id,
            "tampered.txt",
            b"original",
            false,
        )
        .await
        .unwrap();

        // Tamper with the on-disk file by flipping some encrypted bytes.
        let file_path = tmp
            .path()
            .join("libraries")
            .join(&lib_id)
            .join("tampered.txt");
        let mut blob = fs::read(&file_path).await.unwrap();
        // Flip a byte in the ciphertext area (after magic + nonce).
        if blob.len() > 20 {
            blob[16] ^= 0xFF;
        }
        fs::write(&file_path, &blob).await.unwrap();

        let info = get_entry_info(&config, &unlock_state, &lib_id, "tampered.txt", true)
            .await
            .unwrap();

        assert!(info.integrity.is_some());
        let status = info.integrity.unwrap();
        // File hash check catches the tamper before decryption is even attempted.
        assert!(
            status.contains("file_hash_mismatch")
                || status.contains("decryption_failed"),
            "expected failure status, got: {status}"
        );
    }

    // ─── calculate_usage ───────────────────────────────────────────────

    #[tokio::test]
    async fn usage_empty_library() {
        let tmp = TempDir::new().unwrap();
        let config = test_config(&tmp);
        let lib_id = setup_library(&tmp).await;

        let usage = calculate_usage(&config, &lib_id, "").await.unwrap();
        assert_eq!(usage.disk_bytes, 0);
        assert_eq!(usage.file_count, 0);
        assert_eq!(usage.dir_count, 0);
    }

    #[tokio::test]
    async fn usage_with_files_and_dirs() {
        let tmp = TempDir::new().unwrap();
        let config = test_config(&tmp);
        let lib_id = setup_library(&tmp).await;
        let (unlock_state, _dk) = setup_unlock_state(&lib_id);

        upload_file(&config, &unlock_state, &lib_id, "file1.txt", b"aaaa", false)
            .await
            .unwrap();

        upload_file(
            &config,
            &unlock_state,
            &lib_id,
            "sub/file2.txt",
            b"bbbb",
            false,
        )
        .await
        .unwrap();

        create_directory(&config, &lib_id, "empty-dir")
            .await
            .unwrap();

        let usage = calculate_usage(&config, &lib_id, "").await.unwrap();

        assert_eq!(usage.file_count, 2);
        // "sub" + "empty-dir" = 2 directories
        assert_eq!(usage.dir_count, 2);
        assert!(usage.disk_bytes > 0);

        // Each encrypted file for 4 bytes of plaintext should be 4 + 60 = 64 bytes.
        let expected_size_per_file = 4 + ENCRYPTION_OVERHEAD;
        assert_eq!(usage.disk_bytes, expected_size_per_file * 2);
    }

    #[tokio::test]
    async fn usage_subdirectory_only() {
        let tmp = TempDir::new().unwrap();
        let config = test_config(&tmp);
        let lib_id = setup_library(&tmp).await;
        let (unlock_state, _dk) = setup_unlock_state(&lib_id);

        upload_file(
            &config,
            &unlock_state,
            &lib_id,
            "root-file.txt",
            b"root",
            false,
        )
        .await
        .unwrap();

        upload_file(
            &config,
            &unlock_state,
            &lib_id,
            "sub/inner.txt",
            b"inner",
            false,
        )
        .await
        .unwrap();

        let usage = calculate_usage(&config, &lib_id, "sub").await.unwrap();

        assert_eq!(usage.file_count, 1);
        assert_eq!(usage.dir_count, 0);
        assert_eq!(usage.disk_bytes, 5 + ENCRYPTION_OVERHEAD); // "inner".len() + overhead
    }

    #[tokio::test]
    async fn usage_single_file() {
        let tmp = TempDir::new().unwrap();
        let config = test_config(&tmp);
        let lib_id = setup_library(&tmp).await;
        let (unlock_state, _dk) = setup_unlock_state(&lib_id);

        upload_file(
            &config,
            &unlock_state,
            &lib_id,
            "solo.txt",
            b"just me",
            false,
        )
        .await
        .unwrap();

        let usage = calculate_usage(&config, &lib_id, "solo.txt").await.unwrap();
        assert_eq!(usage.file_count, 1);
        assert_eq!(usage.dir_count, 0);
        assert_eq!(usage.disk_bytes, 7 + ENCRYPTION_OVERHEAD);
    }

    #[tokio::test]
    async fn usage_nonexistent_path() {
        let tmp = TempDir::new().unwrap();
        let config = test_config(&tmp);
        let lib_id = setup_library(&tmp).await;

        let result = calculate_usage(&config, &lib_id, "ghost").await;
        assert!(matches!(result, Err(AppError::NotFound)));
    }

    #[tokio::test]
    async fn usage_skips_internal_meta() {
        let tmp = TempDir::new().unwrap();
        let config = test_config(&tmp);
        let lib_id = setup_library(&tmp).await;

        // Write a .irondrive.meta file.
        let meta_path = tmp
            .path()
            .join("libraries")
            .join(&lib_id)
            .join(".irondrive.meta");
        fs::write(&meta_path, b"type = \"library\"\n")
            .await
            .unwrap();

        let usage = calculate_usage(&config, &lib_id, "").await.unwrap();
        // Meta file should not be counted.
        assert_eq!(usage.file_count, 0);
        assert_eq!(usage.disk_bytes, 0);
    }

    // ─── Large file roundtrip ──────────────────────────────────────────

    #[tokio::test]
    async fn upload_download_large_file() {
        let tmp = TempDir::new().unwrap();
        let config = test_config(&tmp);
        let lib_id = setup_library(&tmp).await;
        let (unlock_state, _dk) = setup_unlock_state(&lib_id);

        let large_data: Vec<u8> = (0..100_000u32).flat_map(|i| i.to_le_bytes()).collect();

        upload_file(
            &config,
            &unlock_state,
            &lib_id,
            "large.bin",
            &large_data,
            true,
        )
        .await
        .unwrap();

        let dl = download_file(&config, &unlock_state, &lib_id, "large.bin")
            .await
            .unwrap();

        assert_eq!(dl.data.len(), large_data.len());
        assert_eq!(dl.data, large_data);
    }

    // ─── FsEntry fields ────────────────────────────────────────────────

    #[tokio::test]
    async fn list_entry_has_correct_mime_types() {
        let tmp = TempDir::new().unwrap();
        let config = test_config(&tmp);
        let lib_id = setup_library(&tmp).await;
        let (unlock_state, _dk) = setup_unlock_state(&lib_id);

        upload_file(
            &config,
            &unlock_state,
            &lib_id,
            "photo.jpg",
            b"jpeg-data",
            false,
        )
        .await
        .unwrap();

        upload_file(
            &config,
            &unlock_state,
            &lib_id,
            "doc.pdf",
            b"pdf-data",
            false,
        )
        .await
        .unwrap();

        let entries = list_directory(&config, &unlock_state, &lib_id, "", false)
            .await
            .unwrap();

        let pdf = entries.iter().find(|e| e.name == "doc.pdf").unwrap();
        assert_eq!(pdf.mime_type, Some("application/pdf".into()));

        let jpg = entries.iter().find(|e| e.name == "photo.jpg").unwrap();
        assert_eq!(jpg.mime_type, Some("image/jpeg".into()));
    }

    #[tokio::test]
    async fn list_entry_sizes_are_correct() {
        let tmp = TempDir::new().unwrap();
        let config = test_config(&tmp);
        let lib_id = setup_library(&tmp).await;
        let (unlock_state, _dk) = setup_unlock_state(&lib_id);

        let plaintext = b"exactly twenty bytes";
        assert_eq!(plaintext.len(), 20);

        upload_file(
            &config,
            &unlock_state,
            &lib_id,
            "sized.txt",
            plaintext,
            false,
        )
        .await
        .unwrap();

        let entries = list_directory(&config, &unlock_state, &lib_id, "", false)
            .await
            .unwrap();

        assert_eq!(entries.len(), 1);
        let entry = &entries[0];
        assert_eq!(entry.size, Some(20));
        assert_eq!(entry.disk_size, Some(20 + ENCRYPTION_OVERHEAD));
    }

    // ─── Path traversal guards ─────────────────────────────────────────

    #[tokio::test]
    async fn upload_rejects_traversal() {
        let tmp = TempDir::new().unwrap();
        let config = test_config(&tmp);
        let lib_id = setup_library(&tmp).await;
        let (unlock_state, _dk) = setup_unlock_state(&lib_id);

        let result = upload_file(
            &config,
            &unlock_state,
            &lib_id,
            "../escape.txt",
            b"bad",
            false,
        )
        .await;
        assert!(matches!(result, Err(AppError::Validation(_))));
    }

    #[tokio::test]
    async fn download_rejects_traversal() {
        let tmp = TempDir::new().unwrap();
        let config = test_config(&tmp);
        let lib_id = setup_library(&tmp).await;
        let (unlock_state, _dk) = setup_unlock_state(&lib_id);

        let result = download_file(&config, &unlock_state, &lib_id, "../etc/passwd").await;
        assert!(matches!(result, Err(AppError::Validation(_))));
    }

    #[tokio::test]
    async fn delete_rejects_traversal() {
        let tmp = TempDir::new().unwrap();
        let config = test_config(&tmp);
        let lib_id = setup_library(&tmp).await;

        let result = delete_entry(&config, &lib_id, "../other-lib").await;
        assert!(matches!(result, Err(AppError::Validation(_))));
    }

    #[tokio::test]
    async fn rename_rejects_traversal_in_source() {
        let tmp = TempDir::new().unwrap();
        let config = test_config(&tmp);
        let lib_id = setup_library(&tmp).await;

        let result = rename_entry(&config, &lib_id, "../escape.txt", "safe.txt").await;
        assert!(matches!(result, Err(AppError::Validation(_))));
    }

    #[tokio::test]
    async fn rename_rejects_traversal_in_dest() {
        let tmp = TempDir::new().unwrap();
        let config = test_config(&tmp);
        let lib_id = setup_library(&tmp).await;
        let (unlock_state, _dk) = setup_unlock_state(&lib_id);

        upload_file(&config, &unlock_state, &lib_id, "legit.txt", b"ok", false)
            .await
            .unwrap();

        let result = rename_entry(&config, &lib_id, "legit.txt", "../escape.txt").await;
        assert!(matches!(result, Err(AppError::Validation(_))));
    }

    // ─── Write-verify ──────────────────────────────────────────────────

    #[tokio::test]
    async fn upload_with_write_verify() {
        let tmp = TempDir::new().unwrap();
        let config = test_config(&tmp);
        let lib_id = setup_library(&tmp).await;
        let (unlock_state, _dk) = setup_unlock_state(&lib_id);

        let result = upload_file(
            &config,
            &unlock_state,
            &lib_id,
            "verified.txt",
            b"verified data",
            true,
        )
        .await;

        assert!(result.is_ok());
    }

    // ─── Upload rejects writing over a directory ───────────────────────

    #[tokio::test]
    async fn upload_rejects_directory_as_target() {
        let tmp = TempDir::new().unwrap();
        let config = test_config(&tmp);
        let lib_id = setup_library(&tmp).await;
        let (unlock_state, _dk) = setup_unlock_state(&lib_id);

        create_directory(&config, &lib_id, "mydir").await.unwrap();

        let result = upload_file(&config, &unlock_state, &lib_id, "mydir", b"bad", false).await;

        assert!(matches!(result, Err(AppError::Conflict(_))));
    }

    // ─── create_directory rejects file-as-target ───────────────────────

    #[tokio::test]
    async fn create_directory_rejects_existing_file() {
        let tmp = TempDir::new().unwrap();
        let config = test_config(&tmp);
        let lib_id = setup_library(&tmp).await;
        let (unlock_state, _dk) = setup_unlock_state(&lib_id);

        upload_file(&config, &unlock_state, &lib_id, "file.txt", b"data", false)
            .await
            .unwrap();

        let result = create_directory(&config, &lib_id, "file.txt").await;
        assert!(matches!(result, Err(AppError::Conflict(_))));
    }

    // ─── days_to_ymd ──────────────────────────────────────────────────

    #[test]
    fn days_to_ymd_epoch() {
        assert_eq!(days_to_ymd(0), (1970, 1, 1));
    }

    #[test]
    fn days_to_ymd_known_date() {
        // 2024-01-01 = day 19723
        assert_eq!(days_to_ymd(19723), (2024, 1, 1));
    }

    #[test]
    fn days_to_ymd_leap_day() {
        // 2024-02-29 = day 19782 (2024 is a leap year)
        assert_eq!(days_to_ymd(19782), (2024, 2, 29));
    }

    // ─── format_integrity_status ──────────────────────────────────────

    #[test]
    fn format_integrity_ok() {
        assert_eq!(format_integrity_status(&IntegrityStatus::Ok), "ok");
    }

    #[test]
    fn format_integrity_file_hash_mismatch() {
        assert_eq!(
            format_integrity_status(&IntegrityStatus::FileHashMismatch),
            "file_hash_mismatch"
        );
    }

    #[test]
    fn format_integrity_decryption_failed() {
        let s = format_integrity_status(&IntegrityStatus::DecryptionFailed("bad key".into()));
        assert!(s.starts_with("decryption_failed:"));
        assert!(s.contains("bad key"));
    }
}
