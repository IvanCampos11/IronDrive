use std::path::{Path, PathBuf};

use serde::Serialize;
use uuid::Uuid;

use crate::config::AppConfig;
use crate::db::DbPool;
use crate::errors::AppError;
use crate::services::crypto_service::{verify_file_integrity_async, IntegrityStatus};
use crate::services::unlock_state::UnlockState;

/// A row from the `integrity_events` table.
#[derive(Debug, Clone, sqlx::FromRow, Serialize)]
pub struct IntegrityEvent {
    pub id: String,
    pub target_type: String,
    pub target_id: String,
    pub file_path: String,
    pub event_type: String,
    pub details: Option<String>,
    pub detected_by: String,
    pub acknowledged: i32,
    pub created_at: String,
}

/// Insert an integrity event.
pub async fn record_event(
    pool: &DbPool,
    target_type: &str,
    target_id: &str,
    file_path: &str,
    event_type: &str,
    details: Option<&str>,
    detected_by: &str,
) -> Result<IntegrityEvent, AppError> {
    let id = Uuid::new_v4().to_string();

    let event = sqlx::query_as::<_, IntegrityEvent>(
        r#"
        INSERT INTO integrity_events (id, target_type, target_id, file_path, event_type, details, detected_by)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        RETURNING id, target_type, target_id, file_path, event_type, details, detected_by, acknowledged, created_at
        "#,
    )
    .bind(&id)
    .bind(target_type)
    .bind(target_id)
    .bind(file_path)
    .bind(event_type)
    .bind(details)
    .bind(detected_by)
    .fetch_one(pool)
    .await?;

    Ok(event)
}

/// List integrity events for a given target (library or space).
/// Unacknowledged events come first, then ordered by newest first.
pub async fn list_events(
    pool: &DbPool,
    target_type: &str,
    target_id: &str,
) -> Result<Vec<IntegrityEvent>, AppError> {
    let events = sqlx::query_as::<_, IntegrityEvent>(
        r#"
        SELECT id, target_type, target_id, file_path, event_type, details, detected_by, acknowledged, created_at
        FROM integrity_events
        WHERE target_type = ? AND target_id = ?
        ORDER BY acknowledged ASC, created_at DESC
        "#,
    )
    .bind(target_type)
    .bind(target_id)
    .fetch_all(pool)
    .await?;

    Ok(events)
}

/// List unacknowledged integrity events for a given target.
pub async fn list_unacknowledged(
    pool: &DbPool,
    target_type: &str,
    target_id: &str,
) -> Result<Vec<IntegrityEvent>, AppError> {
    let events = sqlx::query_as::<_, IntegrityEvent>(
        r#"
        SELECT id, target_type, target_id, file_path, event_type, details, detected_by, acknowledged, created_at
        FROM integrity_events
        WHERE target_type = ? AND target_id = ? AND acknowledged = 0
        ORDER BY created_at DESC
        "#,
    )
    .bind(target_type)
    .bind(target_id)
    .fetch_all(pool)
    .await?;

    Ok(events)
}

/// Mark an integrity event as acknowledged. Returns `true` if the row was updated.
pub async fn acknowledge_event(pool: &DbPool, event_id: &str) -> Result<bool, AppError> {
    let result = sqlx::query("UPDATE integrity_events SET acknowledged = 1 WHERE id = ? AND acknowledged = 0")
        .bind(event_id)
        .execute(pool)
        .await?;

    Ok(result.rows_affected() > 0)
}

// ---------------------------------------------------------------------------
// Scanning
// ---------------------------------------------------------------------------

/// Summary returned by `scan_library` / `scan_space`.
#[derive(Debug, Clone, Serialize)]
pub struct ScanResult {
    pub files_scanned: u64,
    pub failures_found: u64,
}

/// Internal metadata filename that should be skipped during scans.
const INTERNAL_META_FILENAME: &str = ".irondrive.meta";

/// Resolve the on-disk root directory for a library.
fn library_root(config: &AppConfig, library_id: &str) -> PathBuf {
    PathBuf::from(&config.data_dir)
        .join("libraries")
        .join(library_id)
}

/// Resolve the on-disk root directory for a space.
fn space_root(config: &AppConfig, space_id: &str) -> PathBuf {
    PathBuf::from(&config.data_dir)
        .join("spaces")
        .join(space_id)
}

/// Walk all files under a library, verify each, and record failures.
pub async fn scan_library(
    pool: &DbPool,
    config: &AppConfig,
    unlock_state: &UnlockState,
    library_id: &str,
) -> Result<ScanResult, AppError> {
    let root = library_root(config, library_id);
    let data_key = unlock_state.get_library_key(library_id);
    scan_directory(pool, "library", library_id, &root, &root, data_key.as_ref()).await
}

/// Walk all files under a space, verify each, and record failures.
pub async fn scan_space(
    pool: &DbPool,
    config: &AppConfig,
    unlock_state: &UnlockState,
    space_id: &str,
) -> Result<ScanResult, AppError> {
    let root = space_root(config, space_id);
    let data_key = unlock_state.get_space_key(space_id);
    scan_directory(pool, "space", space_id, &root, &root, data_key.as_ref()).await
}

/// Recursive directory walker that verifies every file and records integrity events.
///
/// Uses an iterative stack (like `calculate_usage`) to avoid recursion depth limits.
/// Sleeps 10 ms between files to avoid starving request handling.
async fn scan_directory(
    pool: &DbPool,
    target_type: &str,
    target_id: &str,
    root: &Path,
    start: &Path,
    data_key: Option<&crate::services::crypto_service::DataKey>,
) -> Result<ScanResult, AppError> {
    use tokio::fs;

    let mut files_scanned: u64 = 0;
    let mut failures_found: u64 = 0;
    let mut stack = vec![start.to_path_buf()];

    while let Some(dir) = stack.pop() {
        let mut read_dir = match fs::read_dir(&dir).await {
            Ok(rd) => rd,
            Err(e) => {
                tracing::warn!(
                    path = %dir.display(),
                    error = %e,
                    "Skipping unreadable directory during integrity scan"
                );
                continue;
            }
        };

        while let Ok(Some(entry)) = read_dir.next_entry().await {
            let name = entry.file_name();
            let name_str = name.to_string_lossy();

            // Skip internal/hidden files (same rules as list_directory / calculate_usage).
            if name_str == INTERNAL_META_FILENAME || name_str.starts_with('.') {
                continue;
            }

            let entry_meta = match entry.metadata().await {
                Ok(m) => m,
                Err(e) => {
                    tracing::warn!(
                        path = %entry.path().display(),
                        error = %e,
                        "Skipping unreadable entry during integrity scan"
                    );
                    continue;
                }
            };

            if entry_meta.is_dir() {
                stack.push(entry.path());
            } else if entry_meta.is_file() {
                let file_path = entry.path();
                let status = verify_file_integrity_async(data_key, &file_path).await;
                files_scanned += 1;

                match status {
                    IntegrityStatus::Ok => {}
                    IntegrityStatus::FileHashMismatch => {
                        let rel = relative_path(root, &file_path);
                        if let Err(e) = record_event(
                            pool,
                            target_type,
                            target_id,
                            &rel,
                            "checksum_mismatch",
                            Some("File hash mismatch detected during background scan"),
                            "background_scan",
                        )
                        .await
                        {
                            tracing::error!(
                                file = %rel,
                                error = %e,
                                "Failed to record checksum_mismatch event"
                            );
                        }
                        failures_found += 1;
                    }
                    IntegrityStatus::DecryptionFailed(ref msg) => {
                        let rel = relative_path(root, &file_path);
                        let event_type = if msg.contains("truncated") || msg.contains("too small")
                        {
                            "file_truncated"
                        } else {
                            "decrypt_failed"
                        };
                        if let Err(e) = record_event(
                            pool,
                            target_type,
                            target_id,
                            &rel,
                            event_type,
                            Some(msg),
                            "background_scan",
                        )
                        .await
                        {
                            tracing::error!(
                                file = %rel,
                                error = %e,
                                "Failed to record {} event", event_type
                            );
                        }
                        failures_found += 1;
                    }
                }

                // Throttle to avoid starving request handling.
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
        }
    }

    Ok(ScanResult {
        files_scanned,
        failures_found,
    })
}

/// Turn an absolute path into a relative path string from `root`.
fn relative_path(root: &Path, full: &Path) -> String {
    full.strip_prefix(root)
        .unwrap_or(full)
        .to_string_lossy()
        .replace('\\', "/")
}
