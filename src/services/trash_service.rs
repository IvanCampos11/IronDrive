//! Trash: deleted files and folders kept for a while so they can be restored.
//!
//! Deleting moves the item to `<root>/.trash/<id>/<name>` — a rename on the
//! same filesystem, so it's instant and keeps the encrypted bytes untouched —
//! and records it in `trash_items`. Dot-prefixed paths can't be reached
//! through the file APIs and are skipped by listings, usage walks and the
//! integrity scanner, so trashed items stay out of sight. Trash counts toward
//! the owner's quota via `size_bytes`.

use std::path::{Path, PathBuf};

use serde::Serialize;
use tokio::fs;
use uuid::Uuid;

use crate::config::AppConfig;
use crate::db::DbPool;
use crate::errors::AppError;
use crate::services::fs_service::{self, TargetKind};

/// Hidden directory at the root of each library/space holding trashed items.
pub const TRASH_DIR: &str = ".trash";

#[derive(Debug, Clone, Serialize, sqlx::FromRow)]
pub struct TrashItem {
    pub id: String,
    pub target_type: String,
    pub target_id: String,
    pub original_path: String,
    pub is_dir: bool,
    pub size_bytes: i64,
    pub file_count: i64,
    pub deleted_by: Option<String>,
    pub deleted_at: String,
}

impl TrashItem {
    pub fn name(&self) -> &str {
        self.original_path
            .rsplit('/')
            .next()
            .unwrap_or(&self.original_path)
    }

    /// Folder the item was deleted from ("" for the root).
    pub fn parent(&self) -> &str {
        self.original_path
            .rsplit_once('/')
            .map(|(p, _)| p)
            .unwrap_or("")
    }
}

fn item_dir(root: &Path, id: &str) -> PathBuf {
    root.join(TRASH_DIR).join(id)
}

fn validate_id(id: &str) -> Result<(), AppError> {
    Uuid::parse_str(id)
        .map(|_| ())
        .map_err(|_| AppError::NotFound)
}

/// Move a file or folder into the trash. Returns the new trash entry.
pub async fn move_to_trash(
    pool: &DbPool,
    config: &AppConfig,
    kind: TargetKind,
    target_id: &str,
    user_path: &str,
    deleted_by: Option<&str>,
) -> Result<TrashItem, AppError> {
    if user_path.is_empty() {
        return Err(AppError::Validation(
            "Can't delete the top-level folder.".into(),
        ));
    }

    let root = fs_service::root_of(config, kind, target_id);
    let source = fs_service::safe_join_async(root.clone(), user_path.to_string()).await?;
    let meta = fs::metadata(&source).await.map_err(|e| {
        if e.kind() == std::io::ErrorKind::NotFound {
            AppError::NotFound
        } else {
            AppError::Internal(format!("Cannot read entry metadata: {e}"))
        }
    })?;

    // Same belt-and-braces check as permanent delete: never move the root.
    let canonical_root = fs_service::canonicalize_async(root.clone()).await?;
    let canonical_source = fs_service::canonicalize_async(source.clone()).await?;
    if !canonical_source.starts_with(&canonical_root) || canonical_source == canonical_root {
        return Err(AppError::Validation("Path escapes the root.".into()));
    }

    let usage = match kind {
        TargetKind::Library => fs_service::calculate_usage(config, target_id, user_path).await?,
        TargetKind::Space => {
            fs_service::calculate_space_usage(config, target_id, user_path).await?
        }
    };

    let id = Uuid::new_v4().to_string();
    let name = canonical_source
        .file_name()
        .ok_or_else(|| AppError::Internal("Entry has no name".into()))?
        .to_owned();
    let dir = item_dir(&canonical_root, &id);
    fs::create_dir_all(&dir)
        .await
        .map_err(|e| AppError::Internal(format!("Failed to create trash directory: {e}")))?;
    fs::rename(&canonical_source, dir.join(&name))
        .await
        .map_err(|e| AppError::Internal(format!("Failed to move entry to trash: {e}")))?;

    // Store the path as the user sees it (normalized separators).
    let original_path = user_path.replace('\\', "/");
    let inserted = sqlx::query_as::<_, TrashItem>(
        "INSERT INTO trash_items (id, target_type, target_id, original_path, is_dir, size_bytes, file_count, deleted_by)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)
         RETURNING id, target_type, target_id, original_path, is_dir, size_bytes, file_count, deleted_by, deleted_at",
    )
    .bind(&id)
    .bind(kind.as_str())
    .bind(target_id)
    .bind(&original_path)
    .bind(meta.is_dir())
    .bind(usage.disk_bytes as i64)
    .bind(usage.file_count as i64)
    .bind(deleted_by)
    .fetch_one(pool)
    .await;

    match inserted {
        Ok(item) => {
            tracing::info!(target_id, path = user_path, trash_id = %id, "Moved to trash");
            Ok(item)
        }
        Err(e) => {
            // Put it back so nothing goes missing without a record.
            let _ = fs::rename(dir.join(&name), &canonical_source).await;
            let _ = fs::remove_dir(&dir).await;
            Err(e.into())
        }
    }
}

/// Items in the trash of one library or space, newest first.
pub async fn list(
    pool: &DbPool,
    kind: TargetKind,
    target_id: &str,
) -> Result<Vec<TrashItem>, AppError> {
    Ok(sqlx::query_as::<_, TrashItem>(
        "SELECT id, target_type, target_id, original_path, is_dir, size_bytes, file_count, deleted_by, deleted_at
         FROM trash_items WHERE target_type = ? AND target_id = ?
         ORDER BY deleted_at DESC, rowid DESC",
    )
    .bind(kind.as_str())
    .bind(target_id)
    .fetch_all(pool)
    .await?)
}

async fn get(
    pool: &DbPool,
    kind: TargetKind,
    target_id: &str,
    id: &str,
) -> Result<TrashItem, AppError> {
    validate_id(id)?;
    sqlx::query_as::<_, TrashItem>(
        "SELECT id, target_type, target_id, original_path, is_dir, size_bytes, file_count, deleted_by, deleted_at
         FROM trash_items WHERE id = ? AND target_type = ? AND target_id = ?",
    )
    .bind(id)
    .bind(kind.as_str())
    .bind(target_id)
    .fetch_optional(pool)
    .await?
    .ok_or(AppError::NotFound)
}

/// A name that's free in `dir`: `name`, then `name (restored)`,
/// `name (restored 2)`, ... keeping the extension at the end.
async fn free_name(dir: &Path, name: &str, is_dir: bool) -> String {
    if !fs::try_exists(dir.join(name)).await.unwrap_or(true) {
        return name.to_string();
    }
    let (stem, ext) = match name.rfind('.') {
        Some(i) if i > 0 && !is_dir => (&name[..i], &name[i..]),
        _ => (name, ""),
    };
    for n in 1..1000 {
        let suffix = if n == 1 {
            " (restored)".to_string()
        } else {
            format!(" (restored {n})")
        };
        let candidate = format!("{stem}{suffix}{ext}");
        if !fs::try_exists(dir.join(&candidate)).await.unwrap_or(true) {
            return candidate;
        }
    }
    format!("{stem} ({}){ext}", Uuid::new_v4())
}

/// Put an item back where it was deleted from. Missing parent folders are
/// recreated; if the name is taken, the item is restored as "name (restored)".
/// Returns the path it was restored to.
pub async fn restore(
    pool: &DbPool,
    config: &AppConfig,
    kind: TargetKind,
    target_id: &str,
    id: &str,
) -> Result<String, AppError> {
    let item = get(pool, kind, target_id, id).await?;
    let root = fs_service::canonicalize_async(fs_service::root_of(config, kind, target_id)).await?;
    let source = item_dir(&root, id).join(item.name());
    if !fs::try_exists(&source).await.unwrap_or(false) {
        // The files are gone (e.g. removed by hand); drop the stale record.
        forget(pool, id).await?;
        return Err(AppError::NotFound);
    }

    // Recreate the parent folder if needed. If that's impossible (a file now
    // sits where a folder was), restore into the top level instead.
    let mut parent = item.parent().to_string();
    let parent_dir = if parent.is_empty() {
        root.clone()
    } else {
        match fs_service::safe_join_async(root.clone(), parent.clone()).await {
            Ok(dir) if fs::create_dir_all(&dir).await.is_ok() => dir,
            _ => {
                parent.clear();
                root.clone()
            }
        }
    };

    let name = free_name(&parent_dir, item.name(), item.is_dir).await;
    fs::rename(&source, parent_dir.join(&name))
        .await
        .map_err(|e| AppError::Internal(format!("Failed to restore from trash: {e}")))?;
    let _ = fs::remove_dir_all(item_dir(&root, id)).await;
    forget(pool, id).await?;

    let restored = if parent.is_empty() {
        name
    } else {
        format!("{parent}/{name}")
    };
    tracing::info!(target_id, path = %restored, trash_id = id, "Restored from trash");
    Ok(restored)
}

async fn forget(pool: &DbPool, id: &str) -> Result<(), AppError> {
    sqlx::query("DELETE FROM trash_items WHERE id = ?")
        .bind(id)
        .execute(pool)
        .await?;
    Ok(())
}

/// Remove one item from the trash permanently.
pub async fn delete_forever(
    pool: &DbPool,
    config: &AppConfig,
    kind: TargetKind,
    target_id: &str,
    id: &str,
) -> Result<(), AppError> {
    let item = get(pool, kind, target_id, id).await?;
    let root = fs_service::root_of(config, kind, target_id);
    remove_item_files(&root, &item.id).await?;
    forget(pool, &item.id).await
}

async fn remove_item_files(root: &Path, id: &str) -> Result<(), AppError> {
    match fs::remove_dir_all(item_dir(root, id)).await {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(AppError::Internal(format!(
            "Failed to delete trash item: {e}"
        ))),
    }
}

/// Permanently delete everything in one library's or space's trash.
/// Returns how many items were removed.
pub async fn empty(
    pool: &DbPool,
    config: &AppConfig,
    kind: TargetKind,
    target_id: &str,
) -> Result<usize, AppError> {
    let items = list(pool, kind, target_id).await?;
    let root = fs_service::root_of(config, kind, target_id);
    for item in &items {
        remove_item_files(&root, &item.id).await?;
        forget(pool, &item.id).await?;
    }
    Ok(items.len())
}

/// Drop the trash records of a space that is being deleted (its directory,
/// trash included, is removed by the caller).
pub async fn forget_space(pool: &DbPool, space_id: &str) -> Result<(), AppError> {
    sqlx::query("DELETE FROM trash_items WHERE target_type = 'space' AND target_id = ?")
        .bind(space_id)
        .execute(pool)
        .await?;
    Ok(())
}

/// Permanently delete items that have been in the trash longer than
/// `retention_days` (0 disables). Returns how many were removed.
pub async fn purge_expired(
    pool: &DbPool,
    config: &AppConfig,
    retention_days: u64,
) -> Result<usize, AppError> {
    if retention_days == 0 {
        return Ok(0);
    }
    let expired: Vec<TrashItem> = sqlx::query_as(
        "SELECT id, target_type, target_id, original_path, is_dir, size_bytes, file_count, deleted_by, deleted_at
         FROM trash_items WHERE deleted_at < datetime('now', ?)",
    )
    .bind(format!("-{retention_days} days"))
    .fetch_all(pool)
    .await?;

    let mut removed = 0;
    for item in &expired {
        let Some(kind) = TargetKind::parse(&item.target_type) else {
            continue;
        };
        let root = fs_service::root_of(config, kind, &item.target_id);
        match remove_item_files(&root, &item.id).await {
            Ok(()) => {
                forget(pool, &item.id).await?;
                removed += 1;
            }
            Err(e) => tracing::warn!(trash_id = %item.id, error = %e, "Could not purge trash item"),
        }
    }
    Ok(removed)
}
