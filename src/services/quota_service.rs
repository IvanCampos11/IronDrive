//! Storage quotas.
//!
//! A user's quota covers everything they own: their personal library, spaces
//! owned by them, their trash, and chunked uploads still in progress (so
//! parallel uploads can't jointly overshoot). Group-owned spaces are not
//! charged to anyone. Sizes are on-disk (encrypted) bytes, matching what the
//! usage bars show.

use crate::config::AppConfig;
use crate::db::DbPool;
use crate::errors::AppError;
use crate::models::user::User;
use crate::services::fs_service::{self, TargetKind};

/// Where a user's storage goes. All values are on-disk bytes.
#[derive(Debug, Clone, Copy, Default, serde::Serialize)]
pub struct Usage {
    /// Files in the personal library.
    pub files: u64,
    /// Files in spaces the user owns.
    pub spaces: u64,
    /// Items in the user's trash and in the trash of spaces they own.
    pub trash: u64,
    /// Chunked uploads that have started but not finished.
    pub pending: u64,
}

impl Usage {
    pub fn total(&self) -> u64 {
        self.files + self.spaces + self.trash + self.pending
    }
}

/// The user whose quota pays for writes into a library or space, if any.
pub async fn quota_owner(
    pool: &DbPool,
    kind: TargetKind,
    target_id: &str,
) -> Result<Option<User>, AppError> {
    let user_id: Option<(String,)> = match kind {
        TargetKind::Library => {
            sqlx::query_as("SELECT user_id FROM personal_libraries WHERE id = ?")
                .bind(target_id)
                .fetch_optional(pool)
                .await?
        }
        TargetKind::Space => {
            sqlx::query_as("SELECT owner_id FROM spaces WHERE id = ? AND owner_type = 'user'")
                .bind(target_id)
                .fetch_optional(pool)
                .await?
        }
    };
    match user_id {
        Some((id,)) => User::find_by_id(pool, &id).await,
        None => Ok(None),
    }
}

/// Everything charged to `user_id`. `exclude_upload` leaves one in-progress
/// upload out of `pending` (used when that upload is the one being checked).
pub async fn usage_for_user(
    pool: &DbPool,
    config: &AppConfig,
    user_id: &str,
    exclude_upload: Option<&str>,
) -> Result<Usage, AppError> {
    let mut usage = Usage::default();

    let library: Option<(String,)> =
        sqlx::query_as("SELECT id FROM personal_libraries WHERE user_id = ?")
            .bind(user_id)
            .fetch_optional(pool)
            .await?;
    if let Some((library_id,)) = &library {
        usage.files = fs_service::calculate_usage(config, library_id, "")
            .await
            .map(|u| u.disk_bytes)
            .unwrap_or(0);
    }

    let spaces: Vec<(String,)> =
        sqlx::query_as("SELECT id FROM spaces WHERE owner_type = 'user' AND owner_id = ?")
            .bind(user_id)
            .fetch_all(pool)
            .await?;
    for (space_id,) in &spaces {
        usage.spaces += fs_service::calculate_space_usage(config, space_id, "")
            .await
            .map(|u| u.disk_bytes)
            .unwrap_or(0);
    }

    let (trash,): (i64,) = sqlx::query_as(
        "SELECT COALESCE(SUM(size_bytes), 0) FROM trash_items
         WHERE (target_type = 'library' AND target_id IN (SELECT id FROM personal_libraries WHERE user_id = ?1))
            OR (target_type = 'space' AND target_id IN (SELECT id FROM spaces WHERE owner_type = 'user' AND owner_id = ?1))",
    )
    .bind(user_id)
    .fetch_one(pool)
    .await?;
    usage.trash = trash.max(0) as u64;

    let (pending,): (i64,) = sqlx::query_as(
        "SELECT COALESCE(SUM(total_bytes), 0) FROM chunked_uploads
         WHERE expires_at > datetime('now') AND id != ?2
           AND ((target_type = 'library' AND target_id IN (SELECT id FROM personal_libraries WHERE user_id = ?1))
             OR (target_type = 'space' AND target_id IN (SELECT id FROM spaces WHERE owner_type = 'user' AND owner_id = ?1)))",
    )
    .bind(user_id)
    .bind(exclude_upload.unwrap_or(""))
    .fetch_one(pool)
    .await?;
    usage.pending = pending.max(0) as u64;

    Ok(usage)
}

/// On-disk size of a file with `plaintext` bytes once encrypted. Single-shot
/// files add 63 bytes; chunked (STREAM) files add 42 plus 20 per chunk.
pub fn estimated_disk_size(plaintext: u64, chunk_size: u64) -> u64 {
    let segments = plaintext.div_ceil(chunk_size.max(1)).max(1);
    plaintext + 63 + 20 * segments
}

/// Fail with [`AppError::QuotaExceeded`] unless the owner of `target_id` has
/// room for `incoming` more on-disk bytes. If `replacing` names an existing
/// file, its size is credited back, since the write overwrites it.
pub async fn ensure_room(
    pool: &DbPool,
    config: &AppConfig,
    kind: TargetKind,
    target_id: &str,
    incoming: u64,
    replacing: Option<&str>,
    exclude_upload: Option<&str>,
) -> Result<(), AppError> {
    let Some(owner) = quota_owner(pool, kind, target_id).await? else {
        return Ok(());
    };
    let quota = owner.quota_bytes.max(0) as u64;

    let used = usage_for_user(pool, config, &owner.id, exclude_upload)
        .await?
        .total();
    let freed = match replacing {
        Some(path) => fs_service::existing_file_size(config, kind, target_id, path)
            .await
            .unwrap_or(0),
        None => 0,
    };
    let used = used.saturating_sub(freed);

    if used.saturating_add(incoming) > quota {
        return Err(AppError::QuotaExceeded {
            needed: incoming,
            available: quota.saturating_sub(used),
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn disk_size_estimate_matches_formats() {
        // Single-shot: magic 3 + nonce 12 + tag 16 + hash 32.
        assert_eq!(estimated_disk_size(1000, 8 << 20), 1000 + 63 + 20);
        // Three STREAM segments.
        let chunk = 8 << 20;
        assert_eq!(estimated_disk_size(chunk * 3, chunk), chunk * 3 + 63 + 60);
        assert_eq!(estimated_disk_size(0, chunk), 83);
    }
}
