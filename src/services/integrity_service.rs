use serde::Serialize;
use uuid::Uuid;

use crate::db::DbPool;
use crate::errors::AppError;

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
