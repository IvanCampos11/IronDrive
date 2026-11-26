use std::time::Duration;

use sqlx::SqlitePool;

use crate::config::AppConfig;
use crate::services::trash_service;

/// How often to look for trash items past the retention period.
const CLEANUP_INTERVAL: Duration = Duration::from_secs(3600);

/// Background worker loop: permanently deletes trash items older than
/// `trash_retention_days`.
pub async fn trash_cleanup_loop(pool: SqlitePool, config: AppConfig) {
    if config.trash_retention_days == 0 {
        tracing::info!("Trash cleanup: disabled (items are kept until the trash is emptied)");
        return;
    }
    tracing::info!(
        retention_days = config.trash_retention_days,
        "Trash cleanup: worker started (interval: 1h)"
    );

    loop {
        match trash_service::purge_expired(&pool, &config, config.trash_retention_days).await {
            Ok(0) => {}
            Ok(count) => tracing::info!(removed = count, "Trash cleanup: removed expired items"),
            Err(e) => tracing::error!(error = %e, "Trash cleanup: failed"),
        }
        tokio::time::sleep(CLEANUP_INTERVAL).await;
    }
}
