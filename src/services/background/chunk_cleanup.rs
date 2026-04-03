use std::time::Duration;

use sqlx::SqlitePool;

use crate::config::AppConfig;
use crate::services::chunk_service;

/// How often to clean up expired chunked uploads.
const CLEANUP_INTERVAL: Duration = Duration::from_secs(1800); // 30 minutes

/// Background worker loop: periodically removes expired chunked upload sessions.
pub async fn chunk_cleanup_loop(pool: SqlitePool, config: AppConfig) {
    tracing::info!("Chunk cleanup: worker started (interval: 30m)");

    loop {
        tokio::time::sleep(CLEANUP_INTERVAL).await;

        match chunk_service::cleanup_expired_uploads(&pool, &config).await {
            Ok(count) => {
                if count > 0 {
                    tracing::info!(removed = count, "Chunk cleanup: removed expired uploads");
                }
            }
            Err(e) => {
                tracing::error!(error = %e, "Chunk cleanup: failed to clean up uploads");
            }
        }
    }
}
