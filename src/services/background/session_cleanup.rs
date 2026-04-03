use std::time::Duration;

use sqlx::SqlitePool;

use crate::models::session::Session;

/// How often to prune expired sessions.
const CLEANUP_INTERVAL: Duration = Duration::from_secs(3600); // 1 hour

/// Background worker loop: periodically removes expired sessions.
pub async fn session_cleanup_loop(pool: SqlitePool) {
    tracing::info!("Session cleanup: worker started (interval: 1h)");

    loop {
        tokio::time::sleep(CLEANUP_INTERVAL).await;

        match Session::delete_expired(&pool).await {
            Ok(count) => {
                if count > 0 {
                    tracing::info!(removed = count, "Session cleanup: pruned expired sessions");
                }
            }
            Err(e) => {
                tracing::error!(error = %e, "Session cleanup: failed to prune sessions");
            }
        }
    }
}
