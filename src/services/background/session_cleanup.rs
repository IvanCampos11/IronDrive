use std::time::Duration;

use sqlx::SqlitePool;

use crate::models::session::Session;
use crate::services::key_service;
use crate::services::unlock_state::UnlockState;

/// How often to prune expired sessions and lock accounts left without one.
/// Short, because an expired session's keys stay in memory until this runs.
const CLEANUP_INTERVAL: Duration = Duration::from_secs(300); // 5 minutes

/// Background worker loop: periodically removes expired sessions, then locks
/// the keys of accounts that no longer have a live session.
pub async fn session_cleanup_loop(pool: SqlitePool, unlock_state: UnlockState) {
    tracing::info!("Session cleanup: worker started (interval: 5m)");

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

        if let Err(e) = key_service::lock_users_without_sessions(&pool, &unlock_state).await {
            tracing::error!(error = %e, "Session cleanup: failed to lock idle accounts");
        }
    }
}
