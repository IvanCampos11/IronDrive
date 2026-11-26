use std::time::Duration;

use sqlx::SqlitePool;

use crate::config::AppConfig;
use crate::services::integrity_service;
use crate::services::unlock_state::UnlockState;

/// Background worker loop: periodically scans all libraries and spaces.
pub async fn integrity_scan_loop(pool: SqlitePool, config: AppConfig, unlock_state: UnlockState) {
    if !config.integrity_scan_enabled {
        tracing::info!("Integrity scan: disabled via config, worker exiting");
        return;
    }

    let interval = Duration::from_secs(config.integrity_scan_interval_hours * 3600);
    tracing::info!(
        interval_hours = config.integrity_scan_interval_hours,
        "Integrity scan: worker started"
    );

    loop {
        tokio::time::sleep(interval).await;
        integrity_service::scan_everything(&pool, &config, &unlock_state).await;
    }
}
