use std::time::Duration;

use sqlx::SqlitePool;

use crate::config::AppConfig;
use crate::services::integrity_service;
use crate::services::unlock_state::UnlockState;

/// Row returned when querying library IDs for scanning.
#[derive(sqlx::FromRow)]
struct LibraryId {
    id: String,
}

/// Run one full integrity scan pass across all libraries.
async fn run_scan(pool: &SqlitePool, config: &AppConfig, unlock_state: &UnlockState) {
    let libraries: Vec<LibraryId> = match sqlx::query_as::<_, LibraryId>(
        "SELECT id FROM personal_libraries",
    )
    .fetch_all(pool)
    .await
    {
        Ok(libs) => libs,
        Err(e) => {
            tracing::error!(error = %e, "Integrity scan: failed to query libraries");
            return;
        }
    };

    tracing::info!(count = libraries.len(), "Integrity scan: starting");

    let mut total_scanned: u64 = 0;
    let mut total_failures: u64 = 0;

    for lib in &libraries {
        match integrity_service::scan_library(pool, config, unlock_state, &lib.id).await {
            Ok(result) => {
                total_scanned += result.files_scanned;
                total_failures += result.failures_found;
                if result.failures_found > 0 {
                    tracing::warn!(
                        library_id = %lib.id,
                        files_scanned = result.files_scanned,
                        failures = result.failures_found,
                        "Integrity scan: failures detected in library"
                    );
                }
            }
            Err(e) => {
                tracing::error!(
                    library_id = %lib.id,
                    error = %e,
                    "Integrity scan: error scanning library"
                );
            }
        }

        // Throttle between libraries to avoid sustained I/O pressure.
        tokio::time::sleep(Duration::from_secs(1)).await;
    }

    tracing::info!(
        files_scanned = total_scanned,
        failures = total_failures,
        libraries = libraries.len(),
        "Integrity scan: complete"
    );
}

/// Background worker loop: periodically scans all libraries for file integrity.
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
        run_scan(&pool, &config, &unlock_state).await;
    }
}
