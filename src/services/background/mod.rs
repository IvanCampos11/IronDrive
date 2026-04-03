mod chunk_cleanup;
mod integrity_scan;
mod session_cleanup;

use sqlx::SqlitePool;

use crate::config::AppConfig;
use crate::services::unlock_state::UnlockState;

/// Spawns background worker loops on the Tokio runtime.
///
/// Each worker runs in its own `tokio::spawn` task and loops forever.
pub struct BackgroundRunner;

impl BackgroundRunner {
    /// Launch all background workers. Called from the `on_liftoff` fairing
    /// after Rocket has bound the port and all managed state is available.
    ///
    /// `unlock_state` is cloned from Rocket managed state — because
    /// `UnlockState` uses `Arc<DashMap>` internally, the clone shares
    /// the same live key store as the request handlers.
    pub fn start(pool: SqlitePool, config: AppConfig, unlock_state: UnlockState) {
        tokio::spawn(integrity_scan::integrity_scan_loop(
            pool.clone(),
            config.clone(),
            unlock_state,
        ));

        tokio::spawn(session_cleanup::session_cleanup_loop(pool.clone()));

        tokio::spawn(chunk_cleanup::chunk_cleanup_loop(pool, config));

        tracing::info!("BackgroundRunner: all workers launched");
    }
}
