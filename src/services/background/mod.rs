use sqlx::SqlitePool;

use crate::config::AppConfig;
use crate::services::unlock_state::UnlockState;

/// Spawns background worker loops on the Tokio runtime.
///
/// Each worker runs in its own `tokio::spawn` task and loops forever.
/// Workers are added in commit 5; this commit establishes the framework.
pub struct BackgroundRunner;

impl BackgroundRunner {
    /// Launch all background workers. Called from the `on_liftoff` fairing
    /// after Rocket has bound the port and all managed state is available.
    ///
    /// `unlock_state` is cloned from Rocket managed state — because
    /// `UnlockState` uses `Arc<DashMap>` internally, the clone shares
    /// the same live key store as the request handlers.
    pub fn start(
        _pool: SqlitePool,
        _config: AppConfig,
        _unlock_state: UnlockState,
    ) {
        tracing::info!("BackgroundRunner started (no workers registered yet)");
    }
}
