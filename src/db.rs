use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};
use sqlx::SqlitePool;
use std::str::FromStr;
use tracing::info;

/// Type alias used throughout the app.
pub type DbPool = SqlitePool;

/// Create a SQLite connection pool from a database URL string.
///
/// The URL should look like `sqlite:db/irondrive.db?mode=rwc`.
/// This function is framework-free and testable — it takes a plain string,
/// not a Rocket config object.
pub async fn init_pool(db_url: &str) -> Result<DbPool, sqlx::Error> {
    info!(url = %db_url, "Connecting to database");

    let options = SqliteConnectOptions::from_str(db_url)?
        .create_if_missing(true)
        .journal_mode(sqlx::sqlite::SqliteJournalMode::Wal)
        .busy_timeout(std::time::Duration::from_secs(5));

    let pool = SqlitePoolOptions::new()
        .max_connections(5)
        .connect_with(options)
        .await?;

    // Enable foreign keys (SQLite has them off by default)
    sqlx::query("PRAGMA foreign_keys = ON;")
        .execute(&pool)
        .await?;

    Ok(pool)
}

/// Run all SQL migration files from the `migrations/` directory in order.
///
/// We use a simple hand-rolled runner instead of `sqlx::migrate!()` so we can
/// keep plain `.sql` files (no special naming convention required beyond numeric
/// prefix ordering). Each file is executed and tracked in a `_migrations`
/// bookkeeping table so it is never re-applied.
pub async fn run_migrations(pool: &DbPool) -> Result<(), sqlx::Error> {
    // Ensure the bookkeeping table exists
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS _migrations (
            filename TEXT PRIMARY KEY,
            applied_at TEXT NOT NULL DEFAULT (datetime('now'))
        );",
    )
    .execute(pool)
    .await?;

    // Collect and sort migration files
    let migrations_dir = std::path::Path::new("migrations");
    if !migrations_dir.exists() {
        tracing::warn!("No migrations/ directory found — skipping migrations");
        return Ok(());
    }

    let mut files: Vec<String> = std::fs::read_dir(migrations_dir)?
        .filter_map(|entry| {
            let entry = entry.ok()?;
            let name = entry.file_name().into_string().ok()?;
            if name.ends_with(".sql") {
                Some(name)
            } else {
                None
            }
        })
        .collect();

    files.sort();

    let mut applied_count: usize = 0;

    for filename in &files {
        // Check if already applied
        let already_applied: Option<(String,)> =
            sqlx::query_as("SELECT filename FROM _migrations WHERE filename = ?")
                .bind(filename)
                .fetch_optional(pool)
                .await?;

        if already_applied.is_some() {
            continue;
        }

        let path = migrations_dir.join(filename);
        let sql = std::fs::read_to_string(&path).map_err(|e| {
            tracing::error!(file = %filename, error = %e, "Failed to read migration file");
            sqlx::Error::Io(e)
        })?;

        info!(file = %filename, "Applying migration");

        // Execute each statement in the migration file.
        // We split on semicolons so multi-statement files work with SQLite.
        for statement in sql.split(';') {
            let trimmed = statement.trim();
            if trimmed.is_empty() {
                continue;
            }
            sqlx::query(trimmed).execute(pool).await.map_err(|e| {
                tracing::error!(
                    file = %filename,
                    statement = %trimmed,
                    error = %e,
                    "Migration statement failed"
                );
                e
            })?;
        }

        // Record as applied
        sqlx::query("INSERT INTO _migrations (filename) VALUES (?)")
            .bind(filename)
            .execute(pool)
            .await?;

        applied_count += 1;
    }

    info!(
        total_files = files.len(),
        applied = applied_count,
        "Migrations checked"
    );
    Ok(())
}
