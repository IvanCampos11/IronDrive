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

/// A migration file read from disk: its filename and full SQL content.
struct MigrationFile {
    filename: String,
    sql: String,
}

/// Read and sort all `.sql` files from the `migrations/` directory.
///
/// This performs blocking filesystem I/O, so it must be called from a
/// blocking-safe context (e.g. inside `spawn_blocking`).
fn read_migration_files() -> Result<Vec<MigrationFile>, std::io::Error> {
    let migrations_dir = std::path::Path::new("migrations");

    if !migrations_dir.exists() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "migrations/ directory not found — cannot start without schema migrations",
        ));
    }

    let mut filenames: Vec<String> = std::fs::read_dir(migrations_dir)?
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

    filenames.sort();

    let mut migrations = Vec::with_capacity(filenames.len());
    for filename in filenames {
        let path = migrations_dir.join(&filename);
        let sql = std::fs::read_to_string(&path).map_err(|e| {
            tracing::error!(file = %filename, error = %e, "Failed to read migration file");
            e
        })?;
        migrations.push(MigrationFile { filename, sql });
    }

    Ok(migrations)
}

/// Run all SQL migration files from the `migrations/` directory in order.
///
/// We use a simple hand-rolled runner instead of `sqlx::migrate!()` so we can
/// keep plain `.sql` files (no special naming convention required beyond numeric
/// prefix ordering). Each file is executed and tracked in a `_migrations`
/// bookkeeping table so it is never re-applied.
///
/// Returns an error if the `migrations/` directory does not exist (fail-fast),
/// since starting without a schema would lead to hard-to-diagnose runtime
/// failures.
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

    // Read migration files on a blocking thread so we don't stall the
    // Tokio runtime with std::fs calls.
    let migrations = tokio::task::spawn_blocking(read_migration_files)
        .await
        .map_err(|e| sqlx::Error::Io(std::io::Error::new(std::io::ErrorKind::Other, e)))?
        .map_err(sqlx::Error::Io)?;

    let mut applied_count: usize = 0;

    for migration in &migrations {
        // Check if already applied
        let already_applied: Option<(String,)> =
            sqlx::query_as("SELECT filename FROM _migrations WHERE filename = ?")
                .bind(&migration.filename)
                .fetch_optional(pool)
                .await?;

        if already_applied.is_some() {
            continue;
        }

        info!(file = %migration.filename, "Applying migration");

        // Execute the full migration script using raw_sql, which handles
        // multi-statement files natively without naive semicolon splitting.
        // This is safe for triggers, functions, and string literals that
        // contain semicolons.
        sqlx::raw_sql(&migration.sql)
            .execute(pool)
            .await
            .map_err(|e| {
                tracing::error!(
                    file = %migration.filename,
                    error = %e,
                    "Migration failed"
                );
                e
            })?;

        // Record as applied
        sqlx::query("INSERT INTO _migrations (filename) VALUES (?)")
            .bind(&migration.filename)
            .execute(pool)
            .await?;

        applied_count += 1;
    }

    info!(
        total_files = migrations.len(),
        applied = applied_count,
        "Migrations checked"
    );
    Ok(())
}
