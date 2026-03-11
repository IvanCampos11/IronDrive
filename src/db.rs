use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};
use sqlx::SqlitePool;
use std::str::FromStr;
use tracing::info;

pub type DbPool = SqlitePool;

/// Create a SQLite connection pool from a database URL string.
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

    sqlx::query("PRAGMA foreign_keys = ON;")
        .execute(&pool)
        .await?;

    Ok(pool)
}

struct MigrationFile {
    filename: String,
    sql: String,
}

/// Read and sort all `.sql` files from `migrations/`. Blocking I/O.
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

/// Run all `.sql` files from `migrations/` in order, tracking applied files
/// in a `_migrations` table so they're never re-applied.
pub async fn run_migrations(pool: &DbPool) -> Result<(), sqlx::Error> {
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS _migrations (
            filename TEXT PRIMARY KEY,
            applied_at TEXT NOT NULL DEFAULT (datetime('now'))
        );",
    )
    .execute(pool)
    .await?;

    let migrations = tokio::task::spawn_blocking(read_migration_files)
        .await
        .map_err(|e| sqlx::Error::Io(std::io::Error::new(std::io::ErrorKind::Other, e)))?
        .map_err(sqlx::Error::Io)?;

    let mut applied_count: usize = 0;

    for migration in &migrations {
        let already_applied: Option<(String,)> =
            sqlx::query_as("SELECT filename FROM _migrations WHERE filename = ?")
                .bind(&migration.filename)
                .fetch_optional(pool)
                .await?;

        if already_applied.is_some() {
            continue;
        }

        info!(file = %migration.filename, "Applying migration");

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
