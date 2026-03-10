#[macro_use]
extern crate rocket;

use rocket::fairing::AdHoc;
use sqlx::SqlitePool;
use tracing_subscriber::{fmt, EnvFilter};

mod config;
mod db;
mod errors;
mod guards;
mod models;
mod routes;

// ── Startup Helpers ──────────────────────────────────────────────────────────

/// Create required data directories (libraries, spaces, chunks).
/// Panics on failure — the server cannot operate without them.
async fn ensure_data_directories(data_dir: &str) {
    let subdirs = ["libraries", "spaces", ".chunks"];

    for name in subdirs {
        let path = format!("{data_dir}/{name}");
        tokio::fs::create_dir_all(&path)
            .await
            .unwrap_or_else(|e| panic!("Failed to create directory '{path}': {e}"));
        tracing::info!(dir = %path, "Ensured data directory exists");
    }
}

/// Create the database directory if it doesn't already exist.
/// Panics on failure — the server cannot operate without a database.
async fn ensure_db_directory(db_dir: &str) {
    tokio::fs::create_dir_all(db_dir)
        .await
        .unwrap_or_else(|e| panic!("Failed to create database directory '{db_dir}': {e}"));
    tracing::info!(dir = %db_dir, "Ensured database directory exists");
}

/// Open the database connection pool and run all pending migrations.
/// Returns the ready-to-use pool or panics if either step fails.
async fn init_database(db_url: &str) -> SqlitePool {
    let pool = db::init_pool(db_url)
        .await
        .expect("Failed to initialize database pool");

    db::run_migrations(&pool)
        .await
        .expect("Failed to run database migrations");

    tracing::info!("Database ready");
    pool
}

// ── Application Entry Point ──────────────────────────────────────────────────

#[rocket::launch]
async fn rocket() -> _ {
    // Load .env file (ignore if missing — production uses real env vars)
    let _ = dotenvy::dotenv();

    // Initialize structured logging
    fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    // Load and validate app config from environment
    let app_config = config::AppConfig::from_env();
    tracing::info!(
        data_dir = %app_config.data_dir,
        db_dir = %app_config.db_dir,
        "IronDrive starting up"
    );

    // Build the Rocket instance
    rocket::build()
        .manage(app_config)
        .attach(AdHoc::on_ignite("Database Setup", setup_database))
        .mount("/", routes::all_routes())
}

/// Rocket fairing: creates directories, opens the DB pool, runs migrations,
/// and stores the pool in managed state.
async fn setup_database(rocket: rocket::Rocket<rocket::Build>) -> rocket::Rocket<rocket::Build> {
    let cfg = rocket
        .state::<config::AppConfig>()
        .expect("AppConfig must be managed before Database Setup runs");

    ensure_data_directories(&cfg.data_dir).await;
    ensure_db_directory(&cfg.db_dir).await;

    let pool = init_database(&cfg.db_url()).await;

    rocket.manage(pool)
}
