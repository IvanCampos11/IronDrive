#[macro_use]
extern crate rocket;

use rocket::fairing::AdHoc;
use tracing_subscriber::{fmt, EnvFilter};

mod config;
mod db;
mod errors;
mod routes;

#[rocket::launch]
async fn rocket() -> _ {
    // Load .env file (ignore if missing — production may use real env vars)
    let _ = dotenvy::dotenv();

    // Initialize tracing/logging
    fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    // Load app config from environment
    let app_config = config::AppConfig::from_env();
    tracing::info!(data_dir = %app_config.data_dir, db_dir = %app_config.db_dir, "IronDrive starting up");

    // Build Rocket instance
    rocket::build()
        .manage(app_config.clone())
        .attach(AdHoc::on_ignite("Database Setup", |rocket| async {
            let cfg = rocket
                .state::<config::AppConfig>()
                .expect("AppConfig must be managed");

            // Ensure data directories exist
            let data_dir = &cfg.data_dir;
            for subdir in ["libraries", "spaces", ".chunks"] {
                let dir = format!("{data_dir}/{subdir}");
                tokio::fs::create_dir_all(&dir)
                    .await
                    .unwrap_or_else(|e| panic!("Failed to create directory {dir}: {e}"));
                tracing::info!(dir = %dir, "Ensured data directory exists");
            }

            // Ensure database directory exists (separate from file storage)
            let db_dir = &cfg.db_dir;
            tokio::fs::create_dir_all(db_dir)
                .await
                .unwrap_or_else(|e| panic!("Failed to create database directory {db_dir}: {e}"));
            tracing::info!(dir = %db_dir, "Ensured database directory exists");

            // Initialize database pool and run migrations
            let db_url = cfg.db_url();
            let pool = db::init_pool(&db_url)
                .await
                .expect("Failed to initialize database pool");

            db::run_migrations(&pool)
                .await
                .expect("Failed to run database migrations");

            tracing::info!("Database ready");

            rocket.manage(pool)
        }))
        .mount("/", routes::health::routes())
}
