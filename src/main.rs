#[macro_use]
extern crate rocket;

use rocket::fairing::AdHoc;
use rocket::http::Status;
use rocket::request::Request;
use rocket::response::{self, Responder, Response};
use rocket::serde::json::serde_json;
use serde::Serialize;
use sqlx::SqlitePool;
use tracing_subscriber::{fmt, EnvFilter};

mod config;
mod db;
mod errors;
mod guards;
mod models;
mod routes;
mod services;
mod utils;

/// Create required data directories. Panics on failure.
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

/// Create the database directory. Panics on failure.
async fn ensure_db_directory(db_dir: &str) {
    tokio::fs::create_dir_all(db_dir)
        .await
        .unwrap_or_else(|e| panic!("Failed to create database directory '{db_dir}': {e}"));
    tracing::info!(dir = %db_dir, "Ensured database directory exists");
}

/// Open the DB pool and run pending migrations. Panics on failure.
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

#[rocket::launch]
async fn rocket() -> _ {
    let _ = dotenvy::dotenv();

    fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    let app_config = config::AppConfig::from_env();
    tracing::info!(
        data_dir = %app_config.data_dir,
        db_dir = %app_config.db_dir,
        "IronDrive starting up"
    );

    rocket::build()
        .manage(app_config)
        .attach(AdHoc::on_ignite("Database Setup", setup_database))
        .mount("/", routes::all_routes())
        .register(
            "/",
            catchers![catch_400, catch_401, catch_403, catch_404, catch_409, catch_422, catch_500,],
        )
}

// Rocket returns HTML by default for errors — override with JSON.

#[derive(Serialize)]
struct CatcherErrorResponse {
    error: CatcherErrorBody,
}

#[derive(Serialize)]
struct CatcherErrorBody {
    status: u16,
    reason: String,
    description: String,
}

fn catcher_response(status: Status, description: &str) -> CatcherJsonBody {
    let body = CatcherErrorResponse {
        error: CatcherErrorBody {
            status: status.code,
            reason: status.reason_lossy().to_string(),
            description: description.to_string(),
        },
    };
    let json = serde_json::to_string(&body).unwrap_or_else(|_| {
        format!(
            r#"{{"error":{{"status":{},"reason":"{}","description":"serialization failed"}}}}"#,
            status.code,
            status.reason_lossy()
        )
    });
    CatcherJsonBody { status, json }
}

struct CatcherJsonBody {
    status: Status,
    json: String,
}

impl<'r> Responder<'r, 'static> for CatcherJsonBody {
    fn respond_to(self, _request: &'r Request<'_>) -> response::Result<'static> {
        Response::build()
            .status(self.status)
            .header(rocket::http::ContentType::JSON)
            .sized_body(self.json.len(), std::io::Cursor::new(self.json))
            .ok()
    }
}

#[catch(400)]
fn catch_400() -> CatcherJsonBody {
    catcher_response(Status::BadRequest, "The request was invalid.")
}

#[catch(401)]
fn catch_401() -> CatcherJsonBody {
    catcher_response(Status::Unauthorized, "Authentication required.")
}

#[catch(403)]
fn catch_403() -> CatcherJsonBody {
    catcher_response(
        Status::Forbidden,
        "You do not have permission to perform this action.",
    )
}

#[catch(404)]
fn catch_404() -> CatcherJsonBody {
    catcher_response(Status::NotFound, "The requested resource was not found.")
}

#[catch(409)]
fn catch_409() -> CatcherJsonBody {
    catcher_response(
        Status::Conflict,
        "The request conflicts with existing data.",
    )
}

#[catch(422)]
fn catch_422() -> CatcherJsonBody {
    catcher_response(
        Status::UnprocessableEntity,
        "The request body could not be processed.",
    )
}

#[catch(500)]
fn catch_500() -> CatcherJsonBody {
    catcher_response(
        Status::InternalServerError,
        "An internal server error occurred.",
    )
}

/// Dirs, DB pool, migrations, master key bootstrap.
async fn setup_database(rocket: rocket::Rocket<rocket::Build>) -> rocket::Rocket<rocket::Build> {
    let cfg = rocket
        .state::<config::AppConfig>()
        .expect("AppConfig must be managed before Database Setup runs");

    ensure_data_directories(&cfg.data_dir).await;
    ensure_db_directory(&cfg.db_dir).await;

    let pool = init_database(&cfg.db_url()).await;

    let master_key = services::crypto_service::bootstrap_master_key(&pool, &cfg.secret_key)
        .await
        .expect("Failed to bootstrap master encryption key");
    tracing::info!("Master encryption key ready");

    rocket.manage(pool).manage(master_key)
}
