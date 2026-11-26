#[macro_use]
extern crate rocket;

use rocket::fairing::AdHoc;
use rocket::http::Status;
use rocket::request::Request;
use rocket::response::{self, Responder, Response};
use rocket::serde::json::serde_json;
use rocket_dyn_templates::{context, Template};
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

#[cfg(test)]
mod tests;

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
    // dotenv_override so .env always wins over stale shell env vars.
    // Log the outcome so misconfigured working directories are immediately visible.
    let dotenv_result = dotenvy::dotenv_override();

    fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    match dotenv_result {
        Ok(path) => tracing::info!(path = %path.display(), "Loaded .env file"),
        Err(e) => tracing::warn!("No .env file loaded ({e}); using environment variables / defaults"),
    }

    let app_config = config::AppConfig::from_env();
    tracing::info!(
        data_dir = %app_config.data_dir,
        db_dir = %app_config.db_dir,
        max_upload_bytes = app_config.max_upload_bytes,
        default_quota_bytes = app_config.default_quota_bytes,
        "IronDrive starting up"
    );

    rocket::custom(rocket_figment(&app_config))
        .manage(app_config)
        .manage(services::rate_limit::RateLimiter::new())
        .attach(AdHoc::on_ignite("Database Setup", setup_database))
        .attach(templates_fairing())
        .attach(security_headers_fairing())
        .attach(cache_control_fairing())
        .attach(AdHoc::on_liftoff("Background Workers", |rocket| {
            Box::pin(async move {
                let pool = rocket.state::<SqlitePool>().expect("DbPool not managed").clone();
                let config = rocket.state::<config::AppConfig>().expect("AppConfig not managed").clone();
                let unlock_state = rocket.state::<services::unlock_state::UnlockState>()
                    .expect("UnlockState not managed").clone();
                services::background::BackgroundRunner::start(pool, config, unlock_state);
            })
        }))
        .mount("/", routes::all_routes())
        .mount("/static", routes::static_file_server())
        .register(
            "/",
            catchers![catch_400, catch_401, catch_403, catch_404, catch_409, catch_422, catch_500,],
        )
}

/// Build the Rocket Figment, merging `Rocket.toml` defaults with our
/// `IRONDRIVE_SECRET_KEY` so Rocket has a `secret_key` in release mode.
fn rocket_figment(app_config: &config::AppConfig) -> rocket::figment::Figment {
    use rocket::figment::providers::{Env, Format, Serialized, Toml};
    rocket::figment::Figment::from(rocket::Config::default())
        .merge(Toml::file("Rocket.toml").nested())
        .merge(Env::prefixed("ROCKET_").global())
        .merge(Serialized::default("secret_key", app_config.rocket_secret_key()))
}

/// Tera templates plus an `asset_v()` function returning a content hash of
/// the CSS/JS bundle, used as a cache-busting query string. Static files are
/// served with a one-year `immutable` cache, so the URL must change whenever
/// their contents do.
pub fn templates_fairing() -> impl rocket::fairing::Fairing {
    let version = asset_version();
    Template::custom(move |engines| {
        let v = version.clone();
        engines.tera.register_function(
            "asset_v",
            move |_: &std::collections::HashMap<String, rocket_dyn_templates::tera::Value>| {
                Ok(rocket_dyn_templates::tera::Value::String(v.clone()))
            },
        );
    })
}

/// Short SHA-256 over every file in static/css and static/js.
fn asset_version() -> String {
    use sha2::{Digest, Sha256};
    let mut files: Vec<std::path::PathBuf> = ["static/css", "static/js"]
        .iter()
        .filter_map(|dir| std::fs::read_dir(dir).ok())
        .flatten()
        .filter_map(|entry| entry.ok().map(|e| e.path()))
        .filter(|p| p.is_file())
        .collect();
    files.sort();
    if files.is_empty() {
        return env!("CARGO_PKG_VERSION").to_string();
    }
    let mut hasher = Sha256::new();
    for path in files {
        if let Ok(bytes) = std::fs::read(&path) {
            hasher.update(path.to_string_lossy().as_bytes());
            hasher.update(&bytes);
        }
    }
    hex::encode(&hasher.finalize()[..5])
}

/// Attach security headers to every response.
pub fn security_headers_fairing() -> AdHoc {
    AdHoc::on_response("Security Headers", |_req, res| {
        Box::pin(async move {
            use rocket::http::Header;
            res.set_header(Header::new("X-Content-Type-Options", "nosniff"));
            res.set_header(Header::new("X-Frame-Options", "DENY"));
            res.set_header(Header::new(
                "Referrer-Policy",
                "strict-origin-when-cross-origin",
            ));
            res.set_header(Header::new(
                "Permissions-Policy",
                "camera=(), microphone=(), geolocation=()",
            ));
            // Responders serving user file content set a stricter sandbox CSP;
            // don't overwrite it with the app-page policy.
            if !res.headers().contains("Content-Security-Policy") {
                res.set_header(Header::new(
                    "Content-Security-Policy",
                    "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'"
                ));
            }
        })
    })
}

/// Cache-Control: long cache for static assets, no-cache for HTML pages.
pub fn cache_control_fairing() -> AdHoc {
    AdHoc::on_response("Cache-Control", |req, res| {
        Box::pin(async move {
            use rocket::http::Header;
            let path = req.uri().path().as_str();
            if path.starts_with("/static/") {
                res.set_header(Header::new(
                    "Cache-Control",
                    "public, max-age=31536000, immutable",
                ));
            } else {
                res.set_header(Header::new(
                    "Cache-Control",
                    "no-cache, no-store, must-revalidate",
                ));
            }
        })
    })
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
    fn respond_to(self, request: &'r Request<'_>) -> response::Result<'static> {
        // If the request accepts HTML (browser), render an error template
        let accept = request.accept();
        let wants_html = accept.is_some_and(|a| {
            a.iter().any(|q| {
                let mt = q.media_type();
                mt.top() == "text" && mt.sub() == "html"
            })
        });

        if wants_html {
            // Signed-out browsers go to the sign-in page instead of an error page.
            if self.status == Status::Unauthorized {
                return Response::build()
                    .status(Status::SeeOther)
                    .raw_header("Location", "/login")
                    .ok();
            }
            let (title, message) = match self.status.code {
                403 => ("You don't have access", "You don't have permission to view this page."),
                404 => ("Page not found", "This page doesn't exist, or it may have been moved or deleted."),
                400 | 409 | 422 => ("That didn't work", "The request couldn't be processed. Go back and try again."),
                _ => ("Something went wrong", "An unexpected error occurred on the server. Please try again in a moment."),
            };
            let page = Template::render(
                "errors/error",
                context! { code: self.status.code, title: title, message: message },
            );
            if let Ok(template) = page.respond_to(request) {
                return Response::build_from(template).status(self.status).ok();
            }
        }

        // Fallback: JSON response for API clients
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

/// Dirs, DB pool, migrations, master key bootstrap, unlock state.
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

    let unlock_state = services::unlock_state::UnlockState::new();
    tracing::info!("UnlockState initialized (no keys loaded yet)");

    let loaded =
        services::library_service::load_server_mode_keys(&pool, &master_key, &unlock_state)
            .await
            .expect("Failed to load server-mode library keys");
    tracing::info!(
        count = loaded,
        "Server-mode library keys loaded into UnlockState"
    );

    let space_loaded =
        services::space_service::load_server_mode_keys(&pool, &master_key, &unlock_state)
            .await
            .expect("Failed to load server-mode space keys");
    tracing::info!(
        count = space_loaded,
        "Server-mode space keys loaded into UnlockState"
    );

    // Clean up expired chunked upload sessions from previous runs.
    if let Err(e) = services::chunk_service::cleanup_expired_uploads(&pool, cfg).await {
        tracing::warn!(error = %e, "Failed to clean up expired chunked uploads on startup");
    }

    rocket.manage(pool).manage(master_key).manage(unlock_state)
}
