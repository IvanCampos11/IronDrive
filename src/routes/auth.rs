use rocket::serde::json::Json;
use rocket::Route;
use rocket::State;
use serde::{Deserialize, Serialize};

use crate::config::AppConfig;
use crate::db::DbPool;
use crate::errors::AppError;
use crate::guards::auth_guard::{extract_bearer_token, hash_token, AuthenticatedUser};
use crate::services::crypto_service::MasterKey;
use crate::services::library_service;
use crate::services::rate_limit::{ClientIp, RateLimiter};
use crate::services::unlock_state::UnlockState;
use crate::services::{auth_service, key_service};

#[derive(Deserialize)]
pub struct RegisterRequest {
    pub username: String,
    pub email: String,
    pub password: String,
}

#[derive(Serialize)]
pub struct RegisterResponse {
    pub user_id: String,
    pub username: String,
    pub role: String,
    pub setup_complete: bool,
}

#[derive(Deserialize)]
pub struct LoginRequest {
    pub username: String,
    pub password: String,
}

#[derive(Serialize)]
pub struct LoginResponse {
    pub token: String,
    pub setup_complete: bool,
    pub user: LoginUserInfo,
}

#[derive(Serialize)]
pub struct LoginUserInfo {
    pub id: String,
    pub username: String,
    pub email: String,
    pub role: String,
}

#[derive(Serialize)]
pub struct LogoutResponse {
    pub message: String,
}

#[derive(Serialize)]
pub struct SetupLibraryResponse {
    pub library_id: String,
    pub encryption_mode: String,
    pub message: String,
}

/// Extracts the raw bearer token without validating the session.
pub struct RawBearerToken(pub String);

#[rocket::async_trait]
impl<'r> rocket::request::FromRequest<'r> for RawBearerToken {
    type Error = AppError;

    async fn from_request(
        request: &'r rocket::request::Request<'_>,
    ) -> rocket::request::Outcome<Self, Self::Error> {
        match extract_bearer_token(request) {
            Some(token) => rocket::request::Outcome::Success(RawBearerToken(token)),
            None => rocket::request::Outcome::Error((
                rocket::http::Status::Unauthorized,
                AppError::Unauthorized,
            )),
        }
    }
}

/// POST /api/v1/auth/register — Create a new user account. No auth required.
#[post("/api/v1/auth/register", format = "json", data = "<body>")]
pub async fn register(
    pool: &State<DbPool>,
    config: &State<AppConfig>,
    rate_limiter: &State<RateLimiter>,
    client_ip: ClientIp,
    body: Json<RegisterRequest>,
) -> Result<Json<RegisterResponse>, AppError> {
    // Same buckets as the HTML form, so API and page share one budget per IP.
    if !rate_limiter.check(&format!("register:{}", client_ip.0), 5, 900) {
        return Err(AppError::RateLimited);
    }

    let result = auth_service::register(
        pool.inner(),
        config.inner(),
        &body.username,
        &body.email,
        &body.password,
    )
    .await?;

    Ok(Json(RegisterResponse {
        user_id: result.user.id,
        username: result.user.username,
        role: result.user.role,
        setup_complete: result.user.setup_complete,
    }))
}

/// POST /api/v1/auth/login
#[post("/api/v1/auth/login", format = "json", data = "<body>")]
pub async fn login(
    pool: &State<DbPool>,
    config: &State<AppConfig>,
    master_key: &State<MasterKey>,
    unlock_state: &State<UnlockState>,
    rate_limiter: &State<RateLimiter>,
    client_ip: ClientIp,
    body: Json<LoginRequest>,
) -> Result<Json<LoginResponse>, AppError> {
    if !rate_limiter.check(&format!("login:{}", client_ip.0), 10, 900) {
        return Err(AppError::RateLimited);
    }

    let result =
        auth_service::login(pool.inner(), config.inner(), &body.username, &body.password).await?;
    key_service::unlock_after_login(
        pool.inner(),
        master_key.inner(),
        unlock_state.inner(),
        &result.user.id,
        &body.password,
    )
    .await;

    Ok(Json(LoginResponse {
        token: result.token,
        setup_complete: result.setup_complete,
        user: LoginUserInfo {
            id: result.user.id,
            username: result.user.username,
            email: result.user.email,
            role: result.user.role,
        },
    }))
}

/// POST /api/v1/auth/logout
#[post("/api/v1/auth/logout")]
pub async fn logout(
    pool: &State<DbPool>,
    unlock_state: &State<UnlockState>,
    user: AuthenticatedUser,
    raw_token: RawBearerToken,
) -> Result<Json<LogoutResponse>, AppError> {
    let token_hash = hash_token(&raw_token.0);

    auth_service::logout(pool.inner(), &user.0.id, &token_hash).await?;
    key_service::lock_if_no_sessions(pool.inner(), unlock_state.inner(), &user.0.id).await?;

    Ok(Json(LogoutResponse {
        message: "Logged out successfully.".into(),
    }))
}

/// Optional body for `setup-library`. Omit it (or send `{}`) for server tier.
#[derive(Deserialize, Default)]
pub struct SetupLibraryRequest {
    /// `server` (default), `failsafe_user` or `pure_user`.
    #[serde(default)]
    pub tier: Option<String>,
    /// `single` (default: login password unlocks) or `separate`.
    #[serde(default)]
    pub password_mode: Option<String>,
    /// Login password, re-entered. Required for the password tiers.
    #[serde(default)]
    pub password: Option<String>,
    /// Encryption password for `separate` mode.
    #[serde(default)]
    pub encryption_password: Option<String>,
}

/// POST /api/v1/auth/setup-library — One-time personal library init. Returns 409 if already done.
#[post("/api/v1/auth/setup-library", data = "<body>")]
pub async fn setup_library(
    pool: &State<DbPool>,
    config: &State<AppConfig>,
    master_key: &State<MasterKey>,
    unlock_state: &State<UnlockState>,
    user: AuthenticatedUser,
    body: Result<Json<SetupLibraryRequest>, rocket::serde::json::Error<'_>>,
) -> Result<Json<SetupLibraryResponse>, AppError> {
    let body = match body {
        Ok(Json(b)) => b,
        // No body at all: server tier, as before tiers existed.
        Err(rocket::serde::json::Error::Parse(raw, _)) if raw.trim().is_empty() => {
            SetupLibraryRequest::default()
        }
        Err(e) => return Err(AppError::Validation(format!("Invalid request body: {e}"))),
    };
    let tier = body.tier.as_deref().unwrap_or(key_service::TIER_SERVER);
    let password_mode = body
        .password_mode
        .as_deref()
        .unwrap_or(key_service::MODE_SINGLE);
    let wrap_password = key_service::key_password_for(
        pool.inner(),
        &user.0.id,
        tier,
        password_mode,
        body.password.as_deref().unwrap_or(""),
        body.encryption_password.as_deref(),
    )
    .await?;

    let result = library_service::setup_library_with(
        pool.inner(),
        config.inner(),
        master_key.inner(),
        unlock_state.inner(),
        &user.0.id,
        &library_service::EncryptionChoice {
            tier,
            password_mode,
            password: wrap_password.as_deref(),
        },
    )
    .await?;

    Ok(Json(SetupLibraryResponse {
        library_id: result.library.id,
        encryption_mode: result.library.encryption_mode,
        message: "Personal library created successfully.".into(),
    }))
}

pub fn routes() -> Vec<Route> {
    routes![register, login, logout, setup_library]
}
