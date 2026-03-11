use rocket::serde::json::Json;
use rocket::Route;
use rocket::State;
use serde::{Deserialize, Serialize};

use crate::config::AppConfig;
use crate::db::DbPool;
use crate::errors::AppError;
use crate::guards::auth_guard::{extract_bearer_token, hash_token, AuthenticatedUser};
use crate::services::auth_service;

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

/// Extracts the raw bearer token string without validating the session.
/// Used alongside `AuthenticatedUser` in logout to identify which session to destroy.
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

/// POST /api/v1/auth/register — Create a new user account.
/// First user is auto-promoted to admin. No auth required.
#[post("/api/v1/auth/register", format = "json", data = "<body>")]
pub async fn register(
    pool: &State<DbPool>,
    config: &State<AppConfig>,
    body: Json<RegisterRequest>,
) -> Result<Json<RegisterResponse>, AppError> {
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

/// POST /api/v1/auth/login — Authenticate and return a session token.
#[post("/api/v1/auth/login", format = "json", data = "<body>")]
pub async fn login(
    pool: &State<DbPool>,
    config: &State<AppConfig>,
    body: Json<LoginRequest>,
) -> Result<Json<LoginResponse>, AppError> {
    let result =
        auth_service::login(pool.inner(), config.inner(), &body.username, &body.password).await?;

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

/// POST /api/v1/auth/logout — Destroy the current session only.
#[post("/api/v1/auth/logout")]
pub async fn logout(
    pool: &State<DbPool>,
    user: AuthenticatedUser,
    raw_token: RawBearerToken,
) -> Result<Json<LogoutResponse>, AppError> {
    let token_hash = hash_token(&raw_token.0);

    auth_service::logout(pool.inner(), &user.0.id, &token_hash).await?;

    Ok(Json(LogoutResponse {
        message: "Logged out successfully.".into(),
    }))
}

pub fn routes() -> Vec<Route> {
    routes![register, login, logout]
}
