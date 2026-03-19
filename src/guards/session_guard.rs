use rocket::http::Status;
use rocket::request::{FromRequest, Outcome, Request};

use crate::db::DbPool;
use crate::errors::AppError;
use crate::guards::auth_guard::{hash_token, is_valid_token_format};
use crate::models::session::Session;
use crate::models::user::User;

pub const COOKIE_NAME: &str = "irondrive_session";

/// Request guard for browser pages: reads session token from a cookie
/// instead of the Authorization header.
pub struct SessionUser(pub User);

/// Like SessionUser but also requires setup_complete == true.
pub struct SessionSetupComplete(pub User);

/// Extracts the raw session token from cookie, if present and valid format.
fn extract_cookie_token(request: &Request<'_>) -> Option<String> {
    let cookie = request.cookies().get(COOKIE_NAME)?;
    let token = cookie.value().trim().to_string();
    if token.is_empty() {
        return None;
    }
    Some(token)
}

/// Validate cookie token → session → user. Shared logic.
async fn validate_session_cookie(request: &Request<'_>) -> Outcome<User, AppError> {
    let token = match extract_cookie_token(request) {
        Some(t) => t,
        None => return Outcome::Error((Status::Unauthorized, AppError::Unauthorized)),
    };

    if !is_valid_token_format(&token) {
        return Outcome::Error((Status::Unauthorized, AppError::Unauthorized));
    }

    let pool = match request.rocket().state::<DbPool>() {
        Some(p) => p,
        None => {
            return Outcome::Error((
                Status::InternalServerError,
                AppError::Internal("Database pool not available".into()),
            ));
        }
    };

    let token_hash = hash_token(&token);

    let session = match Session::validate(pool, &token_hash).await {
        Ok(Some(s)) => s,
        Ok(None) => return Outcome::Error((Status::Unauthorized, AppError::Unauthorized)),
        Err(_) => {
            return Outcome::Error((
                Status::InternalServerError,
                AppError::Internal("Session validation failed".into()),
            ));
        }
    };

    let user = match User::find_by_id(pool, &session.user_id).await {
        Ok(Some(u)) => u,
        Ok(None) => {
            let _ = Session::delete(pool, &session.id).await;
            return Outcome::Error((Status::Unauthorized, AppError::Unauthorized));
        }
        Err(_) => {
            return Outcome::Error((
                Status::InternalServerError,
                AppError::Internal("User lookup failed".into()),
            ));
        }
    };

    if !user.is_active {
        return Outcome::Error((Status::Forbidden, AppError::Forbidden));
    }

    Outcome::Success(user)
}

#[rocket::async_trait]
impl<'r> FromRequest<'r> for SessionUser {
    type Error = AppError;

    async fn from_request(request: &'r Request<'_>) -> Outcome<Self, Self::Error> {
        match validate_session_cookie(request).await {
            Outcome::Success(user) => Outcome::Success(SessionUser(user)),
            Outcome::Error(e) => Outcome::Error(e),
            Outcome::Forward(s) => Outcome::Forward(s),
        }
    }
}

#[rocket::async_trait]
impl<'r> FromRequest<'r> for SessionSetupComplete {
    type Error = AppError;

    async fn from_request(request: &'r Request<'_>) -> Outcome<Self, Self::Error> {
        match validate_session_cookie(request).await {
            Outcome::Success(user) => {
                if !user.setup_complete {
                    return Outcome::Error((
                        Status::Forbidden,
                        AppError::Validation("Setup not complete.".into()),
                    ));
                }
                Outcome::Success(SessionSetupComplete(user))
            }
            Outcome::Error(e) => Outcome::Error(e),
            Outcome::Forward(s) => Outcome::Forward(s),
        }
    }
}
