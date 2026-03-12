use rocket::http::Status;
use rocket::request::{FromRequest, Outcome, Request};

use crate::errors::AppError;
use crate::models::user::User;

use super::auth_guard::AuthenticatedUser;

/// Request guard: delegates to `AuthenticatedUser`, then checks `setup_complete == true`.
/// Returns 401 if not authenticated, 403 if setup has not been completed.
///
/// Use this on any route that requires the user to have a fully initialized
/// personal library (i.e. all M5+ filesystem routes).
pub struct SetupComplete(pub User);

#[rocket::async_trait]
impl<'r> FromRequest<'r> for SetupComplete {
    type Error = AppError;

    async fn from_request(request: &'r Request<'_>) -> Outcome<Self, Self::Error> {
        let authenticated = match request.guard::<AuthenticatedUser>().await {
            Outcome::Success(auth) => auth,
            Outcome::Error((status, err)) => return Outcome::Error((status, err)),
            Outcome::Forward(status) => return Outcome::Forward(status),
        };

        if !authenticated.0.setup_complete {
            tracing::warn!(
                user_id = %authenticated.0.id,
                username = %authenticated.0.username,
                "User attempted to access a resource before completing setup"
            );
            return Outcome::Error((
                Status::Forbidden,
                AppError::Validation(
                    "Setup is not complete. Please complete library setup first.".into(),
                ),
            ));
        }

        Outcome::Success(SetupComplete(authenticated.0))
    }
}
