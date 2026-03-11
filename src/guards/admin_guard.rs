use rocket::request::{FromRequest, Outcome, Request};

use crate::errors::AppError;
use crate::models::user::User;

use super::auth_guard::AuthenticatedUser;

/// Request guard: delegates to `AuthenticatedUser`, then checks `role == "admin"`.
/// Returns 401 if not authenticated, 403 if not admin.
pub struct AdminUser(pub User);

#[rocket::async_trait]
impl<'r> FromRequest<'r> for AdminUser {
    type Error = AppError;

    async fn from_request(request: &'r Request<'_>) -> Outcome<Self, Self::Error> {
        let authenticated = match request.guard::<AuthenticatedUser>().await {
            Outcome::Success(auth) => auth,
            Outcome::Error((status, err)) => return Outcome::Error((status, err)),
            Outcome::Forward(status) => return Outcome::Forward(status),
        };

        if !authenticated.0.is_admin() {
            tracing::warn!(
                user_id = %authenticated.0.id,
                role = %authenticated.0.role,
                "Non-admin user attempted to access admin-only resource"
            );
            return Outcome::Error((rocket::http::Status::Forbidden, AppError::Forbidden));
        }

        Outcome::Success(AdminUser(authenticated.0))
    }
}
