use rocket::request::{FromRequest, Outcome, Request};

use crate::errors::AppError;
use crate::models::user::User;

use super::auth_guard::AuthenticatedUser;

/// Request guard that ensures the caller is an authenticated **admin** user.
///
/// Usage in a route handler:
///
/// ```ignore
/// #[get("/admin/something")]
/// async fn admin_only(admin: AdminUser) -> &'static str {
///     // Only reachable if the caller has role == "admin"
///     "secret admin stuff"
/// }
/// ```
///
/// Internally this delegates to [`AuthenticatedUser`] first (so the full
/// token → session → user pipeline runs), then checks `user.role == "admin"`.
///
/// # Failure Responses
///
/// * **401 Unauthorized** — no valid session (propagated from `AuthenticatedUser`).
/// * **403 Forbidden** — valid session but the user is not an admin.
pub struct AdminUser(pub User);

#[rocket::async_trait]
impl<'r> FromRequest<'r> for AdminUser {
    type Error = AppError;

    async fn from_request(request: &'r Request<'_>) -> Outcome<Self, Self::Error> {
        // Step 1: Run the AuthenticatedUser guard to get a valid, logged-in user.
        let authenticated = match request.guard::<AuthenticatedUser>().await {
            Outcome::Success(auth) => auth,
            // Forward the original failure (401) as-is — don't mask it as 403.
            Outcome::Error((status, err)) => return Outcome::Error((status, err)),
            Outcome::Forward(status) => return Outcome::Forward(status),
        };

        // Step 2: Check admin role.
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
