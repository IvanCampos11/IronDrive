//! Space permission request guards.
//!
//! **API guards** (bearer token auth via `SetupComplete`):
//! - [`SpaceReader`] — at least `read` permission
//! - [`SpaceWriter`] — at least `write` permission
//! - [`SpaceAdmin`] — `admin` permission
//!
//! **Session guards** (cookie auth via `SessionSetupComplete`):
//! - [`SessionSpaceReader`] — at least `read` permission
//! - [`SessionSpaceWriter`] — at least `write` permission
//! - [`SessionSpaceAdmin`] — `admin` permission
//!
//! Each guard authenticates the user, extracts the space ID from the request
//! URI (the segment immediately after `"spaces"`), resolves the user's effective
//! permission, and rejects the request if the required level is not met.

use rocket::http::Status;
use rocket::request::{FromRequest, Outcome, Request};

use crate::db::DbPool;
use crate::errors::AppError;
use crate::models::space::{Space, SpaceWithMeta};
use crate::models::user::User;

use super::session_guard::SessionSetupComplete;
use super::setup_guard::SetupComplete;

// ---------------------------------------------------------------------------
// Permission levels
// ---------------------------------------------------------------------------

const LEVEL_READ: u8 = 1;
const LEVEL_WRITE: u8 = 2;
const LEVEL_ADMIN: u8 = 3;

fn permission_level(perm: &str) -> u8 {
    match perm {
        "read" => LEVEL_READ,
        "write" => LEVEL_WRITE,
        "admin" => LEVEL_ADMIN,
        _ => 0,
    }
}

// ---------------------------------------------------------------------------
// Space ID extraction
// ---------------------------------------------------------------------------

/// Extract the space ID from the request URI path.
///
/// Looks for the segment immediately following `"spaces"` in the path.
/// Works for both `/api/v1/spaces/<id>/…` and `/spaces/<id>/…`.
fn extract_space_id(request: &Request<'_>) -> Option<String> {
    let path = request.uri().path().as_str();
    let mut segments = path.split('/');
    while let Some(seg) = segments.next() {
        if seg == "spaces" {
            if let Some(id) = segments.next() {
                if !id.is_empty() {
                    return Some(id.to_string());
                }
            }
        }
    }
    None
}

// ---------------------------------------------------------------------------
// Core permission check (auth-agnostic)
// ---------------------------------------------------------------------------

/// Given an authenticated user, extract space_id from the URI, load the space
/// with user-scoped metadata, and verify the user meets `required_level`.
async fn check_space_permission(
    request: &Request<'_>,
    user_id: &str,
    required_level: u8,
) -> Result<SpaceWithMeta, (Status, AppError)> {
    let space_id = extract_space_id(request).ok_or((
        Status::BadRequest,
        AppError::Validation("Missing space ID in request path.".into()),
    ))?;

    let pool = request.rocket().state::<DbPool>().ok_or((
        Status::InternalServerError,
        AppError::Internal("Database pool not available".into()),
    ))?;

    let space_meta = Space::find_for_user(pool, user_id, &space_id)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, space_id = %space_id, "Space guard: failed to load space");
            (
                Status::InternalServerError,
                AppError::Internal("Failed to load space.".into()),
            )
        })?
        .ok_or((Status::NotFound, AppError::NotFound))?;

    let actual_level = permission_level(&space_meta.user_permission);
    if actual_level < required_level {
        return Err((Status::Forbidden, AppError::Forbidden));
    }

    Ok(space_meta)
}

// ---------------------------------------------------------------------------
// API guards (bearer token via SetupComplete)
// ---------------------------------------------------------------------------

/// Authenticated user with at least `read` access to the space in the URI.
#[allow(dead_code)]
pub struct SpaceReader {
    pub user: User,
    pub space: SpaceWithMeta,
}

/// Authenticated user with at least `write` access to the space in the URI.
#[allow(dead_code)]
pub struct SpaceWriter {
    pub user: User,
    pub space: SpaceWithMeta,
}

/// Authenticated user with `admin` access to the space in the URI.
#[allow(dead_code)]
pub struct SpaceAdmin {
    pub user: User,
    pub space: SpaceWithMeta,
}

#[rocket::async_trait]
impl<'r> FromRequest<'r> for SpaceReader {
    type Error = AppError;

    async fn from_request(request: &'r Request<'_>) -> Outcome<Self, Self::Error> {
        let auth = match request.guard::<SetupComplete>().await {
            Outcome::Success(a) => a,
            Outcome::Error((s, e)) => return Outcome::Error((s, e)),
            Outcome::Forward(s) => return Outcome::Forward(s),
        };
        match check_space_permission(request, &auth.0.id, LEVEL_READ).await {
            Ok(space) => Outcome::Success(SpaceReader { user: auth.0, space }),
            Err((s, e)) => Outcome::Error((s, e)),
        }
    }
}

#[rocket::async_trait]
impl<'r> FromRequest<'r> for SpaceWriter {
    type Error = AppError;

    async fn from_request(request: &'r Request<'_>) -> Outcome<Self, Self::Error> {
        let auth = match request.guard::<SetupComplete>().await {
            Outcome::Success(a) => a,
            Outcome::Error((s, e)) => return Outcome::Error((s, e)),
            Outcome::Forward(s) => return Outcome::Forward(s),
        };
        match check_space_permission(request, &auth.0.id, LEVEL_WRITE).await {
            Ok(space) => Outcome::Success(SpaceWriter { user: auth.0, space }),
            Err((s, e)) => Outcome::Error((s, e)),
        }
    }
}

#[rocket::async_trait]
impl<'r> FromRequest<'r> for SpaceAdmin {
    type Error = AppError;

    async fn from_request(request: &'r Request<'_>) -> Outcome<Self, Self::Error> {
        let auth = match request.guard::<SetupComplete>().await {
            Outcome::Success(a) => a,
            Outcome::Error((s, e)) => return Outcome::Error((s, e)),
            Outcome::Forward(s) => return Outcome::Forward(s),
        };
        match check_space_permission(request, &auth.0.id, LEVEL_ADMIN).await {
            Ok(space) => Outcome::Success(SpaceAdmin { user: auth.0, space }),
            Err((s, e)) => Outcome::Error((s, e)),
        }
    }
}

// ---------------------------------------------------------------------------
// Session guards (cookie via SessionSetupComplete)
// ---------------------------------------------------------------------------

/// Session-authenticated user with at least `read` access to the space.
#[allow(dead_code)]
pub struct SessionSpaceReader {
    pub user: User,
    pub space: SpaceWithMeta,
}

/// Session-authenticated user with at least `write` access to the space.
#[allow(dead_code)]
pub struct SessionSpaceWriter {
    pub user: User,
    pub space: SpaceWithMeta,
}

/// Session-authenticated user with `admin` access to the space.
#[allow(dead_code)]
pub struct SessionSpaceAdmin {
    pub user: User,
    pub space: SpaceWithMeta,
}

#[rocket::async_trait]
impl<'r> FromRequest<'r> for SessionSpaceReader {
    type Error = AppError;

    async fn from_request(request: &'r Request<'_>) -> Outcome<Self, Self::Error> {
        let auth = match request.guard::<SessionSetupComplete>().await {
            Outcome::Success(a) => a,
            Outcome::Error((s, e)) => return Outcome::Error((s, e)),
            Outcome::Forward(s) => return Outcome::Forward(s),
        };
        match check_space_permission(request, &auth.0.id, LEVEL_READ).await {
            Ok(space) => Outcome::Success(SessionSpaceReader { user: auth.0, space }),
            Err((s, e)) => Outcome::Error((s, e)),
        }
    }
}

#[rocket::async_trait]
impl<'r> FromRequest<'r> for SessionSpaceWriter {
    type Error = AppError;

    async fn from_request(request: &'r Request<'_>) -> Outcome<Self, Self::Error> {
        let auth = match request.guard::<SessionSetupComplete>().await {
            Outcome::Success(a) => a,
            Outcome::Error((s, e)) => return Outcome::Error((s, e)),
            Outcome::Forward(s) => return Outcome::Forward(s),
        };
        match check_space_permission(request, &auth.0.id, LEVEL_WRITE).await {
            Ok(space) => Outcome::Success(SessionSpaceWriter { user: auth.0, space }),
            Err((s, e)) => Outcome::Error((s, e)),
        }
    }
}

#[rocket::async_trait]
impl<'r> FromRequest<'r> for SessionSpaceAdmin {
    type Error = AppError;

    async fn from_request(request: &'r Request<'_>) -> Outcome<Self, Self::Error> {
        let auth = match request.guard::<SessionSetupComplete>().await {
            Outcome::Success(a) => a,
            Outcome::Error((s, e)) => return Outcome::Error((s, e)),
            Outcome::Forward(s) => return Outcome::Forward(s),
        };
        match check_space_permission(request, &auth.0.id, LEVEL_ADMIN).await {
            Ok(space) => Outcome::Success(SessionSpaceAdmin { user: auth.0, space }),
            Err((s, e)) => Outcome::Error((s, e)),
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // permission_level
    // -----------------------------------------------------------------------

    #[test]
    fn permission_level_read() {
        assert_eq!(permission_level("read"), LEVEL_READ);
    }

    #[test]
    fn permission_level_write() {
        assert_eq!(permission_level("write"), LEVEL_WRITE);
    }

    #[test]
    fn permission_level_admin() {
        assert_eq!(permission_level("admin"), LEVEL_ADMIN);
    }

    #[test]
    fn permission_level_unknown_returns_zero() {
        assert_eq!(permission_level("superadmin"), 0);
        assert_eq!(permission_level(""), 0);
    }

    #[test]
    fn permission_ordering() {
        assert!(permission_level("read") < permission_level("write"));
        assert!(permission_level("write") < permission_level("admin"));
    }

    // -----------------------------------------------------------------------
    // extract_space_id — uses a mock URI helper since we can't easily
    // construct a full Rocket Request in unit tests. We test the parsing
    // logic via a standalone function that operates on a path string.
    // -----------------------------------------------------------------------

    fn extract_id_from_path(path: &str) -> Option<String> {
        let mut segments = path.split('/');
        while let Some(seg) = segments.next() {
            if seg == "spaces" {
                if let Some(id) = segments.next() {
                    if !id.is_empty() {
                        return Some(id.to_string());
                    }
                }
            }
        }
        None
    }

    #[test]
    fn extract_api_space_id() {
        assert_eq!(
            extract_id_from_path("/api/v1/spaces/abc-123"),
            Some("abc-123".into())
        );
    }

    #[test]
    fn extract_api_space_id_with_subpath() {
        assert_eq!(
            extract_id_from_path("/api/v1/spaces/abc-123/fs"),
            Some("abc-123".into())
        );
    }

    #[test]
    fn extract_page_space_id() {
        assert_eq!(
            extract_id_from_path("/spaces/abc-123"),
            Some("abc-123".into())
        );
    }

    #[test]
    fn extract_page_space_id_with_settings() {
        assert_eq!(
            extract_id_from_path("/spaces/abc-123/settings"),
            Some("abc-123".into())
        );
    }

    #[test]
    fn extract_uuid_style_id() {
        let uuid = "8655a343-0d5b-44fc-bc70-8ba24035d0c7";
        assert_eq!(
            extract_id_from_path(&format!("/api/v1/spaces/{}/fs", uuid)),
            Some(uuid.into())
        );
    }

    #[test]
    fn extract_no_id_when_spaces_is_leaf() {
        assert_eq!(extract_id_from_path("/api/v1/spaces"), None);
        assert_eq!(extract_id_from_path("/api/v1/spaces/"), None);
    }

    #[test]
    fn extract_no_id_without_spaces_segment() {
        assert_eq!(extract_id_from_path("/api/v1/library/abc"), None);
        assert_eq!(extract_id_from_path("/files"), None);
    }

    #[test]
    fn extract_first_spaces_segment_wins() {
        // Pathological but deterministic: picks the first "spaces" segment.
        assert_eq!(
            extract_id_from_path("/spaces/first/nested/spaces/second"),
            Some("first".into())
        );
    }
}
