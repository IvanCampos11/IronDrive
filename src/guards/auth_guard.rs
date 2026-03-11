use rocket::http::Status;
use rocket::request::{FromRequest, Outcome, Request};
use sha2::{Digest, Sha256};

use crate::db::DbPool;
use crate::errors::AppError;
use crate::models::session::Session;
use crate::models::user::User;

const TOKEN_MIN_LEN: usize = 32;
const TOKEN_MAX_LEN: usize = 512;

/// Request guard: extracts bearer token, validates the session, loads the user.
/// Returns 401 if missing/invalid/expired, 403 if the account is deactivated.
pub struct AuthenticatedUser(pub User);

#[rocket::async_trait]
impl<'r> FromRequest<'r> for AuthenticatedUser {
    type Error = AppError;

    async fn from_request(request: &'r Request<'_>) -> Outcome<Self, Self::Error> {
        let token = match extract_bearer_token(request) {
            Some(t) => t,
            None => {
                return Outcome::Error((Status::Unauthorized, AppError::Unauthorized));
            }
        };

        if !is_valid_token_format(&token) {
            return Outcome::Error((Status::Unauthorized, AppError::Unauthorized));
        }

        let pool = match request.rocket().state::<DbPool>() {
            Some(p) => p,
            None => {
                tracing::error!("DbPool not found in managed state");
                return Outcome::Error((
                    Status::InternalServerError,
                    AppError::Internal("Database pool not available".into()),
                ));
            }
        };

        let token_hash = hash_token(&token);

        let session = match Session::validate(pool, &token_hash).await {
            Ok(Some(s)) => s,
            Ok(None) => {
                return Outcome::Error((Status::Unauthorized, AppError::Unauthorized));
            }
            Err(e) => {
                tracing::error!(error = %e, "Failed to validate session");
                return Outcome::Error((
                    Status::InternalServerError,
                    AppError::Internal("Session validation failed".into()),
                ));
            }
        };

        let user = match User::find_by_id(pool, &session.user_id).await {
            Ok(Some(u)) => u,
            Ok(None) => {
                tracing::warn!(
                    user_id = %session.user_id,
                    session_id = %session.id,
                    "Session references a deleted user — removing session"
                );
                let _ = Session::delete(pool, &session.id).await;
                return Outcome::Error((Status::Unauthorized, AppError::Unauthorized));
            }
            Err(e) => {
                tracing::error!(error = %e, "Failed to load user for session");
                return Outcome::Error((
                    Status::InternalServerError,
                    AppError::Internal("User lookup failed".into()),
                ));
            }
        };

        if !user.is_active {
            tracing::info!(
                user_id = %user.id,
                username = %user.username,
                "Rejected request from deactivated account"
            );
            return Outcome::Error((Status::Forbidden, AppError::Forbidden));
        }

        Outcome::Success(AuthenticatedUser(user))
    }
}

/// Extract the raw bearer token from the `Authorization` header.
/// Returns `None` if the header is missing, not Bearer, or empty.
pub(crate) fn extract_bearer_token(request: &Request<'_>) -> Option<String> {
    let header_value = request.headers().get_one("Authorization")?;
    let trimmed = header_value.trim();

    let token_part = if let Some(rest) = trimmed.strip_prefix("Bearer ") {
        rest
    } else if let Some(rest) = trimmed.strip_prefix("bearer ") {
        rest
    } else if trimmed.len() > 7 && trimmed[..7].eq_ignore_ascii_case("bearer ") {
        &trimmed[7..]
    } else {
        return None;
    };

    let token = token_part.trim();
    if token.is_empty() {
        return None;
    }

    Some(token.to_string())
}

/// Check that a token has a sane length and contains only safe characters
/// (alphanumeric, `-`, `_`, `.`, `+`, `/`, `=`).
fn is_valid_token_format(token: &str) -> bool {
    let len = token.len();
    if len < TOKEN_MIN_LEN || len > TOKEN_MAX_LEN {
        return false;
    }

    token.bytes().all(|b| {
        b.is_ascii_alphanumeric()
            || b == b'-'
            || b == b'_'
            || b == b'.'
            || b == b'+'
            || b == b'/'
            || b == b'='
    })
}

/// SHA-256 hex digest of a raw session token. Matches `sessions.token_hash`.
pub fn hash_token(token: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(token.as_bytes());
    let result = hasher.finalize();
    hex::encode(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_token_is_deterministic() {
        let a = hash_token("my-secret-token");
        let b = hash_token("my-secret-token");
        assert_eq!(a, b);
    }

    #[test]
    fn hash_token_is_64_hex_chars() {
        let h = hash_token("anything");
        assert_eq!(h.len(), 64);
        assert!(h.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn hash_token_differs_for_different_inputs() {
        let a = hash_token("token-a");
        let b = hash_token("token-b");
        assert_ne!(a, b);
    }

    #[test]
    fn hash_token_known_value() {
        // SHA-256("test") = 9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08
        let h = hash_token("test");
        assert_eq!(
            h,
            "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
        );
    }

    #[test]
    fn valid_hex_token() {
        let token = "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2";
        assert!(is_valid_token_format(token));
    }

    #[test]
    fn valid_base64_token() {
        let token = "dGhpcyBpcyBhIHRlc3QgdG9rZW4gZm9yIGF1dGg=";
        assert!(is_valid_token_format(token));
    }

    #[test]
    fn valid_base64url_token() {
        let token = "abc-def_ghi.jkl+mno/pqr=stu=vwx-yz01";
        assert!(is_valid_token_format(token));
    }

    #[test]
    fn rejects_too_short_token() {
        let token = "abc";
        assert!(!is_valid_token_format(token));
    }

    #[test]
    fn rejects_empty_token() {
        assert!(!is_valid_token_format(""));
    }

    #[test]
    fn rejects_token_at_min_boundary_minus_one() {
        let token = "a".repeat(TOKEN_MIN_LEN - 1);
        assert!(!is_valid_token_format(&token));
    }

    #[test]
    fn accepts_token_at_min_boundary() {
        let token = "a".repeat(TOKEN_MIN_LEN);
        assert!(is_valid_token_format(&token));
    }

    #[test]
    fn accepts_token_at_max_boundary() {
        let token = "a".repeat(TOKEN_MAX_LEN);
        assert!(is_valid_token_format(&token));
    }

    #[test]
    fn rejects_token_over_max_boundary() {
        let token = "a".repeat(TOKEN_MAX_LEN + 1);
        assert!(!is_valid_token_format(&token));
    }

    #[test]
    fn rejects_token_with_spaces() {
        let token = "abcdefghijklmnop qrstuvwxyz012345";
        assert!(!is_valid_token_format(token));
    }

    #[test]
    fn rejects_token_with_null_byte() {
        let mut token = "a".repeat(TOKEN_MIN_LEN);
        unsafe {
            token.as_bytes_mut()[5] = 0;
        }
        assert!(!is_valid_token_format(&token));
    }

    #[test]
    fn rejects_token_with_newline() {
        let mut token = "a".repeat(TOKEN_MIN_LEN);
        token.replace_range(10..11, "\n");
        assert!(!is_valid_token_format(&token));
    }

    #[test]
    fn rejects_token_with_unicode() {
        let token = format!("{}é{}", "a".repeat(16), "b".repeat(16));
        assert!(!is_valid_token_format(&token));
    }

    #[test]
    fn rejects_token_with_angle_brackets() {
        let token = format!("<script>{}</script>", "a".repeat(TOKEN_MIN_LEN));
        assert!(!is_valid_token_format(&token));
    }

    /// Mirrors `extract_bearer_token` parsing but takes a raw string for unit testing.
    fn parse_bearer_value(header_value: &str) -> Option<String> {
        let trimmed = header_value.trim();

        let token_part = if let Some(rest) = trimmed.strip_prefix("Bearer ") {
            rest
        } else if let Some(rest) = trimmed.strip_prefix("bearer ") {
            rest
        } else if trimmed.len() > 7 && trimmed[..7].eq_ignore_ascii_case("bearer ") {
            &trimmed[7..]
        } else {
            return None;
        };

        let token = token_part.trim();
        if token.is_empty() {
            return None;
        }

        Some(token.to_string())
    }

    #[test]
    fn parse_standard_bearer() {
        let result = parse_bearer_value("Bearer abc123def456");
        assert_eq!(result.as_deref(), Some("abc123def456"));
    }

    #[test]
    fn parse_lowercase_bearer() {
        let result = parse_bearer_value("bearer abc123def456");
        assert_eq!(result.as_deref(), Some("abc123def456"));
    }

    #[test]
    fn parse_mixed_case_bearer() {
        let result = parse_bearer_value("BEARER abc123def456");
        assert_eq!(result.as_deref(), Some("abc123def456"));
    }

    #[test]
    fn parse_bearer_with_leading_whitespace() {
        let result = parse_bearer_value("  Bearer abc123def456  ");
        assert_eq!(result.as_deref(), Some("abc123def456"));
    }

    #[test]
    fn parse_bearer_with_extra_space_after_prefix() {
        let result = parse_bearer_value("Bearer  abc123def456");
        assert_eq!(result.as_deref(), Some("abc123def456"));
    }

    #[test]
    fn parse_empty_header() {
        assert!(parse_bearer_value("").is_none());
    }

    #[test]
    fn parse_bearer_prefix_only() {
        assert!(parse_bearer_value("Bearer ").is_none());
    }

    #[test]
    fn parse_bearer_prefix_only_with_spaces() {
        assert!(parse_bearer_value("Bearer    ").is_none());
    }

    #[test]
    fn parse_wrong_scheme() {
        assert!(parse_bearer_value("Basic abc123def456").is_none());
    }

    #[test]
    fn parse_no_space_after_bearer() {
        assert!(parse_bearer_value("Bearertoken").is_none());
    }

    #[test]
    fn parse_just_the_word_bearer() {
        assert!(parse_bearer_value("Bearer").is_none());
    }

    #[test]
    fn parse_random_garbage() {
        assert!(parse_bearer_value("not-a-real-header").is_none());
    }

    #[test]
    fn parse_empty_after_trim() {
        assert!(parse_bearer_value("   ").is_none());
    }
}
