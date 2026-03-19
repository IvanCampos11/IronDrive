use rocket::http::{Cookie, CookieJar, SameSite, Status};
use rocket::request::{FromRequest, Outcome, Request};

use crate::errors::AppError;

pub const CSRF_COOKIE: &str = "csrf_token";
const TOKEN_LEN: usize = 64;

/// Ensure a CSRF cookie exists and return the token value.
/// If no valid token is present, generate a new one and set the cookie.
pub fn ensure_csrf_token(cookies: &CookieJar<'_>) -> String {
    if let Some(cookie) = cookies.get(CSRF_COOKIE) {
        let value = cookie.value();
        if value.len() == TOKEN_LEN && value.bytes().all(|b| b.is_ascii_alphanumeric()) {
            return value.to_string();
        }
    }

    let token = generate_token();
    let mut cookie = Cookie::new(CSRF_COOKIE, token.clone());
    cookie.set_same_site(SameSite::Strict);
    cookie.set_http_only(false);
    cookie.set_path("/");
    cookies.add(cookie);

    token
}

/// Validate that a form-submitted token matches the CSRF cookie.
pub fn validate_csrf(cookies: &CookieJar<'_>, submitted: &str) -> Result<(), AppError> {
    let cookie_val = cookies
        .get(CSRF_COOKIE)
        .map(|c| c.value().to_string())
        .unwrap_or_default();

    if cookie_val.is_empty()
        || submitted.is_empty()
        || !constant_time_eq(cookie_val.as_bytes(), submitted.as_bytes())
    {
        return Err(AppError::Forbidden);
    }

    Ok(())
}

/// Request guard for XHR endpoints — validates X-CSRF-Token header against cookie.
pub struct CsrfXhr;

#[rocket::async_trait]
impl<'r> FromRequest<'r> for CsrfXhr {
    type Error = AppError;

    async fn from_request(request: &'r Request<'_>) -> Outcome<Self, Self::Error> {
        let header_token = request.headers().get_one("X-CSRF-Token").unwrap_or("");
        let cookie_token = request
            .cookies()
            .get(CSRF_COOKIE)
            .map(|c| c.value())
            .unwrap_or("");

        if header_token.is_empty()
            || cookie_token.is_empty()
            || !constant_time_eq(header_token.as_bytes(), cookie_token.as_bytes())
        {
            return Outcome::Error((Status::Forbidden, AppError::Forbidden));
        }

        Outcome::Success(CsrfXhr)
    }
}

fn generate_token() -> String {
    use rand::Rng;
    rand::thread_rng()
        .sample_iter(&rand::distributions::Alphanumeric)
        .take(TOKEN_LEN)
        .map(char::from)
        .collect()
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn constant_time_eq_matches() {
        assert!(constant_time_eq(b"hello", b"hello"));
    }

    #[test]
    fn constant_time_eq_rejects_different() {
        assert!(!constant_time_eq(b"hello", b"world"));
    }

    #[test]
    fn constant_time_eq_rejects_different_lengths() {
        assert!(!constant_time_eq(b"short", b"longer"));
    }

    #[test]
    fn generated_token_length() {
        let token = generate_token();
        assert_eq!(token.len(), TOKEN_LEN);
        assert!(token.chars().all(|c| c.is_ascii_alphanumeric()));
    }
}
