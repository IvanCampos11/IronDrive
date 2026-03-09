use rocket::http::Status;
use rocket::request::Request;
use rocket::response::{self, Responder, Response};
use rocket::serde::json::serde_json;
use serde::Serialize;

/// Unified error type for the entire application.
///
/// Every variant maps to an HTTP status code. The `Responder` implementation
/// converts each variant to a JSON error response with the appropriate status.
/// Sensitive details (e.g., SQL errors, key material) are logged but **never**
/// exposed to the client.
#[derive(Debug, thiserror::Error)]
pub enum AppError {
    // ── Client Errors ────────────────────────────────────────────────
    #[error("not found")]
    NotFound,

    #[error("unauthorized")]
    Unauthorized,

    #[error("forbidden")]
    Forbidden,

    #[error("conflict: {0}")]
    Conflict(String),

    #[error("quota exceeded")]
    QuotaExceeded,

    #[error("library/space is locked — unlock first")]
    Locked,

    #[error("recovery not available for this encryption mode")]
    RecoveryNotAvailable,

    #[error("validation error: {0}")]
    Validation(String),

    #[error("incorrect passphrase")]
    BadPassphrase,

    // ── Server Errors ────────────────────────────────────────────────
    #[error("internal error: {0}")]
    Internal(String),

    #[error(transparent)]
    Sqlx(#[from] sqlx::Error),

    #[error(transparent)]
    Io(#[from] std::io::Error),
}

/// JSON body returned to the client on error.
#[derive(Serialize)]
struct ErrorResponse {
    error: ErrorBody,
}

#[derive(Serialize)]
struct ErrorBody {
    status: u16,
    reason: String,
    description: String,
}

impl AppError {
    /// Map each variant to the appropriate HTTP status code.
    pub fn status(&self) -> Status {
        match self {
            AppError::NotFound => Status::NotFound,
            AppError::Unauthorized => Status::Unauthorized,
            AppError::Forbidden => Status::Forbidden,
            AppError::Conflict(_) => Status::Conflict,
            AppError::QuotaExceeded => Status::PayloadTooLarge,
            AppError::Locked => Status::Locked,
            AppError::RecoveryNotAvailable => Status::UnprocessableEntity,
            AppError::Validation(_) => Status::BadRequest,
            AppError::BadPassphrase => Status::Unauthorized,
            AppError::Internal(_) => Status::InternalServerError,
            AppError::Sqlx(_) => Status::InternalServerError,
            AppError::Io(_) => Status::InternalServerError,
        }
    }

    /// Returns the client-safe description string.
    ///
    /// For server errors we return a generic message so we never leak
    /// SQL queries, file paths, or key material to the caller.
    fn client_message(&self) -> String {
        match self {
            // Client errors — safe to surface the message.
            AppError::NotFound => "The requested resource was not found.".into(),
            AppError::Unauthorized => "Authentication required.".into(),
            AppError::Forbidden => "You do not have permission to perform this action.".into(),
            AppError::Conflict(msg) => msg.clone(),
            AppError::QuotaExceeded => "Storage quota exceeded.".into(),
            AppError::Locked => "Library or space is locked. Unlock it first.".into(),
            AppError::RecoveryNotAvailable => {
                "Recovery is not available for this encryption mode.".into()
            }
            AppError::Validation(msg) => msg.clone(),
            AppError::BadPassphrase => "Incorrect passphrase.".into(),

            // Server errors — never expose internals.
            AppError::Internal(_) | AppError::Sqlx(_) | AppError::Io(_) => {
                "An internal server error occurred.".into()
            }
        }
    }
}

impl<'r> Responder<'r, 'static> for AppError {
    fn respond_to(self, _request: &'r Request<'_>) -> response::Result<'static> {
        // Log the full error for server-side diagnostics.
        match &self {
            AppError::Sqlx(e) => {
                tracing::error!(error = %e, "Database error");
            }
            AppError::Io(e) => {
                tracing::error!(error = %e, "I/O error");
            }
            AppError::Internal(msg) => {
                tracing::error!(error = %msg, "Internal error");
            }
            _ => {
                tracing::debug!(error = %self, "Client error");
            }
        }

        let status = self.status();
        let body = ErrorResponse {
            error: ErrorBody {
                status: status.code,
                reason: status.reason_lossy().to_string(),
                description: self.client_message(),
            },
        };

        let json = serde_json::to_string(&body)
            .unwrap_or_else(|_| r#"{"error":"serialization failed"}"#.into());

        Response::build()
            .status(status)
            .header(rocket::http::ContentType::JSON)
            .sized_body(json.len(), std::io::Cursor::new(json))
            .ok()
    }
}
