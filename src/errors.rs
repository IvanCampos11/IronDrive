use rocket::http::Status;
use rocket::request::Request;
use rocket::response::{self, Responder, Response};
use rocket::serde::json::serde_json;
use serde::Serialize;

/// Unified error type. Each variant maps to an HTTP status code and is
/// converted to a JSON response. Sensitive details are logged but never
/// exposed to the client.
#[derive(Debug, thiserror::Error)]
pub enum AppError {
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

    #[error("internal error: {0}")]
    Internal(String),

    #[error(transparent)]
    Sqlx(#[from] sqlx::Error),

    #[error(transparent)]
    Io(#[from] std::io::Error),
}

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

    /// Client-safe description. Server errors return a generic message.
    fn client_message(&self) -> String {
        match self {
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

            AppError::Internal(_) | AppError::Sqlx(_) | AppError::Io(_) => {
                "An internal server error occurred.".into()
            }
        }
    }
}

impl<'r> Responder<'r, 'static> for AppError {
    fn respond_to(self, _request: &'r Request<'_>) -> response::Result<'static> {
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
