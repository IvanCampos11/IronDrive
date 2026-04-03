use rocket::serde::json::Json;
use rocket::Route;
use rocket::State;
use serde::Serialize;

use crate::config::AppConfig;
use crate::db::DbPool;
use crate::errors::AppError;
use crate::guards::csrf_guard::CsrfXhr;
use crate::guards::{AdminUser, SetupComplete};
use crate::models::library::PersonalLibrary;
use crate::services::integrity_service::{self, IntegrityEvent, ScanResult};
use crate::services::unlock_state::UnlockState;

// ---------------------------------------------------------------------------
// Response types
// ---------------------------------------------------------------------------

#[derive(Serialize)]
pub struct EventsResponse {
    pub events: Vec<IntegrityEvent>,
}

#[derive(Serialize)]
pub struct AcknowledgeResponse {
    pub acknowledged: bool,
    pub message: String,
}

#[derive(Serialize)]
pub struct ScanResponse {
    #[serde(flatten)]
    pub result: ScanResult,
    pub message: String,
}

#[derive(Serialize)]
pub struct NotificationsResponse {
    pub count: usize,
    pub events: Vec<IntegrityEvent>,
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

async fn require_library(pool: &DbPool, user_id: &str) -> Result<PersonalLibrary, AppError> {
    PersonalLibrary::find_by_user(pool, user_id)
        .await?
        .ok_or(AppError::NotFound)
}

// ---------------------------------------------------------------------------
// Routes — authenticated user (own library)
// ---------------------------------------------------------------------------

/// GET /api/v1/library/integrity/events
///
/// List all integrity events for the current user's library.
#[get("/api/v1/library/integrity/events")]
pub async fn list_events(
    pool: &State<DbPool>,
    user: SetupComplete,
) -> Result<Json<EventsResponse>, AppError> {
    let lib = require_library(pool.inner(), &user.0.id).await?;
    let events = integrity_service::list_events(pool.inner(), "library", &lib.id).await?;
    Ok(Json(EventsResponse { events }))
}

/// POST /api/v1/library/integrity/events/<id>/acknowledge
///
/// Acknowledge (dismiss) a single integrity event.
#[post("/api/v1/library/integrity/events/<id>/acknowledge")]
pub async fn acknowledge_event(
    pool: &State<DbPool>,
    user: SetupComplete,
    _csrf: CsrfXhr,
    id: &str,
) -> Result<Json<AcknowledgeResponse>, AppError> {
    let lib = require_library(pool.inner(), &user.0.id).await?;

    // Verify the event belongs to this user's library before acknowledging.
    let events = integrity_service::list_events(pool.inner(), "library", &lib.id).await?;
    if !events.iter().any(|e| e.id == id) {
        return Err(AppError::NotFound);
    }

    let acked = integrity_service::acknowledge_event(pool.inner(), id).await?;
    Ok(Json(AcknowledgeResponse {
        acknowledged: acked,
        message: if acked {
            "Event acknowledged.".into()
        } else {
            "Event was already acknowledged or not found.".into()
        },
    }))
}

/// GET /api/v1/users/me/notifications
///
/// Unacknowledged integrity events for the current user's library.
#[get("/api/v1/users/me/notifications")]
pub async fn notifications(
    pool: &State<DbPool>,
    user: SetupComplete,
) -> Result<Json<NotificationsResponse>, AppError> {
    let lib = require_library(pool.inner(), &user.0.id).await?;
    let events =
        integrity_service::list_unacknowledged(pool.inner(), "library", &lib.id).await?;
    let count = events.len();
    Ok(Json(NotificationsResponse { count, events }))
}

// ---------------------------------------------------------------------------
// Routes — admin
// ---------------------------------------------------------------------------

/// GET /api/v1/admin/integrity/events?target_type=<t>&target_id=<id>
///
/// List integrity events. Admin can query any library or space.
#[get("/api/v1/admin/integrity/events?<target_type>&<target_id>")]
pub async fn admin_list_events(
    pool: &State<DbPool>,
    _admin: AdminUser,
    target_type: Option<String>,
    target_id: Option<String>,
) -> Result<Json<EventsResponse>, AppError> {
    let t_type = target_type.as_deref().unwrap_or("library");
    let t_id = target_id.as_deref().unwrap_or("");

    if t_id.is_empty() {
        return Err(AppError::Validation("target_id is required".into()));
    }

    let events = integrity_service::list_events(pool.inner(), t_type, t_id).await?;
    Ok(Json(EventsResponse { events }))
}

/// POST /api/v1/admin/integrity/scan?target_type=<t>&target_id=<id>
///
/// Trigger a manual integrity scan on a specific library or space.
#[post("/api/v1/admin/integrity/scan?<target_type>&<target_id>")]
pub async fn admin_scan(
    pool: &State<DbPool>,
    config: &State<AppConfig>,
    unlock_state: &State<UnlockState>,
    _admin: AdminUser,
    _csrf: CsrfXhr,
    target_type: Option<String>,
    target_id: Option<String>,
) -> Result<Json<ScanResponse>, AppError> {
    let t_type = target_type.as_deref().unwrap_or("library");
    let t_id = target_id
        .as_deref()
        .filter(|s| !s.is_empty())
        .ok_or_else(|| AppError::Validation("target_id is required".into()))?;

    let result = match t_type {
        "library" => {
            integrity_service::scan_library(
                pool.inner(),
                config.inner(),
                unlock_state.inner(),
                t_id,
            )
            .await?
        }
        "space" => {
            integrity_service::scan_space(
                pool.inner(),
                config.inner(),
                unlock_state.inner(),
                t_id,
            )
            .await?
        }
        _ => return Err(AppError::Validation("target_type must be 'library' or 'space'".into())),
    };

    Ok(Json(ScanResponse {
        message: format!(
            "Scan complete: {} files scanned, {} failures found.",
            result.files_scanned, result.failures_found
        ),
        result,
    }))
}

// ---------------------------------------------------------------------------
// Route collection
// ---------------------------------------------------------------------------

pub fn routes() -> Vec<Route> {
    routes![
        list_events,
        acknowledge_event,
        notifications,
        admin_list_events,
        admin_scan,
    ]
}
