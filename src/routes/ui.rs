//! Browser-UI endpoints added on top of the core page routes:
//! integrity alerts (the bell), the file details panel, the sidebar's
//! spaces list, and the admin page.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};

use rocket::form::Form;
use rocket::http::{CookieJar, Status};
use rocket::response::{Flash, Redirect};
use rocket::serde::json::Json;
use rocket::{Route, State};
use rocket_dyn_templates::{context, Template};
use serde_json::{json, Value};

use crate::config::{parse_size, AppConfig};
use crate::db::DbPool;
use crate::errors::AppError;
use crate::guards::csrf_guard::{ensure_csrf_token, validate_csrf, CsrfXhr};
use crate::guards::session_guard::SessionSetupComplete;
use crate::guards::space_guard::SessionSpaceReader;
use crate::models::library::PersonalLibrary;
use crate::models::session::Session;
use crate::models::space::{Space, SpaceAccess};
use crate::models::user::User;
use crate::routes::pages::{
    file_icon, file_name_from_path, format_bytes, icon_glyph, json_error, parent_path,
    require_library, JsonResult,
};
use crate::services::fs_service::{self, TargetKind};
use crate::services::integrity_service::{self, IntegrityEvent};
use crate::services::unlock_state::UnlockState;

// ---------------------------------------------------------------------------
// Integrity alerts
// ---------------------------------------------------------------------------

/// Link to the folder containing `path` in a library or space.
fn folder_href(base: &str, path: &str) -> String {
    let parent = parent_path(path);
    if parent.is_empty() {
        base.to_string()
    } else {
        format!("{base}?path={}", urlencode(&parent))
    }
}

fn urlencode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || b"-_.~/".contains(&b) {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

fn alert_view(ev: &IntegrityEvent, location: &str, base: &str, can_dismiss: bool) -> Value {
    json!({
        "id": ev.id,
        "title": integrity_service::describe_event_type(&ev.event_type),
        "file_name": file_name_from_path(&ev.file_path),
        "file_path": ev.file_path,
        "location": location,
        "href": folder_href(base, &ev.file_path),
        "created_at": ev.created_at,
        "can_dismiss": can_dismiss,
    })
}

/// Open events for `kind/id`. Events whose file has since been deleted or
/// renamed are resolved automatically so the bell doesn't point at nothing.
async fn live_events(
    pool: &DbPool,
    config: &AppConfig,
    kind: TargetKind,
    id: &str,
) -> Vec<IntegrityEvent> {
    let events = integrity_service::list_unacknowledged(pool, kind.as_str(), id)
        .await
        .unwrap_or_default();
    let mut live = Vec::with_capacity(events.len());
    for ev in events {
        if fs_service::entry_exists(config, kind, id, &ev.file_path)
            .await
            .unwrap_or(true)
        {
            live.push(ev);
        } else {
            let _ = integrity_service::acknowledge_event(pool, &ev.id).await;
        }
    }
    live
}

/// Every open integrity alert the user can see: their library plus each
/// space they have access to.
async fn alerts_for(pool: &DbPool, config: &AppConfig, user: &User) -> Vec<Value> {
    let mut alerts = Vec::new();
    if let Ok(Some(lib)) = PersonalLibrary::find_by_user(pool, &user.id).await {
        for ev in live_events(pool, config, TargetKind::Library, &lib.id).await {
            alerts.push(alert_view(&ev, "My files", "/files", true));
        }
    }
    if let Ok(spaces) = Space::find_all_for_user(pool, &user.id).await {
        for sp in spaces {
            let can_dismiss = sp.user_permission == "write" || sp.user_permission == "admin";
            let base = format!("/spaces/{}", sp.space.id);
            for ev in live_events(pool, config, TargetKind::Space, &sp.space.id).await {
                alerts.push(alert_view(&ev, &sp.space.name, &base, can_dismiss));
            }
        }
    }
    alerts.sort_by(|a, b| b["created_at"].as_str().cmp(&a["created_at"].as_str()));
    alerts.truncate(50);
    alerts
}

/// GET /notifications — the bell button and its menu (HTMX partial).
#[get("/notifications")]
pub async fn notifications(
    pool: &State<DbPool>,
    config: &State<AppConfig>,
    user: SessionSetupComplete,
) -> Template {
    let alerts = alerts_for(pool.inner(), config.inner(), &user.0).await;
    Template::render(
        "partials/notifications",
        context! { count: alerts.len(), alerts: alerts },
    )
}

/// Can `user` dismiss this event? Library owners, and space editors/admins.
async fn can_dismiss(pool: &DbPool, user: &User, ev: &IntegrityEvent) -> Result<bool, AppError> {
    Ok(match ev.target_type.as_str() {
        "library" => PersonalLibrary::find_by_user(pool, &user.id)
            .await?
            .is_some_and(|lib| lib.id == ev.target_id),
        "space" => matches!(
            SpaceAccess::resolve_user_permission(pool, &user.id, &ev.target_id)
                .await?
                .as_deref(),
            Some("write") | Some("admin")
        ),
        _ => false,
    } || user.role == "admin")
}

/// POST /notifications/<id>/dismiss — XHR: acknowledge one alert.
#[post("/notifications/<id>/dismiss")]
pub async fn dismiss_notification(
    pool: &State<DbPool>,
    _csrf: CsrfXhr,
    user: SessionSetupComplete,
    id: &str,
) -> JsonResult {
    let ev = integrity_service::get_event(pool.inner(), id)
        .await
        .map_err(json_error)?
        .ok_or_else(|| json_error(AppError::NotFound))?;
    if !can_dismiss(pool.inner(), &user.0, &ev)
        .await
        .map_err(json_error)?
    {
        return Err(json_error(AppError::NotFound));
    }
    integrity_service::acknowledge_event(pool.inner(), id)
        .await
        .map_err(json_error)?;
    Ok(Json(json!({ "ok": true })))
}

// ---------------------------------------------------------------------------
// Details panel
// ---------------------------------------------------------------------------

fn kind_label(kind: &str, mime: Option<&str>) -> String {
    match kind {
        "folder" => "Folder".into(),
        "image" => "Image".into(),
        "video" => "Video".into(),
        "audio" => "Audio".into(),
        "pdf" => "PDF document".into(),
        "archive" => "Archive".into(),
        "code" => "Code".into(),
        "text" => "Text".into(),
        "document" => "Document".into(),
        "spreadsheet" => "Spreadsheet".into(),
        "presentation" => "Presentation".into(),
        _ => mime.map(str::to_string).unwrap_or_else(|| "File".into()),
    }
}

async fn entry_details(
    pool: &DbPool,
    config: &AppConfig,
    unlock_state: &UnlockState,
    kind: TargetKind,
    target_id: &str,
    root_name: &str,
    path: &str,
) -> Result<Value, AppError> {
    if path.is_empty() {
        return Err(AppError::Validation("Choose a file or folder.".into()));
    }
    let entry = match kind {
        TargetKind::Library => {
            fs_service::get_entry_info(config, unlock_state, target_id, path, false).await?
        }
        TargetKind::Space => {
            fs_service::get_space_entry_info(config, unlock_state, target_id, path, false).await?
        }
    };
    let icon = file_icon(&entry.name, entry.is_dir, entry.mime_type.as_deref());

    let contents = if entry.is_dir {
        let usage = match kind {
            TargetKind::Library => fs_service::calculate_usage(config, target_id, path).await?,
            TargetKind::Space => fs_service::calculate_space_usage(config, target_id, path).await?,
        };
        Some(json!({
            "files": usage.file_count,
            "folders": usage.dir_count,
            "disk_size": format_bytes(usage.disk_bytes),
        }))
    } else {
        None
    };

    let prefix = format!("{path}/");
    let problems: Vec<Value> = live_events(pool, config, kind, target_id)
        .await
        .into_iter()
        .filter(|ev| ev.file_path == path || ev.file_path.starts_with(&prefix))
        .map(|ev| {
            json!({
                "title": integrity_service::describe_event_type(&ev.event_type),
                "file_path": ev.file_path,
                "detected_at": ev.created_at,
            })
        })
        .collect();

    let parent = parent_path(path);
    Ok(json!({
        "name": entry.name,
        "path": entry.path,
        "is_dir": entry.is_dir,
        "icon": icon,
        "glyph": icon_glyph(icon),
        "type": kind_label(icon, entry.mime_type.as_deref()),
        "mime_type": entry.mime_type,
        "size": entry.size.map(format_bytes),
        "size_bytes": entry.size,
        "disk_size": entry.disk_size.map(format_bytes),
        "modified": entry.modified,
        "location": if parent.is_empty() { root_name.to_string() } else { format!("{root_name} / {}", parent.replace('/', " / ")) },
        "contents": contents,
        "problems": problems,
    }))
}

/// GET /files/info?<path> — JSON for the details panel.
#[get("/files/info?<path>")]
pub async fn files_info(
    pool: &State<DbPool>,
    config: &State<AppConfig>,
    unlock_state: &State<UnlockState>,
    user: SessionSetupComplete,
    path: String,
) -> JsonResult {
    let lib = require_library(pool.inner(), &user.0.id)
        .await
        .map_err(json_error)?;
    entry_details(
        pool.inner(),
        config.inner(),
        unlock_state.inner(),
        TargetKind::Library,
        &lib.id,
        "My files",
        &path,
    )
    .await
    .map(Json)
    .map_err(json_error)
}

/// GET /spaces/<space_id>/info?<path> — JSON for the details panel.
#[get("/spaces/<space_id>/info?<path>")]
pub async fn space_info(
    pool: &State<DbPool>,
    config: &State<AppConfig>,
    unlock_state: &State<UnlockState>,
    reader: SessionSpaceReader,
    space_id: &str,
    path: String,
) -> JsonResult {
    entry_details(
        pool.inner(),
        config.inner(),
        unlock_state.inner(),
        TargetKind::Space,
        space_id,
        &reader.space.space.name,
        &path,
    )
    .await
    .map(Json)
    .map_err(json_error)
}

/// Fully decrypt one file to confirm it's intact; record an alert if not.
async fn verify_entry(
    pool: &DbPool,
    config: &AppConfig,
    unlock_state: &UnlockState,
    kind: TargetKind,
    target_id: &str,
    path: &str,
) -> Result<Value, AppError> {
    let entry = match kind {
        TargetKind::Library => {
            fs_service::get_entry_info(config, unlock_state, target_id, path, true).await?
        }
        TargetKind::Space => {
            fs_service::get_space_entry_info(config, unlock_state, target_id, path, true).await?
        }
    };
    if entry.is_dir {
        return Err(AppError::Validation("Choose a file to check.".into()));
    }
    let status = entry.integrity.unwrap_or_default();
    if status == "ok" {
        // A clean check resolves any earlier alert (e.g. the file was restored).
        let resolved =
            integrity_service::resolve_events_for_path(pool, kind.as_str(), target_id, path)
                .await?;
        let message = if resolved > 0 {
            "The file is intact now — its alert has been cleared."
        } else {
            "No problems found — the file is intact."
        };
        return Ok(json!({ "ok": true, "message": message, "resolved": resolved }));
    }
    let event_type = if status.contains("truncated") || status.contains("too small") {
        "file_truncated"
    } else if status == "file_hash_mismatch" {
        "checksum_mismatch"
    } else {
        "decrypt_failed"
    };
    integrity_service::record_event(
        pool,
        kind.as_str(),
        target_id,
        path,
        event_type,
        Some(&status),
        "manual_check",
    )
    .await?;
    Ok(json!({ "ok": false, "message": integrity_service::describe_event_type(event_type) }))
}

/// POST /files/verify?<path> — XHR: check one file's integrity now.
#[post("/files/verify?<path>")]
pub async fn files_verify(
    pool: &State<DbPool>,
    config: &State<AppConfig>,
    unlock_state: &State<UnlockState>,
    _csrf: CsrfXhr,
    user: SessionSetupComplete,
    path: String,
) -> JsonResult {
    let lib = require_library(pool.inner(), &user.0.id)
        .await
        .map_err(json_error)?;
    verify_entry(
        pool.inner(),
        config.inner(),
        unlock_state.inner(),
        TargetKind::Library,
        &lib.id,
        &path,
    )
    .await
    .map(Json)
    .map_err(json_error)
}

/// POST /spaces/<space_id>/verify?<path> — XHR: check one file's integrity now.
#[post("/spaces/<space_id>/verify?<path>")]
pub async fn space_verify(
    pool: &State<DbPool>,
    config: &State<AppConfig>,
    unlock_state: &State<UnlockState>,
    _csrf: CsrfXhr,
    _reader: SessionSpaceReader,
    space_id: &str,
    path: String,
) -> JsonResult {
    verify_entry(
        pool.inner(),
        config.inner(),
        unlock_state.inner(),
        TargetKind::Space,
        space_id,
        &path,
    )
    .await
    .map(Json)
    .map_err(json_error)
}

// ---------------------------------------------------------------------------
// Sidebar: spaces list + admin link
// ---------------------------------------------------------------------------

const SIDEBAR_SPACES: usize = 8;

/// GET /nav/extra — spaces under the "Spaces" nav item, and the admin link.
#[get("/nav/extra")]
pub async fn nav_extra(pool: &State<DbPool>, user: SessionSetupComplete) -> Template {
    let mut spaces: Vec<(String, String)> = Space::find_all_for_user(pool.inner(), &user.0.id)
        .await
        .unwrap_or_default()
        .into_iter()
        .map(|s| (s.space.id, s.space.name))
        .collect();
    spaces.sort_by_key(|(_, name)| name.to_lowercase());
    let more = spaces.len().saturating_sub(SIDEBAR_SPACES);
    spaces.truncate(SIDEBAR_SPACES);
    let spaces: Vec<Value> = spaces
        .into_iter()
        .map(|(id, name)| json!({ "id": id, "name": name }))
        .collect();
    Template::render(
        "partials/nav_extra",
        context! { spaces: spaces, more: more, is_admin: user.0.role == "admin" },
    )
}

// ---------------------------------------------------------------------------
// Admin
// ---------------------------------------------------------------------------

static SCAN_RUNNING: AtomicBool = AtomicBool::new(false);

fn require_admin(user: &User) -> Result<(), Status> {
    if user.role == "admin" {
        Ok(())
    } else {
        Err(Status::Forbidden)
    }
}

/// GET /admin — users, quotas, and integrity overview.
#[get("/admin")]
pub async fn admin_page(
    pool: &State<DbPool>,
    config: &State<AppConfig>,
    cookies: &CookieJar<'_>,
    user: SessionSetupComplete,
    flash: Option<rocket::request::FlashMessage<'_>>,
) -> Result<Template, Status> {
    require_admin(&user.0)?;
    let pool = pool.inner();
    let config = config.inner();

    let libraries: Vec<(String, String)> =
        sqlx::query_as("SELECT id, user_id FROM personal_libraries")
            .fetch_all(pool)
            .await
            .map_err(|_| Status::InternalServerError)?;
    let lib_by_user: HashMap<&str, &str> = libraries
        .iter()
        .map(|(l, u)| (u.as_str(), l.as_str()))
        .collect();

    let users = User::list_all(pool)
        .await
        .map_err(|_| Status::InternalServerError)?;
    let mut rows = Vec::with_capacity(users.len());
    for u in &users {
        let used = match lib_by_user.get(u.id.as_str()) {
            Some(lib) => fs_service::calculate_usage(config, lib, "")
                .await
                .map(|r| r.disk_bytes)
                .unwrap_or(0),
            None => 0,
        };
        let pct = if u.quota_bytes > 0 {
            ((used as f64 / u.quota_bytes as f64) * 100.0).min(100.0) as u64
        } else {
            0
        };
        rows.push(json!({
            "id": u.id,
            "username": u.username,
            "email": u.email,
            "role": u.role,
            "is_active": u.is_active,
            "setup_complete": u.setup_complete,
            "created_at": u.created_at,
            "used": format_bytes(used),
            "quota": format_bytes(u.quota_bytes.max(0) as u64),
            "usage_pct": pct,
            "is_self": u.id == user.0.id,
        }));
    }

    // Name each alert's location: "<user>'s files" or the space name.
    let user_by_lib: HashMap<&str, &str> = libraries
        .iter()
        .map(|(l, u)| (l.as_str(), u.as_str()))
        .collect();
    let name_by_user: HashMap<&str, &str> = users
        .iter()
        .map(|u| (u.id.as_str(), u.username.as_str()))
        .collect();
    let events = integrity_service::list_all_unacknowledged(pool, 100)
        .await
        .unwrap_or_default();
    let mut alerts = Vec::with_capacity(events.len());
    for ev in &events {
        let location = if ev.target_type == "library" {
            user_by_lib
                .get(ev.target_id.as_str())
                .and_then(|u| name_by_user.get(u))
                .map(|n| format!("{n}'s files"))
                .unwrap_or_else(|| "Deleted library".into())
        } else {
            Space::find_by_id(pool, &ev.target_id)
                .await
                .ok()
                .flatten()
                .map(|s| format!("Space: {}", s.name))
                .unwrap_or_else(|| "Deleted space".into())
        };
        alerts.push(json!({
            "id": ev.id,
            "title": integrity_service::describe_event_type(&ev.event_type),
            "file_path": ev.file_path,
            "location": location,
            "detected_by": ev.detected_by,
            "created_at": ev.created_at,
        }));
    }

    Ok(Template::render(
        "admin/index",
        context! {
            user: &user.0.username,
            csrf_token: ensure_csrf_token(cookies),
            current_path: "admin",
            users: rows,
            user_count: users.len(),
            active_count: users.iter().filter(|u| u.is_active).count(),
            alerts: alerts,
            registration_enabled: config.registration_enabled,
            scan_enabled: config.integrity_scan_enabled,
            scan_interval_hours: config.integrity_scan_interval_hours,
            scan_running: SCAN_RUNNING.load(Ordering::Relaxed),
            default_quota: format_bytes(config.default_quota_bytes),
            flash_kind: flash.as_ref().map(|f| f.kind().to_string()),
            flash_msg: flash.as_ref().map(|f| f.message().to_string()),
        },
    ))
}

#[derive(FromForm)]
pub struct QuotaForm {
    pub quota: String,
    pub csrf_token: String,
}

/// POST /admin/users/<id>/quota — set a user's storage quota ("10 GB", "500 MB", …).
#[post("/admin/users/<id>/quota", data = "<form>")]
pub async fn admin_set_quota(
    pool: &State<DbPool>,
    cookies: &CookieJar<'_>,
    user: SessionSetupComplete,
    id: &str,
    form: Form<QuotaForm>,
) -> Result<Flash<Redirect>, Status> {
    require_admin(&user.0)?;
    let back = || Redirect::to("/admin");
    if validate_csrf(cookies, &form.csrf_token).is_err() {
        return Ok(Flash::error(
            back(),
            "Your session changed — please try again.",
        ));
    }
    let Some(bytes) = parse_size(&form.quota).filter(|b| *b > 0 && *b <= i64::MAX as u64) else {
        return Ok(Flash::error(back(), "Enter a size like 10 GB or 500 MB."));
    };
    match User::set_quota(pool.inner(), id, bytes as i64).await {
        Ok(true) => Ok(Flash::success(
            back(),
            format!("Quota set to {}.", format_bytes(bytes)),
        )),
        Ok(false) => Ok(Flash::error(back(), "That user no longer exists.")),
        Err(_) => Err(Status::InternalServerError),
    }
}

#[derive(FromForm)]
pub struct ActiveForm {
    pub active: bool,
    pub csrf_token: String,
}

/// POST /admin/users/<id>/active — enable or disable an account.
/// Disabling also signs the user out everywhere.
#[post("/admin/users/<id>/active", data = "<form>")]
pub async fn admin_set_active(
    pool: &State<DbPool>,
    cookies: &CookieJar<'_>,
    user: SessionSetupComplete,
    id: &str,
    form: Form<ActiveForm>,
) -> Result<Flash<Redirect>, Status> {
    require_admin(&user.0)?;
    let back = || Redirect::to("/admin");
    if validate_csrf(cookies, &form.csrf_token).is_err() {
        return Ok(Flash::error(
            back(),
            "Your session changed — please try again.",
        ));
    }
    if id == user.0.id {
        return Ok(Flash::error(back(), "You can't disable your own account."));
    }
    match User::set_active(pool.inner(), id, form.active).await {
        Ok(true) => {
            if !form.active {
                let _ = Session::delete_all_for_user(pool.inner(), id).await;
            }
            Ok(Flash::success(
                back(),
                if form.active {
                    "Account enabled."
                } else {
                    "Account disabled and signed out."
                },
            ))
        }
        Ok(false) => Ok(Flash::error(back(), "That user no longer exists.")),
        Err(_) => Err(Status::InternalServerError),
    }
}

/// POST /admin/scan — XHR: start a full integrity scan in the background.
#[post("/admin/scan")]
pub async fn admin_scan(
    pool: &State<DbPool>,
    config: &State<AppConfig>,
    unlock_state: &State<UnlockState>,
    _csrf: CsrfXhr,
    user: SessionSetupComplete,
) -> Result<Json<Value>, Status> {
    require_admin(&user.0)?;
    if SCAN_RUNNING.swap(true, Ordering::SeqCst) {
        return Ok(Json(
            json!({ "started": false, "message": "A scan is already running." }),
        ));
    }
    let (pool, config, unlock_state) = (
        pool.inner().clone(),
        config.inner().clone(),
        unlock_state.inner().clone(),
    );
    tokio::spawn(async move {
        integrity_service::scan_everything(&pool, &config, &unlock_state).await;
        SCAN_RUNNING.store(false, Ordering::SeqCst);
    });
    Ok(Json(
        json!({ "started": true, "message": "Scan started. New problems will appear here and in users' alerts." }),
    ))
}

pub fn routes() -> Vec<Route> {
    routes![
        notifications,
        dismiss_notification,
        files_info,
        space_info,
        files_verify,
        space_verify,
        nav_extra,
        admin_page,
        admin_set_quota,
        admin_set_active,
        admin_scan,
    ]
}
