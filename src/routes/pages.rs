use rocket::form::Form;
use rocket::http::{Cookie, CookieJar, SameSite, Status};
use rocket::request::FlashMessage;
use rocket::response::{Flash, Redirect};
use rocket::serde::json::serde_json;
use rocket::Route;
use rocket::State;
use rocket_dyn_templates::{context, Template};

use crate::config::AppConfig;
use crate::db::DbPool;
use crate::errors::AppError;
use crate::guards::csrf_guard::{ensure_csrf_token, validate_csrf, CsrfXhr};
use crate::guards::session_guard::{SessionSetupComplete, SessionUser, COOKIE_NAME};
use crate::models::library::PersonalLibrary;
use crate::services::crypto_service::MasterKey;
use crate::services::rate_limit::{ClientIp, RateLimiter};
use crate::services::unlock_state::UnlockState;
use crate::services::{auth_service, chunk_service, fs_service, group_service, library_service};

// ---------------------------------------------------------------------------
// Form structs
// ---------------------------------------------------------------------------

#[derive(FromForm)]
pub struct LoginForm {
    pub username: String,
    pub password: String,
    pub csrf_token: String,
}

#[derive(FromForm)]
pub struct RegisterForm {
    pub username: String,
    pub email: String,
    pub password: String,
    pub password_confirm: String,
    pub csrf_token: String,
}

#[derive(FromForm)]
pub struct CsrfOnlyForm {
    pub csrf_token: String,
}

#[derive(FromForm)]
pub struct MkdirForm {
    pub name: String,
    pub path: String,
    pub csrf_token: String,
}

#[derive(FromForm)]
pub struct RenameForm {
    pub old_path: String,
    pub new_name: String,
    pub csrf_token: String,
}

#[derive(FromForm)]
pub struct MoveForm {
    pub old_path: String,
    pub target_dir: String,
    pub return_path: Option<String>,
    pub csrf_token: String,
}

#[derive(FromForm)]
pub struct DeleteForm {
    pub path: String,
    pub csrf_token: String,
}

#[derive(FromForm)]
pub struct CreateGroupForm {
    pub name: String,
    pub description: Option<String>,
    pub csrf_token: String,
}

#[derive(serde::Deserialize)]
pub struct BulkDeleteRequest {
    pub paths: Vec<String>,
}

#[derive(serde::Deserialize)]
pub struct BulkMoveRequest {
    pub paths: Vec<String>,
    pub target_dir: String,
}

#[derive(serde::Deserialize)]
pub struct ChunkedInitRequest {
    pub path: String,
    pub total_chunks: u32,
    pub total_bytes: u64,
    pub checksum_sha256: Option<String>,
}

#[derive(serde::Deserialize)]
pub struct ChunkedCompleteRequest {
    pub upload_id: String,
    pub verify: Option<bool>,
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn set_session_cookie(cookies: &CookieJar<'_>, token: &str) {
    let mut cookie = Cookie::new(COOKIE_NAME, token.to_string());
    cookie.set_http_only(true);
    cookie.set_same_site(SameSite::Lax);
    cookie.set_path("/");
    cookies.add(cookie);
}

fn clear_session_cookie(cookies: &CookieJar<'_>) {
    cookies.remove(Cookie::from(COOKIE_NAME));
}

/// Look up the user's personal library.
async fn require_library(pool: &DbPool, user_id: &str) -> Result<PersonalLibrary, AppError> {
    PersonalLibrary::find_by_user(pool, user_id)
        .await?
        .ok_or(AppError::NotFound)
}

/// Format bytes into something human readable.
fn format_bytes(bytes: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = 1024 * 1024;
    const GB: u64 = 1024 * 1024 * 1024;

    if bytes >= GB {
        format!("{:.1} GB", bytes as f64 / GB as f64)
    } else if bytes >= MB {
        format!("{:.1} MB", bytes as f64 / MB as f64)
    } else if bytes >= KB {
        format!("{:.1} KB", bytes as f64 / KB as f64)
    } else {
        format!("{bytes} B")
    }
}

// ---------------------------------------------------------------------------
// Auth pages
// ---------------------------------------------------------------------------

/// GET / — redirect to files or login.
#[get("/")]
pub async fn index(user: Option<SessionUser>) -> Redirect {
    match user {
        Some(u) => {
            if u.0.setup_complete {
                Redirect::to(uri!(files_page(path = Option::<String>::None)))
            } else {
                Redirect::to(uri!(setup_page))
            }
        }
        None => Redirect::to(uri!(login_page)),
    }
}

/// GET /login
#[get("/login")]
pub async fn login_page(
    user: Option<SessionUser>,
    cookies: &CookieJar<'_>,
    flash: Option<FlashMessage<'_>>,
) -> Result<Template, Redirect> {
    if user.is_some() {
        return Err(Redirect::to(uri!(index)));
    }
    let csrf_token = ensure_csrf_token(cookies);
    Ok(Template::render(
        "auth/login",
        context! {
            csrf_token: csrf_token,
            flash_kind: flash.as_ref().map(|f| f.kind().to_string()),
            flash_msg: flash.as_ref().map(|f| f.message().to_string()),
        },
    ))
}

/// POST /login
#[post("/login", data = "<form>")]
pub async fn login_submit(
    pool: &State<DbPool>,
    config: &State<AppConfig>,
    cookies: &CookieJar<'_>,
    rate_limiter: &State<RateLimiter>,
    client_ip: ClientIp,
    form: Form<LoginForm>,
) -> Result<Redirect, Flash<Redirect>> {
    validate_csrf(cookies, &form.csrf_token).map_err(|_| {
        Flash::error(
            Redirect::to(uri!(login_page)),
            "Invalid request. Please try again.",
        )
    })?;

    if !rate_limiter.check(&format!("login:{}", client_ip.0), 10, 900) {
        return Err(Flash::error(
            Redirect::to(uri!(login_page)),
            "Too many login attempts. Please wait 15 minutes.",
        ));
    }

    let result =
        auth_service::login(pool.inner(), config.inner(), &form.username, &form.password).await;

    match result {
        Ok(login_result) => {
            set_session_cookie(cookies, &login_result.token);
            if login_result.setup_complete {
                Ok(Redirect::to(uri!(files_page(
                    path = Option::<String>::None
                ))))
            } else {
                Ok(Redirect::to(uri!(setup_page)))
            }
        }
        Err(_) => Err(Flash::error(
            Redirect::to(uri!(login_page)),
            "Invalid username or password.",
        )),
    }
}

/// GET /register
#[get("/register")]
pub async fn register_page(
    user: Option<SessionUser>,
    cookies: &CookieJar<'_>,
    flash: Option<FlashMessage<'_>>,
) -> Result<Template, Redirect> {
    if user.is_some() {
        return Err(Redirect::to(uri!(index)));
    }
    let csrf_token = ensure_csrf_token(cookies);
    Ok(Template::render(
        "auth/register",
        context! {
            csrf_token: csrf_token,
            flash_kind: flash.as_ref().map(|f| f.kind().to_string()),
            flash_msg: flash.as_ref().map(|f| f.message().to_string()),
        },
    ))
}

/// POST /register
#[post("/register", data = "<form>")]
pub async fn register_submit(
    pool: &State<DbPool>,
    config: &State<AppConfig>,
    cookies: &CookieJar<'_>,
    rate_limiter: &State<RateLimiter>,
    client_ip: ClientIp,
    form: Form<RegisterForm>,
) -> Result<Flash<Redirect>, Flash<Redirect>> {
    validate_csrf(cookies, &form.csrf_token).map_err(|_| {
        Flash::error(
            Redirect::to(uri!(register_page)),
            "Invalid request. Please try again.",
        )
    })?;

    if !rate_limiter.check(&format!("register:{}", client_ip.0), 5, 900) {
        return Err(Flash::error(
            Redirect::to(uri!(register_page)),
            "Too many registration attempts. Please wait 15 minutes.",
        ));
    }

    if form.password != form.password_confirm {
        return Err(Flash::error(
            Redirect::to(uri!(register_page)),
            "Passwords do not match.",
        ));
    }

    match auth_service::register(
        pool.inner(),
        config.inner(),
        &form.username,
        &form.email,
        &form.password,
    )
    .await
    {
        Ok(_) => Ok(Flash::success(
            Redirect::to(uri!(login_page)),
            "Account created! Please log in.",
        )),
        Err(AppError::Conflict(msg)) => Err(Flash::error(Redirect::to(uri!(register_page)), msg)),
        Err(AppError::Validation(msg)) => Err(Flash::error(Redirect::to(uri!(register_page)), msg)),
        Err(_) => Err(Flash::error(
            Redirect::to(uri!(register_page)),
            "Registration failed. Please try again.",
        )),
    }
}

/// POST /logout
#[post("/logout", data = "<form>")]
pub async fn logout_submit(
    pool: &State<DbPool>,
    cookies: &CookieJar<'_>,
    user: Option<SessionUser>,
    form: Form<CsrfOnlyForm>,
) -> Redirect {
    if validate_csrf(cookies, &form.csrf_token).is_err() {
        return Redirect::to(uri!(login_page));
    }
    if let Some(session_user) = user {
        if let Some(cookie) = cookies.get(COOKIE_NAME) {
            let token_hash = crate::guards::auth_guard::hash_token(cookie.value());
            let _ = auth_service::logout(pool.inner(), &session_user.0.id, &token_hash).await;
        }
    }
    clear_session_cookie(cookies);
    Redirect::to(uri!(login_page))
}

// ---------------------------------------------------------------------------
// Setup wizard
// ---------------------------------------------------------------------------

/// GET /setup
#[get("/setup")]
pub async fn setup_page(
    user: SessionUser,
    cookies: &CookieJar<'_>,
    flash: Option<FlashMessage<'_>>,
) -> Result<Template, Redirect> {
    if user.0.setup_complete {
        return Err(Redirect::to(uri!(files_page(
            path = Option::<String>::None
        ))));
    }
    let csrf_token = ensure_csrf_token(cookies);
    Ok(Template::render(
        "setup/wizard",
        context! {
            user: &user.0.username,
            csrf_token: csrf_token,
            flash_kind: flash.as_ref().map(|f| f.kind().to_string()),
            flash_msg: flash.as_ref().map(|f| f.message().to_string()),
        },
    ))
}

/// POST /setup
#[post("/setup", data = "<form>")]
pub async fn setup_submit(
    pool: &State<DbPool>,
    config: &State<AppConfig>,
    master_key: &State<MasterKey>,
    unlock_state: &State<UnlockState>,
    cookies: &CookieJar<'_>,
    user: SessionUser,
    form: Form<CsrfOnlyForm>,
) -> Result<Redirect, Flash<Redirect>> {
    validate_csrf(cookies, &form.csrf_token).map_err(|_| {
        Flash::error(
            Redirect::to(uri!(setup_page)),
            "Invalid request. Please try again.",
        )
    })?;

    if user.0.setup_complete {
        return Ok(Redirect::to(uri!(files_page(
            path = Option::<String>::None
        ))));
    }

    match library_service::setup_library(
        pool.inner(),
        config.inner(),
        master_key.inner(),
        unlock_state.inner(),
        &user.0.id,
    )
    .await
    {
        Ok(_) => Ok(Redirect::to(uri!(files_page(
            path = Option::<String>::None
        )))),
        Err(_) => Err(Flash::error(
            Redirect::to(uri!(setup_page)),
            "Library setup failed. Please try again.",
        )),
    }
}

// ---------------------------------------------------------------------------
// File browser
// ---------------------------------------------------------------------------

/// GET /files?<path>
#[get("/files?<path>")]
pub async fn files_page(
    pool: &State<DbPool>,
    config: &State<AppConfig>,
    unlock_state: &State<UnlockState>,
    cookies: &CookieJar<'_>,
    user: SessionSetupComplete,
    path: Option<String>,
    flash: Option<FlashMessage<'_>>,
) -> Result<Template, Redirect> {
    let lib = match require_library(pool.inner(), &user.0.id).await {
        Ok(l) => l,
        Err(_) => return Err(Redirect::to(uri!(setup_page))),
    };

    let user_path = path.as_deref().unwrap_or("");

    let entries: Vec<fs_service::FsEntry> = fs_service::list_directory(
        config.inner(),
        unlock_state.inner(),
        &lib.id,
        user_path,
        false,
    )
    .await
    .unwrap_or_default();

    // Build breadcrumb segments
    let breadcrumbs = build_breadcrumbs(user_path);

    // Format entries for display
    let display_entries: Vec<serde_json::Value> = entries
        .iter()
        .map(|e| {
            serde_json::json!({
                "name": e.name,
                "path": e.path,
                "is_dir": e.is_dir,
                "size": e.size.map(format_bytes),
                "raw_size": e.size.unwrap_or(0),
                "disk_size": e.disk_size.map(format_bytes),
                "mime_type": e.mime_type,
                "modified": e.modified.as_deref().map(format_timestamp),
                "raw_modified": e.modified,
                "icon": file_icon(&e.name, e.is_dir, e.mime_type.as_deref()),
            })
        })
        .collect();

    let csrf_token = ensure_csrf_token(cookies);

    Ok(Template::render(
        "files/browser",
        context! {
            user: &user.0.username,
            csrf_token: csrf_token,
            chunk_size_bytes: config.chunk_size_bytes,
            max_parallel_chunks: config.max_parallel_chunks,
            path: user_path,
            entries: display_entries,
            breadcrumbs: breadcrumbs,
            is_root: user_path.is_empty(),
            flash_kind: flash.as_ref().map(|f| f.kind().to_string()),
            flash_msg: flash.as_ref().map(|f| f.message().to_string()),
        },
    ))
}

/// GET /files/partial?<path> — HTMX partial for file list swap
#[get("/files/partial?<path>")]
pub async fn files_partial(
    pool: &State<DbPool>,
    config: &State<AppConfig>,
    unlock_state: &State<UnlockState>,
    user: SessionSetupComplete,
    path: Option<String>,
) -> Result<Template, Status> {
    let lib = require_library(pool.inner(), &user.0.id)
        .await
        .map_err(|_| Status::NotFound)?;

    let user_path = path.as_deref().unwrap_or("");

    let entries = fs_service::list_directory(
        config.inner(),
        unlock_state.inner(),
        &lib.id,
        user_path,
        false,
    )
    .await
    .unwrap_or_default();

    let breadcrumbs = build_breadcrumbs(user_path);

    let display_entries: Vec<serde_json::Value> = entries
        .iter()
        .map(|e| {
            serde_json::json!({
                "name": e.name,
                "path": e.path,
                "is_dir": e.is_dir,
                "size": e.size.map(format_bytes),
                "raw_size": e.size.unwrap_or(0),
                "disk_size": e.disk_size.map(format_bytes),
                "mime_type": e.mime_type,
                "modified": e.modified.as_deref().map(format_timestamp),
                "raw_modified": e.modified,
                "icon": file_icon(&e.name, e.is_dir, e.mime_type.as_deref()),
            })
        })
        .collect();

    Ok(Template::render(
        "partials/file_list",
        context! {
            path: user_path,
            entries: display_entries,
            breadcrumbs: breadcrumbs,
            is_root: user_path.is_empty(),
        },
    ))
}

/// GET /files/folders?<path> — session-auth folder listing for move modal
#[get("/files/folders?<path>")]
pub async fn files_folders(
    pool: &State<DbPool>,
    config: &State<AppConfig>,
    unlock_state: &State<UnlockState>,
    user: SessionSetupComplete,
    path: Option<String>,
) -> Result<rocket::serde::json::Json<serde_json::Value>, (Status, rocket::serde::json::Json<serde_json::Value>)> {
    let lib = require_library(pool.inner(), &user.0.id)
        .await
        .map_err(|_| {
            (
                Status::NotFound,
                rocket::serde::json::Json(serde_json::json!({"error": "Library not found."})),
            )
        })?;

    let user_path = path.as_deref().unwrap_or("");

    let entries = fs_service::list_directory(
        config.inner(),
        unlock_state.inner(),
        &lib.id,
        user_path,
        false,
    )
    .await
    .map_err(|e| {
        (
            e.status(),
            rocket::serde::json::Json(serde_json::json!({"error": e.to_string()})),
        )
    })?;

    let folders: Vec<serde_json::Value> = entries
        .into_iter()
        .filter(|e| e.is_dir)
        .map(|e| {
            serde_json::json!({
                "name": e.name,
                "path": e.path,
            })
        })
        .collect();

    Ok(rocket::serde::json::Json(serde_json::json!({
        "path": user_path,
        "entries": folders,
    })))
}

// ---------------------------------------------------------------------------
// File operations (form-based for HTMX)
// ---------------------------------------------------------------------------

/// POST /files/mkdir
#[post("/files/mkdir", data = "<form>")]
pub async fn mkdir_submit(
    pool: &State<DbPool>,
    config: &State<AppConfig>,
    cookies: &CookieJar<'_>,
    user: SessionSetupComplete,
    form: Form<MkdirForm>,
) -> Result<Flash<Redirect>, Flash<Redirect>> {
    validate_csrf(cookies, &form.csrf_token).map_err(|_| {
        Flash::error(
            Redirect::to(uri!(files_page(path = Some(form.path.clone())))),
            "Invalid request. Please try again.",
        )
    })?;

    let lib = require_library(pool.inner(), &user.0.id)
        .await
        .map_err(|_| {
            Flash::error(
                Redirect::to(uri!(files_page(path = Some(form.path.clone())))),
                "Library not found.",
            )
        })?;

    let full_path = if form.path.is_empty() {
        form.name.clone()
    } else {
        format!("{}/{}", form.path, form.name)
    };

    match fs_service::create_directory(config.inner(), &lib.id, &full_path).await {
        Ok(_) => Ok(Flash::success(
            Redirect::to(uri!(files_page(path = Some(form.path.clone())))),
            format!("Folder \"{}\" created.", form.name),
        )),
        Err(AppError::Conflict(msg)) => Err(Flash::error(
            Redirect::to(uri!(files_page(path = Some(form.path.clone())))),
            msg,
        )),
        Err(AppError::Validation(msg)) => Err(Flash::error(
            Redirect::to(uri!(files_page(path = Some(form.path.clone())))),
            msg,
        )),
        Err(_) => Err(Flash::error(
            Redirect::to(uri!(files_page(path = Some(form.path.clone())))),
            "Failed to create folder.",
        )),
    }
}

/// POST /files/rename
#[post("/files/rename", data = "<form>")]
pub async fn rename_submit(
    pool: &State<DbPool>,
    config: &State<AppConfig>,
    cookies: &CookieJar<'_>,
    user: SessionSetupComplete,
    form: Form<RenameForm>,
) -> Result<Flash<Redirect>, Flash<Redirect>> {
    validate_csrf(cookies, &form.csrf_token).map_err(|_| {
        Flash::error(
            Redirect::to(uri!(files_page(path = Option::<String>::None))),
            "Invalid request. Please try again.",
        )
    })?;

    let lib = require_library(pool.inner(), &user.0.id)
        .await
        .map_err(|_| {
            Flash::error(
                Redirect::to(uri!(files_page(path = Option::<String>::None))),
                "Library not found.",
            )
        })?;

    // Compute parent dir and new full path
    let parent = parent_path(&form.old_path);
    let new_path = if parent.is_empty() {
        form.new_name.clone()
    } else {
        format!("{}/{}", parent, form.new_name)
    };

    match fs_service::rename_entry(config.inner(), &lib.id, &form.old_path, &new_path).await {
        Ok(_) => Ok(Flash::success(
            Redirect::to(uri!(files_page(
                path = if parent.is_empty() {
                    None
                } else {
                    Some(parent)
                }
            ))),
            format!("Renamed to \"{}\".", form.new_name),
        )),
        Err(AppError::Validation(msg)) => Err(Flash::error(
            Redirect::to(uri!(files_page(
                path = if parent.is_empty() {
                    None
                } else {
                    Some(parent)
                }
            ))),
            msg,
        )),
        Err(_) => Err(Flash::error(
            Redirect::to(uri!(files_page(
                path = if parent.is_empty() {
                    None
                } else {
                    Some(parent)
                }
            ))),
            "Rename failed.",
        )),
    }
}

/// POST /files/move
#[post("/files/move", data = "<form>")]
pub async fn move_submit(
    pool: &State<DbPool>,
    config: &State<AppConfig>,
    cookies: &CookieJar<'_>,
    user: SessionSetupComplete,
    form: Form<MoveForm>,
) -> Result<Flash<Redirect>, Flash<Redirect>> {
    validate_csrf(cookies, &form.csrf_token).map_err(|_| {
        Flash::error(
            Redirect::to(uri!(files_page(path = Option::<String>::None))),
            "Invalid request. Please try again.",
        )
    })?;

    let lib = require_library(pool.inner(), &user.0.id)
        .await
        .map_err(|_| {
            Flash::error(
                Redirect::to(uri!(files_page(path = Option::<String>::None))),
                "Library not found.",
            )
        })?;

    let name = file_name_from_path(&form.old_path);
    if name.is_empty() {
        return Err(Flash::error(
            Redirect::to(uri!(files_page(path = Option::<String>::None))),
            "Invalid source path.",
        ));
    }

    let target_dir = normalize_dir_path(&form.target_dir);
    let new_path = join_dir_and_name(&target_dir, &name);

    let return_dir = normalize_dir_path(form.return_path.as_deref().unwrap_or(""));
    let redirect_path = if return_dir.is_empty() {
        None
    } else {
        Some(return_dir)
    };

    match fs_service::rename_entry(config.inner(), &lib.id, &form.old_path, &new_path).await {
        Ok(_) => Ok(Flash::success(
            Redirect::to(uri!(files_page(path = redirect_path))),
            "Moved successfully.",
        )),
        Err(AppError::Validation(msg)) => Err(Flash::error(
            Redirect::to(uri!(files_page(path = Option::<String>::None))),
            msg,
        )),
        Err(AppError::Conflict(msg)) => Err(Flash::error(
            Redirect::to(uri!(files_page(path = Option::<String>::None))),
            msg,
        )),
        Err(_) => Err(Flash::error(
            Redirect::to(uri!(files_page(path = Option::<String>::None))),
            "Move failed.",
        )),
    }
}

/// POST /files/delete
#[post("/files/delete", data = "<form>")]
pub async fn delete_submit(
    pool: &State<DbPool>,
    config: &State<AppConfig>,
    cookies: &CookieJar<'_>,
    user: SessionSetupComplete,
    form: Form<DeleteForm>,
) -> Result<Flash<Redirect>, Flash<Redirect>> {
    validate_csrf(cookies, &form.csrf_token).map_err(|_| {
        Flash::error(
            Redirect::to(uri!(files_page(path = Option::<String>::None))),
            "Invalid request. Please try again.",
        )
    })?;

    let lib = require_library(pool.inner(), &user.0.id)
        .await
        .map_err(|_| {
            Flash::error(
                Redirect::to(uri!(files_page(path = Option::<String>::None))),
                "Library not found.",
            )
        })?;

    let parent = parent_path(&form.path);

    match fs_service::delete_entry(config.inner(), &lib.id, &form.path).await {
        Ok(_) => Ok(Flash::success(
            Redirect::to(uri!(files_page(
                path = if parent.is_empty() {
                    None
                } else {
                    Some(parent)
                }
            ))),
            "Deleted successfully.",
        )),
        Err(_) => Err(Flash::error(
            Redirect::to(uri!(files_page(
                path = if parent.is_empty() {
                    None
                } else {
                    Some(parent)
                }
            ))),
            "Delete failed.",
        )),
    }
}

/// POST /files/bulk-delete — XHR JSON endpoint for multi-file delete
#[post("/files/bulk-delete", data = "<data>")]
pub async fn bulk_delete(
    pool: &State<DbPool>,
    config: &State<AppConfig>,
    _csrf: CsrfXhr,
    user: SessionSetupComplete,
    data: rocket::serde::json::Json<BulkDeleteRequest>,
) -> rocket::serde::json::Json<serde_json::Value> {
    let lib = match require_library(pool.inner(), &user.0.id).await {
        Ok(l) => l,
        Err(_) => {
            return rocket::serde::json::Json(
                serde_json::json!({"deleted": 0, "errors": ["Library not found."]}),
            )
        }
    };

    if data.paths.is_empty() || data.paths.len() > 500 {
        return rocket::serde::json::Json(
            serde_json::json!({"deleted": 0, "errors": ["Invalid number of paths (1–500)."]}),
        );
    }

    let mut deleted = 0u32;
    let mut errors: Vec<String> = Vec::new();

    for path in &data.paths {
        match fs_service::delete_entry(config.inner(), &lib.id, path).await {
            Ok(_) => deleted += 1,
            Err(e) => errors.push(format!("{}: {}", path, e)),
        }
    }

    rocket::serde::json::Json(serde_json::json!({
        "deleted": deleted,
        "errors": errors,
    }))
}

/// POST /files/bulk-move — XHR JSON endpoint for multi-file/folder move
#[post("/files/bulk-move", data = "<data>")]
pub async fn bulk_move(
    pool: &State<DbPool>,
    config: &State<AppConfig>,
    _csrf: CsrfXhr,
    user: SessionSetupComplete,
    data: rocket::serde::json::Json<BulkMoveRequest>,
) -> rocket::serde::json::Json<serde_json::Value> {
    let lib = match require_library(pool.inner(), &user.0.id).await {
        Ok(l) => l,
        Err(_) => {
            return rocket::serde::json::Json(
                serde_json::json!({"moved": 0, "errors": ["Library not found."]}),
            )
        }
    };

    if data.paths.is_empty() || data.paths.len() > 500 {
        return rocket::serde::json::Json(
            serde_json::json!({"moved": 0, "errors": ["Invalid number of paths (1–500)."]}),
        );
    }

    let target_dir = normalize_dir_path(&data.target_dir);
    let mut moved = 0u32;
    let mut errors: Vec<String> = Vec::new();

    for old_path in &data.paths {
        let name = file_name_from_path(old_path);
        if name.is_empty() {
            errors.push(format!("{}: Invalid source path.", old_path));
            continue;
        }

        let new_path = join_dir_and_name(&target_dir, &name);
        match fs_service::rename_entry(config.inner(), &lib.id, old_path, &new_path).await {
            Ok(_) => moved += 1,
            Err(e) => errors.push(format!("{}: {}", old_path, e)),
        }
    }

    rocket::serde::json::Json(serde_json::json!({
        "moved": moved,
        "errors": errors,
    }))
}

/// POST /files/upload?<path> — receives raw file data from XHR
#[post("/files/upload?<path>", data = "<data>")]
pub async fn upload_file(
    pool: &State<DbPool>,
    config: &State<AppConfig>,
    unlock_state: &State<UnlockState>,
    _csrf: CsrfXhr,
    user: SessionSetupComplete,
    path: String,
    data: rocket::data::Data<'_>,
) -> Result<
    rocket::serde::json::Json<serde_json::Value>,
    (Status, rocket::serde::json::Json<serde_json::Value>),
> {
    use rocket::data::ToByteUnit;

    let lib = require_library(pool.inner(), &user.0.id)
        .await
        .map_err(|_| {
            (
                Status::NotFound,
                rocket::serde::json::Json(serde_json::json!({"error": "Library not found."})),
            )
        })?;

    let max_bytes = config.max_upload_bytes;
    let hard_cap: u64 = 50 * 1024 * 1024;
    let allowed = std::cmp::min(max_bytes, hard_cap);
    let stream = data.open(allowed.bytes()).into_bytes().await.map_err(|e| {
        (
            Status::InternalServerError,
            rocket::serde::json::Json(serde_json::json!({"error": format!("Read failed: {e}")})),
        )
    })?;

    if !stream.is_complete() {
        return Err((
            Status::PayloadTooLarge,
            rocket::serde::json::Json(
                serde_json::json!({"error": format!("File exceeds maximum size of {} bytes.", allowed)}),
            ),
        ));
    }

    let bytes = stream.into_inner();

    match fs_service::upload_file(
        config.inner(),
        unlock_state.inner(),
        &lib.id,
        &path,
        &bytes,
        false,
    )
    .await
    {
        Ok(result) => Ok(rocket::serde::json::Json(serde_json::json!({
            "success": true,
            "path": result.path,
            "size": result.size,
            "disk_size": result.disk_size,
            "checksum_sha256": result.checksum_sha256,
            "mime_type": result.mime_type,
        }))),
        Err(e) => Err((
            e.status(),
            rocket::serde::json::Json(serde_json::json!({"error": e.to_string()})),
        )),
    }
}

/// POST /files/chunked/init — starts a chunked upload session for the browser UI.
#[post("/files/chunked/init", data = "<body>")]
pub async fn chunked_init_upload(
    pool: &State<DbPool>,
    config: &State<AppConfig>,
    _csrf: CsrfXhr,
    user: SessionSetupComplete,
    body: rocket::serde::json::Json<ChunkedInitRequest>,
) -> Result<
    rocket::serde::json::Json<serde_json::Value>,
    (Status, rocket::serde::json::Json<serde_json::Value>),
> {
    let lib = require_library(pool.inner(), &user.0.id)
        .await
        .map_err(|_| {
            (
                Status::NotFound,
                rocket::serde::json::Json(serde_json::json!({"error": "Library not found."})),
            )
        })?;

    let result = chunk_service::init_upload(
        pool.inner(),
        config.inner(),
        chunk_service::InitUploadParams {
            user_id: user.0.id.clone(),
            library_id: lib.id,
            target_path: body.path.clone(),
            total_chunks: body.total_chunks,
            total_bytes: body.total_bytes,
            checksum_sha256: body.checksum_sha256.clone(),
        },
    )
    .await
    .map_err(|e| {
        tracing::warn!(
            user = %user.0.id,
            path = %body.path,
            total_bytes = body.total_bytes,
            total_chunks = body.total_chunks,
            chunk_size_bytes = config.chunk_size_bytes,
            max_upload_bytes = config.max_upload_bytes,
            error = %e,
            "chunked init rejected"
        );
        (
            e.status(),
            rocket::serde::json::Json(serde_json::json!({"error": e.to_string()})),
        )
    })?;

    Ok(rocket::serde::json::Json(serde_json::json!({
        "upload_id": result.upload_id,
        "chunk_size_bytes": result.chunk_size_bytes,
        "total_chunks": result.total_chunks,
        "total_bytes": result.total_bytes,
        "expires_at": result.expires_at,
    })))
}

/// PUT /files/chunked/upload/<upload_id>/<chunk_index> — receives one chunk.
#[put("/files/chunked/upload/<upload_id>/<chunk_index>", data = "<data>")]
pub async fn chunked_receive_chunk(
    pool: &State<DbPool>,
    config: &State<AppConfig>,
    _csrf: CsrfXhr,
    user: SessionSetupComplete,
    upload_id: &str,
    chunk_index: u32,
    data: rocket::data::Data<'_>,
) -> Result<
    rocket::serde::json::Json<serde_json::Value>,
    (Status, rocket::serde::json::Json<serde_json::Value>),
> {
    use rocket::data::ToByteUnit;

    let lib = require_library(pool.inner(), &user.0.id)
        .await
        .map_err(|_| {
            (
                Status::NotFound,
                rocket::serde::json::Json(serde_json::json!({"error": "Library not found."})),
            )
        })?;

    let allowed = (config.chunk_size_bytes + 1).bytes();
    let stream = data.open(allowed).into_bytes().await.map_err(|e| {
        (
            Status::InternalServerError,
            rocket::serde::json::Json(
                serde_json::json!({"error": format!("Failed to read chunk data: {e}")}),
            ),
        )
    })?;

    if !stream.is_complete() {
        return Err((
            Status::PayloadTooLarge,
            rocket::serde::json::Json(serde_json::json!({
                "error": format!("Chunk exceeds the maximum chunk size of {} bytes.", config.chunk_size_bytes)
            })),
        ));
    }

    let result = chunk_service::receive_chunk(
        pool.inner(),
        config.inner(),
        &user.0.id,
        &lib.id,
        upload_id,
        chunk_index,
        &stream.into_inner(),
    )
    .await
    .map_err(|e| {
        (
            e.status(),
            rocket::serde::json::Json(serde_json::json!({"error": e.to_string()})),
        )
    })?;

    Ok(rocket::serde::json::Json(serde_json::json!({
        "upload_id": result.upload_id,
        "chunk_index": result.chunk_index,
        "received_chunks": result.received_chunks,
        "total_chunks": result.total_chunks,
    })))
}

/// POST /files/chunked/complete — assembles and persists a chunked upload.
#[post("/files/chunked/complete", data = "<body>")]
pub async fn chunked_complete_upload(
    pool: &State<DbPool>,
    config: &State<AppConfig>,
    unlock_state: &State<UnlockState>,
    _csrf: CsrfXhr,
    user: SessionSetupComplete,
    body: rocket::serde::json::Json<ChunkedCompleteRequest>,
) -> Result<
    rocket::serde::json::Json<serde_json::Value>,
    (Status, rocket::serde::json::Json<serde_json::Value>),
> {
    let lib = require_library(pool.inner(), &user.0.id)
        .await
        .map_err(|_| {
            (
                Status::NotFound,
                rocket::serde::json::Json(serde_json::json!({"error": "Library not found."})),
            )
        })?;

    let result = chunk_service::complete_upload(
        pool.inner(),
        config.inner(),
        unlock_state.inner(),
        &user.0.id,
        &lib.id,
        &body.upload_id,
        body.verify.unwrap_or(false),
    )
    .await
    .map_err(|e| {
        (
            e.status(),
            rocket::serde::json::Json(serde_json::json!({"error": e.to_string()})),
        )
    })?;

    Ok(rocket::serde::json::Json(serde_json::json!({
        "success": true,
        "path": result.path,
        "size": result.size,
        "disk_size": result.disk_size,
        "checksum_sha256": result.checksum_sha256,
        "mime_type": result.mime_type,
    })))
}

/// DELETE /files/chunked/cancel?upload_id=<id> — cancels a chunked upload.
#[delete("/files/chunked/cancel?<upload_id>")]
pub async fn chunked_cancel_upload(
    pool: &State<DbPool>,
    config: &State<AppConfig>,
    _csrf: CsrfXhr,
    user: SessionSetupComplete,
    upload_id: String,
) -> Result<
    rocket::serde::json::Json<serde_json::Value>,
    (Status, rocket::serde::json::Json<serde_json::Value>),
> {
    let lib = require_library(pool.inner(), &user.0.id)
        .await
        .map_err(|_| {
            (
                Status::NotFound,
                rocket::serde::json::Json(serde_json::json!({"error": "Library not found."})),
            )
        })?;

    chunk_service::cancel_upload(
        pool.inner(),
        config.inner(),
        &user.0.id,
        &lib.id,
        &upload_id,
    )
    .await
    .map_err(|e| {
        (
            e.status(),
            rocket::serde::json::Json(serde_json::json!({"error": e.to_string()})),
        )
    })?;

    Ok(rocket::serde::json::Json(serde_json::json!({
        "success": true,
        "upload_id": upload_id,
    })))
}

/// GET /files/chunked/download/init?<path> — initialize chunked browser download.
#[get("/files/chunked/download/init?<path>")]
pub async fn chunked_init_download(
    pool: &State<DbPool>,
    config: &State<AppConfig>,
    unlock_state: &State<UnlockState>,
    user: SessionSetupComplete,
    path: String,
) -> Result<
    rocket::serde::json::Json<serde_json::Value>,
    (Status, rocket::serde::json::Json<serde_json::Value>),
> {
    let lib = require_library(pool.inner(), &user.0.id)
        .await
        .map_err(|_| {
            (
                Status::NotFound,
                rocket::serde::json::Json(serde_json::json!({"error": "Library not found."})),
            )
        })?;

    let result = chunk_service::init_download(
        config.inner(),
        unlock_state.inner(),
        &user.0.id,
        &lib.id,
        &path,
    )
    .await
    .map_err(|e| {
        (
            e.status(),
            rocket::serde::json::Json(serde_json::json!({"error": e.to_string()})),
        )
    })?;

    Ok(rocket::serde::json::Json(serde_json::json!({
        "token": result.token,
        "filename": result.filename,
        "mime_type": result.mime_type,
        "chunk_size_bytes": result.chunk_size_bytes,
        "total_chunks": result.total_chunks,
        "total_bytes": result.total_bytes,
        "expires_at": result.expires_at,
    })))
}

/// GET /files/chunked/download/chunk?<token>&<index> — stream one chunk for browser download.
#[get("/files/chunked/download/chunk?<token>&<index>")]
pub async fn chunked_download_chunk(
    config: &State<AppConfig>,
    unlock_state: &State<UnlockState>,
    user: SessionSetupComplete,
    token: String,
    index: u32,
) -> Result<
    crate::routes::library::FileChunkDownload,
    (Status, rocket::serde::json::Json<serde_json::Value>),
> {
    let result = chunk_service::serve_chunk(
        config.inner(),
        unlock_state.inner(),
        &user.0.id,
        &token,
        index,
    )
    .await
    .map_err(|e| {
        (
            e.status(),
            rocket::serde::json::Json(serde_json::json!({"error": e.to_string()})),
        )
    })?;

    let content_type = result
        .mime_type
        .as_deref()
        .and_then(|m| {
            let parts: Vec<&str> = m.splitn(2, '/').collect();
            if parts.len() == 2 {
                Some(rocket::http::ContentType::new(
                    parts[0].to_string(),
                    parts[1].to_string(),
                ))
            } else {
                None
            }
        })
        .unwrap_or(rocket::http::ContentType::Binary);

    Ok(crate::routes::library::FileChunkDownload {
        data: result.data,
        content_type,
        checksum_sha256: result.checksum_sha256,
        chunk_index: result.chunk_index,
        total_chunks: result.total_chunks,
        total_bytes: result.total_bytes,
    })
}

/// GET /files/download?<path> — browser download
#[get("/files/download?<path>")]
pub async fn download_file(
    pool: &State<DbPool>,
    config: &State<AppConfig>,
    unlock_state: &State<UnlockState>,
    user: SessionSetupComplete,
    path: String,
) -> Result<crate::routes::library::FileDownload, Flash<Redirect>> {
    let lib = require_library(pool.inner(), &user.0.id)
        .await
        .map_err(|_| {
            Flash::error(
                Redirect::to(uri!(files_page(path = Option::<String>::None))),
                "Library not found.",
            )
        })?;

    let result = fs_service::download_file(config.inner(), unlock_state.inner(), &lib.id, &path)
        .await
        .map_err(|_| {
            Flash::error(
                Redirect::to(uri!(files_page(path = Option::<String>::None))),
                "Download failed.",
            )
        })?;

    let content_type = result
        .mime_type
        .as_deref()
        .and_then(|m| {
            let parts: Vec<&str> = m.splitn(2, '/').collect();
            if parts.len() == 2 {
                Some(rocket::http::ContentType::new(
                    parts[0].to_string(),
                    parts[1].to_string(),
                ))
            } else {
                None
            }
        })
        .unwrap_or(rocket::http::ContentType::Binary);

    Ok(crate::routes::library::FileDownload {
        data: result.data,
        filename: result.filename,
        content_type,
        checksum_sha256: result.checksum_sha256,
    })
}

// ---------------------------------------------------------------------------
// Sidebar usage snippet (HTMX partial)
// ---------------------------------------------------------------------------

/// GET /usage/sidebar — tiny HTMX partial for the sidebar storage bar
#[get("/usage/sidebar")]
pub async fn usage_sidebar(
    pool: &State<DbPool>,
    config: &State<AppConfig>,
    user: SessionSetupComplete,
) -> Result<Template, Status> {
    let lib = require_library(pool.inner(), &user.0.id)
        .await
        .map_err(|_| Status::NotFound)?;

    let usage = fs_service::calculate_usage(config.inner(), &lib.id, "")
        .await
        .unwrap_or(fs_service::UsageResult {
            disk_bytes: 0,
            file_count: 0,
            dir_count: 0,
        });

    let pct = if user.0.quota_bytes > 0 {
        (usage.disk_bytes as f64 / user.0.quota_bytes as f64 * 100.0).min(100.0) as u64
    } else {
        0u64
    };

    Ok(Template::render(
        "partials/sidebar_usage",
        context! {
            disk_bytes_fmt: format_bytes(usage.disk_bytes),
            quota_bytes_fmt: format_bytes(user.0.quota_bytes as u64),
            usage_pct: pct,
        },
    ))
}

// ---------------------------------------------------------------------------
// Usage page
// ---------------------------------------------------------------------------

/// GET /usage
#[get("/usage")]
pub async fn usage_page(
    pool: &State<DbPool>,
    config: &State<AppConfig>,
    cookies: &CookieJar<'_>,
    user: SessionSetupComplete,
) -> Result<Template, Redirect> {
    let lib = match require_library(pool.inner(), &user.0.id).await {
        Ok(l) => l,
        Err(_) => return Err(Redirect::to(uri!(setup_page))),
    };

    let usage = fs_service::calculate_usage(config.inner(), &lib.id, "")
        .await
        .unwrap_or(fs_service::UsageResult {
            disk_bytes: 0,
            file_count: 0,
            dir_count: 0,
        });

    Ok(Template::render(
        "files/usage",
        context! {
            user: &user.0.username,
            csrf_token: ensure_csrf_token(cookies),
            disk_bytes: usage.disk_bytes,
            disk_bytes_fmt: format_bytes(usage.disk_bytes),
            file_count: usage.file_count,
            dir_count: usage.dir_count,
            quota_bytes: user.0.quota_bytes,
            quota_bytes_fmt: format_bytes(user.0.quota_bytes as u64),
            usage_pct: if user.0.quota_bytes > 0 { (usage.disk_bytes as f64 / user.0.quota_bytes as f64 * 100.0).min(100.0) as u64 } else { 0u64 },
        },
    ))
}

// ---------------------------------------------------------------------------
// Settings page
// ---------------------------------------------------------------------------

/// GET /settings
#[get("/settings")]
pub async fn settings_page(
    pool: &State<DbPool>,
    cookies: &CookieJar<'_>,
    user: SessionSetupComplete,
) -> Result<Template, Redirect> {
    let lib = PersonalLibrary::find_by_user(pool.inner(), &user.0.id)
        .await
        .ok()
        .flatten();

    Ok(Template::render(
        "settings/index",
        context! {
            user_id: &user.0.id,
            username: &user.0.username,
            csrf_token: ensure_csrf_token(cookies),
            email: &user.0.email,
            role: &user.0.role,
            created_at: &user.0.created_at,
            library_id: lib.as_ref().map(|l| l.id.as_str()),
            encryption_mode: lib.as_ref().map(|l| l.encryption_mode.as_str()),
            library_created: lib.as_ref().map(|l| l.created_at.as_str()),
        },
    ))
}

// ---------------------------------------------------------------------------
// Groups pages
// ---------------------------------------------------------------------------

/// GET /groups
#[get("/groups")]
pub async fn groups_page(
    pool: &State<DbPool>,
    cookies: &CookieJar<'_>,
    user: SessionSetupComplete,
    flash: Option<FlashMessage<'_>>,
) -> Template {
    let groups_data = group_service::list_user_groups(pool.inner(), &user.0.id)
        .await
        .unwrap_or_default();

    let groups: Vec<serde_json::Value> = groups_data
        .into_iter()
        .map(|g| {
            serde_json::json!({
                "id": g.group.id,
                "name": g.group.name,
                "description": g.group.description,
                "created_by": g.group.created_by,
                "created_at": format_timestamp(&g.group.created_at),
                "member_count": g.member_count,
                "user_role": g.user_role,
            })
        })
        .collect();

    Template::render(
        "groups/index",
        context! {
            user: &user.0.username,
            csrf_token: ensure_csrf_token(cookies),
            current_path: "groups",
            groups: groups,
            flash_kind: flash.as_ref().map(|f| f.kind().to_string()),
            flash_msg: flash.as_ref().map(|f| f.message().to_string()),
        },
    )
}

/// POST /groups/create
#[post("/groups/create", data = "<form>")]
pub async fn groups_create_submit(
    pool: &State<DbPool>,
    cookies: &CookieJar<'_>,
    user: SessionSetupComplete,
    form: Form<CreateGroupForm>,
) -> Result<Flash<Redirect>, Flash<Redirect>> {
    validate_csrf(cookies, &form.csrf_token).map_err(|_| {
        Flash::error(
            Redirect::to(uri!(groups_page)),
            "Invalid request. Please try again.",
        )
    })?;

    match group_service::create_group(
        pool.inner(),
        &user.0.id,
        &form.name,
        form.description.as_deref(),
    )
    .await
    {
        Ok(g) => Ok(Flash::success(
            Redirect::to(uri!(groups_page)),
            format!("Group \"{}\" created.", g.group.name),
        )),
        Err(AppError::Conflict(msg)) => {
            Err(Flash::error(Redirect::to(uri!(groups_page)), msg))
        }
        Err(AppError::Validation(msg)) => {
            Err(Flash::error(Redirect::to(uri!(groups_page)), msg))
        }
        Err(_) => Err(Flash::error(
            Redirect::to(uri!(groups_page)),
            "Failed to create group. Please try again.",
        )),
    }
}

// ---------------------------------------------------------------------------
// Utility functions
// ---------------------------------------------------------------------------

fn build_breadcrumbs(path: &str) -> Vec<serde_json::Value> {
    let mut crumbs = vec![serde_json::json!({ "name": "Files", "path": "" })];
    if !path.is_empty() {
        let mut accumulated = String::new();
        for segment in path.split('/') {
            if segment.is_empty() {
                continue;
            }
            if !accumulated.is_empty() {
                accumulated.push('/');
            }
            accumulated.push_str(segment);
            crumbs.push(serde_json::json!({
                "name": segment,
                "path": accumulated.clone(),
            }));
        }
    }
    crumbs
}

fn parent_path(path: &str) -> String {
    match path.rfind('/') {
        Some(pos) => path[..pos].to_string(),
        None => String::new(),
    }
}

fn normalize_dir_path(path: &str) -> String {
    path.trim().trim_matches('/').to_string()
}

fn file_name_from_path(path: &str) -> String {
    path.rsplit('/').next().unwrap_or("").to_string()
}

fn join_dir_and_name(dir: &str, name: &str) -> String {
    if dir.is_empty() {
        name.to_string()
    } else {
        format!("{}/{}", dir, name)
    }
}

fn format_timestamp(ts: &str) -> String {
    // ISO-8601 → "Mar 19, 2026 14:30"
    match chrono::NaiveDateTime::parse_from_str(ts, "%Y-%m-%dT%H:%M:%S%.f") {
        Ok(dt) => dt.format("%b %d, %Y %H:%M").to_string(),
        Err(_) => match chrono::NaiveDateTime::parse_from_str(ts, "%Y-%m-%d %H:%M:%S") {
            Ok(dt) => dt.format("%b %d, %Y %H:%M").to_string(),
            Err(_) => ts.to_string(),
        },
    }
}

fn file_icon(name: &str, is_dir: bool, mime: Option<&str>) -> &'static str {
    if is_dir {
        return "folder";
    }
    match mime {
        Some(m) if m.starts_with("image/") => "image",
        Some(m) if m.starts_with("video/") => "video",
        Some(m) if m.starts_with("audio/") => "audio",
        Some(m) if m.starts_with("text/") => "text",
        Some("application/pdf") => "pdf",
        Some(m) if m.contains("zip") || m.contains("tar") || m.contains("compress") => "archive",
        _ => {
            let ext = name.rsplit('.').next().unwrap_or("");
            match ext.to_ascii_lowercase().as_str() {
                "pdf" => "pdf",
                "doc" | "docx" | "odt" => "document",
                "xls" | "xlsx" | "ods" | "csv" => "spreadsheet",
                "ppt" | "pptx" | "odp" => "presentation",
                "zip" | "tar" | "gz" | "bz2" | "xz" | "7z" | "rar" => "archive",
                "rs" | "py" | "js" | "ts" | "go" | "c" | "cpp" | "h" | "java" | "rb" | "php"
                | "sh" | "toml" | "yaml" | "yml" | "json" | "xml" | "html" | "css" => "code",
                _ => "file",
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Route collection
// ---------------------------------------------------------------------------

pub fn routes() -> Vec<Route> {
    routes![
        index,
        login_page,
        login_submit,
        register_page,
        register_submit,
        logout_submit,
        setup_page,
        setup_submit,
        files_page,
        files_partial,
        files_folders,
        mkdir_submit,
        rename_submit,
        move_submit,
        delete_submit,
        bulk_delete,
        bulk_move,
        upload_file,
        chunked_init_upload,
        chunked_receive_chunk,
        chunked_complete_upload,
        chunked_cancel_upload,
        chunked_init_download,
        chunked_download_chunk,
        download_file,
        usage_sidebar,
        usage_page,
        settings_page,
        groups_page,
        groups_create_submit,
    ]
}
