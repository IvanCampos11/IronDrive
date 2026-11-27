#![allow(
    clippy::result_large_err,
    reason = "Form handlers return Flash<Redirect> on both arms; Rocket sends either straight back as the response, so boxing the error buys nothing."
)]

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
use crate::guards::space_guard::{SessionSpaceAdmin, SessionSpaceReader, SessionSpaceWriter};
use crate::models::group::Group;
use crate::models::library::PersonalLibrary;
use crate::models::user::User;
use crate::services::crypto_service::MasterKey;
use crate::services::fs_service::TargetKind;
use crate::services::rate_limit::{ClientIp, RateLimiter};
use crate::services::unlock_state::UnlockState;
use crate::services::{
    auth_service, chunk_service, fs_service, group_service, key_service, library_service,
    quota_service, space_service, trash_service,
};

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

#[derive(FromForm)]
pub struct EditGroupForm {
    pub name: String,
    pub description: Option<String>,
    pub csrf_token: String,
}

#[derive(FromForm)]
pub struct AddMemberForm {
    pub username: String,
    pub role: String,
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

#[derive(FromForm)]
pub struct CreateSpaceForm {
    pub name: String,
    pub csrf_token: String,
    /// `standard` (default) or `password`.
    pub protection: Option<String>,
    pub password: Option<String>,
    pub password_confirm: Option<String>,
}

#[derive(FromForm)]
pub struct RenameSpaceForm {
    pub name: String,
    pub csrf_token: String,
}

#[derive(FromForm)]
pub struct GrantAccessForm {
    pub grantee_type: String,
    pub grantee_id: String,
    pub permission: String,
    pub csrf_token: String,
}

#[derive(FromForm)]
pub struct UpdateAccessForm {
    pub grantee_type: String,
    pub grantee_id: String,
    pub permission: String,
    pub csrf_token: String,
}

#[derive(FromForm)]
pub struct RevokeAccessForm {
    pub grantee_type: String,
    pub grantee_id: String,
    pub csrf_token: String,
}

#[derive(FromForm)]
pub struct UpdateMemberRoleForm {
    pub role: String,
    pub csrf_token: String,
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn set_session_cookie(cookies: &CookieJar<'_>, token: &str, secure: bool) {
    let mut cookie = Cookie::new(COOKIE_NAME, token.to_string());
    cookie.set_http_only(true);
    cookie.set_secure(secure);
    cookie.set_same_site(SameSite::Lax);
    cookie.set_path("/");
    cookies.add(cookie);
}

fn clear_session_cookie(cookies: &CookieJar<'_>) {
    cookies.remove(Cookie::from(COOKIE_NAME));
}

/// Look up the user's personal library.
pub(crate) async fn require_library(
    pool: &DbPool,
    user_id: &str,
) -> Result<PersonalLibrary, AppError> {
    PersonalLibrary::find_by_user(pool, user_id)
        .await?
        .ok_or(AppError::NotFound)
}

/// Format bytes into something human readable.
pub(crate) fn format_bytes(bytes: u64) -> String {
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
#[allow(clippy::too_many_arguments)]
pub async fn login_submit(
    pool: &State<DbPool>,
    config: &State<AppConfig>,
    master_key: &State<MasterKey>,
    unlock_state: &State<UnlockState>,
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
            set_session_cookie(cookies, &login_result.token, config.secure_cookies);
            key_service::unlock_after_login(
                pool.inner(),
                master_key.inner(),
                unlock_state.inner(),
                &login_result.user.id,
                &form.password,
            )
            .await;
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
        Err(AppError::RegistrationClosed) => Err(Flash::error(
            Redirect::to(uri!(register_page)),
            "Registration is disabled on this server. Ask an administrator for an account.",
        )),
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
    unlock_state: &State<UnlockState>,
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
            if let Err(e) = key_service::lock_if_no_sessions(
                pool.inner(),
                unlock_state.inner(),
                &session_user.0.id,
            )
            .await
            {
                tracing::error!(error = %e, "Failed to lock account keys after logout");
            }
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

/// Setup wizard form. Only `csrf_token` is required: no tier means server.
#[derive(FromForm)]
pub struct SetupForm {
    pub csrf_token: String,
    pub tier: Option<String>,
    pub password_mode: Option<String>,
    pub password: Option<String>,
    pub encryption_password: Option<String>,
    pub encryption_password_confirm: Option<String>,
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
    form: Form<SetupForm>,
) -> Result<Redirect, Flash<Redirect>> {
    let fail = |msg: String| Flash::error(Redirect::to(uri!(setup_page)), msg);
    validate_csrf(cookies, &form.csrf_token)
        .map_err(|_| fail("Invalid request. Please try again.".into()))?;

    if user.0.setup_complete {
        return Ok(Redirect::to(uri!(files_page(
            path = Option::<String>::None
        ))));
    }

    let tier = form.tier.as_deref().unwrap_or(key_service::TIER_SERVER);
    let password_mode = form
        .password_mode
        .as_deref()
        .unwrap_or(key_service::MODE_SINGLE);
    if password_mode == key_service::MODE_SEPARATE
        && form.encryption_password != form.encryption_password_confirm
    {
        return Err(fail("The encryption passwords don't match.".into()));
    }
    let wrap_password = key_service::key_password_for(
        pool.inner(),
        &user.0.id,
        tier,
        password_mode,
        form.password.as_deref().unwrap_or(""),
        form.encryption_password.as_deref(),
    )
    .await
    .map_err(|e| match e {
        AppError::BadPassphrase => fail("That isn't your login password.".into()),
        e => fail(e.client_message()),
    })?;

    library_service::setup_library_with(
        pool.inner(),
        config.inner(),
        master_key.inner(),
        unlock_state.inner(),
        &user.0.id,
        &library_service::EncryptionChoice {
            tier,
            password_mode,
            password: wrap_password.as_deref(),
        },
    )
    .await
    .map_err(|e| match e {
        AppError::Validation(m) | AppError::Conflict(m) => fail(m),
        _ => fail("Library setup failed. Please try again.".into()),
    })?;
    Ok(Redirect::to(uri!(files_page(
        path = Option::<String>::None
    ))))
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
    if !unlock_state.is_library_unlocked(&lib.id) {
        return Err(Redirect::to("/unlock?next=/files"));
    }

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
    let flagged = flagged_paths(pool.inner(), "library", &lib.id).await;
    let display_entries: Vec<serde_json::Value> =
        entries.iter().map(|e| entry_view(e, &flagged)).collect();

    let csrf_token = ensure_csrf_token(cookies);

    Ok(Template::render(
        "browser/page",
        context! {
            user: &user.0.username,
            csrf_token: csrf_token,
            current_path: "files",
            chunk_size_bytes: config.chunk_size_bytes,
            max_parallel_chunks: config.max_parallel_chunks,
            base_url: "/files",
            root_name: "My files",
            path: user_path,
            entries: display_entries,
            breadcrumbs: breadcrumbs,
            can_write: true,
            is_admin: false,
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

    let flagged = flagged_paths(pool.inner(), "library", &lib.id).await;
    let display_entries: Vec<serde_json::Value> =
        entries.iter().map(|e| entry_view(e, &flagged)).collect();

    Ok(Template::render(
        "browser/listing",
        context! {
            base_url: "/files",
            root_name: "My files",
            path: user_path,
            entries: display_entries,
            breadcrumbs: breadcrumbs,
            can_write: true,
            is_admin: false,
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
            rocket::serde::json::Json(serde_json::json!({"error": e.client_message()})),
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

    match trash_service::move_to_trash(
        pool.inner(),
        config.inner(),
        TargetKind::Library,
        &lib.id,
        &form.path,
        Some(&user.0.id),
    )
    .await
    {
        Ok(_) => Ok(Flash::success(
            Redirect::to(uri!(files_page(
                path = if parent.is_empty() {
                    None
                } else {
                    Some(parent)
                }
            ))),
            "Moved to trash.",
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

/// Move each path to the trash. Returns the trash ids (for Undo) and
/// user-facing errors for the paths that failed.
async fn trash_paths(
    pool: &DbPool,
    config: &AppConfig,
    kind: TargetKind,
    target_id: &str,
    paths: &[String],
    user_id: &str,
) -> (Vec<String>, Vec<String>) {
    let mut ids = Vec::new();
    let mut errors = Vec::new();
    for path in paths {
        match trash_service::move_to_trash(pool, config, kind, target_id, path, Some(user_id)).await
        {
            Ok(item) => ids.push(item.id),
            Err(e) => errors.push(bulk_error(path, &e)),
        }
    }
    (ids, errors)
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

    let (trash_ids, errors) = trash_paths(
        pool.inner(),
        config.inner(),
        TargetKind::Library,
        &lib.id,
        &data.paths,
        &user.0.id,
    )
    .await;

    rocket::serde::json::Json(serde_json::json!({
        "deleted": trash_ids.len(),
        "trash_ids": trash_ids,
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
            Err(e) => errors.push(bulk_error(old_path, &e)),
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

    let allowed = config.direct_upload_limit();
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
                serde_json::json!({"error": format!("File exceeds the {} limit for a single upload.", format_bytes(allowed))}),
            ),
        ));
    }

    let bytes = stream.into_inner();

    quota_service::ensure_room(
        pool.inner(),
        config.inner(),
        TargetKind::Library,
        &lib.id,
        quota_service::estimated_disk_size(bytes.len() as u64, config.chunk_size_bytes),
        Some(&path),
        None,
    )
    .await
    .map_err(json_error)?;

    match fs_service::upload_file_owned(
        config.inner(),
        unlock_state.inner(),
        &lib.id,
        &path,
        bytes,
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
            rocket::serde::json::Json(serde_json::json!({"error": e.client_message()})),
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
            target_id: lib.id,
            target_type: "library".to_string(),
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
            rocket::serde::json::Json(serde_json::json!({"error": e.client_message()})),
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
        "library",
        upload_id,
        chunk_index,
        &stream.into_inner(),
    )
    .await
    .map_err(|e| {
        (
            e.status(),
            rocket::serde::json::Json(serde_json::json!({"error": e.client_message()})),
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
        "library",
        &body.upload_id,
        body.verify.unwrap_or(false),
    )
    .await
    .map_err(|e| {
        (
            e.status(),
            rocket::serde::json::Json(serde_json::json!({"error": e.client_message()})),
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
        "library",
        &upload_id,
    )
    .await
    .map_err(|e| {
        (
            e.status(),
            rocket::serde::json::Json(serde_json::json!({"error": e.client_message()})),
        )
    })?;

    Ok(rocket::serde::json::Json(serde_json::json!({
        "success": true,
        "upload_id": upload_id,
    })))
}

/// GET /files/download?<path> — browser download
/// Errors are plain statuses rather than redirects: the browser fetches this
/// with `<a download>`, which reports a non-2xx response as a failed download
/// (a redirect to an HTML page would be saved as the "file").
#[get("/files/download?<path>")]
pub async fn download_file(
    pool: &State<DbPool>,
    config: &State<AppConfig>,
    unlock_state: &State<UnlockState>,
    user: SessionSetupComplete,
    range: crate::routes::download::RangeHeader,
    path: String,
) -> Result<crate::routes::download::StreamedDownload, (Status, String)> {
    let fail = |e: AppError| (e.status(), e.client_message());
    let lib = require_library(pool.inner(), &user.0.id)
        .await
        .map_err(fail)?;
    crate::routes::download::stream_file(
        pool.inner(),
        config.inner(),
        unlock_state.inner(),
        TargetKind::Library,
        &lib.id,
        &path,
        &range,
    )
    .await
    .map_err(fail)
}

// ---------------------------------------------------------------------------
// Sidebar usage snippet (HTMX partial)
// ---------------------------------------------------------------------------

/// Percentage of `quota` used, 0–100. A quota of 0 or less means unlimited.
pub(crate) fn usage_percent(used: u64, quota: i64) -> u64 {
    if quota > 0 {
        (used as f64 / quota as f64 * 100.0).min(100.0) as u64
    } else {
        0
    }
}

/// GET /usage/sidebar — tiny HTMX partial for the sidebar storage bar
#[get("/usage/sidebar")]
pub async fn usage_sidebar(
    pool: &State<DbPool>,
    config: &State<AppConfig>,
    user: SessionSetupComplete,
) -> Result<Template, Status> {
    let usage = quota_service::usage_for_user(pool.inner(), config.inner(), &user.0.id, None)
        .await
        .unwrap_or_default();
    let used = usage.total();

    Ok(Template::render(
        "partials/sidebar_usage",
        context! {
            disk_bytes_fmt: format_bytes(used),
            quota_bytes_fmt: format_bytes(user.0.quota_bytes.max(0) as u64),
            usage_pct: usage_percent(used, user.0.quota_bytes),
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

    let counts = fs_service::calculate_usage(config.inner(), &lib.id, "")
        .await
        .unwrap_or(fs_service::UsageResult {
            disk_bytes: 0,
            file_count: 0,
            dir_count: 0,
        });
    let usage = quota_service::usage_for_user(pool.inner(), config.inner(), &user.0.id, None)
        .await
        .unwrap_or_default();
    let used = usage.total();
    let quota = user.0.quota_bytes.max(0) as u64;

    let breakdown: Vec<serde_json::Value> = [
        ("My files", "folder", usage.files, "/files"),
        ("Spaces you own", "workspaces", usage.spaces, "/spaces"),
        ("Trash", "delete", usage.trash, "/trash"),
        ("Uploads in progress", "upload", usage.pending, ""),
    ]
    .into_iter()
    .filter(|(label, _, bytes, _)| *bytes > 0 || *label != "Uploads in progress")
    .map(|(label, icon, bytes, href)| {
        serde_json::json!({
            "label": label,
            "icon": icon,
            "bytes": format_bytes(bytes),
            "pct": usage_percent(bytes, used.max(1) as i64),
            "href": href,
        })
    })
    .collect();

    Ok(Template::render(
        "files/usage",
        context! {
            user: &user.0.username,
            current_path: "usage",
            csrf_token: ensure_csrf_token(cookies),
            disk_bytes: used,
            disk_bytes_fmt: format_bytes(used),
            available_fmt: format_bytes(quota.saturating_sub(used)),
            file_count: counts.file_count,
            dir_count: counts.dir_count,
            quota_bytes: user.0.quota_bytes,
            quota_bytes_fmt: format_bytes(quota),
            usage_pct: usage_percent(used, user.0.quota_bytes),
            breakdown: breakdown,
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
    unlock_state: &State<UnlockState>,
    cookies: &CookieJar<'_>,
    user: SessionSetupComplete,
    flash: Option<FlashMessage<'_>>,
) -> Result<Template, Redirect> {
    let lib = PersonalLibrary::find_by_user(pool.inner(), &user.0.id)
        .await
        .ok()
        .flatten();
    let encryption = crate::routes::encryption::encryption_status(
        pool.inner(),
        unlock_state.inner(),
        &user.0.id,
    )
    .await
    .ok();
    let notices = crate::services::recovery_service::notices_for(pool.inner(), &user.0.id, false)
        .await
        .unwrap_or_default();

    Ok(Template::render(
        "settings/index",
        context! {
            user: &user.0.username,
            current_path: "settings",
            version: env!("CARGO_PKG_VERSION"),
            user_id: &user.0.id,
            username: &user.0.username,
            csrf_token: ensure_csrf_token(cookies),
            email: &user.0.email,
            role: &user.0.role,
            created_at: &user.0.created_at,
            library_id: lib.as_ref().map(|l| l.id.as_str()),
            encryption_mode: lib.as_ref().map(|l| l.encryption_mode.as_str()),
            library_created: lib.as_ref().map(|l| l.created_at.as_str()),
            encryption: encryption,
            notices: notices,
            flash_kind: flash.as_ref().map(|f| f.kind().to_string()),
            flash_msg: flash.as_ref().map(|f| f.message().to_string()),
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
                "created_at": &g.group.created_at,
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
        Err(AppError::Conflict(msg)) => Err(Flash::error(Redirect::to(uri!(groups_page)), msg)),
        Err(AppError::Validation(msg)) => Err(Flash::error(Redirect::to(uri!(groups_page)), msg)),
        Err(_) => Err(Flash::error(
            Redirect::to(uri!(groups_page)),
            "Failed to create group. Please try again.",
        )),
    }
}

/// GET /groups/<id>
#[get("/groups/<id>")]
pub async fn group_detail_page(
    pool: &State<DbPool>,
    cookies: &CookieJar<'_>,
    user: SessionSetupComplete,
    id: &str,
    flash: Option<FlashMessage<'_>>,
) -> Result<Template, Flash<Redirect>> {
    let group_meta = group_service::get_group(pool.inner(), &user.0.id, id)
        .await
        .map_err(|e| {
            tracing::warn!(group_id = %id, error = %e, "group_detail_page: group lookup failed");
            Flash::error(
                Redirect::to(uri!(groups_page)),
                "Group not found or you are not a member.",
            )
        })?;

    let members_data = group_service::list_members(pool.inner(), &user.0.id, id)
        .await
        .unwrap_or_default();

    let is_owner = group_meta.user_role == "owner";
    let is_manager = group_meta.user_role == "manager";

    let members: Vec<serde_json::Value> = members_data
        .into_iter()
        .map(|m| {
            serde_json::json!({
                "user_id": m.user_id,
                "username": m.username,
                "email": m.email,
                "role": m.role,
                "joined_at": &m.joined_at,
            })
        })
        .collect();

    Ok(Template::render(
        "groups/detail",
        context! {
            user: &user.0.username,
            csrf_token: ensure_csrf_token(cookies),
            current_path: "groups",
            group: serde_json::json!({
                "id": group_meta.group.id,
                "name": group_meta.group.name,
                "description": group_meta.group.description,
                "created_by": group_meta.group.created_by,
                "created_at": &group_meta.group.created_at,
            }),
            group_id: &group_meta.group.id,
            user_role: &group_meta.user_role,
            member_count: group_meta.member_count,
            is_owner: is_owner,
            is_manager: is_manager,
            members: members,
            flash_kind: flash.as_ref().map(|f| f.kind().to_string()),
            flash_msg: flash.as_ref().map(|f| f.message().to_string()),
        },
    ))
}

/// POST /groups/<id>/edit
#[post("/groups/<id>/edit", data = "<form>")]
pub async fn group_edit_submit(
    pool: &State<DbPool>,
    cookies: &CookieJar<'_>,
    user: SessionSetupComplete,
    id: &str,
    form: Form<EditGroupForm>,
) -> Result<Flash<Redirect>, Flash<Redirect>> {
    let redirect_to = uri!(group_detail_page(id = id));
    validate_csrf(cookies, &form.csrf_token).map_err(|_| {
        Flash::error(
            Redirect::to(redirect_to.clone()),
            "Invalid request. Please try again.",
        )
    })?;

    match group_service::update_group(
        pool.inner(),
        &user.0.id,
        id,
        &form.name,
        form.description.as_deref(),
    )
    .await
    {
        Ok(_) => Ok(Flash::success(Redirect::to(redirect_to), "Group updated.")),
        Err(AppError::Forbidden) => Err(Flash::error(
            Redirect::to(redirect_to),
            "You don't have permission to edit this group.",
        )),
        Err(AppError::Validation(msg)) => Err(Flash::error(Redirect::to(redirect_to), msg)),
        Err(AppError::Conflict(msg)) => Err(Flash::error(Redirect::to(redirect_to), msg)),
        Err(_) => Err(Flash::error(
            Redirect::to(redirect_to),
            "Failed to update group.",
        )),
    }
}

/// POST /groups/<id>/delete
#[post("/groups/<id>/delete", data = "<form>")]
pub async fn group_delete_submit(
    pool: &State<DbPool>,
    unlock_state: &State<UnlockState>,
    cookies: &CookieJar<'_>,
    user: SessionSetupComplete,
    id: &str,
    form: Form<CsrfOnlyForm>,
) -> Result<Flash<Redirect>, Flash<Redirect>> {
    validate_csrf(cookies, &form.csrf_token).map_err(|_| {
        Flash::error(
            Redirect::to(uri!(groups_page)),
            "Invalid request. Please try again.",
        )
    })?;

    let spaces = key_service::spaces_of_group(pool.inner(), id)
        .await
        .unwrap_or_default();
    let result = group_service::delete_group(pool.inner(), &user.0.id, id).await;
    if result.is_ok() {
        key_service::resync_spaces(pool.inner(), unlock_state.inner(), &spaces).await;
    }
    match result {
        Ok(_) => Ok(Flash::success(
            Redirect::to(uri!(groups_page)),
            "Group deleted.",
        )),
        Err(AppError::Forbidden) => Err(Flash::error(
            Redirect::to(uri!(groups_page)),
            "Only the group owner can delete the group.",
        )),
        Err(_) => Err(Flash::error(
            Redirect::to(uri!(groups_page)),
            "Failed to delete group.",
        )),
    }
}

/// Re-sync the key envelopes of every space a group owns or was granted.
async fn resync_group(pool: &DbPool, unlock_state: &UnlockState, group_id: &str) {
    match key_service::spaces_of_group(pool, group_id).await {
        Ok(spaces) => key_service::resync_spaces(pool, unlock_state, &spaces).await,
        Err(e) => tracing::error!(group_id = %group_id, error = %e, "Failed to list group spaces"),
    }
}

/// POST /groups/<id>/members/add
#[post("/groups/<id>/members/add", data = "<form>")]
pub async fn group_add_member_submit(
    pool: &State<DbPool>,
    unlock_state: &State<UnlockState>,
    cookies: &CookieJar<'_>,
    user: SessionSetupComplete,
    id: &str,
    form: Form<AddMemberForm>,
) -> Result<Flash<Redirect>, Flash<Redirect>> {
    let redirect_to = uri!(group_detail_page(id = id));
    validate_csrf(cookies, &form.csrf_token).map_err(|_| {
        Flash::error(
            Redirect::to(redirect_to.clone()),
            "Invalid request. Please try again.",
        )
    })?;

    let result =
        group_service::add_member(pool.inner(), &user.0.id, id, &form.username, &form.role).await;
    if result.is_ok() {
        resync_group(pool.inner(), unlock_state.inner(), id).await;
    }
    match result {
        Ok(_) => Ok(Flash::success(
            Redirect::to(redirect_to),
            format!("Added {} to the group.", form.username),
        )),
        Err(AppError::NotFound) => Err(Flash::error(
            Redirect::to(redirect_to),
            format!("User \"{}\" not found.", form.username),
        )),
        Err(AppError::Conflict(msg)) => Err(Flash::error(Redirect::to(redirect_to), msg)),
        Err(AppError::Validation(msg)) => Err(Flash::error(Redirect::to(redirect_to), msg)),
        Err(AppError::Forbidden) => Err(Flash::error(
            Redirect::to(redirect_to),
            "You don't have permission to add members.",
        )),
        Err(_) => Err(Flash::error(
            Redirect::to(redirect_to),
            "Failed to add member.",
        )),
    }
}

/// POST /groups/<id>/members/<user_id>/remove
#[post("/groups/<id>/members/<user_id>/remove", data = "<form>")]
pub async fn group_remove_member_submit(
    pool: &State<DbPool>,
    unlock_state: &State<UnlockState>,
    cookies: &CookieJar<'_>,
    user: SessionSetupComplete,
    id: &str,
    user_id: &str,
    form: Form<CsrfOnlyForm>,
) -> Result<Flash<Redirect>, Flash<Redirect>> {
    let redirect_to = uri!(group_detail_page(id = id));
    validate_csrf(cookies, &form.csrf_token).map_err(|_| {
        Flash::error(
            Redirect::to(redirect_to.clone()),
            "Invalid request. Please try again.",
        )
    })?;

    let result = group_service::remove_member(pool.inner(), &user.0.id, id, user_id).await;
    if result.is_ok() {
        resync_group(pool.inner(), unlock_state.inner(), id).await;
    }
    match result {
        Ok(_) => Ok(Flash::success(Redirect::to(redirect_to), "Member removed.")),
        Err(AppError::Validation(msg)) => Err(Flash::error(Redirect::to(redirect_to), msg)),
        Err(AppError::Forbidden) => Err(Flash::error(
            Redirect::to(redirect_to),
            "You don't have permission to remove members.",
        )),
        Err(_) => Err(Flash::error(
            Redirect::to(redirect_to),
            "Failed to remove member.",
        )),
    }
}

/// POST /groups/<id>/members/<user_id>/role
#[post("/groups/<id>/members/<user_id>/role", data = "<form>")]
pub async fn group_update_member_role_submit(
    pool: &State<DbPool>,
    cookies: &CookieJar<'_>,
    user: SessionSetupComplete,
    id: &str,
    user_id: &str,
    form: Form<UpdateMemberRoleForm>,
) -> Result<Flash<Redirect>, Flash<Redirect>> {
    let redirect_to = uri!(group_detail_page(id = id));
    validate_csrf(cookies, &form.csrf_token).map_err(|_| {
        Flash::error(
            Redirect::to(redirect_to.clone()),
            "Invalid request. Please try again.",
        )
    })?;

    match group_service::update_member_role(pool.inner(), &user.0.id, id, user_id, &form.role).await
    {
        Ok(_) => Ok(Flash::success(Redirect::to(redirect_to), "Role updated.")),
        Err(AppError::Validation(msg)) => Err(Flash::error(Redirect::to(redirect_to), msg)),
        Err(AppError::Forbidden) => Err(Flash::error(
            Redirect::to(redirect_to),
            "Only the group owner can change roles.",
        )),
        Err(_) => Err(Flash::error(
            Redirect::to(redirect_to),
            "Failed to update role.",
        )),
    }
}

// ---------------------------------------------------------------------------
// Utility functions
// ---------------------------------------------------------------------------

fn build_breadcrumbs(path: &str) -> Vec<serde_json::Value> {
    let mut crumbs = Vec::new();
    let mut accumulated = String::new();
    for segment in path.split('/').filter(|s| !s.is_empty()) {
        if !accumulated.is_empty() {
            accumulated.push('/');
        }
        accumulated.push_str(segment);
        crumbs.push(serde_json::json!({ "name": segment, "path": accumulated.clone() }));
    }
    crumbs
}

pub(crate) fn parent_path(path: &str) -> String {
    match path.rfind('/') {
        Some(pos) => path[..pos].to_string(),
        None => String::new(),
    }
}

pub(crate) fn normalize_dir_path(path: &str) -> String {
    path.trim().trim_matches('/').to_string()
}

pub(crate) fn file_name_from_path(path: &str) -> String {
    path.rsplit('/').next().unwrap_or("").to_string()
}

pub(crate) fn join_dir_and_name(dir: &str, name: &str) -> String {
    if dir.is_empty() {
        name.to_string()
    } else {
        format!("{}/{}", dir, name)
    }
}

pub(crate) fn format_timestamp(ts: &str) -> String {
    // ISO-8601 → "Mar 19, 2026 14:30" (UTC; the browser re-renders it in local time)
    let ts = ts.trim_end_matches('Z');
    match chrono::NaiveDateTime::parse_from_str(ts, "%Y-%m-%dT%H:%M:%S%.f") {
        Ok(dt) => dt.format("%b %d, %Y %H:%M").to_string(),
        Err(_) => match chrono::NaiveDateTime::parse_from_str(ts, "%Y-%m-%d %H:%M:%S") {
            Ok(dt) => dt.format("%b %d, %Y %H:%M").to_string(),
            Err(_) => ts.to_string(),
        },
    }
}

pub(crate) fn file_icon(name: &str, is_dir: bool, mime: Option<&str>) -> &'static str {
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

/// Material Symbols glyph for a `file_icon` kind.
pub(crate) fn icon_glyph(kind: &str) -> &'static str {
    match kind {
        "folder" => "folder",
        "image" => "image",
        "video" => "movie",
        "audio" => "music_note",
        "pdf" => "picture_as_pdf",
        "archive" => "folder_zip",
        "code" => "code",
        "text" => "description",
        "document" => "article",
        "spreadsheet" => "table_chart",
        "presentation" => "slideshow",
        _ => "draft",
    }
}

/// Template view-model for one directory entry (see templates/browser/item).
pub(crate) fn entry_view(e: &fs_service::FsEntry, flagged: &[String]) -> serde_json::Value {
    let icon = file_icon(&e.name, e.is_dir, e.mime_type.as_deref());
    // "file": this file has an open integrity alert; "inside": a folder containing one.
    let prefix = format!("{}/", e.path);
    let problem = if flagged.contains(&e.path) {
        Some("file")
    } else if e.is_dir && flagged.iter().any(|p| p.starts_with(&prefix)) {
        Some("inside")
    } else {
        None
    };
    serde_json::json!({
        "name": e.name,
        "path": e.path,
        "is_dir": e.is_dir,
        "size": e.size.map(format_bytes),
        "raw_size": e.size.unwrap_or(0),
        "modified": e.modified.as_deref().map(format_timestamp),
        "raw_modified": e.modified,
        "icon": icon,
        "glyph": icon_glyph(icon),
        "problem": problem,
    })
}

/// Paths with open integrity alerts in a library or space.
async fn flagged_paths(pool: &DbPool, target_type: &str, target_id: &str) -> Vec<String> {
    crate::services::integrity_service::list_unacknowledged(pool, target_type, target_id)
        .await
        .map(|evs| evs.into_iter().map(|e| e.file_path).collect())
        .unwrap_or_default()
}

/// Validate a single file/folder name typed by the user.
fn validate_entry_name(name: &str) -> Result<&str, AppError> {
    let name = name.trim();
    if name.is_empty() {
        return Err(AppError::Validation("Name can't be empty.".into()));
    }
    if name.contains('/') || name.contains('\\') {
        return Err(AppError::Validation("Names can't contain slashes.".into()));
    }
    if name.starts_with('.') {
        return Err(AppError::Validation("Names can't start with a dot.".into()));
    }
    if name.len() > 255 {
        return Err(AppError::Validation("That name is too long.".into()));
    }
    Ok(name)
}

/// JSON error body for XHR endpoints: `{"error": "<user-facing message>"}`.
pub(crate) fn json_error(e: AppError) -> (Status, rocket::serde::json::Json<serde_json::Value>) {
    if matches!(
        e,
        AppError::Internal(_) | AppError::Sqlx(_) | AppError::Io(_)
    ) {
        tracing::error!(error = %e, "File operation failed");
    }
    (
        e.status(),
        rocket::serde::json::Json(serde_json::json!({ "error": e.client_message() })),
    )
}

/// One line per failed item in bulk responses, e.g. `report.pdf: Not found.`
fn bulk_error(path: &str, e: &AppError) -> String {
    format!("{}: {}", file_name_from_path(path), e.client_message())
}

/// `create_directory` is idempotent (mkdir -p); the UI wants "name taken" instead.
async fn ensure_name_free(
    config: &AppConfig,
    kind: fs_service::TargetKind,
    target_id: &str,
    path: &str,
) -> Result<(), (Status, rocket::serde::json::Json<serde_json::Value>)> {
    if fs_service::entry_exists(config, kind, target_id, path)
        .await
        .map_err(json_error)?
    {
        return Err(json_error(AppError::Conflict(format!(
            "“{}” already exists here.",
            file_name_from_path(path)
        ))));
    }
    Ok(())
}

pub(crate) type JsonResult = Result<
    rocket::serde::json::Json<serde_json::Value>,
    (Status, rocket::serde::json::Json<serde_json::Value>),
>;

#[derive(serde::Deserialize)]
pub struct MkdirRequest {
    pub path: String,
    pub name: String,
}

#[derive(serde::Deserialize)]
pub struct RenameRequest {
    pub path: String,
    pub new_name: String,
}

/// POST /files/api/mkdir — XHR: create a folder, returns `{"path"}`.
#[post("/files/api/mkdir", data = "<body>")]
pub async fn api_mkdir(
    pool: &State<DbPool>,
    config: &State<AppConfig>,
    _csrf: CsrfXhr,
    user: SessionSetupComplete,
    body: rocket::serde::json::Json<MkdirRequest>,
) -> JsonResult {
    let lib = require_library(pool.inner(), &user.0.id)
        .await
        .map_err(json_error)?;
    let name = validate_entry_name(&body.name).map_err(json_error)?;
    let full = join_dir_and_name(&normalize_dir_path(&body.path), name);
    ensure_name_free(
        config.inner(),
        fs_service::TargetKind::Library,
        &lib.id,
        &full,
    )
    .await?;
    fs_service::create_directory(config.inner(), &lib.id, &full)
        .await
        .map_err(json_error)?;
    Ok(rocket::serde::json::Json(
        serde_json::json!({ "path": full }),
    ))
}

/// POST /files/api/rename — XHR: rename in place, returns `{"path"}`.
#[post("/files/api/rename", data = "<body>")]
pub async fn api_rename(
    pool: &State<DbPool>,
    config: &State<AppConfig>,
    _csrf: CsrfXhr,
    user: SessionSetupComplete,
    body: rocket::serde::json::Json<RenameRequest>,
) -> JsonResult {
    let lib = require_library(pool.inner(), &user.0.id)
        .await
        .map_err(json_error)?;
    let name = validate_entry_name(&body.new_name).map_err(json_error)?;
    let new_path = join_dir_and_name(&parent_path(&body.path), name);
    fs_service::rename_entry(config.inner(), &lib.id, &body.path, &new_path)
        .await
        .map_err(json_error)?;
    Ok(rocket::serde::json::Json(
        serde_json::json!({ "path": new_path }),
    ))
}

/// POST /spaces/<space_id>/api/mkdir — XHR: create a folder in a space.
#[post("/spaces/<space_id>/api/mkdir", data = "<body>")]
pub async fn space_api_mkdir(
    config: &State<AppConfig>,
    _csrf: CsrfXhr,
    _writer: SessionSpaceWriter,
    space_id: &str,
    body: rocket::serde::json::Json<MkdirRequest>,
) -> JsonResult {
    let name = validate_entry_name(&body.name).map_err(json_error)?;
    let full = join_dir_and_name(&normalize_dir_path(&body.path), name);
    ensure_name_free(
        config.inner(),
        fs_service::TargetKind::Space,
        space_id,
        &full,
    )
    .await?;
    fs_service::create_space_directory(config.inner(), space_id, &full)
        .await
        .map_err(json_error)?;
    Ok(rocket::serde::json::Json(
        serde_json::json!({ "path": full }),
    ))
}

/// POST /spaces/<space_id>/api/rename — XHR: rename an entry in a space.
#[post("/spaces/<space_id>/api/rename", data = "<body>")]
pub async fn space_api_rename(
    config: &State<AppConfig>,
    _csrf: CsrfXhr,
    _writer: SessionSpaceWriter,
    space_id: &str,
    body: rocket::serde::json::Json<RenameRequest>,
) -> JsonResult {
    let name = validate_entry_name(&body.new_name).map_err(json_error)?;
    let new_path = join_dir_and_name(&parent_path(&body.path), name);
    fs_service::rename_space_entry(config.inner(), space_id, &body.path, &new_path)
        .await
        .map_err(json_error)?;
    Ok(rocket::serde::json::Json(
        serde_json::json!({ "path": new_path }),
    ))
}

// ---------------------------------------------------------------------------
// Spaces — page routes
// ---------------------------------------------------------------------------

/// GET /spaces — list all spaces the user can access
#[get("/spaces")]
pub async fn spaces_page(
    pool: &State<DbPool>,
    cookies: &CookieJar<'_>,
    user: SessionSetupComplete,
    flash: Option<FlashMessage<'_>>,
) -> Template {
    let spaces_data = space_service::list_user_spaces(pool.inner(), &user.0.id)
        .await
        .unwrap_or_default();

    let spaces: Vec<serde_json::Value> = spaces_data
        .into_iter()
        .map(|s| {
            serde_json::json!({
                "id": s.space.id,
                "name": s.space.name,
                "encryption_mode": s.space.encryption_mode,
                "owner_type": s.space.owner_type,
                "owner_id": s.space.owner_id,
                "created_at": &s.space.created_at,
                "grantee_count": s.grantee_count,
                "user_permission": s.user_permission,
            })
        })
        .collect();

    Template::render(
        "spaces/index",
        context! {
            user: &user.0.username,
            csrf_token: ensure_csrf_token(cookies),
            current_path: "spaces",
            spaces: spaces,
            flash_kind: flash.as_ref().map(|f| f.kind().to_string()),
            flash_msg: flash.as_ref().map(|f| f.message().to_string()),
        },
    )
}

/// POST /spaces/create
#[post("/spaces/create", data = "<form>")]
pub async fn spaces_create_submit(
    pool: &State<DbPool>,
    config: &State<AppConfig>,
    master_key: &State<MasterKey>,
    unlock_state: &State<UnlockState>,
    cookies: &CookieJar<'_>,
    user: SessionSetupComplete,
    form: Form<CreateSpaceForm>,
) -> Result<Flash<Redirect>, Flash<Redirect>> {
    validate_csrf(cookies, &form.csrf_token).map_err(|_| {
        Flash::error(
            Redirect::to(uri!(spaces_page)),
            "Invalid request. Please try again.",
        )
    })?;

    let password = if form.protection.as_deref() == Some("password") {
        if form.password != form.password_confirm {
            return Err(Flash::error(
                Redirect::to(uri!(spaces_page)),
                "The space passwords don't match.",
            ));
        }
        Some(form.password.as_deref().unwrap_or(""))
    } else {
        None
    };
    match space_service::create_space_with(
        pool.inner(),
        config.inner(),
        master_key.inner(),
        unlock_state.inner(),
        "user",
        &user.0.id,
        &user.0.id,
        &form.name,
        password,
    )
    .await
    {
        Ok(s) => Ok(Flash::success(
            Redirect::to(format!("/spaces/{}", s.space.id)),
            format!("Space \"{}\" created.", s.space.name),
        )),
        Err(AppError::Validation(msg)) => Err(Flash::error(Redirect::to(uri!(spaces_page)), msg)),
        Err(_) => Err(Flash::error(
            Redirect::to(uri!(spaces_page)),
            "Failed to create space. Please try again.",
        )),
    }
}

/// GET /spaces/<space_id> — space file browser
#[get("/spaces/<space_id>?<path>")]
#[allow(clippy::too_many_arguments)] // Rocket handler: one argument per guard/param
pub async fn space_browser_page(
    pool: &State<DbPool>,
    config: &State<AppConfig>,
    unlock_state: &State<UnlockState>,
    cookies: &CookieJar<'_>,
    reader: SessionSpaceReader,
    space_id: &str,
    path: Option<String>,
    flash: Option<FlashMessage<'_>>,
) -> Template {
    let csrf_token = ensure_csrf_token(cookies);
    let lock_state = key_service::space_access_state(
        pool.inner(),
        unlock_state.inner(),
        &reader.space.space,
        &reader.user.id,
    )
    .await
    .unwrap_or(key_service::SpaceLockState::Open);
    if lock_state != key_service::SpaceLockState::Open {
        return Template::render(
            "spaces/locked",
            context! {
                user: &reader.user.username,
                csrf_token: csrf_token,
                current_path: "spaces",
                space: &reader.space.space,
                is_admin: reader.space.user_permission == "admin",
                state: crate::routes::encryption::lock_state_name(lock_state),
                flash_kind: flash.as_ref().map(|f| f.kind().to_string()),
                flash_msg: flash.as_ref().map(|f| f.message().to_string()),
            },
        );
    }
    if reader.space.space.encryption_mode == key_service::SPACE_MEMBERS {
        // Safety net: seal access for anyone added while the key was away.
        key_service::resync_space(pool.inner(), unlock_state.inner(), space_id).await;
    }

    let user_path = path.as_deref().unwrap_or("");

    let entries: Vec<fs_service::FsEntry> = fs_service::list_space_directory(
        config.inner(),
        unlock_state.inner(),
        space_id,
        user_path,
        false,
    )
    .await
    .unwrap_or_default();

    let breadcrumbs = build_breadcrumbs(user_path);

    let flagged = flagged_paths(pool.inner(), "space", space_id).await;
    let display_entries: Vec<serde_json::Value> =
        entries.iter().map(|e| entry_view(e, &flagged)).collect();

    let can_write =
        reader.space.user_permission == "write" || reader.space.user_permission == "admin";
    let is_admin = reader.space.user_permission == "admin";

    Template::render(
        "browser/page",
        context! {
            user: &reader.user.username,
            csrf_token: csrf_token,
            current_path: "spaces",
            chunk_size_bytes: config.chunk_size_bytes,
            max_parallel_chunks: config.max_parallel_chunks,
            base_url: format!("/spaces/{space_id}"),
            root_name: &reader.space.space.name,
            space_id: space_id,
            path: user_path,
            entries: display_entries,
            breadcrumbs: breadcrumbs,
            can_write: can_write,
            is_admin: is_admin,
            space_mode: &reader.space.space.encryption_mode,
            flash_kind: flash.as_ref().map(|f| f.kind().to_string()),
            flash_msg: flash.as_ref().map(|f| f.message().to_string()),
        },
    )
}

/// GET /spaces/<space_id>/partial?<path> — HTMX partial for space file list swap
#[get("/spaces/<space_id>/partial?<path>")]
pub async fn space_browser_partial(
    pool: &State<DbPool>,
    config: &State<AppConfig>,
    unlock_state: &State<UnlockState>,
    cookies: &CookieJar<'_>,
    reader: SessionSpaceReader,
    space_id: &str,
    path: Option<String>,
) -> Result<Template, Status> {
    let user_path = path.as_deref().unwrap_or("");

    let entries = fs_service::list_space_directory(
        config.inner(),
        unlock_state.inner(),
        space_id,
        user_path,
        false,
    )
    .await
    .unwrap_or_default();

    let breadcrumbs = build_breadcrumbs(user_path);

    let flagged = flagged_paths(pool.inner(), "space", space_id).await;
    let display_entries: Vec<serde_json::Value> =
        entries.iter().map(|e| entry_view(e, &flagged)).collect();

    let can_write =
        reader.space.user_permission == "write" || reader.space.user_permission == "admin";
    let is_admin = reader.space.user_permission == "admin";

    Ok(Template::render(
        "browser/listing",
        context! {
            base_url: format!("/spaces/{space_id}"),
            root_name: &reader.space.space.name,
            space_id: space_id,
            path: user_path,
            entries: display_entries,
            breadcrumbs: breadcrumbs,
            can_write: can_write,
            is_admin: is_admin,
            csrf_token: ensure_csrf_token(cookies),
            space_mode: &reader.space.space.encryption_mode,
        },
    ))
}

/// GET /spaces/<space_id>/folders?<path> — session-auth folder listing for move modal
#[get("/spaces/<space_id>/folders?<path>")]
pub async fn space_folders(
    config: &State<AppConfig>,
    unlock_state: &State<UnlockState>,
    _reader: SessionSpaceReader,
    space_id: &str,
    path: Option<String>,
) -> Result<
    rocket::serde::json::Json<serde_json::Value>,
    (Status, rocket::serde::json::Json<serde_json::Value>),
> {
    let user_path = path.as_deref().unwrap_or("");

    let entries = fs_service::list_space_directory(
        config.inner(),
        unlock_state.inner(),
        space_id,
        user_path,
        false,
    )
    .await
    .map_err(|_| {
        (
            Status::InternalServerError,
            rocket::serde::json::Json(serde_json::json!({"error": "Failed to list directory."})),
        )
    })?;

    let folders: Vec<serde_json::Value> = entries
        .iter()
        .filter(|e| e.is_dir)
        .map(|e| {
            serde_json::json!({
                "name": e.name,
                "path": e.path,
            })
        })
        .collect();

    Ok(rocket::serde::json::Json(
        serde_json::json!({ "path": user_path, "entries": folders }),
    ))
}

/// GET /search/grantees?q=<query> — search users and groups by name prefix (for typeahead)
#[get("/search/grantees?<q>")]
pub async fn search_grantees(
    pool: &State<DbPool>,
    _session: SessionSetupComplete,
    q: &str,
) -> Result<rocket::serde::json::Json<serde_json::Value>, Status> {
    let q = q.trim();
    if q.is_empty() || q.len() > 100 {
        return Ok(rocket::serde::json::Json(
            serde_json::json!({ "results": [] }),
        ));
    }

    let users = User::search_by_prefix(pool.inner(), q, 5)
        .await
        .unwrap_or_default();
    let groups = Group::search_by_name_prefix(pool.inner(), q, 5)
        .await
        .unwrap_or_default();

    let mut results: Vec<serde_json::Value> = Vec::new();

    for u in users {
        results.push(serde_json::json!({
            "type": "user",
            "id": u.id,
            "name": u.username,
        }));
    }
    for g in groups {
        results.push(serde_json::json!({
            "type": "group",
            "id": g.id,
            "name": g.name,
        }));
    }

    Ok(rocket::serde::json::Json(
        serde_json::json!({ "results": results }),
    ))
}

/// GET /spaces/<space_id>/settings — space settings & access management
#[get("/spaces/<space_id>/settings")]
pub async fn space_settings_page(
    pool: &State<DbPool>,
    unlock_state: &State<UnlockState>,
    cookies: &CookieJar<'_>,
    admin: SessionSpaceAdmin,
    space_id: &str,
    flash: Option<FlashMessage<'_>>,
) -> Template {
    let key_open = key_service::space_access_state(
        pool.inner(),
        unlock_state.inner(),
        &admin.space.space,
        &admin.user.id,
    )
    .await
    .is_ok_and(|s| s == key_service::SpaceLockState::Open);
    let access_entries = space_service::list_access(pool.inner(), &admin.user.id, space_id)
        .await
        .unwrap_or_default();

    let access_display: Vec<serde_json::Value> = access_entries
        .into_iter()
        .map(|a| {
            serde_json::json!({
                "grantee_type": a.grantee_type,
                "grantee_id": a.grantee_id,
                "grantee_name": a.grantee_name,
                "permission": a.permission,
                "granted_at": &a.granted_at,
            })
        })
        .collect();

    Template::render(
        "spaces/settings",
        context! {
            user: &admin.user.username,
            csrf_token: ensure_csrf_token(cookies),
            current_path: "spaces",
            space: serde_json::json!({
                "id": admin.space.space.id,
                "name": admin.space.space.name,
                "owner_type": admin.space.space.owner_type,
                "owner_id": admin.space.space.owner_id,
                "created_at": &admin.space.space.created_at,
                "grantee_count": admin.space.grantee_count,
                "encryption_mode": &admin.space.space.encryption_mode,
            }),
            key_open: key_open,
            space_id: space_id,
            user_permission: &admin.space.user_permission,
            is_admin: true,
            access_entries: access_display,
            flash_kind: flash.as_ref().map(|f| f.kind().to_string()),
            flash_msg: flash.as_ref().map(|f| f.message().to_string()),
        },
    )
}

/// POST /spaces/<space_id>/settings/rename
#[post("/spaces/<space_id>/settings/rename", data = "<form>")]
pub async fn space_rename_submit(
    pool: &State<DbPool>,
    cookies: &CookieJar<'_>,
    _admin: SessionSpaceAdmin,
    space_id: &str,
    form: Form<RenameSpaceForm>,
) -> Result<Flash<Redirect>, Flash<Redirect>> {
    let redir_url = format!("/spaces/{}/settings", space_id);
    validate_csrf(cookies, &form.csrf_token).map_err(|_| {
        Flash::error(
            Redirect::to(redir_url.clone()),
            "Invalid request. Please try again.",
        )
    })?;

    match space_service::update_space(pool.inner(), &_admin.user.id, space_id, &form.name).await {
        Ok(s) => Ok(Flash::success(
            Redirect::to(redir_url.clone()),
            format!("Space renamed to \"{}\".", s.name),
        )),
        Err(AppError::Validation(msg)) => Err(Flash::error(Redirect::to(redir_url.clone()), msg)),
        Err(_) => Err(Flash::error(
            Redirect::to(redir_url),
            "Failed to rename space.",
        )),
    }
}

/// POST /spaces/<space_id>/settings/delete
#[post("/spaces/<space_id>/settings/delete", data = "<form>")]
pub async fn space_delete_submit(
    pool: &State<DbPool>,
    config: &State<AppConfig>,
    unlock_state: &State<UnlockState>,
    cookies: &CookieJar<'_>,
    admin: SessionSpaceAdmin,
    space_id: &str,
    form: Form<CsrfOnlyForm>,
) -> Result<Flash<Redirect>, Flash<Redirect>> {
    validate_csrf(cookies, &form.csrf_token).map_err(|_| {
        Flash::error(
            Redirect::to(format!("/spaces/{}/settings", space_id)),
            "Invalid request. Please try again.",
        )
    })?;

    match space_service::delete_space(
        pool.inner(),
        config.inner(),
        unlock_state.inner(),
        &admin.user.id,
        space_id,
    )
    .await
    {
        Ok(()) => Ok(Flash::success(
            Redirect::to(uri!(spaces_page)),
            "Space deleted.",
        )),
        Err(_) => Err(Flash::error(
            Redirect::to(format!("/spaces/{}/settings", space_id)),
            "Failed to delete space.",
        )),
    }
}

/// POST /spaces/<space_id>/settings/grant
#[post("/spaces/<space_id>/settings/grant", data = "<form>")]
pub async fn space_grant_access_submit(
    pool: &State<DbPool>,
    unlock_state: &State<UnlockState>,
    cookies: &CookieJar<'_>,
    admin: SessionSpaceAdmin,
    space_id: &str,
    form: Form<GrantAccessForm>,
) -> Result<Flash<Redirect>, Flash<Redirect>> {
    let redir_url = format!("/spaces/{}/settings", space_id);
    validate_csrf(cookies, &form.csrf_token).map_err(|_| {
        Flash::error(
            Redirect::to(redir_url.clone()),
            "Invalid request. Please try again.",
        )
    })?;

    let result = match form.grantee_type.as_str() {
        "user" => {
            // Look up username from ID for the service call
            match User::find_by_id(pool.inner(), &form.grantee_id).await {
                Ok(Some(target)) => {
                    space_service::grant_user_access(
                        pool.inner(),
                        &admin.user.id,
                        space_id,
                        &target.username,
                        &form.permission,
                    )
                    .await
                }
                Ok(None) => Err(AppError::NotFound),
                Err(e) => Err(e),
            }
        }
        "group" => {
            space_service::grant_group_access(
                pool.inner(),
                &admin.user.id,
                space_id,
                &form.grantee_id,
                &form.permission,
            )
            .await
        }
        _ => {
            return Err(Flash::error(
                Redirect::to(redir_url.clone()),
                "Invalid grantee type.",
            ))
        }
    };

    if result.is_ok() {
        key_service::resync_space(pool.inner(), unlock_state.inner(), space_id).await;
    }
    match result {
        Ok(_) => Ok(Flash::success(
            Redirect::to(redir_url.clone()),
            "Access granted.",
        )),
        Err(AppError::NotFound) => Err(Flash::error(
            Redirect::to(redir_url.clone()),
            "User or group not found.",
        )),
        Err(AppError::Validation(msg)) => Err(Flash::error(Redirect::to(redir_url.clone()), msg)),
        Err(_) => Err(Flash::error(
            Redirect::to(redir_url),
            "Failed to grant access.",
        )),
    }
}

/// POST /spaces/<space_id>/access/update
#[post("/spaces/<space_id>/access/update", data = "<form>")]
pub async fn space_update_access_submit(
    pool: &State<DbPool>,
    cookies: &CookieJar<'_>,
    admin: SessionSpaceAdmin,
    space_id: &str,
    form: Form<UpdateAccessForm>,
) -> Result<Flash<Redirect>, Flash<Redirect>> {
    let redir_url = format!("/spaces/{}/settings", space_id);
    validate_csrf(cookies, &form.csrf_token).map_err(|_| {
        Flash::error(
            Redirect::to(redir_url.clone()),
            "Invalid request. Please try again.",
        )
    })?;

    match space_service::update_access_permission(
        pool.inner(),
        &admin.user.id,
        space_id,
        &form.grantee_type,
        &form.grantee_id,
        &form.permission,
    )
    .await
    {
        Ok(_) => Ok(Flash::success(
            Redirect::to(redir_url.clone()),
            "Permission updated.",
        )),
        Err(AppError::Validation(msg)) => Err(Flash::error(Redirect::to(redir_url.clone()), msg)),
        Err(_) => Err(Flash::error(
            Redirect::to(redir_url),
            "Failed to update permission.",
        )),
    }
}

/// POST /spaces/<space_id>/access/revoke
#[post("/spaces/<space_id>/access/revoke", data = "<form>")]
pub async fn space_revoke_access_submit(
    pool: &State<DbPool>,
    unlock_state: &State<UnlockState>,
    cookies: &CookieJar<'_>,
    admin: SessionSpaceAdmin,
    space_id: &str,
    form: Form<RevokeAccessForm>,
) -> Result<Flash<Redirect>, Flash<Redirect>> {
    let redir_url = format!("/spaces/{}/settings", space_id);
    validate_csrf(cookies, &form.csrf_token).map_err(|_| {
        Flash::error(
            Redirect::to(redir_url.clone()),
            "Invalid request. Please try again.",
        )
    })?;

    let result = space_service::revoke_access(
        pool.inner(),
        &admin.user.id,
        space_id,
        &form.grantee_type,
        &form.grantee_id,
    )
    .await;
    if result.is_ok() {
        key_service::resync_space(pool.inner(), unlock_state.inner(), space_id).await;
    }
    match result {
        Ok(()) => Ok(Flash::success(
            Redirect::to(redir_url.clone()),
            "Access revoked.",
        )),
        Err(_) => Err(Flash::error(
            Redirect::to(redir_url),
            "Failed to revoke access.",
        )),
    }
}

/// POST /spaces/<space_id>/mkdir
#[post("/spaces/<space_id>/mkdir", data = "<form>")]
pub async fn space_mkdir_submit(
    config: &State<AppConfig>,
    cookies: &CookieJar<'_>,
    _writer: SessionSpaceWriter,
    space_id: &str,
    form: Form<MkdirForm>,
) -> Result<Flash<Redirect>, Flash<Redirect>> {
    let return_path = form.path.clone();
    let redir_url = if return_path.is_empty() {
        format!("/spaces/{}", space_id)
    } else {
        format!("/spaces/{}?path={}", space_id, return_path)
    };

    validate_csrf(cookies, &form.csrf_token).map_err(|_| {
        Flash::error(
            Redirect::to(redir_url.clone()),
            "Invalid request. Please try again.",
        )
    })?;

    let full_path = if form.path.is_empty() {
        form.name.clone()
    } else {
        format!("{}/{}", form.path, form.name)
    };

    match fs_service::create_space_directory(config.inner(), space_id, &full_path).await {
        Ok(_) => Ok(Flash::success(
            Redirect::to(redir_url.clone()),
            format!("Folder \"{}\" created.", form.name),
        )),
        Err(AppError::Conflict(msg)) => Err(Flash::error(Redirect::to(redir_url.clone()), msg)),
        Err(AppError::Validation(msg)) => Err(Flash::error(Redirect::to(redir_url.clone()), msg)),
        Err(_) => Err(Flash::error(
            Redirect::to(redir_url),
            "Failed to create folder.",
        )),
    }
}

/// POST /spaces/<space_id>/rename (file/dir rename within space)
#[post("/spaces/<space_id>/rename", data = "<form>")]
pub async fn space_rename_entry_submit(
    config: &State<AppConfig>,
    cookies: &CookieJar<'_>,
    _writer: SessionSpaceWriter,
    space_id: &str,
    form: Form<RenameForm>,
) -> Result<Flash<Redirect>, Flash<Redirect>> {
    let return_parent = parent_path(&form.old_path);
    let redir_url = if return_parent.is_empty() {
        format!("/spaces/{}", space_id)
    } else {
        format!("/spaces/{}?path={}", space_id, return_parent)
    };

    validate_csrf(cookies, &form.csrf_token).map_err(|_| {
        Flash::error(
            Redirect::to(redir_url.clone()),
            "Invalid request. Please try again.",
        )
    })?;

    let parent = parent_path(&form.old_path);
    let new_path = if parent.is_empty() {
        form.new_name.clone()
    } else {
        format!("{}/{}", parent, form.new_name)
    };

    match fs_service::rename_space_entry(config.inner(), space_id, &form.old_path, &new_path).await
    {
        Ok(_) => Ok(Flash::success(
            Redirect::to(redir_url.clone()),
            format!("Renamed to \"{}\".", form.new_name),
        )),
        Err(AppError::Validation(msg)) => Err(Flash::error(Redirect::to(redir_url.clone()), msg)),
        Err(_) => Err(Flash::error(Redirect::to(redir_url), "Rename failed.")),
    }
}

/// POST /spaces/<space_id>/move
#[post("/spaces/<space_id>/move", data = "<form>")]
pub async fn space_move_entry_submit(
    config: &State<AppConfig>,
    cookies: &CookieJar<'_>,
    _writer: SessionSpaceWriter,
    space_id: &str,
    form: Form<MoveForm>,
) -> Result<Flash<Redirect>, Flash<Redirect>> {
    let redir_url = format!("/spaces/{}", space_id);

    validate_csrf(cookies, &form.csrf_token).map_err(|_| {
        Flash::error(
            Redirect::to(redir_url.clone()),
            "Invalid request. Please try again.",
        )
    })?;

    let name = file_name_from_path(&form.old_path);
    if name.is_empty() {
        return Err(Flash::error(
            Redirect::to(redir_url),
            "Invalid source path.",
        ));
    }

    let target_dir = normalize_dir_path(&form.target_dir);
    let new_path = join_dir_and_name(&target_dir, &name);

    match fs_service::rename_space_entry(config.inner(), space_id, &form.old_path, &new_path).await
    {
        Ok(_) => Ok(Flash::success(
            Redirect::to(redir_url.clone()),
            "Moved successfully.",
        )),
        Err(AppError::Validation(msg)) => Err(Flash::error(Redirect::to(redir_url.clone()), msg)),
        Err(AppError::Conflict(msg)) => Err(Flash::error(Redirect::to(redir_url.clone()), msg)),
        Err(_) => Err(Flash::error(Redirect::to(redir_url), "Move failed.")),
    }
}

/// POST /spaces/<space_id>/delete (file/dir delete within space)
#[post("/spaces/<space_id>/delete", data = "<form>")]
pub async fn space_delete_entry_submit(
    pool: &State<DbPool>,
    config: &State<AppConfig>,
    cookies: &CookieJar<'_>,
    writer: SessionSpaceWriter,
    space_id: &str,
    form: Form<DeleteForm>,
) -> Result<Flash<Redirect>, Flash<Redirect>> {
    let parent = parent_path(&form.path);
    let redir_url = if parent.is_empty() {
        format!("/spaces/{}", space_id)
    } else {
        format!("/spaces/{}?path={}", space_id, parent)
    };

    validate_csrf(cookies, &form.csrf_token).map_err(|_| {
        Flash::error(
            Redirect::to(redir_url.clone()),
            "Invalid request. Please try again.",
        )
    })?;

    match trash_service::move_to_trash(
        pool.inner(),
        config.inner(),
        TargetKind::Space,
        space_id,
        &form.path,
        Some(&writer.user.id),
    )
    .await
    {
        Ok(_) => Ok(Flash::success(
            Redirect::to(redir_url.clone()),
            "Moved to trash.",
        )),
        Err(_) => Err(Flash::error(Redirect::to(redir_url), "Delete failed.")),
    }
}

/// POST /spaces/<space_id>/bulk-delete — XHR JSON endpoint
#[post("/spaces/<space_id>/bulk-delete", data = "<data>")]
pub async fn space_bulk_delete(
    pool: &State<DbPool>,
    config: &State<AppConfig>,
    _csrf: CsrfXhr,
    writer: SessionSpaceWriter,
    space_id: &str,
    data: rocket::serde::json::Json<BulkDeleteRequest>,
) -> rocket::serde::json::Json<serde_json::Value> {
    if data.paths.is_empty() || data.paths.len() > 500 {
        return rocket::serde::json::Json(
            serde_json::json!({"deleted": 0, "errors": ["Invalid number of paths (1–500)."]}),
        );
    }

    let (trash_ids, errors) = trash_paths(
        pool.inner(),
        config.inner(),
        TargetKind::Space,
        space_id,
        &data.paths,
        &writer.user.id,
    )
    .await;

    rocket::serde::json::Json(serde_json::json!({
        "deleted": trash_ids.len(),
        "trash_ids": trash_ids,
        "errors": errors,
    }))
}

/// POST /spaces/<space_id>/bulk-move — XHR JSON endpoint
#[post("/spaces/<space_id>/bulk-move", data = "<data>")]
pub async fn space_bulk_move(
    config: &State<AppConfig>,
    _csrf: CsrfXhr,
    _writer: SessionSpaceWriter,
    space_id: &str,
    data: rocket::serde::json::Json<BulkMoveRequest>,
) -> rocket::serde::json::Json<serde_json::Value> {
    let target_dir = normalize_dir_path(&data.target_dir);
    let mut moved = 0u64;
    let mut errors: Vec<String> = Vec::new();

    for path in &data.paths {
        let name = file_name_from_path(path);
        if name.is_empty() {
            errors.push(format!("{}: invalid path", path));
            continue;
        }
        let new_path = join_dir_and_name(&target_dir, &name);
        match fs_service::rename_space_entry(config.inner(), space_id, path, &new_path).await {
            Ok(_) => moved += 1,
            Err(e) => errors.push(bulk_error(path, &e)),
        }
    }

    rocket::serde::json::Json(serde_json::json!({
        "moved": moved,
        "errors": errors,
    }))
}

/// POST /spaces/<space_id>/upload — single-file upload
#[post("/spaces/<space_id>/upload?<path>", data = "<data>")]
#[allow(clippy::too_many_arguments)]
pub async fn space_upload_file(
    pool: &State<DbPool>,
    config: &State<AppConfig>,
    unlock_state: &State<UnlockState>,
    _csrf: CsrfXhr,
    _writer: SessionSpaceWriter,
    space_id: &str,
    path: String,
    data: rocket::data::Data<'_>,
) -> Result<
    rocket::serde::json::Json<serde_json::Value>,
    (Status, rocket::serde::json::Json<serde_json::Value>),
> {
    use rocket::data::ToByteUnit;

    let allowed = config.direct_upload_limit();
    let stream = data.open(allowed.bytes()).into_bytes().await.map_err(|e| {
        (
            Status::InternalServerError,
            rocket::serde::json::Json(
                serde_json::json!({"error": format!("Failed to read upload data: {e}")}),
            ),
        )
    })?;

    if !stream.is_complete() {
        return Err((
            Status::PayloadTooLarge,
            rocket::serde::json::Json(serde_json::json!({
                "error": format!("File exceeds the {} limit for a single upload.", format_bytes(allowed))
            })),
        ));
    }

    let bytes = stream.into_inner();

    quota_service::ensure_room(
        pool.inner(),
        config.inner(),
        TargetKind::Space,
        space_id,
        quota_service::estimated_disk_size(bytes.len() as u64, config.chunk_size_bytes),
        Some(&path),
        None,
    )
    .await
    .map_err(json_error)?;

    let result = fs_service::upload_space_file_owned(
        config.inner(),
        unlock_state.inner(),
        space_id,
        &path,
        bytes,
        true,
    )
    .await
    .map_err(json_error)?;

    Ok(rocket::serde::json::Json(serde_json::json!({
        "success": true,
        "path": result.path,
        "size": result.size,
        "disk_size": result.disk_size,
        "checksum_sha256": result.checksum_sha256,
        "mime_type": result.mime_type,
    })))
}

/// GET /spaces/<space_id>/download?<path> — browser download
#[get("/spaces/<space_id>/download?<path>")]
pub async fn space_download_file(
    pool: &State<DbPool>,
    config: &State<AppConfig>,
    unlock_state: &State<UnlockState>,
    _reader: SessionSpaceReader,
    range: crate::routes::download::RangeHeader,
    space_id: &str,
    path: String,
) -> Result<crate::routes::download::StreamedDownload, (Status, String)> {
    crate::routes::download::stream_file(
        pool.inner(),
        config.inner(),
        unlock_state.inner(),
        TargetKind::Space,
        space_id,
        &path,
        &range,
    )
    .await
    .map_err(|e| (e.status(), e.client_message()))
}

// ---------------------------------------------------------------------------
// Space chunked upload / download
// ---------------------------------------------------------------------------

/// POST /spaces/<space_id>/chunked/init — start a chunked upload to a space.
#[post("/spaces/<space_id>/chunked/init", data = "<body>")]
pub async fn space_chunked_init_upload(
    pool: &State<DbPool>,
    config: &State<AppConfig>,
    _csrf: CsrfXhr,
    writer: SessionSpaceWriter,
    space_id: &str,
    body: rocket::serde::json::Json<ChunkedInitRequest>,
) -> Result<
    rocket::serde::json::Json<serde_json::Value>,
    (Status, rocket::serde::json::Json<serde_json::Value>),
> {
    let result = chunk_service::init_upload(
        pool.inner(),
        config.inner(),
        chunk_service::InitUploadParams {
            user_id: writer.user.id.clone(),
            target_id: space_id.to_string(),
            target_type: "space".to_string(),
            target_path: body.path.clone(),
            total_chunks: body.total_chunks,
            total_bytes: body.total_bytes,
            checksum_sha256: body.checksum_sha256.clone(),
        },
    )
    .await
    .map_err(|e| {
        (
            e.status(),
            rocket::serde::json::Json(serde_json::json!({"error": e.client_message()})),
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

/// PUT /spaces/<space_id>/chunked/upload/<upload_id>/<chunk_index> — receive one chunk.
#[allow(clippy::too_many_arguments)]
#[put(
    "/spaces/<space_id>/chunked/upload/<upload_id>/<chunk_index>",
    data = "<data>"
)]
pub async fn space_chunked_receive_chunk(
    pool: &State<DbPool>,
    config: &State<AppConfig>,
    _csrf: CsrfXhr,
    writer: SessionSpaceWriter,
    space_id: &str,
    upload_id: &str,
    chunk_index: u32,
    data: rocket::data::Data<'_>,
) -> Result<
    rocket::serde::json::Json<serde_json::Value>,
    (Status, rocket::serde::json::Json<serde_json::Value>),
> {
    use rocket::data::ToByteUnit;

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
        &writer.user.id,
        space_id,
        "space",
        upload_id,
        chunk_index,
        &stream.into_inner(),
    )
    .await
    .map_err(|e| {
        (
            e.status(),
            rocket::serde::json::Json(serde_json::json!({"error": e.client_message()})),
        )
    })?;

    Ok(rocket::serde::json::Json(serde_json::json!({
        "upload_id": result.upload_id,
        "chunk_index": result.chunk_index,
        "received_chunks": result.received_chunks,
        "total_chunks": result.total_chunks,
    })))
}

/// POST /spaces/<space_id>/chunked/complete — assemble chunked upload in a space.
#[post("/spaces/<space_id>/chunked/complete", data = "<body>")]
pub async fn space_chunked_complete_upload(
    pool: &State<DbPool>,
    config: &State<AppConfig>,
    unlock_state: &State<UnlockState>,
    _csrf: CsrfXhr,
    writer: SessionSpaceWriter,
    space_id: &str,
    body: rocket::serde::json::Json<ChunkedCompleteRequest>,
) -> Result<
    rocket::serde::json::Json<serde_json::Value>,
    (Status, rocket::serde::json::Json<serde_json::Value>),
> {
    let result = chunk_service::complete_upload(
        pool.inner(),
        config.inner(),
        unlock_state.inner(),
        &writer.user.id,
        space_id,
        "space",
        &body.upload_id,
        body.verify.unwrap_or(false),
    )
    .await
    .map_err(|e| {
        (
            e.status(),
            rocket::serde::json::Json(serde_json::json!({"error": e.client_message()})),
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

/// DELETE /spaces/<space_id>/chunked/cancel?upload_id=<id> — cancel chunked upload in a space.
#[delete("/spaces/<space_id>/chunked/cancel?<upload_id>")]
pub async fn space_chunked_cancel_upload(
    pool: &State<DbPool>,
    config: &State<AppConfig>,
    _csrf: CsrfXhr,
    writer: SessionSpaceWriter,
    space_id: &str,
    upload_id: String,
) -> Result<
    rocket::serde::json::Json<serde_json::Value>,
    (Status, rocket::serde::json::Json<serde_json::Value>),
> {
    chunk_service::cancel_upload(
        pool.inner(),
        config.inner(),
        &writer.user.id,
        space_id,
        "space",
        &upload_id,
    )
    .await
    .map_err(|e| {
        (
            e.status(),
            rocket::serde::json::Json(serde_json::json!({"error": e.client_message()})),
        )
    })?;

    Ok(rocket::serde::json::Json(serde_json::json!({
        "success": true,
        "upload_id": upload_id,
    })))
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
        api_mkdir,
        api_rename,
        upload_file,
        chunked_init_upload,
        chunked_receive_chunk,
        chunked_complete_upload,
        chunked_cancel_upload,
        download_file,
        usage_sidebar,
        usage_page,
        settings_page,
        groups_page,
        groups_create_submit,
        group_detail_page,
        group_edit_submit,
        group_delete_submit,
        group_add_member_submit,
        group_remove_member_submit,
        group_update_member_role_submit,
        spaces_page,
        spaces_create_submit,
        search_grantees,
        space_browser_page,
        space_browser_partial,
        space_folders,
        space_settings_page,
        space_rename_submit,
        space_delete_submit,
        space_grant_access_submit,
        space_update_access_submit,
        space_revoke_access_submit,
        space_mkdir_submit,
        space_rename_entry_submit,
        space_move_entry_submit,
        space_delete_entry_submit,
        space_bulk_delete,
        space_bulk_move,
        space_api_mkdir,
        space_api_rename,
        space_upload_file,
        space_download_file,
        space_chunked_init_upload,
        space_chunked_receive_chunk,
        space_chunked_complete_upload,
        space_chunked_cancel_upload,
    ]
}
