//! Browser pages for encryption: the unlock page, Settings › Security forms,
//! unlocking/locking password-protected spaces, space protection, the reset
//! page, the admin "reset password" action and security notices.

// Handlers return Redirect/Flash<Redirect> as the error arm; Rocket sends it
// straight back, so boxing it would buy nothing.
#![allow(clippy::result_large_err)]

use rocket::form::Form;
use rocket::http::CookieJar;
use rocket::request::FlashMessage;
use rocket::response::{Flash, Redirect};
use rocket::serde::json::Json;
use rocket::{Route, State};
use rocket_dyn_templates::{context, Template};

use crate::db::DbPool;
use crate::errors::AppError;
use crate::guards::csrf_guard::{ensure_csrf_token, validate_csrf, CsrfXhr};
use crate::guards::space_guard::{SessionSpaceAdmin, SessionSpaceReader};
use crate::guards::SessionSetupComplete;
use crate::services::crypto_service::MasterKey;
use crate::services::key_service;
use crate::services::rate_limit::{ClientIp, RateLimiter};
use crate::services::recovery_service;
use crate::services::unlock_state::UnlockState;

use super::encryption::{UNLOCK_ATTEMPTS, UNLOCK_WINDOW_SECS};
use super::pages::{json_error, JsonResult};

/// Only same-site paths are allowed as a post-unlock destination.
fn safe_next(next: Option<&str>) -> String {
    match next {
        Some(n) if n.starts_with('/') && !n.starts_with("//") && !n.contains('\\') => n.into(),
        _ => "/files".into(),
    }
}

fn flash_err(to: &str, e: AppError) -> Flash<Redirect> {
    let msg = match e {
        AppError::BadPassphrase => "That password isn't right.".into(),
        e => e.client_message(),
    };
    Flash::error(Redirect::to(to.to_owned()), msg)
}

// ---------------------------------------------------------------------------
// Account unlock / lock
// ---------------------------------------------------------------------------

/// GET /unlock — "your files are locked" page for password-tier accounts.
#[get("/unlock?<next>")]
pub async fn unlock_page(
    pool: &State<DbPool>,
    unlock_state: &State<UnlockState>,
    cookies: &CookieJar<'_>,
    user: SessionSetupComplete,
    next: Option<String>,
    flash: Option<FlashMessage<'_>>,
) -> Result<Template, Redirect> {
    let next = safe_next(next.as_deref());
    if key_service::is_user_unlocked(pool.inner(), unlock_state.inner(), &user.0.id)
        .await
        .unwrap_or(true)
    {
        return Err(Redirect::to(next));
    }
    let separate = key_service::find_user_keys(pool.inner(), &user.0.id)
        .await
        .ok()
        .flatten()
        .is_some_and(|k| k.password_mode == key_service::MODE_SEPARATE);
    Ok(Template::render(
        "auth/unlock",
        context! {
            username: &user.0.username,
            separate: separate,
            next: next,
            csrf_token: ensure_csrf_token(cookies),
            flash_kind: flash.as_ref().map(|f| f.kind().to_string()),
            flash_msg: flash.as_ref().map(|f| f.message().to_string()),
        },
    ))
}

#[derive(FromForm)]
pub struct UnlockForm {
    pub csrf_token: String,
    pub password: String,
    pub next: Option<String>,
}

/// POST /unlock
#[post("/unlock", data = "<form>")]
#[allow(clippy::too_many_arguments)]
pub async fn unlock_submit(
    pool: &State<DbPool>,
    master_key: &State<MasterKey>,
    unlock_state: &State<UnlockState>,
    rate_limiter: &State<RateLimiter>,
    cookies: &CookieJar<'_>,
    user: SessionSetupComplete,
    form: Form<UnlockForm>,
) -> Result<Redirect, Flash<Redirect>> {
    let next = safe_next(form.next.as_deref());
    let back = format!("/unlock?next={}", urlencoding_min(&next));
    validate_csrf(cookies, &form.csrf_token)
        .map_err(|_| flash_err(&back, AppError::Validation("Please try again.".into())))?;
    if !rate_limiter.check(
        &format!("unlock:{}", user.0.id),
        UNLOCK_ATTEMPTS,
        UNLOCK_WINDOW_SECS,
    ) {
        return Err(flash_err(&back, AppError::RateLimited));
    }
    key_service::unlock_user(
        pool.inner(),
        master_key.inner(),
        unlock_state.inner(),
        &user.0.id,
        Some(&form.password),
    )
    .await
    .map_err(|e| flash_err(&back, e))?;
    Ok(Redirect::to(next))
}

/// Percent-encode the few characters that matter inside a query value.
fn urlencoding_min(s: &str) -> String {
    s.replace('%', "%25")
        .replace('&', "%26")
        .replace('#', "%23")
        .replace('?', "%3F")
        .replace('+', "%2B")
        .replace(' ', "%20")
}

#[derive(FromForm)]
pub struct CsrfForm {
    pub csrf_token: String,
}

/// POST /lock — lock the account's keys now (stays signed in).
#[post("/lock", data = "<form>")]
pub async fn lock_submit(
    pool: &State<DbPool>,
    unlock_state: &State<UnlockState>,
    cookies: &CookieJar<'_>,
    user: SessionSetupComplete,
    form: Form<CsrfForm>,
) -> Result<Redirect, Flash<Redirect>> {
    validate_csrf(cookies, &form.csrf_token).map_err(|_| {
        flash_err(
            "/settings",
            AppError::Validation("Please try again.".into()),
        )
    })?;
    key_service::lock_user(pool.inner(), unlock_state.inner(), &user.0.id)
        .await
        .map_err(|e| flash_err("/settings", e))?;
    Ok(Redirect::to("/unlock?next=/files"))
}

// ---------------------------------------------------------------------------
// Settings › Security
// ---------------------------------------------------------------------------

#[derive(FromForm)]
pub struct TierForm {
    pub csrf_token: String,
    pub current_password: String,
    pub tier: String,
    pub password_mode: Option<String>,
    pub encryption_password: Option<String>,
    pub encryption_password_confirm: Option<String>,
}

/// POST /settings/encryption — switch tier / password mode.
#[post("/settings/encryption", data = "<form>")]
#[allow(clippy::too_many_arguments)]
pub async fn change_tier_submit(
    pool: &State<DbPool>,
    master_key: &State<MasterKey>,
    unlock_state: &State<UnlockState>,
    rate_limiter: &State<RateLimiter>,
    cookies: &CookieJar<'_>,
    user: SessionSetupComplete,
    form: Form<TierForm>,
) -> Result<Flash<Redirect>, Flash<Redirect>> {
    const BACK: &str = "/settings#security";
    validate_csrf(cookies, &form.csrf_token)
        .map_err(|_| flash_err(BACK, AppError::Validation("Please try again.".into())))?;
    if !rate_limiter.check(
        &format!("unlock:{}", user.0.id),
        UNLOCK_ATTEMPTS,
        UNLOCK_WINDOW_SECS,
    ) {
        return Err(flash_err(BACK, AppError::RateLimited));
    }
    let mode = form
        .password_mode
        .as_deref()
        .unwrap_or(key_service::MODE_SINGLE);
    if mode == key_service::MODE_SEPARATE
        && form.encryption_password != form.encryption_password_confirm
    {
        return Err(flash_err(
            BACK,
            AppError::Validation("The encryption passwords don't match.".into()),
        ));
    }
    key_service::change_tier_checked(
        pool.inner(),
        master_key.inner(),
        unlock_state.inner(),
        &user.0.id,
        &form.current_password,
        &form.tier,
        mode,
        form.encryption_password.as_deref(),
    )
    .await
    .map_err(|e| flash_err(BACK, e))?;
    Ok(Flash::success(
        Redirect::to(BACK),
        "Encryption settings updated.",
    ))
}

#[derive(FromForm)]
pub struct PasswordForm {
    pub csrf_token: String,
    pub current_password: String,
    pub new_password: String,
    pub new_password_confirm: String,
}

/// POST /settings/password — change the login password.
#[post("/settings/password", data = "<form>")]
#[allow(clippy::too_many_arguments)]
pub async fn change_password_submit(
    pool: &State<DbPool>,
    master_key: &State<MasterKey>,
    unlock_state: &State<UnlockState>,
    rate_limiter: &State<RateLimiter>,
    cookies: &CookieJar<'_>,
    user: SessionSetupComplete,
    form: Form<PasswordForm>,
) -> Result<Flash<Redirect>, Flash<Redirect>> {
    const BACK: &str = "/settings#security";
    validate_csrf(cookies, &form.csrf_token)
        .map_err(|_| flash_err(BACK, AppError::Validation("Please try again.".into())))?;
    if !rate_limiter.check(
        &format!("unlock:{}", user.0.id),
        UNLOCK_ATTEMPTS,
        UNLOCK_WINDOW_SECS,
    ) {
        return Err(flash_err(BACK, AppError::RateLimited));
    }
    if form.new_password != form.new_password_confirm {
        return Err(flash_err(
            BACK,
            AppError::Validation("The new passwords don't match.".into()),
        ));
    }
    key_service::change_login_password(
        pool.inner(),
        master_key.inner(),
        unlock_state.inner(),
        &user.0.id,
        &form.current_password,
        &form.new_password,
    )
    .await
    .map_err(|e| flash_err(BACK, e))?;
    Ok(Flash::success(Redirect::to(BACK), "Password changed."))
}

/// POST /settings/encryption-password — change the separate encryption password.
#[post("/settings/encryption-password", data = "<form>")]
pub async fn change_encryption_password_submit(
    pool: &State<DbPool>,
    master_key: &State<MasterKey>,
    rate_limiter: &State<RateLimiter>,
    cookies: &CookieJar<'_>,
    user: SessionSetupComplete,
    form: Form<PasswordForm>,
) -> Result<Flash<Redirect>, Flash<Redirect>> {
    const BACK: &str = "/settings#security";
    validate_csrf(cookies, &form.csrf_token)
        .map_err(|_| flash_err(BACK, AppError::Validation("Please try again.".into())))?;
    if !rate_limiter.check(
        &format!("unlock:{}", user.0.id),
        UNLOCK_ATTEMPTS,
        UNLOCK_WINDOW_SECS,
    ) {
        return Err(flash_err(BACK, AppError::RateLimited));
    }
    if form.new_password != form.new_password_confirm {
        return Err(flash_err(
            BACK,
            AppError::Validation("The new passwords don't match.".into()),
        ));
    }
    key_service::change_encryption_password(
        pool.inner(),
        master_key.inner(),
        &user.0.id,
        &form.current_password,
        &form.new_password,
    )
    .await
    .map_err(|e| flash_err(BACK, e))?;
    Ok(Flash::success(
        Redirect::to(BACK),
        "Encryption password changed.",
    ))
}

// ---------------------------------------------------------------------------
// Spaces
// ---------------------------------------------------------------------------

#[derive(FromForm)]
pub struct SpacePasswordForm {
    pub csrf_token: String,
    pub password: String,
}

/// POST /spaces/<id>/unlock — type a password-protected space's password.
#[post("/spaces/<space_id>/unlock", data = "<form>")]
pub async fn space_unlock_submit(
    unlock_state: &State<UnlockState>,
    rate_limiter: &State<RateLimiter>,
    cookies: &CookieJar<'_>,
    reader: SessionSpaceReader,
    space_id: &str,
    form: Form<SpacePasswordForm>,
) -> Result<Redirect, Flash<Redirect>> {
    let back = format!("/spaces/{space_id}");
    validate_csrf(cookies, &form.csrf_token)
        .map_err(|_| flash_err(&back, AppError::Validation("Please try again.".into())))?;
    if !rate_limiter.check(
        &format!("space-unlock:{}:{}", space_id, reader.user.id),
        UNLOCK_ATTEMPTS,
        UNLOCK_WINDOW_SECS,
    ) {
        return Err(flash_err(&back, AppError::RateLimited));
    }
    key_service::unlock_password_space(
        unlock_state.inner(),
        &reader.space.space,
        &reader.user.id,
        &form.password,
    )
    .await
    .map_err(|e| flash_err(&back, e))?;
    Ok(Redirect::to(back))
}

/// POST /spaces/<id>/lock — close a password-protected space for yourself.
#[post("/spaces/<space_id>/lock", data = "<form>")]
pub async fn space_lock_submit(
    unlock_state: &State<UnlockState>,
    cookies: &CookieJar<'_>,
    reader: SessionSpaceReader,
    space_id: &str,
    form: Form<CsrfForm>,
) -> Redirect {
    if validate_csrf(cookies, &form.csrf_token).is_ok() {
        key_service::lock_password_space(unlock_state.inner(), space_id, &reader.user.id);
    }
    Redirect::to(format!("/spaces/{space_id}"))
}

#[derive(FromForm)]
pub struct ProtectionForm {
    pub csrf_token: String,
    pub mode: String,
    pub password: Option<String>,
    pub password_confirm: Option<String>,
}

/// POST /spaces/<id>/settings/protection — change how the space key is protected.
#[post("/spaces/<space_id>/settings/protection", data = "<form>")]
pub async fn space_protection_submit(
    pool: &State<DbPool>,
    master_key: &State<MasterKey>,
    unlock_state: &State<UnlockState>,
    cookies: &CookieJar<'_>,
    admin: SessionSpaceAdmin,
    space_id: &str,
    form: Form<ProtectionForm>,
) -> Result<Flash<Redirect>, Flash<Redirect>> {
    let back = format!("/spaces/{space_id}/settings");
    validate_csrf(cookies, &form.csrf_token)
        .map_err(|_| flash_err(&back, AppError::Validation("Please try again.".into())))?;
    if form.mode == key_service::SPACE_PASSWORD && form.password != form.password_confirm {
        return Err(flash_err(
            &back,
            AppError::Validation("The passwords don't match.".into()),
        ));
    }
    key_service::set_space_protection(
        pool.inner(),
        master_key.inner(),
        unlock_state.inner(),
        space_id,
        &admin.user.id,
        &form.mode,
        form.password.as_deref().filter(|p| !p.is_empty()),
    )
    .await
    .map_err(|e| match e {
        AppError::Locked => flash_err(
            &back,
            AppError::Validation(
                "Open the space first: its key has to be unlocked to change how it's protected."
                    .into(),
            ),
        ),
        e => flash_err(&back, e),
    })?;
    Ok(Flash::success(Redirect::to(back), "Protection updated."))
}

// ---------------------------------------------------------------------------
// Password reset (admin-issued code)
// ---------------------------------------------------------------------------

/// GET /reset — redeem a reset code. Works signed out.
#[get("/reset")]
pub async fn reset_page(cookies: &CookieJar<'_>, flash: Option<FlashMessage<'_>>) -> Template {
    Template::render(
        "auth/reset",
        context! {
            csrf_token: ensure_csrf_token(cookies),
            flash_kind: flash.as_ref().map(|f| f.kind().to_string()),
            flash_msg: flash.as_ref().map(|f| f.message().to_string()),
        },
    )
}

#[derive(FromForm)]
pub struct ResetForm {
    pub csrf_token: String,
    pub username: String,
    pub code: String,
    pub new_password: String,
    pub new_password_confirm: String,
    pub new_encryption_password: Option<String>,
}

/// POST /reset
#[post("/reset", data = "<form>")]
#[allow(clippy::too_many_arguments)]
pub async fn reset_submit(
    pool: &State<DbPool>,
    master_key: &State<MasterKey>,
    unlock_state: &State<UnlockState>,
    rate_limiter: &State<RateLimiter>,
    client_ip: ClientIp,
    cookies: &CookieJar<'_>,
    form: Form<ResetForm>,
) -> Result<Flash<Redirect>, Flash<Redirect>> {
    const BACK: &str = "/reset";
    validate_csrf(cookies, &form.csrf_token)
        .map_err(|_| flash_err(BACK, AppError::Validation("Please try again.".into())))?;
    if !rate_limiter.check(&format!("reset:{}", client_ip.0), 10, 900) {
        return Err(flash_err(BACK, AppError::RateLimited));
    }
    if form.new_password != form.new_password_confirm {
        return Err(flash_err(
            BACK,
            AppError::Validation("The new passwords don't match.".into()),
        ));
    }
    recovery_service::redeem_reset_code(
        pool.inner(),
        master_key.inner(),
        unlock_state.inner(),
        &form.username,
        &form.code,
        &form.new_password,
        form.new_encryption_password
            .as_deref()
            .filter(|p| !p.is_empty()),
    )
    .await
    .map_err(|e| match e {
        AppError::BadPassphrase => Flash::error(
            Redirect::to(BACK),
            "That username and code don't match a valid reset. Codes expire after 24 hours and work once.",
        ),
        e => flash_err(BACK, e),
    })?;
    Ok(Flash::success(
        Redirect::to("/login"),
        "Password reset. Sign in with your new password.",
    ))
}

#[derive(serde::Deserialize)]
pub struct AdminResetRequest {
    #[serde(default)]
    pub reason: Option<String>,
}

/// POST /admin/users/<id>/reset — XHR: issue a one-time reset code.
#[post("/admin/users/<id>/reset", format = "json", data = "<body>")]
pub async fn admin_reset(
    pool: &State<DbPool>,
    _csrf: CsrfXhr,
    user: SessionSetupComplete,
    id: &str,
    body: Json<AdminResetRequest>,
) -> JsonResult {
    if user.0.role != "admin" {
        return Err(json_error(AppError::Forbidden));
    }
    if id == user.0.id {
        return Err(json_error(AppError::Validation(
            "Change your own password in Settings.".into(),
        )));
    }
    let issued =
        recovery_service::issue_reset_code(pool.inner(), &user.0.id, id, body.reason.as_deref())
            .await
            .map_err(|e| match e {
                AppError::RecoveryNotAvailable => json_error(AppError::Validation(
                    "This person uses Maximum protection with one password. Resetting it would \
                     make their files unreadable, so it can't be done here."
                        .into(),
                )),
                e => json_error(e),
            })?;
    Ok(Json(serde_json::to_value(issued).unwrap_or_default()))
}

/// POST /notifications/security/<id>/dismiss — XHR: acknowledge a reset notice.
#[post("/notifications/security/<id>/dismiss")]
pub async fn dismiss_security_notice(
    pool: &State<DbPool>,
    _csrf: CsrfXhr,
    user: SessionSetupComplete,
    id: &str,
) -> JsonResult {
    recovery_service::acknowledge_notice(pool.inner(), &user.0.id, id)
        .await
        .map_err(json_error)?;
    Ok(Json(serde_json::json!({ "ok": true })))
}

pub fn routes() -> Vec<Route> {
    routes![
        unlock_page,
        unlock_submit,
        lock_submit,
        change_tier_submit,
        change_password_submit,
        change_encryption_password_submit,
        space_unlock_submit,
        space_lock_submit,
        space_protection_submit,
        reset_page,
        reset_submit,
        admin_reset,
        dismiss_security_notice,
    ]
}
