//! API routes for account encryption tiers and space protection.
//!
//! - `GET  /api/v1/auth/encryption`            tier, password mode, locked state
//! - `PUT  /api/v1/auth/encryption`            switch tier (re-checks the login password)
//! - `POST /api/v1/auth/unlock` / `lock`       unlock / lock the account's keys
//! - `POST /api/v1/auth/password`              change the login password
//! - `POST /api/v1/auth/encryption-password`   change the separate encryption password
//! - `POST /api/v1/spaces/<id>/unlock` / `lock` open / close a password-protected space
//! - `PUT  /api/v1/spaces/<id>/protection`     change how a space's key is protected
//! - `POST /api/v1/admin/users/<id>/reset`     admin: issue a one-time reset code
//! - `POST /api/v1/auth/reset`                 redeem a reset code (no sign-in)
//! - `GET  /api/v1/users/me/security-notices`  resets of your account
//! - `POST /api/v1/users/me/security-notices/<id>/ack`

use rocket::serde::json::Json;
use rocket::{Route, State};
use serde::{Deserialize, Serialize};

use crate::db::DbPool;
use crate::errors::AppError;
use crate::guards::admin_guard::AdminUser;
use crate::guards::setup_guard::SetupComplete;
use crate::guards::space_guard::{SpaceAdmin, SpaceReader};
use crate::services::crypto_service::MasterKey;
use crate::services::key_service::{self, SpaceLockState};
use crate::services::rate_limit::{ClientIp, RateLimiter};
use crate::services::recovery_service::{self, IssuedCode, SecurityNotice};
use crate::services::unlock_state::UnlockState;

/// Password guesses allowed per account (or per space and member) per window.
pub const UNLOCK_ATTEMPTS: u32 = 10;
pub const UNLOCK_WINDOW_SECS: u64 = 900;

#[derive(Serialize)]
pub struct EncryptionStatus {
    /// `server`, `failsafe_user` or `pure_user`.
    pub tier: String,
    /// `single` (login password unlocks) or `separate` (encryption password).
    pub password_mode: String,
    /// Whether the account's keys are in memory right now.
    pub unlocked: bool,
    /// Whether an admin can recover the keys if every password is forgotten.
    pub recoverable: bool,
}

#[derive(Deserialize)]
pub struct PasswordBody {
    pub password: String,
}

#[derive(Deserialize)]
pub struct ChangeTierBody {
    pub current_password: String,
    pub tier: String,
    #[serde(default = "default_mode")]
    pub password_mode: String,
    #[serde(default)]
    pub encryption_password: Option<String>,
}

fn default_mode() -> String {
    key_service::MODE_SINGLE.into()
}

#[derive(Deserialize)]
pub struct ChangePasswordBody {
    pub current_password: String,
    pub new_password: String,
}

#[derive(Deserialize)]
pub struct SpaceProtectionBody {
    /// `server`, `members` or `password`.
    pub mode: String,
    /// New space password (required for `password`).
    #[serde(default)]
    pub password: Option<String>,
}

#[derive(Serialize)]
pub struct Message {
    pub message: String,
}

#[derive(Serialize)]
pub struct SpaceLockStatus {
    pub encryption_mode: String,
    /// `open`, `needs_password`, `account_locked` or `waiting_for_key`.
    pub state: &'static str,
}

pub fn lock_state_name(state: SpaceLockState) -> &'static str {
    match state {
        SpaceLockState::Open => "open",
        SpaceLockState::NeedsPassword => "needs_password",
        SpaceLockState::AccountLocked => "account_locked",
        SpaceLockState::WaitingForKey => "waiting_for_key",
    }
}

fn msg(m: &str) -> Json<Message> {
    Json(Message { message: m.into() })
}

/// Status of the signed-in account's encryption.
pub async fn encryption_status(
    pool: &DbPool,
    unlock: &UnlockState,
    user_id: &str,
) -> Result<EncryptionStatus, AppError> {
    let keys = key_service::find_user_keys(pool, user_id).await?;
    let unlocked = key_service::is_user_unlocked(pool, unlock, user_id).await?;
    Ok(match keys {
        Some(k) => EncryptionStatus {
            recoverable: k.tier != key_service::TIER_PURE,
            tier: k.tier,
            password_mode: k.password_mode,
            unlocked,
        },
        None => EncryptionStatus {
            tier: key_service::TIER_SERVER.into(),
            password_mode: key_service::MODE_SINGLE.into(),
            unlocked,
            recoverable: true,
        },
    })
}

#[get("/api/v1/auth/encryption")]
pub async fn get_encryption(
    pool: &State<DbPool>,
    unlock_state: &State<UnlockState>,
    user: SetupComplete,
) -> Result<Json<EncryptionStatus>, AppError> {
    Ok(Json(
        encryption_status(pool.inner(), unlock_state.inner(), &user.0.id).await?,
    ))
}

#[put("/api/v1/auth/encryption", format = "json", data = "<body>")]
pub async fn put_encryption(
    pool: &State<DbPool>,
    master_key: &State<MasterKey>,
    unlock_state: &State<UnlockState>,
    rate_limiter: &State<RateLimiter>,
    user: SetupComplete,
    body: Json<ChangeTierBody>,
) -> Result<Json<EncryptionStatus>, AppError> {
    if !rate_limiter.check(
        &format!("unlock:{}", user.0.id),
        UNLOCK_ATTEMPTS,
        UNLOCK_WINDOW_SECS,
    ) {
        return Err(AppError::RateLimited);
    }
    key_service::change_tier_checked(
        pool.inner(),
        master_key.inner(),
        unlock_state.inner(),
        &user.0.id,
        &body.current_password,
        &body.tier,
        &body.password_mode,
        body.encryption_password.as_deref(),
    )
    .await?;
    Ok(Json(
        encryption_status(pool.inner(), unlock_state.inner(), &user.0.id).await?,
    ))
}

#[post("/api/v1/auth/unlock", format = "json", data = "<body>")]
pub async fn unlock_account(
    pool: &State<DbPool>,
    master_key: &State<MasterKey>,
    unlock_state: &State<UnlockState>,
    rate_limiter: &State<RateLimiter>,
    user: SetupComplete,
    body: Json<PasswordBody>,
) -> Result<Json<EncryptionStatus>, AppError> {
    if !rate_limiter.check(
        &format!("unlock:{}", user.0.id),
        UNLOCK_ATTEMPTS,
        UNLOCK_WINDOW_SECS,
    ) {
        return Err(AppError::RateLimited);
    }
    key_service::unlock_user(
        pool.inner(),
        master_key.inner(),
        unlock_state.inner(),
        &user.0.id,
        Some(&body.password),
    )
    .await?;
    Ok(Json(
        encryption_status(pool.inner(), unlock_state.inner(), &user.0.id).await?,
    ))
}

#[post("/api/v1/auth/lock")]
pub async fn lock_account(
    pool: &State<DbPool>,
    unlock_state: &State<UnlockState>,
    user: SetupComplete,
) -> Result<Json<EncryptionStatus>, AppError> {
    key_service::lock_user(pool.inner(), unlock_state.inner(), &user.0.id).await?;
    Ok(Json(
        encryption_status(pool.inner(), unlock_state.inner(), &user.0.id).await?,
    ))
}

#[post("/api/v1/auth/password", format = "json", data = "<body>")]
pub async fn change_password(
    pool: &State<DbPool>,
    master_key: &State<MasterKey>,
    unlock_state: &State<UnlockState>,
    rate_limiter: &State<RateLimiter>,
    user: SetupComplete,
    body: Json<ChangePasswordBody>,
) -> Result<Json<Message>, AppError> {
    if !rate_limiter.check(
        &format!("unlock:{}", user.0.id),
        UNLOCK_ATTEMPTS,
        UNLOCK_WINDOW_SECS,
    ) {
        return Err(AppError::RateLimited);
    }
    key_service::change_login_password(
        pool.inner(),
        master_key.inner(),
        unlock_state.inner(),
        &user.0.id,
        &body.current_password,
        &body.new_password,
    )
    .await?;
    Ok(msg("Password changed."))
}

#[post("/api/v1/auth/encryption-password", format = "json", data = "<body>")]
pub async fn change_encryption_password(
    pool: &State<DbPool>,
    master_key: &State<MasterKey>,
    rate_limiter: &State<RateLimiter>,
    user: SetupComplete,
    body: Json<ChangePasswordBody>,
) -> Result<Json<Message>, AppError> {
    if !rate_limiter.check(
        &format!("unlock:{}", user.0.id),
        UNLOCK_ATTEMPTS,
        UNLOCK_WINDOW_SECS,
    ) {
        return Err(AppError::RateLimited);
    }
    key_service::change_encryption_password(
        pool.inner(),
        master_key.inner(),
        &user.0.id,
        &body.current_password,
        &body.new_password,
    )
    .await?;
    Ok(msg("Encryption password changed."))
}

#[get("/api/v1/spaces/<_id>/lock-state")]
pub async fn space_lock_state(
    pool: &State<DbPool>,
    unlock_state: &State<UnlockState>,
    _id: &str,
    reader: SpaceReader,
) -> Result<Json<SpaceLockStatus>, AppError> {
    let state = key_service::space_access_state(
        pool.inner(),
        unlock_state.inner(),
        &reader.space.space,
        &reader.user.id,
    )
    .await?;
    Ok(Json(SpaceLockStatus {
        encryption_mode: reader.space.space.encryption_mode.clone(),
        state: lock_state_name(state),
    }))
}

#[post("/api/v1/spaces/<_id>/unlock", format = "json", data = "<body>")]
pub async fn unlock_space(
    unlock_state: &State<UnlockState>,
    rate_limiter: &State<RateLimiter>,
    _id: &str,
    reader: SpaceReader,
    body: Json<PasswordBody>,
) -> Result<Json<Message>, AppError> {
    if !rate_limiter.check(
        &format!("space-unlock:{}:{}", reader.space.space.id, reader.user.id),
        UNLOCK_ATTEMPTS,
        UNLOCK_WINDOW_SECS,
    ) {
        return Err(AppError::RateLimited);
    }
    key_service::unlock_password_space(
        unlock_state.inner(),
        &reader.space.space,
        &reader.user.id,
        &body.password,
    )
    .await?;
    Ok(msg("Space unlocked."))
}

#[post("/api/v1/spaces/<_id>/lock")]
pub async fn lock_space(
    unlock_state: &State<UnlockState>,
    _id: &str,
    reader: SpaceReader,
) -> Json<Message> {
    if reader.space.space.encryption_mode == key_service::SPACE_PASSWORD {
        key_service::lock_password_space(
            unlock_state.inner(),
            &reader.space.space.id,
            &reader.user.id,
        );
    }
    msg("Space locked.")
}

#[put("/api/v1/spaces/<_id>/protection", format = "json", data = "<body>")]
pub async fn set_space_protection(
    pool: &State<DbPool>,
    master_key: &State<MasterKey>,
    unlock_state: &State<UnlockState>,
    _id: &str,
    admin: SpaceAdmin,
    body: Json<SpaceProtectionBody>,
) -> Result<Json<SpaceLockStatus>, AppError> {
    key_service::set_space_protection(
        pool.inner(),
        master_key.inner(),
        unlock_state.inner(),
        &admin.space.space.id,
        &admin.user.id,
        &body.mode,
        body.password.as_deref().filter(|p| !p.is_empty()),
    )
    .await?;
    Ok(Json(SpaceLockStatus {
        encryption_mode: key_service::validate_space_mode(&body.mode)?.into(),
        state: "open",
    }))
}

#[derive(Deserialize)]
pub struct IssueResetBody {
    #[serde(default)]
    pub reason: Option<String>,
}

#[derive(Deserialize)]
pub struct RedeemResetBody {
    pub username: String,
    pub code: String,
    pub new_password: String,
    #[serde(default)]
    pub new_encryption_password: Option<String>,
}

#[post("/api/v1/admin/users/<id>/reset", format = "json", data = "<body>")]
pub async fn issue_reset(
    pool: &State<DbPool>,
    admin: AdminUser,
    id: &str,
    body: Json<IssueResetBody>,
) -> Result<Json<IssuedCode>, AppError> {
    Ok(Json(
        recovery_service::issue_reset_code(pool.inner(), &admin.0.id, id, body.reason.as_deref())
            .await?,
    ))
}

#[post("/api/v1/auth/reset", format = "json", data = "<body>")]
pub async fn redeem_reset(
    pool: &State<DbPool>,
    master_key: &State<MasterKey>,
    unlock_state: &State<UnlockState>,
    rate_limiter: &State<RateLimiter>,
    client_ip: ClientIp,
    body: Json<RedeemResetBody>,
) -> Result<Json<Message>, AppError> {
    if !rate_limiter.check(&format!("reset:{}", client_ip.0), 10, 900) {
        return Err(AppError::RateLimited);
    }
    recovery_service::redeem_reset_code(
        pool.inner(),
        master_key.inner(),
        unlock_state.inner(),
        &body.username,
        &body.code,
        &body.new_password,
        body.new_encryption_password.as_deref(),
    )
    .await?;
    Ok(msg("Password reset. Sign in with your new password."))
}

#[get("/api/v1/users/me/security-notices")]
pub async fn security_notices(
    pool: &State<DbPool>,
    user: SetupComplete,
) -> Result<Json<Vec<SecurityNotice>>, AppError> {
    Ok(Json(
        recovery_service::notices_for(pool.inner(), &user.0.id, false).await?,
    ))
}

#[post("/api/v1/users/me/security-notices/<id>/ack")]
pub async fn ack_security_notice(
    pool: &State<DbPool>,
    user: SetupComplete,
    id: &str,
) -> Result<Json<Message>, AppError> {
    recovery_service::acknowledge_notice(pool.inner(), &user.0.id, id).await?;
    Ok(msg("Dismissed."))
}

pub fn routes() -> Vec<Route> {
    routes![
        get_encryption,
        put_encryption,
        unlock_account,
        lock_account,
        change_password,
        change_encryption_password,
        space_lock_state,
        unlock_space,
        lock_space,
        set_space_protection,
        issue_reset,
        redeem_reset,
        security_notices,
        ack_security_notice,
    ]
}
