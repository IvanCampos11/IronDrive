//! Admin-issued password resets and failsafe key recovery.
//!
//! An admin issues a one-time reset code for an account (shown once, valid
//! 24 hours) and passes it to the person out of band. The person redeems it on
//! the reset page with a new password. What happens to their keys depends on
//! their tier:
//!
//! | Tier / mode              | Reset does                                       |
//! |--------------------------|--------------------------------------------------|
//! | `server`                 | new login password                               |
//! | `failsafe_user` single   | new login password; keys recovered under it      |
//! | `failsafe_user` separate | new login + new encryption password (recovered)  |
//! | `pure_user` separate     | new login password; keys untouched               |
//! | `pure_user` single       | refused: the keys are locked by that password    |
//!
//! Every redeemed reset is written to `recovery_audit_log` (append-only) and
//! shown to the person as a security notice until they dismiss it. The admin
//! never learns the new password; the code only lets the holder choose one.

use chrono::{Duration, Utc};
use rand::Rng;
use serde::Serialize;
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::db::DbPool;
use crate::errors::AppError;
use crate::models::user::User;
use crate::services::auth_service;
use crate::services::crypto_service::MasterKey;
use crate::services::key_service::{self, MODE_SEPARATE, MODE_SINGLE, TIER_FAILSAFE, TIER_PURE};
use crate::services::unlock_state::UnlockState;

const CODE_TTL_HOURS: i64 = 24;
/// Crockford-style alphabet: no 0/O, 1/I/L confusion.
const CODE_ALPHABET: &[u8] = b"ABCDEFGHJKMNPQRSTVWXYZ23456789";
const CODE_GROUPS: usize = 4;
const CODE_GROUP_LEN: usize = 4;

/// What redeeming a reset code will do, so the admin can tell the person.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ResetKind {
    /// Only the login password changes.
    Password,
    /// Login password changes and the encryption keys are recovered.
    KeyRecovery,
    /// Login password changes; encryption keys keep their own password.
    PasswordOnly,
}

#[derive(Debug, Clone, Serialize)]
pub struct IssuedCode {
    pub code: String,
    pub expires_at: String,
    pub kind: ResetKind,
    /// The person must also choose a new encryption password.
    pub needs_encryption_password: bool,
}

fn normalize_code(code: &str) -> String {
    code.chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .map(|c| c.to_ascii_uppercase())
        .collect()
}

fn hash_code(code: &str) -> String {
    hex::encode(Sha256::digest(normalize_code(code).as_bytes()))
}

fn generate_code() -> String {
    let mut rng = rand::thread_rng();
    (0..CODE_GROUPS)
        .map(|_| {
            (0..CODE_GROUP_LEN)
                .map(|_| CODE_ALPHABET[rng.gen_range(0..CODE_ALPHABET.len())] as char)
                .collect::<String>()
        })
        .collect::<Vec<_>>()
        .join("-")
}

/// How a reset would treat this account's keys.
pub async fn reset_kind(pool: &DbPool, user_id: &str) -> Result<(ResetKind, bool), AppError> {
    Ok(match key_service::find_user_keys(pool, user_id).await? {
        None => (ResetKind::Password, false),
        Some(k) if k.is_server() => (ResetKind::Password, false),
        Some(k) if k.tier == TIER_FAILSAFE => {
            (ResetKind::KeyRecovery, k.password_mode == MODE_SEPARATE)
        }
        Some(k) if k.tier == TIER_PURE && k.password_mode == MODE_SEPARATE => {
            (ResetKind::PasswordOnly, false)
        }
        Some(_) => return Err(AppError::RecoveryNotAvailable),
    })
}

/// Issue a reset code for `target_user_id`. Replaces any unused code.
pub async fn issue_reset_code(
    pool: &DbPool,
    admin_id: &str,
    target_user_id: &str,
    reason: Option<&str>,
) -> Result<IssuedCode, AppError> {
    User::find_by_id(pool, target_user_id)
        .await?
        .ok_or(AppError::NotFound)?;
    let (kind, needs_encryption_password) = reset_kind(pool, target_user_id).await?;
    let reason = reason.map(str::trim).filter(|r| !r.is_empty());
    if reason.is_some_and(|r| r.chars().count() > 500) {
        return Err(AppError::Validation(
            "Keep the reason under 500 characters.".into(),
        ));
    }

    let code = generate_code();
    let expires_at = (Utc::now() + Duration::hours(CODE_TTL_HOURS))
        .format("%Y-%m-%d %H:%M:%S")
        .to_string();

    let mut tx = pool.begin().await?;
    sqlx::query("DELETE FROM password_resets WHERE user_id = ? AND used_at IS NULL")
        .bind(target_user_id)
        .execute(&mut *tx)
        .await?;
    sqlx::query(
        "INSERT INTO password_resets (id, user_id, code_hash, issued_by, reason, expires_at)
         VALUES (?, ?, ?, ?, ?, ?)",
    )
    .bind(Uuid::new_v4().to_string())
    .bind(target_user_id)
    .bind(hash_code(&code))
    .bind(admin_id)
    .bind(reason)
    .bind(&expires_at)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;

    tracing::info!(admin_id = %admin_id, user_id = %target_user_id, kind = ?kind,
        "Password reset code issued");
    Ok(IssuedCode {
        code,
        expires_at,
        kind,
        needs_encryption_password,
    })
}

/// Redeem a reset code. A wrong username or code, or an expired or used one,
/// is the same [`AppError::BadPassphrase`] so the page can't be used to probe
/// accounts. Signs the account out everywhere.
pub async fn redeem_reset_code(
    pool: &DbPool,
    master: &MasterKey,
    unlock: &UnlockState,
    username: &str,
    code: &str,
    new_password: &str,
    new_encryption_password: Option<&str>,
) -> Result<(), AppError> {
    let user = User::find_by_username(pool, username.trim())
        .await?
        .ok_or(AppError::BadPassphrase)?;
    let row: Option<(String, String, Option<String>)> = sqlx::query_as(
        "SELECT id, issued_by, reason FROM password_resets
         WHERE user_id = ? AND code_hash = ? AND used_at IS NULL
           AND expires_at > datetime('now')",
    )
    .bind(&user.id)
    .bind(hash_code(code))
    .fetch_optional(pool)
    .await?;
    let (reset_id, issued_by, reason) = row.ok_or(AppError::BadPassphrase)?;

    let new_hash = auth_service::hash_new_password(new_password).await?;
    let (kind, _) = reset_kind(pool, &user.id).await?;
    let keys = key_service::find_user_keys(pool, &user.id).await?;

    // New wrap for recovered keys: under the login password (single mode) or
    // a new encryption password (separate mode).
    let rewrap = match (&keys, kind) {
        (Some(k), ResetKind::KeyRecovery) => {
            let wrap_password = if k.password_mode == MODE_SINGLE {
                new_password.to_owned()
            } else {
                let p = new_encryption_password
                    .filter(|p| !p.is_empty())
                    .ok_or_else(|| {
                        AppError::Validation("Choose a new encryption password too.".into())
                    })?;
                key_service::validate_key_password(p)?;
                if p == new_password {
                    return Err(AppError::Validation(
                        "Your encryption password must be different from your login password."
                            .into(),
                    ));
                }
                p.to_owned()
            };
            Some(key_service::recovered_wrap(master, k, &wrap_password).await?)
        }
        _ => None,
    };

    let mut tx = pool.begin().await?;
    let used = sqlx::query(
        "UPDATE password_resets SET used_at = datetime('now') WHERE id = ? AND used_at IS NULL",
    )
    .bind(&reset_id)
    .execute(&mut *tx)
    .await?;
    if used.rows_affected() != 1 {
        return Err(AppError::BadPassphrase);
    }
    sqlx::query("UPDATE users SET password_hash = ?, updated_at = datetime('now') WHERE id = ?")
        .bind(&new_hash)
        .bind(&user.id)
        .execute(&mut *tx)
        .await?;
    if let Some((wrapped, salt)) = &rewrap {
        sqlx::query(
            "UPDATE user_keys SET wrapped_private_key = ?, kdf_salt = ?, updated_at = datetime('now')
             WHERE user_id = ?",
        )
        .bind(wrapped)
        .bind(salt)
        .bind(&user.id)
        .execute(&mut *tx)
        .await?;
    }
    sqlx::query(
        "INSERT INTO recovery_audit_log (id, target_type, target_id, target_user_id, recovered_by, reason)
         VALUES (?, ?, ?, ?, ?, ?)",
    )
    .bind(Uuid::new_v4().to_string())
    .bind(if rewrap.is_some() { "keys" } else { "password" })
    .bind(&user.id)
    .bind(&user.id)
    .bind(&issued_by)
    .bind(&reason)
    .execute(&mut *tx)
    .await?;
    sqlx::query("DELETE FROM sessions WHERE user_id = ?")
        .bind(&user.id)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;

    key_service::lock_user(pool, unlock, &user.id).await?;
    tracing::warn!(user_id = %user.id, issued_by = %issued_by, keys_recovered = rewrap.is_some(),
        "Password reset redeemed");
    Ok(())
}

/// A reset as the account owner sees it.
#[derive(Debug, Clone, Serialize, sqlx::FromRow)]
pub struct SecurityNotice {
    pub id: String,
    /// `keys` (encryption keys were recovered) or `password`.
    pub target_type: String,
    pub admin_username: String,
    pub reason: Option<String>,
    pub acknowledged: bool,
    pub created_at: String,
}

/// Resets of this account, newest first. `only_open` limits to undismissed.
pub async fn notices_for(
    pool: &DbPool,
    user_id: &str,
    only_open: bool,
) -> Result<Vec<SecurityNotice>, AppError> {
    let sql = format!(
        "SELECT l.id, l.target_type, COALESCE(u.username, 'an administrator') AS admin_username,
                l.reason, l.acknowledged, l.created_at
         FROM recovery_audit_log l LEFT JOIN users u ON u.id = l.recovered_by
         WHERE l.target_user_id = ? {}
         ORDER BY l.created_at DESC",
        if only_open {
            "AND l.acknowledged = 0"
        } else {
            ""
        }
    );
    Ok(sqlx::query_as::<_, SecurityNotice>(&sql)
        .bind(user_id)
        .fetch_all(pool)
        .await?)
}

/// Mark a notice as seen. Only its owner can.
pub async fn acknowledge_notice(pool: &DbPool, user_id: &str, id: &str) -> Result<(), AppError> {
    let done = sqlx::query(
        "UPDATE recovery_audit_log SET acknowledged = 1 WHERE id = ? AND target_user_id = ?",
    )
    .bind(id)
    .bind(user_id)
    .execute(pool)
    .await?;
    if done.rows_affected() == 0 {
        return Err(AppError::NotFound);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn codes_are_grouped_and_unambiguous() {
        let c = generate_code();
        assert_eq!(c.len(), CODE_GROUPS * CODE_GROUP_LEN + CODE_GROUPS - 1);
        assert!(c
            .chars()
            .all(|ch| ch == '-' || CODE_ALPHABET.contains(&(ch as u8))));
        assert_ne!(generate_code(), c);
    }

    #[test]
    fn code_matching_ignores_case_spaces_and_dashes() {
        assert_eq!(hash_code("abcd-efgh"), hash_code(" ABCD EFGH "));
        assert_ne!(hash_code("ABCD-EFGH"), hash_code("ABCD-EFGJ"));
    }
}
