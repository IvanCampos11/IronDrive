//! User-managed encryption: account tiers, unlocking, and how space keys reach
//! the people a space is shared with.
//!
//! # Account tiers (`user_keys.tier`)
//!
//! | Tier            | Private key wrapped by          | Locked when            |
//! |-----------------|---------------------------------|------------------------|
//! | `server`        | master key                      | never                  |
//! | `failsafe_user` | password (+ master-key recovery) | no session is signed in |
//! | `pure_user`     | password only                   | no session is signed in |
//!
//! With `password_mode = 'single'` the login password is that password, so
//! signing in unlocks the keys. With `'separate'` a second encryption password
//! does, on the unlock page.
//!
//! # Space protection (`spaces.encryption_mode`)
//!
//! - `server`: data key wrapped by the master key; always available.
//! - `members`: data key sealed to each member's public key
//!   (`space_key_envelopes`). Available while any member who can open it is
//!   unlocked. Members never type anything extra.
//! - `password`: data key wrapped by the space password. Every member types it.
//!
//! The server does the encryption, so "locked" protects data at rest: while
//! nobody who can open a key is signed in, the server can't read those files.

use sqlx::FromRow;
use zeroize::Zeroizing;

use crate::db::DbPool;
use crate::errors::AppError;
use crate::models::library::PersonalLibrary;
use crate::models::space::Space;
use crate::services::crypto_service::{
    aes_gcm_unwrap, aes_gcm_wrap, wrap_data_key, DataKey, MasterKey,
};
use crate::services::key_crypto::{self, UserSecret};
use crate::services::unlock_state::UnlockState;

pub const TIER_SERVER: &str = "server";
pub const TIER_FAILSAFE: &str = "failsafe_user";
pub const TIER_PURE: &str = "pure_user";
pub const MODE_SINGLE: &str = "single";
pub const MODE_SEPARATE: &str = "separate";

pub const SPACE_SERVER: &str = "server";
pub const SPACE_MEMBERS: &str = "members";
pub const SPACE_PASSWORD: &str = "password";

/// Shortest password accepted for wrapping keys (space or encryption password).
pub const MIN_KEY_PASSWORD_LEN: usize = 8;

pub fn validate_tier(tier: &str) -> Result<&'static str, AppError> {
    match tier {
        TIER_SERVER => Ok(TIER_SERVER),
        TIER_FAILSAFE => Ok(TIER_FAILSAFE),
        TIER_PURE => Ok(TIER_PURE),
        _ => Err(AppError::Validation(
            "Encryption tier must be server, failsafe_user or pure_user.".into(),
        )),
    }
}

pub fn validate_password_mode(mode: &str) -> Result<&'static str, AppError> {
    match mode {
        MODE_SINGLE => Ok(MODE_SINGLE),
        MODE_SEPARATE => Ok(MODE_SEPARATE),
        _ => Err(AppError::Validation(
            "Password mode must be single or separate.".into(),
        )),
    }
}

pub fn validate_space_mode(mode: &str) -> Result<&'static str, AppError> {
    match mode {
        SPACE_SERVER => Ok(SPACE_SERVER),
        SPACE_MEMBERS => Ok(SPACE_MEMBERS),
        SPACE_PASSWORD => Ok(SPACE_PASSWORD),
        _ => Err(AppError::Validation(
            "Space protection must be server, members or password.".into(),
        )),
    }
}

pub fn validate_key_password(password: &str) -> Result<(), AppError> {
    if password.chars().count() < MIN_KEY_PASSWORD_LEN {
        return Err(AppError::Validation(format!(
            "Use at least {MIN_KEY_PASSWORD_LEN} characters for the password."
        )));
    }
    Ok(())
}

/// A row of `user_keys`.
#[derive(Debug, Clone, FromRow)]
pub struct UserKeys {
    #[allow(dead_code)]
    pub user_id: String,
    pub tier: String,
    pub password_mode: String,
    pub public_key: Vec<u8>,
    pub wrapped_private_key: Vec<u8>,
    pub kdf_salt: Option<Vec<u8>>,
    pub recovery_private_key: Option<Vec<u8>>,
}

impl UserKeys {
    pub fn is_server(&self) -> bool {
        self.tier == TIER_SERVER
    }

    /// Signing in with the login password unlocks these keys.
    pub fn unlocks_at_login(&self) -> bool {
        !self.is_server() && self.password_mode == MODE_SINGLE
    }
}

pub async fn find_user_keys(pool: &DbPool, user_id: &str) -> Result<Option<UserKeys>, AppError> {
    Ok(sqlx::query_as::<_, UserKeys>(
        "SELECT user_id, tier, password_mode, public_key, wrapped_private_key, kdf_salt,
                recovery_private_key
         FROM user_keys WHERE user_id = ?",
    )
    .bind(user_id)
    .fetch_optional(pool)
    .await?)
}

/// The stored forms of a private key for one tier.
struct WrappedSecret {
    wrapped: Vec<u8>,
    salt: Option<Vec<u8>>,
    recovery: Option<Vec<u8>>,
}

async fn wrap_secret(
    master: &MasterKey,
    secret: &UserSecret,
    tier: &str,
    password: Option<&str>,
) -> Result<WrappedSecret, AppError> {
    if tier == TIER_SERVER {
        return Ok(WrappedSecret {
            wrapped: aes_gcm_wrap(master.as_bytes(), secret.as_bytes())?,
            salt: None,
            recovery: None,
        });
    }
    let password = password.ok_or_else(|| {
        AppError::Validation("A password is required for this encryption tier.".into())
    })?;
    let salt = key_crypto::new_salt();
    let wrapped = key_crypto::wrap_with_password(password, &salt, secret.as_bytes()).await?;
    let recovery = if tier == TIER_FAILSAFE {
        Some(aes_gcm_wrap(master.as_bytes(), secret.as_bytes())?)
    } else {
        None
    };
    Ok(WrappedSecret {
        wrapped,
        salt: Some(salt),
        recovery,
    })
}

/// Create a user's key pair (during setup). Returns the private key so the
/// caller can unlock the account straight away.
pub async fn create_user_keys(
    pool: &DbPool,
    master: &MasterKey,
    user_id: &str,
    tier: &str,
    password_mode: &str,
    password: Option<&str>,
) -> Result<UserSecret, AppError> {
    let tier = validate_tier(tier)?;
    let password_mode = validate_password_mode(password_mode)?;
    let secret = UserSecret::generate();
    let w = wrap_secret(master, &secret, tier, password).await?;
    sqlx::query(
        "INSERT INTO user_keys (user_id, tier, password_mode, public_key, wrapped_private_key,
                                kdf_salt, recovery_private_key)
         VALUES (?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(user_id)
    .bind(tier)
    .bind(password_mode)
    .bind(secret.public_key().to_vec())
    .bind(&w.wrapped)
    .bind(&w.salt)
    .bind(&w.recovery)
    .execute(pool)
    .await?;
    Ok(secret)
}

/// Unwrap a user's private key. Password tiers need `password`
/// ([`AppError::Locked`] without one, [`AppError::BadPassphrase`] if wrong).
pub async fn open_user_secret(
    master: &MasterKey,
    keys: &UserKeys,
    password: Option<&str>,
) -> Result<UserSecret, AppError> {
    if keys.is_server() {
        let raw = aes_gcm_unwrap(master.as_bytes(), &keys.wrapped_private_key)?;
        return Ok(UserSecret::from_bytes(raw));
    }
    let password = password.ok_or(AppError::Locked)?;
    let salt = keys
        .kdf_salt
        .as_deref()
        .ok_or_else(|| AppError::Internal("Password tier without a KDF salt".into()))?;
    let raw = key_crypto::unwrap_with_password(password, salt, &keys.wrapped_private_key).await?;
    Ok(UserSecret::from_bytes(*raw))
}

/// Unlock an account: load its private key, its library key and every
/// `members` space key it holds an envelope for.
pub async fn unlock_user(
    pool: &DbPool,
    master: &MasterKey,
    unlock: &UnlockState,
    user_id: &str,
    password: Option<&str>,
) -> Result<(), AppError> {
    let keys = find_user_keys(pool, user_id)
        .await?
        .ok_or(AppError::NotFound)?;
    let secret = open_user_secret(master, &keys, password).await?;
    unlock.insert_user_secret(user_id, &secret);
    load_keys_for_user(pool, unlock, user_id, &secret).await
}

/// Is this account's own key material in memory? Server-tier accounts always
/// are; accounts set up before keys existed count as unlocked too.
pub async fn is_user_unlocked(
    pool: &DbPool,
    unlock: &UnlockState,
    user_id: &str,
) -> Result<bool, AppError> {
    if unlock.is_user_unlocked(user_id) {
        return Ok(true);
    }
    Ok(match find_user_keys(pool, user_id).await? {
        Some(keys) => keys.is_server(),
        None => true,
    })
}

async fn load_keys_for_user(
    pool: &DbPool,
    unlock: &UnlockState,
    user_id: &str,
    secret: &UserSecret,
) -> Result<(), AppError> {
    if let Some(lib) = PersonalLibrary::find_by_user(pool, user_id).await? {
        if lib.encryption_mode != TIER_SERVER && !unlock.is_library_unlocked(&lib.id) {
            match key_crypto::open(secret, &lib.encrypted_data_key) {
                Ok(k) => unlock.insert_library_key(&lib.id, &DataKey::from_bytes(k.as_ref())),
                Err(e) => tracing::error!(library_id = %lib.id, error = %e,
                    "Could not open library key with the user's private key"),
            }
        }
    }

    let envelopes: Vec<(String, Vec<u8>)> = sqlx::query_as(
        "SELECT e.space_id, e.sealed_key FROM space_key_envelopes e
         JOIN spaces s ON s.id = e.space_id
         WHERE e.user_id = ? AND e.sealed_key IS NOT NULL AND s.encryption_mode = 'members'",
    )
    .bind(user_id)
    .fetch_all(pool)
    .await?;
    for (space_id, sealed) in envelopes {
        if !unlock.is_space_unlocked(&space_id) {
            match key_crypto::open(secret, &sealed) {
                Ok(k) => unlock.insert_space_key(&space_id, &DataKey::from_bytes(k.as_ref())),
                Err(e) => {
                    tracing::error!(space_id = %space_id, error = %e,
                        "Could not open space envelope");
                    continue;
                }
            }
        }
        fulfil_pending(pool, unlock, &space_id).await?;
    }
    Ok(())
}

/// Lock an account: drop its private key, its library key, and any `members`
/// space key nobody else who is unlocked can open. Password-protected spaces
/// the user opened are locked again too. Server-tier keys stay loaded.
pub async fn lock_user(pool: &DbPool, unlock: &UnlockState, user_id: &str) -> Result<(), AppError> {
    for space_id in unlock.spaces_unlocked_by(user_id) {
        if unlock.unmark_space_unlocked_by(&space_id, user_id) {
            unlock.remove_space_key(&space_id);
        }
    }

    let Some(keys) = find_user_keys(pool, user_id).await? else {
        return Ok(());
    };
    if keys.is_server() {
        return Ok(());
    }
    unlock.remove_user_secret(user_id);

    if let Some(lib) = PersonalLibrary::find_by_user(pool, user_id).await? {
        if lib.encryption_mode != TIER_SERVER {
            unlock.remove_library_key(&lib.id);
        }
    }

    let spaces: Vec<(String,)> = sqlx::query_as(
        "SELECT e.space_id FROM space_key_envelopes e
         JOIN spaces s ON s.id = e.space_id
         WHERE e.user_id = ? AND e.sealed_key IS NOT NULL AND s.encryption_mode = 'members'",
    )
    .bind(user_id)
    .fetch_all(pool)
    .await?;
    for (space_id,) in spaces {
        let holders: Vec<(String,)> = sqlx::query_as(
            "SELECT user_id FROM space_key_envelopes
             WHERE space_id = ? AND sealed_key IS NOT NULL AND user_id != ?",
        )
        .bind(&space_id)
        .bind(user_id)
        .fetch_all(pool)
        .await?;
        if !holders.iter().any(|(h,)| unlock.is_user_unlocked(h)) {
            unlock.remove_space_key(&space_id);
        }
    }
    tracing::info!(user_id = %user_id, "Account keys locked");
    Ok(())
}

/// Lock the account if it has no live sessions left (after a logout, or when
/// sessions expire).
pub async fn lock_if_no_sessions(
    pool: &DbPool,
    unlock: &UnlockState,
    user_id: &str,
) -> Result<(), AppError> {
    let (live,): (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM sessions WHERE user_id = ? AND expires_at > datetime('now')",
    )
    .bind(user_id)
    .fetch_one(pool)
    .await?;
    if live == 0 {
        lock_user(pool, unlock, user_id).await?;
    }
    Ok(())
}

/// Lock every unlocked account that no longer has a live session.
pub async fn lock_users_without_sessions(
    pool: &DbPool,
    unlock: &UnlockState,
) -> Result<(), AppError> {
    let mut users = unlock.unlocked_user_ids();
    users.extend(unlock.users_with_space_unlocks());
    users.sort();
    users.dedup();
    for user_id in users {
        lock_if_no_sessions(pool, unlock, &user_id).await?;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Boot
// ---------------------------------------------------------------------------

/// Give every set-up account from before key pairs existed a server-tier key
/// pair, matching how its library is already protected.
pub async fn ensure_keys_for_existing_users(
    pool: &DbPool,
    master: &MasterKey,
) -> Result<usize, AppError> {
    let users: Vec<(String,)> = sqlx::query_as(
        "SELECT u.id FROM users u
         WHERE u.setup_complete = 1
           AND NOT EXISTS (SELECT 1 FROM user_keys k WHERE k.user_id = u.id)",
    )
    .fetch_all(pool)
    .await?;
    for (user_id,) in &users {
        create_user_keys(pool, master, user_id, TIER_SERVER, MODE_SINGLE, None).await?;
    }
    Ok(users.len())
}

/// Unlock every server-tier account at boot. This also loads the `members`
/// spaces they belong to and seals any pending envelopes.
pub async fn unlock_server_tier_users(
    pool: &DbPool,
    master: &MasterKey,
    unlock: &UnlockState,
) -> Result<usize, AppError> {
    let users: Vec<(String,)> =
        sqlx::query_as("SELECT user_id FROM user_keys WHERE tier = 'server'")
            .fetch_all(pool)
            .await?;
    let mut n = 0;
    for (user_id,) in users {
        match unlock_user(pool, master, unlock, &user_id, None).await {
            Ok(()) => n += 1,
            Err(e) => tracing::error!(user_id = %user_id, error = %e,
                "Could not unlock server-tier account at boot"),
        }
    }
    Ok(n)
}

// ---------------------------------------------------------------------------
// Space envelopes
// ---------------------------------------------------------------------------

/// Everyone with any access to a space: owner, owner-group members, direct
/// grants and members of granted groups.
pub async fn users_with_access(pool: &DbPool, space_id: &str) -> Result<Vec<String>, AppError> {
    let rows: Vec<(String,)> = sqlx::query_as(
        "SELECT owner_id FROM spaces WHERE id = ?1 AND owner_type = 'user'
         UNION
         SELECT gm.user_id FROM spaces s
           JOIN group_members gm ON gm.group_id = s.owner_id
          WHERE s.id = ?1 AND s.owner_type = 'group'
         UNION
         SELECT grantee_id FROM space_access WHERE space_id = ?1 AND grantee_type = 'user'
         UNION
         SELECT gm.user_id FROM space_access sa
           JOIN group_members gm ON gm.group_id = sa.grantee_id
          WHERE sa.space_id = ?1 AND sa.grantee_type = 'group'",
    )
    .bind(space_id)
    .fetch_all(pool)
    .await?;
    Ok(rows.into_iter().map(|(u,)| u).collect())
}

/// Bring a space's envelopes in line with who can access it: new members get
/// one (sealed now if the key is loaded, otherwise pending) and people who
/// lost access lose theirs. Non-`members` spaces have none.
pub async fn sync_space_envelopes(
    pool: &DbPool,
    unlock: &UnlockState,
    space_id: &str,
) -> Result<(), AppError> {
    let mode: Option<(String,)> = sqlx::query_as("SELECT encryption_mode FROM spaces WHERE id = ?")
        .bind(space_id)
        .fetch_optional(pool)
        .await?;
    let Some((mode,)) = mode else {
        return Ok(());
    };
    if mode != SPACE_MEMBERS {
        sqlx::query("DELETE FROM space_key_envelopes WHERE space_id = ?")
            .bind(space_id)
            .execute(pool)
            .await?;
        return Ok(());
    }

    let members = users_with_access(pool, space_id).await?;
    let existing: Vec<(String,)> =
        sqlx::query_as("SELECT user_id FROM space_key_envelopes WHERE space_id = ?")
            .bind(space_id)
            .fetch_all(pool)
            .await?;
    for (user_id,) in &existing {
        if !members.contains(user_id) {
            sqlx::query("DELETE FROM space_key_envelopes WHERE space_id = ? AND user_id = ?")
                .bind(space_id)
                .bind(user_id)
                .execute(pool)
                .await?;
        }
    }
    for user_id in &members {
        sqlx::query(
            "INSERT OR IGNORE INTO space_key_envelopes (space_id, user_id, sealed_key)
             VALUES (?, ?, NULL)",
        )
        .bind(space_id)
        .bind(user_id)
        .execute(pool)
        .await?;
    }
    fulfil_pending(pool, unlock, space_id).await?;
    Ok(())
}

/// Spaces a group owns or has a grant on.
pub async fn spaces_of_group(pool: &DbPool, group_id: &str) -> Result<Vec<String>, AppError> {
    let rows: Vec<(String,)> = sqlx::query_as(
        "SELECT id FROM spaces WHERE owner_type = 'group' AND owner_id = ?1
         UNION
         SELECT space_id FROM space_access WHERE grantee_type = 'group' AND grantee_id = ?1",
    )
    .bind(group_id)
    .fetch_all(pool)
    .await?;
    Ok(rows.into_iter().map(|(s,)| s).collect())
}

/// Seal the space key for every pending member who has a key pair. No-op if
/// the key isn't loaded.
pub async fn fulfil_pending(
    pool: &DbPool,
    unlock: &UnlockState,
    space_id: &str,
) -> Result<usize, AppError> {
    let Some(key) = unlock.get_space_key(space_id) else {
        return Ok(0);
    };
    let pending: Vec<(String, Vec<u8>)> = sqlx::query_as(
        "SELECT e.user_id, k.public_key FROM space_key_envelopes e
         JOIN user_keys k ON k.user_id = e.user_id
         WHERE e.space_id = ? AND e.sealed_key IS NULL",
    )
    .bind(space_id)
    .fetch_all(pool)
    .await?;
    let mut sealed_count = 0;
    for (user_id, public_key) in pending {
        let sealed = key_crypto::seal(&public_key, key.as_bytes())?;
        sqlx::query(
            "UPDATE space_key_envelopes SET sealed_key = ?
             WHERE space_id = ? AND user_id = ? AND sealed_key IS NULL",
        )
        .bind(&sealed)
        .bind(space_id)
        .bind(&user_id)
        .execute(pool)
        .await?;
        sealed_count += 1;
        // A member who is unlocked right now can use the space immediately;
        // nothing else to do since the key is already in memory.
    }
    if sealed_count > 0 {
        tracing::info!(space_id = %space_id, count = sealed_count, "Sealed pending space keys");
    }
    Ok(sealed_count)
}

/// Seal pending envelopes for a user whose spaces are loaded by someone else
/// (called when they get a key pair or unlock).
pub async fn fulfil_pending_for_user(
    pool: &DbPool,
    unlock: &UnlockState,
    user_id: &str,
) -> Result<(), AppError> {
    let rows: Vec<(String,)> = sqlx::query_as(
        "SELECT space_id FROM space_key_envelopes WHERE user_id = ? AND sealed_key IS NULL",
    )
    .bind(user_id)
    .fetch_all(pool)
    .await?;
    for (space_id,) in rows {
        fulfil_pending(pool, unlock, &space_id).await?;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Space protection
// ---------------------------------------------------------------------------

/// Protection a "standard" (not password-protected) space gets: it follows
/// the creator's account tier.
pub fn standard_space_mode(creator: Option<&UserKeys>) -> &'static str {
    match creator {
        Some(k) if !k.is_server() => SPACE_MEMBERS,
        _ => SPACE_SERVER,
    }
}

/// What to store in `spaces.encrypted_data_key` / `spaces.salt` for a mode.
/// `members` stores nothing there; the envelopes hold the key.
pub async fn space_key_material(
    master: &MasterKey,
    mode: &str,
    password: Option<&str>,
    data_key: &DataKey,
) -> Result<(Vec<u8>, Option<Vec<u8>>), AppError> {
    match validate_space_mode(mode)? {
        SPACE_SERVER => Ok((wrap_data_key(master, data_key)?, None)),
        SPACE_MEMBERS => Ok((Vec::new(), None)),
        _ => {
            let password = password
                .ok_or_else(|| AppError::Validation("Choose a password for this space.".into()))?;
            validate_key_password(password)?;
            let salt = key_crypto::new_salt();
            let wrapped =
                key_crypto::wrap_with_password(password, &salt, data_key.as_bytes()).await?;
            Ok((wrapped, Some(salt)))
        }
    }
}

/// Open a password-protected space for one member.
pub async fn unlock_password_space(
    unlock: &UnlockState,
    space: &Space,
    user_id: &str,
    password: &str,
) -> Result<(), AppError> {
    if space.encryption_mode != SPACE_PASSWORD {
        return Ok(());
    }
    let salt = space
        .salt
        .as_deref()
        .ok_or_else(|| AppError::Internal("Password space without a salt".into()))?;
    let key = key_crypto::unwrap_with_password(password, salt, &space.encrypted_data_key).await?;
    if !unlock.is_space_unlocked(&space.id) {
        unlock.insert_space_key(&space.id, &DataKey::from_bytes(key.as_ref()));
    }
    unlock.mark_space_unlocked_by(&space.id, user_id);
    Ok(())
}

/// Lock a password-protected space for one member; the key leaves memory
/// once nobody has it open.
pub fn lock_password_space(unlock: &UnlockState, space_id: &str, user_id: &str) {
    if unlock.unmark_space_unlocked_by(space_id, user_id) {
        unlock.remove_space_key(space_id);
    }
}

/// Can `user_id` use the files of this space right now?
pub async fn space_access_state(
    pool: &DbPool,
    unlock: &UnlockState,
    space: &Space,
    user_id: &str,
) -> Result<SpaceLockState, AppError> {
    Ok(match space.encryption_mode.as_str() {
        SPACE_PASSWORD if !unlock.has_unlocked_space(&space.id, user_id) => {
            SpaceLockState::NeedsPassword
        }
        SPACE_MEMBERS if !unlock.is_space_unlocked(&space.id) => {
            if !is_user_unlocked(pool, unlock, user_id).await? {
                SpaceLockState::AccountLocked
            } else {
                SpaceLockState::WaitingForKey
            }
        }
        _ => SpaceLockState::Open,
    })
}

/// Why a space's files can't be used yet, from one member's point of view.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SpaceLockState {
    Open,
    /// Password-protected and this member hasn't typed the password.
    NeedsPassword,
    /// The member's own account keys are locked (e.g. after a restart).
    AccountLocked,
    /// Nobody who holds the key has been online since this member was added.
    WaitingForKey,
}

/// Change how a space's key is protected. The key must be loaded (and, for a
/// password space, unlocked by `actor_id`). Changing a space password is
/// `password` → `password` with the new one. Everyone else's unlocks of a
/// password space are dropped, so they type the new password.
pub async fn set_space_protection(
    pool: &DbPool,
    master: &MasterKey,
    unlock: &UnlockState,
    space_id: &str,
    actor_id: &str,
    new_mode: &str,
    password: Option<&str>,
) -> Result<(), AppError> {
    let new_mode = validate_space_mode(new_mode)?;
    let space = Space::find_by_id(pool, space_id)
        .await?
        .ok_or(AppError::NotFound)?;
    if space.encryption_mode == SPACE_PASSWORD && !unlock.has_unlocked_space(space_id, actor_id) {
        return Err(AppError::Locked);
    }
    let key = unlock.get_space_key(space_id).ok_or(AppError::Locked)?;
    let (blob, salt) = space_key_material(master, new_mode, password, &key).await?;

    sqlx::query(
        "UPDATE spaces SET encryption_mode = ?, encrypted_data_key = ?, salt = ?,
                verify_blob = NULL, recovery_blob = NULL
         WHERE id = ?",
    )
    .bind(new_mode)
    .bind(&blob)
    .bind(&salt)
    .bind(space_id)
    .execute(pool)
    .await?;

    unlock.clear_space_unlocks(space_id);
    if new_mode == SPACE_PASSWORD {
        unlock.mark_space_unlocked_by(space_id, actor_id);
    }
    sync_space_envelopes(pool, unlock, space_id).await?;
    tracing::info!(space_id = %space_id, from = %space.encryption_mode, to = %new_mode,
        "Space protection changed");
    Ok(())
}

// ---------------------------------------------------------------------------
// Account tier changes, password changes, recovery
// ---------------------------------------------------------------------------

/// Switch an unlocked account to another tier / password mode. `password` is
/// the one that will unlock the keys: the login password for `single`, the
/// new encryption password for `separate`. Ignored for `server`.
pub async fn change_tier(
    pool: &DbPool,
    master: &MasterKey,
    unlock: &UnlockState,
    user_id: &str,
    tier: &str,
    password_mode: &str,
    password: Option<&str>,
) -> Result<(), AppError> {
    let tier = validate_tier(tier)?;
    let password_mode = if tier == TIER_SERVER {
        MODE_SINGLE
    } else {
        validate_password_mode(password_mode)?
    };
    let keys = find_user_keys(pool, user_id)
        .await?
        .ok_or(AppError::NotFound)?;
    let secret = match unlock.get_user_secret(user_id) {
        Some(s) => s,
        None if keys.is_server() => open_user_secret(master, &keys, None).await?,
        None => return Err(AppError::Locked),
    };
    let lib = PersonalLibrary::find_by_user(pool, user_id)
        .await?
        .ok_or(AppError::NotFound)?;
    let lib_key = unlock.get_library_key(&lib.id).ok_or(AppError::Locked)?;

    let w = wrap_secret(master, &secret, tier, password).await?;
    let lib_blob = if tier == TIER_SERVER {
        wrap_data_key(master, &lib_key)?
    } else {
        key_crypto::seal(&keys.public_key, lib_key.as_bytes())?
    };

    let mut tx = pool.begin().await?;
    sqlx::query(
        "UPDATE user_keys SET tier = ?, password_mode = ?, wrapped_private_key = ?, kdf_salt = ?,
                recovery_private_key = ?, updated_at = datetime('now')
         WHERE user_id = ?",
    )
    .bind(tier)
    .bind(password_mode)
    .bind(&w.wrapped)
    .bind(&w.salt)
    .bind(&w.recovery)
    .bind(user_id)
    .execute(&mut *tx)
    .await?;
    sqlx::query(
        "UPDATE personal_libraries SET encryption_mode = ?, encrypted_data_key = ?,
                salt = NULL, verify_blob = NULL, recovery_blob = NULL
         WHERE id = ?",
    )
    .bind(tier)
    .bind(&lib_blob)
    .bind(&lib.id)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;

    // Keep the account usable for the rest of this session.
    unlock.insert_user_secret(user_id, &secret);
    tracing::info!(user_id = %user_id, from = %keys.tier, to = %tier, mode = %password_mode,
        "Encryption tier changed");
    Ok(())
}

async fn store_password_wrap(
    pool: &DbPool,
    user_id: &str,
    secret: &UserSecret,
    password: &str,
) -> Result<(), AppError> {
    let salt = key_crypto::new_salt();
    let wrapped = key_crypto::wrap_with_password(password, &salt, secret.as_bytes()).await?;
    sqlx::query(
        "UPDATE user_keys SET wrapped_private_key = ?, kdf_salt = ?, updated_at = datetime('now')
         WHERE user_id = ?",
    )
    .bind(&wrapped)
    .bind(&salt)
    .bind(user_id)
    .execute(pool)
    .await?;
    Ok(())
}

/// The private key re-wrapped under `new_password`, from the master-key
/// recovery copy. Returns `(wrapped, salt)`, or
/// [`AppError::RecoveryNotAvailable`] for anything but `failsafe_user`.
pub async fn recovered_wrap(
    master: &MasterKey,
    keys: &UserKeys,
    new_password: &str,
) -> Result<(Vec<u8>, Vec<u8>), AppError> {
    if keys.tier != TIER_FAILSAFE {
        return Err(AppError::RecoveryNotAvailable);
    }
    let blob = keys
        .recovery_private_key
        .as_deref()
        .ok_or(AppError::RecoveryNotAvailable)?;
    let raw = Zeroizing::new(aes_gcm_unwrap(master.as_bytes(), blob)?);
    let secret = UserSecret::from_bytes(*raw);
    let salt = key_crypto::new_salt();
    let wrapped = key_crypto::wrap_with_password(new_password, &salt, secret.as_bytes()).await?;
    Ok((wrapped, salt))
}

/// Re-wrap a failsafe account's private key from its master-key recovery copy.
#[cfg(test)]
pub async fn recover_with_master_key(
    pool: &DbPool,
    master: &MasterKey,
    user_id: &str,
    new_password: &str,
) -> Result<(), AppError> {
    let keys = find_user_keys(pool, user_id)
        .await?
        .ok_or(AppError::NotFound)?;
    let (wrapped, salt) = recovered_wrap(master, &keys, new_password).await?;
    sqlx::query("UPDATE user_keys SET wrapped_private_key = ?, kdf_salt = ? WHERE user_id = ?")
        .bind(&wrapped)
        .bind(&salt)
        .bind(user_id)
        .execute(pool)
        .await?;
    Ok(())
}

/// After a successful sign-in: unlock `single`-mode accounts with the login
/// password. Failures are logged, not returned; the account just stays locked
/// and the unlock page takes over.
pub async fn unlock_after_login(
    pool: &DbPool,
    master: &MasterKey,
    unlock: &UnlockState,
    user_id: &str,
    login_password: &str,
) {
    match find_user_keys(pool, user_id).await {
        Ok(Some(keys)) if keys.unlocks_at_login() && !unlock.is_user_unlocked(user_id) => {
            if let Err(e) = unlock_user(pool, master, unlock, user_id, Some(login_password)).await {
                tracing::warn!(user_id = %user_id, error = %e,
                    "Sign-in succeeded but the account keys did not unlock");
            }
        }
        Ok(_) => {}
        Err(e) => tracing::error!(user_id = %user_id, error = %e, "Could not load account keys"),
    }
}

/// [`sync_space_envelopes`] after an access change that already committed:
/// failures are logged (opening the space re-syncs) rather than failing the
/// request.
pub async fn resync_space(pool: &DbPool, unlock: &UnlockState, space_id: &str) {
    if let Err(e) = sync_space_envelopes(pool, unlock, space_id).await {
        tracing::error!(space_id = %space_id, error = %e, "Failed to sync space key envelopes");
    }
}

/// Re-sync the given spaces (e.g. those a group touched before it changed).
pub async fn resync_spaces(pool: &DbPool, unlock: &UnlockState, space_ids: &[String]) {
    for id in space_ids {
        resync_space(pool, unlock, id).await;
    }
}

// ---------------------------------------------------------------------------
// Account operations that touch both the login password and the keys
// ---------------------------------------------------------------------------

/// Change the login password. In `single` mode on a password tier, the keys
/// are re-wrapped under the new password in the same transaction, so the two
/// can't drift apart.
pub async fn change_login_password(
    pool: &DbPool,
    master: &MasterKey,
    unlock: &UnlockState,
    user_id: &str,
    current: &str,
    new_password: &str,
) -> Result<(), AppError> {
    crate::services::auth_service::verify_user_password(pool, user_id, current).await?;
    let new_hash = crate::services::auth_service::hash_new_password(new_password).await?;

    let rewrap = match find_user_keys(pool, user_id).await? {
        Some(keys) if keys.unlocks_at_login() => {
            let secret = match unlock.get_user_secret(user_id) {
                Some(s) => s,
                None => open_user_secret(master, &keys, Some(current)).await?,
            };
            let salt = key_crypto::new_salt();
            let wrapped =
                key_crypto::wrap_with_password(new_password, &salt, secret.as_bytes()).await?;
            Some((wrapped, salt))
        }
        _ => None,
    };

    let mut tx = pool.begin().await?;
    sqlx::query("UPDATE users SET password_hash = ?, updated_at = datetime('now') WHERE id = ?")
        .bind(&new_hash)
        .bind(user_id)
        .execute(&mut *tx)
        .await?;
    if let Some((wrapped, salt)) = &rewrap {
        sqlx::query(
            "UPDATE user_keys SET wrapped_private_key = ?, kdf_salt = ?, updated_at = datetime('now')
             WHERE user_id = ?",
        )
        .bind(wrapped)
        .bind(salt)
        .bind(user_id)
        .execute(&mut *tx)
        .await?;
    }
    tx.commit().await?;
    tracing::info!(user_id = %user_id, keys_rewrapped = rewrap.is_some(), "Login password changed");
    Ok(())
}

/// Change the separate encryption password (`separate` mode only).
pub async fn change_encryption_password(
    pool: &DbPool,
    master: &MasterKey,
    user_id: &str,
    current: &str,
    new_password: &str,
) -> Result<(), AppError> {
    let keys = find_user_keys(pool, user_id)
        .await?
        .ok_or(AppError::NotFound)?;
    if keys.is_server() || keys.password_mode != MODE_SEPARATE {
        return Err(AppError::Validation(
            "Your account doesn't use a separate encryption password.".into(),
        ));
    }
    validate_key_password(new_password)?;
    let secret = open_user_secret(master, &keys, Some(current)).await?;
    store_password_wrap(pool, user_id, &secret, new_password).await?;
    tracing::info!(user_id = %user_id, "Encryption password changed");
    Ok(())
}

/// Switch tiers after re-checking the login password. For `separate` mode,
/// `encryption_password` is the new encryption password; for `single` the
/// login password itself wraps the keys.
#[allow(clippy::too_many_arguments)]
pub async fn change_tier_checked(
    pool: &DbPool,
    master: &MasterKey,
    unlock: &UnlockState,
    user_id: &str,
    login_password: &str,
    tier: &str,
    password_mode: &str,
    encryption_password: Option<&str>,
) -> Result<(), AppError> {
    if validate_tier(tier)? == TIER_SERVER {
        // key_password_for doesn't need the password for this tier, but a
        // tier change always re-checks it.
        crate::services::auth_service::verify_user_password(pool, user_id, login_password).await?;
    }
    let wrap_password = key_password_for(
        pool,
        user_id,
        tier,
        password_mode,
        login_password,
        encryption_password,
    )
    .await?;
    change_tier(
        pool,
        master,
        unlock,
        user_id,
        tier,
        password_mode,
        wrap_password.as_deref(),
    )
    .await
}

/// Which password will wrap the keys for a tier choice, after checking the
/// login password. `None` for server tier. In `single` mode it's the login
/// password; in `separate` mode the (different) encryption password.
pub async fn key_password_for(
    pool: &DbPool,
    user_id: &str,
    tier: &str,
    password_mode: &str,
    login_password: &str,
    encryption_password: Option<&str>,
) -> Result<Option<String>, AppError> {
    let tier = validate_tier(tier)?;
    if tier == TIER_SERVER {
        return Ok(None);
    }
    crate::services::auth_service::verify_user_password(pool, user_id, login_password).await?;
    if validate_password_mode(password_mode)? == MODE_SINGLE {
        return Ok(Some(login_password.to_owned()));
    }
    let p = encryption_password
        .filter(|p| !p.is_empty())
        .ok_or_else(|| AppError::Validation("Choose an encryption password.".into()))?;
    validate_key_password(p)?;
    if p == login_password {
        return Err(AppError::Validation(
            "Your encryption password must be different from your login password.".into(),
        ));
    }
    Ok(Some(p.to_owned()))
}
