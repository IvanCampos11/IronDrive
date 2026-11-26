//! Key material for user-managed encryption.
//!
//! - Every user has an X25519 key pair. The private half is wrapped by the
//!   master key (`server` tier) or by a key derived from a password
//!   (`failsafe_user` / `pure_user`).
//! - Library and space data keys are *sealed* to a user's public key. Sealing
//!   only needs the public key, so a space can be shared with anyone without
//!   them being online.
//! - Password-protected spaces wrap their data key with a key derived from the
//!   space password instead.
//!
//! Wrapped and sealed blobs are AES-256-GCM, so a wrong password or key shows
//! up as an authentication failure, never as garbage key bytes.

use argon2::{Algorithm, Argon2, Params, Version};
use hkdf::Hkdf;
use rand::rngs::OsRng;
use rand::RngCore;
use sha2::Sha256;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::errors::AppError;
use crate::services::crypto_service::{aes_gcm_unwrap, aes_gcm_wrap};

pub const KEY_LEN: usize = 32;
const SEAL_INFO: &[u8] = b"irondrive/seal/v1";
const WRAPPED_LEN: usize = 12 + KEY_LEN + 16;
const SEALED_LEN: usize = KEY_LEN + WRAPPED_LEN;

/// First byte of every KDF salt: which Argon2 parameters it was made with.
const KDF_V1: u8 = 1;
const SALT_RANDOM_LEN: usize = 16;

/// Argon2id parameters for password-derived keys (v1). Tests use tiny ones so
/// debug builds stay fast; the format is the same.
#[cfg(not(test))]
const KDF_V1_PARAMS: (u32, u32, u32) = (64 * 1024, 3, 1);
#[cfg(test)]
const KDF_V1_PARAMS: (u32, u32, u32) = (256, 1, 1);

/// A user's X25519 private key. Zeroized on drop.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct UserSecret([u8; KEY_LEN]);

impl UserSecret {
    pub fn generate() -> Self {
        let mut bytes = [0u8; KEY_LEN];
        OsRng.fill_bytes(&mut bytes);
        Self(bytes)
    }

    pub fn from_bytes(bytes: [u8; KEY_LEN]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; KEY_LEN] {
        &self.0
    }

    pub fn public_key(&self) -> [u8; KEY_LEN] {
        PublicKey::from(&StaticSecret::from(self.0)).to_bytes()
    }
}

fn seal_kek(shared: &[u8; KEY_LEN], eph_pub: &[u8], recipient: &[u8]) -> Zeroizing<[u8; KEY_LEN]> {
    let mut salt = [0u8; 2 * KEY_LEN];
    salt[..KEY_LEN].copy_from_slice(eph_pub);
    salt[KEY_LEN..].copy_from_slice(recipient);
    let hk = Hkdf::<Sha256>::new(Some(&salt), shared);
    let mut kek = Zeroizing::new([0u8; KEY_LEN]);
    hk.expand(SEAL_INFO, kek.as_mut())
        .expect("32 bytes is a valid HKDF-SHA256 output length");
    kek
}

fn public_key_from(bytes: &[u8]) -> Result<PublicKey, AppError> {
    let arr: [u8; KEY_LEN] = bytes
        .try_into()
        .map_err(|_| AppError::Internal("Public key has the wrong length".into()))?;
    Ok(PublicKey::from(arr))
}

/// Seal a 32-byte key to a recipient's public key.
/// Output: ephemeral public key (32) ‖ nonce ‖ ciphertext ‖ tag.
pub fn seal(recipient_public: &[u8], key: &[u8; KEY_LEN]) -> Result<Vec<u8>, AppError> {
    let recipient = public_key_from(recipient_public)?;
    let eph = StaticSecret::random_from_rng(OsRng);
    let eph_pub = PublicKey::from(&eph);
    let shared = eph.diffie_hellman(&recipient);
    if !shared.was_contributory() {
        return Err(AppError::Internal("Recipient public key is invalid".into()));
    }
    let kek = seal_kek(shared.as_bytes(), eph_pub.as_bytes(), recipient.as_bytes());
    let wrapped = aes_gcm_wrap(&kek, key)?;
    let mut out = Vec::with_capacity(SEALED_LEN);
    out.extend_from_slice(eph_pub.as_bytes());
    out.extend_from_slice(&wrapped);
    Ok(out)
}

/// Open a key sealed with [`seal`].
pub fn open(secret: &UserSecret, sealed: &[u8]) -> Result<Zeroizing<[u8; KEY_LEN]>, AppError> {
    if sealed.len() != SEALED_LEN {
        return Err(AppError::Internal("Sealed key has the wrong length".into()));
    }
    let (eph_bytes, wrapped) = sealed.split_at(KEY_LEN);
    let eph_pub = public_key_from(eph_bytes)?;
    let own = StaticSecret::from(*secret.as_bytes());
    let shared = own.diffie_hellman(&eph_pub);
    if !shared.was_contributory() {
        return Err(AppError::Internal("Sealed key is invalid".into()));
    }
    let own_pub = PublicKey::from(&own);
    let kek = seal_kek(shared.as_bytes(), eph_pub.as_bytes(), own_pub.as_bytes());
    Ok(Zeroizing::new(aes_gcm_unwrap(&kek, wrapped)?))
}

/// A fresh salt for [`wrap_with_password`], tagged with the KDF version.
pub fn new_salt() -> Vec<u8> {
    let mut salt = vec![KDF_V1; 1 + SALT_RANDOM_LEN];
    OsRng.fill_bytes(&mut salt[1..]);
    salt
}

/// Argon2id(password, salt) → 32-byte key. CPU- and memory-heavy: call from
/// `spawn_blocking` (or use the async helpers below).
fn derive_password_key(password: &str, salt: &[u8]) -> Result<Zeroizing<[u8; KEY_LEN]>, AppError> {
    let (version, random) = salt
        .split_first()
        .ok_or_else(|| AppError::Internal("Empty KDF salt".into()))?;
    let (m, t, p) = match *version {
        KDF_V1 => KDF_V1_PARAMS,
        v => return Err(AppError::Internal(format!("Unknown KDF version {v}"))),
    };
    let params = Params::new(m, t, p, Some(KEY_LEN))
        .map_err(|e| AppError::Internal(format!("Bad KDF params: {e}")))?;
    let mut out = Zeroizing::new([0u8; KEY_LEN]);
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
        .hash_password_into(password.as_bytes(), random, out.as_mut())
        .map_err(|e| AppError::Internal(format!("Key derivation failed: {e}")))?;
    Ok(out)
}

/// Wrap `key` with a key derived from `password` and `salt`.
pub async fn wrap_with_password(
    password: &str,
    salt: &[u8],
    key: &[u8; KEY_LEN],
) -> Result<Vec<u8>, AppError> {
    let password = Zeroizing::new(password.to_owned());
    let salt = salt.to_vec();
    let key = Zeroizing::new(*key);
    tokio::task::spawn_blocking(move || {
        let kek = derive_password_key(&password, &salt)?;
        aes_gcm_wrap(&kek, &key)
    })
    .await
    .map_err(|e| AppError::Internal(format!("Key derivation task failed: {e}")))?
}

/// Unwrap a key made by [`wrap_with_password`]. A wrong password is
/// [`AppError::BadPassphrase`].
pub async fn unwrap_with_password(
    password: &str,
    salt: &[u8],
    wrapped: &[u8],
) -> Result<Zeroizing<[u8; KEY_LEN]>, AppError> {
    if wrapped.len() != WRAPPED_LEN {
        return Err(AppError::Internal(
            "Wrapped key has the wrong length".into(),
        ));
    }
    let password = Zeroizing::new(password.to_owned());
    let salt = salt.to_vec();
    let wrapped = wrapped.to_vec();
    tokio::task::spawn_blocking(move || {
        let kek = derive_password_key(&password, &salt)?;
        aes_gcm_unwrap(&kek, &wrapped)
            .map(Zeroizing::new)
            .map_err(|_| AppError::BadPassphrase)
    })
    .await
    .map_err(|e| AppError::Internal(format!("Key derivation task failed: {e}")))?
}

#[cfg(test)]
mod tests {
    use super::*;

    fn random_key() -> [u8; KEY_LEN] {
        let mut k = [0u8; KEY_LEN];
        OsRng.fill_bytes(&mut k);
        k
    }

    #[test]
    fn seal_round_trips_and_is_randomised() {
        let alice = UserSecret::generate();
        let key = random_key();
        let a = seal(&alice.public_key(), &key).unwrap();
        let b = seal(&alice.public_key(), &key).unwrap();
        assert_eq!(a.len(), SEALED_LEN);
        assert_ne!(a, b, "each seal uses a fresh ephemeral key");
        assert_eq!(*open(&alice, &a).unwrap(), key);
        assert_eq!(*open(&alice, &b).unwrap(), key);
    }

    #[test]
    fn sealed_key_cannot_be_opened_by_someone_else() {
        let alice = UserSecret::generate();
        let bob = UserSecret::generate();
        let sealed = seal(&alice.public_key(), &random_key()).unwrap();
        assert!(open(&bob, &sealed).is_err());
    }

    #[test]
    fn tampered_seal_is_rejected() {
        let alice = UserSecret::generate();
        let mut sealed = seal(&alice.public_key(), &random_key()).unwrap();
        for i in [0, 40, SEALED_LEN - 1] {
            sealed[i] ^= 1;
            assert!(open(&alice, &sealed).is_err(), "flip at byte {i}");
            sealed[i] ^= 1;
        }
        assert!(open(&alice, &sealed[1..]).is_err());
    }

    #[test]
    fn low_order_public_key_is_refused() {
        assert!(seal(&[0u8; KEY_LEN], &random_key()).is_err());
    }

    #[tokio::test]
    async fn password_wrap_round_trips() {
        let salt = new_salt();
        let key = random_key();
        let wrapped = wrap_with_password("hunter2 but longer", &salt, &key)
            .await
            .unwrap();
        let back = unwrap_with_password("hunter2 but longer", &salt, &wrapped)
            .await
            .unwrap();
        assert_eq!(*back, key);
    }

    #[tokio::test]
    async fn wrong_password_or_salt_is_bad_passphrase() {
        let salt = new_salt();
        let wrapped = wrap_with_password("right", &salt, &random_key())
            .await
            .unwrap();
        assert!(matches!(
            unwrap_with_password("wrong", &salt, &wrapped).await,
            Err(AppError::BadPassphrase)
        ));
        assert!(matches!(
            unwrap_with_password("right", &new_salt(), &wrapped).await,
            Err(AppError::BadPassphrase)
        ));
    }

    #[test]
    fn unknown_kdf_version_is_an_error() {
        let mut salt = new_salt();
        salt[0] = 99;
        assert!(derive_password_key("x", &salt).is_err());
    }
}
