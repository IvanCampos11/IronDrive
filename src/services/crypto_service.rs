use aes_gcm::aead::{Aead, KeyInit, OsRng};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use base64::Engine;
use rand::RngCore;
use sqlx::Row;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::db::DbPool;
use crate::errors::AppError;

const MASTER_KEY_DB_KEY: &str = "master_key_encrypted";
const NONCE_LEN: usize = 12;
const KEY_LEN: usize = 32;
const TAG_LEN: usize = 16;
const WRAPPED_BLOB_LEN: usize = NONCE_LEN + KEY_LEN + TAG_LEN;

/// Decrypted master key, held in Rocket managed state for the server's lifetime.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct MasterKey {
    key: [u8; KEY_LEN],
}

impl MasterKey {
    pub fn as_bytes(&self) -> &[u8; KEY_LEN] {
        &self.key
    }
}

/// First boot: generate master key, encrypt with IRONDRIVE_SECRET_KEY, store in DB.
/// Subsequent boots: load from DB and decrypt.
pub async fn bootstrap_master_key(
    pool: &DbPool,
    secret_key_b64: &str,
) -> Result<MasterKey, AppError> {
    let mut wrapping_key = decode_secret_key(secret_key_b64)?;

    let result = match load_encrypted_master_key(pool).await? {
        Some(blob) => {
            tracing::info!("Master key found in database — decrypting");
            unwrap_master_key(&wrapping_key, &blob)
        }
        None => {
            tracing::info!("No master key in database — generating a new one");
            let key = generate_master_key();
            let blob = wrap_master_key(&wrapping_key, &key)?;
            store_encrypted_master_key(pool, &blob).await?;
            tracing::info!("Master key generated and stored");
            Ok(key)
        }
    };

    wrapping_key.zeroize();
    result
}

/// Decode base64 IRONDRIVE_SECRET_KEY into a 32-byte AES key.
fn decode_secret_key(secret_key_b64: &str) -> Result<[u8; KEY_LEN], AppError> {
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(secret_key_b64.trim())
        .map_err(|e| {
            AppError::Internal(format!("IRONDRIVE_SECRET_KEY is not valid base64: {e}"))
        })?;

    let key: [u8; KEY_LEN] = bytes.try_into().map_err(|v: Vec<u8>| {
        AppError::Internal(format!(
            "IRONDRIVE_SECRET_KEY must decode to exactly {KEY_LEN} bytes, got {}",
            v.len()
        ))
    })?;

    Ok(key)
}

fn generate_master_key() -> MasterKey {
    let mut key = [0u8; KEY_LEN];
    OsRng.fill_bytes(&mut key);
    MasterKey { key }
}

/// Encrypt master key with wrapping key. Returns nonce ‖ ciphertext ‖ tag.
fn wrap_master_key(
    wrapping_key: &[u8; KEY_LEN],
    master_key: &MasterKey,
) -> Result<Vec<u8>, AppError> {
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(wrapping_key));

    let mut nonce_bytes = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, master_key.key.as_slice())
        .map_err(|e| AppError::Internal(format!("Failed to encrypt master key: {e}")))?;

    let mut blob = Vec::with_capacity(NONCE_LEN + ciphertext.len());
    blob.extend_from_slice(&nonce_bytes);
    blob.extend_from_slice(&ciphertext);

    Ok(blob)
}

/// Decrypt master key from stored nonce ‖ ciphertext ‖ tag blob.
fn unwrap_master_key(wrapping_key: &[u8; KEY_LEN], blob: &[u8]) -> Result<MasterKey, AppError> {
    if blob.len() != WRAPPED_BLOB_LEN {
        return Err(AppError::Internal(format!(
            "Encrypted master key blob has wrong size ({} bytes, expected exactly {WRAPPED_BLOB_LEN})",
            blob.len(),
        )));
    }

    let (nonce_bytes, ciphertext) = blob.split_at(NONCE_LEN);
    let nonce = Nonce::from_slice(nonce_bytes);
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(wrapping_key));

    let plaintext = cipher.decrypt(nonce, ciphertext).map_err(|_| {
        AppError::Internal(
            "Failed to decrypt master key — IRONDRIVE_SECRET_KEY may have changed or the \
             stored key is corrupt. If you changed your secret key, data encrypted with \
             the old key is unrecoverable."
                .to_string(),
        )
    })?;

    let key: [u8; KEY_LEN] = plaintext.try_into().map_err(|v: Vec<u8>| {
        AppError::Internal(format!(
            "Decrypted master key has wrong length: expected {KEY_LEN}, got {}",
            v.len()
        ))
    })?;

    Ok(MasterKey { key })
}

/// Load encrypted master key from DB. Returns None on first boot.
async fn load_encrypted_master_key(pool: &DbPool) -> Result<Option<Vec<u8>>, AppError> {
    let row = sqlx::query("SELECT value FROM server_config WHERE key = ?")
        .bind(MASTER_KEY_DB_KEY)
        .fetch_optional(pool)
        .await?;

    Ok(row.map(|r| r.get("value")))
}

/// Store encrypted master key. Uses INSERT OR IGNORE to handle concurrent first boots,
/// then verifies the stored blob matches what we wrote.
async fn store_encrypted_master_key(pool: &DbPool, blob: &[u8]) -> Result<(), AppError> {
    sqlx::query("INSERT OR IGNORE INTO server_config (key, value) VALUES (?, ?)")
        .bind(MASTER_KEY_DB_KEY)
        .bind(blob)
        .execute(pool)
        .await?;

    let stored = load_encrypted_master_key(pool)
        .await?
        .ok_or_else(|| AppError::Internal("Master key row missing after INSERT".to_string()))?;

    if stored != blob {
        return Err(AppError::Internal(
            "Another process stored a different master key — restart to load it".to_string(),
        ));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn test_pool() -> DbPool {
        let pool = sqlx::SqlitePool::connect("sqlite::memory:")
            .await
            .expect("in-memory pool");

        sqlx::query(
            "CREATE TABLE server_config (
                key   TEXT PRIMARY KEY,
                value BLOB NOT NULL
            );",
        )
        .execute(&pool)
        .await
        .expect("create table");

        pool
    }

    fn test_secret_key() -> String {
        let mut bytes = [0u8; KEY_LEN];
        OsRng.fill_bytes(&mut bytes);
        base64::engine::general_purpose::STANDARD.encode(bytes)
    }

    #[test]
    fn decode_secret_key_valid() {
        let key_b64 = test_secret_key();
        let key = decode_secret_key(&key_b64).unwrap();
        assert_eq!(key.len(), KEY_LEN);
    }

    #[test]
    fn decode_secret_key_trims_whitespace() {
        let key_b64 = format!("  {} \n", test_secret_key());
        assert!(decode_secret_key(&key_b64).is_ok());
    }

    #[test]
    fn decode_secret_key_rejects_bad_base64() {
        let result = decode_secret_key("not-valid-base64!!!");
        assert!(result.is_err());
    }

    #[test]
    fn decode_secret_key_rejects_wrong_length() {
        let short = base64::engine::general_purpose::STANDARD.encode([0u8; 16]);
        assert!(decode_secret_key(&short).is_err());

        let long = base64::engine::general_purpose::STANDARD.encode([0u8; 64]);
        assert!(decode_secret_key(&long).is_err());
    }

    #[test]
    fn wrap_unwrap_roundtrip() {
        let mut wrapping_key = [0u8; KEY_LEN];
        OsRng.fill_bytes(&mut wrapping_key);

        let master = generate_master_key();
        let original_bytes = *master.as_bytes();

        let blob = wrap_master_key(&wrapping_key, &master).unwrap();
        assert_eq!(blob.len(), WRAPPED_BLOB_LEN);

        let recovered = unwrap_master_key(&wrapping_key, &blob).unwrap();
        assert_eq!(*recovered.as_bytes(), original_bytes);
    }

    #[test]
    fn unwrap_with_wrong_key_fails() {
        let mut wrapping_key = [0u8; KEY_LEN];
        OsRng.fill_bytes(&mut wrapping_key);

        let master = generate_master_key();
        let blob = wrap_master_key(&wrapping_key, &master).unwrap();

        let mut wrong_key = [0u8; KEY_LEN];
        OsRng.fill_bytes(&mut wrong_key);

        assert!(unwrap_master_key(&wrong_key, &blob).is_err());
    }

    #[test]
    fn unwrap_with_tampered_blob_fails() {
        let mut wrapping_key = [0u8; KEY_LEN];
        OsRng.fill_bytes(&mut wrapping_key);

        let master = generate_master_key();
        let mut blob = wrap_master_key(&wrapping_key, &master).unwrap();

        blob[NONCE_LEN + 5] ^= 0xFF;

        assert!(unwrap_master_key(&wrapping_key, &blob).is_err());
    }

    #[test]
    fn unwrap_rejects_truncated_blob() {
        assert!(unwrap_master_key(&[0u8; KEY_LEN], &[0u8; 10]).is_err());
    }

    #[test]
    fn unwrap_rejects_oversized_blob() {
        assert!(unwrap_master_key(&[0u8; KEY_LEN], &[0u8; WRAPPED_BLOB_LEN + 1]).is_err());
    }

    #[test]
    fn generated_master_keys_are_unique() {
        let k1 = generate_master_key();
        let k2 = generate_master_key();
        assert_ne!(k1.as_bytes(), k2.as_bytes());
    }

    #[test]
    fn wrap_produces_unique_blobs_for_same_key() {
        let mut wrapping_key = [0u8; KEY_LEN];
        OsRng.fill_bytes(&mut wrapping_key);

        let master = generate_master_key();
        let blob1 = wrap_master_key(&wrapping_key, &master).unwrap();
        let blob2 = wrap_master_key(&wrapping_key, &master).unwrap();

        // Different nonces → different ciphertext
        assert_ne!(blob1, blob2);

        // Both decrypt to the same key
        let k1 = unwrap_master_key(&wrapping_key, &blob1).unwrap();
        let k2 = unwrap_master_key(&wrapping_key, &blob2).unwrap();
        assert_eq!(k1.as_bytes(), k2.as_bytes());
    }

    #[tokio::test]
    async fn bootstrap_generates_on_first_boot() {
        let pool = test_pool().await;
        let secret = test_secret_key();

        let master = bootstrap_master_key(&pool, &secret).await.unwrap();
        assert_eq!(master.as_bytes().len(), KEY_LEN);

        let row = sqlx::query("SELECT value FROM server_config WHERE key = ?")
            .bind(MASTER_KEY_DB_KEY)
            .fetch_optional(&pool)
            .await
            .unwrap();
        assert!(row.is_some());
    }

    #[tokio::test]
    async fn bootstrap_loads_on_subsequent_boot() {
        let pool = test_pool().await;
        let secret = test_secret_key();

        let master1 = bootstrap_master_key(&pool, &secret).await.unwrap();
        let bytes1 = *master1.as_bytes();

        let master2 = bootstrap_master_key(&pool, &secret).await.unwrap();
        assert_eq!(*master2.as_bytes(), bytes1);
    }

    #[tokio::test]
    async fn bootstrap_fails_with_wrong_secret_on_reload() {
        let pool = test_pool().await;
        let secret1 = test_secret_key();
        let secret2 = test_secret_key();

        bootstrap_master_key(&pool, &secret1).await.unwrap();
        assert!(bootstrap_master_key(&pool, &secret2).await.is_err());
    }
}
