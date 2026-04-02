use std::path::Path;

use aes_gcm::aead::{Aead, AeadInPlace, KeyInit, OsRng};
use aes_gcm::aead::stream::{EncryptorBE32, DecryptorBE32};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use base64::Engine;
use rand::RngCore;
use sha2::{Digest, Sha256};
use sqlx::Row;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::db::DbPool;
use crate::errors::AppError;

const MASTER_KEY_DB_KEY: &str = "master_key_encrypted";
const NONCE_LEN: usize = 12;
const KEY_LEN: usize = 32;
const TAG_LEN: usize = 16;
const WRAPPED_KEY_LEN: usize = NONCE_LEN + KEY_LEN + TAG_LEN;

/// Buffer size for streaming SHA-256 reads.
const HASH_BUF_SIZE: usize = 64 * 1024;

// ---------------------------------------------------------------------------
// STREAM format constants
// ---------------------------------------------------------------------------
//
// On-disk layout for chunk-assembled (large) files:
//
//  [STREAM_MAGIC: 3 bytes 0x49 0x44 0x02]
//  [stream_nonce: 7 bytes]
//  repeated per segment:
//    [seg_payload_len: 4 bytes LE]
//    [ciphertext+tag: seg_payload_len bytes]
//  [file_hash: 32 bytes]   ← SHA-256 of everything before this
//
// STREAM-BE32 over AES-256-GCM. Each segment has an independent auth tag;
// the BE32 counter prevents replay/reorder. External nonce is 7 bytes
// (AES-GCM 12-byte nonce minus 5 bytes for the BE32 counter).

/// Identifies a STREAM-encrypted file on disk.
const STREAM_MAGIC: [u8; 3] = [0x49, 0x44, 0x02]; // "ID\x02"
/// External nonce length for STREAM-BE32 (12 - 5 = 7).
const STREAM_NONCE_LEN: usize = 7;
/// 4-byte LE length prefix per segment on disk.
const STREAM_SEGMENT_HEADER_LEN: usize = 4;

// ---------------------------------------------------------------------------
// Single-shot format constants
// ---------------------------------------------------------------------------
//
// On-disk layout for small files (< chunk threshold):
//
//  [SINGLE_MAGIC 3B] [nonce 12B] [ciphertext+tag (N+16)B] [file_hash 32B]
//
// file_hash = SHA-256(everything before the last 32 bytes)

/// Identifies a single-shot encrypted file on disk.
const SINGLE_MAGIC: [u8; 3] = [0x49, 0x44, 0x01]; // "ID\x01"

/// Trailing SHA-256 hash length appended to every encrypted file.
const FILE_HASH_LEN: usize = 32;

/// All magic prefixes are 3 bytes.
const MAGIC_LEN: usize = 3;

/// Smallest valid single-shot file: magic(3) + nonce(12) + tag(16) + file_hash(32) = 63.
const MIN_SINGLE_FILE_LEN: usize = MAGIC_LEN + NONCE_LEN + TAG_LEN + FILE_HASH_LEN;

/// Smallest valid stream file: magic(3) + stream_nonce(7) + file_hash(32) = 42.
const MIN_STREAM_FILE_LEN: usize = MAGIC_LEN + STREAM_NONCE_LEN + FILE_HASH_LEN;

/// Decrypted master key, held in Rocket managed state for the server's lifetime.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct MasterKey {
    key: [u8; KEY_LEN],
}

impl MasterKey {
    #[cfg_attr(not(test), allow(dead_code))]
    pub fn as_bytes(&self) -> &[u8; KEY_LEN] {
        &self.key
    }
}

/// Decrypted per-library/space data key for file encryption.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct DataKey {
    key: [u8; KEY_LEN],
}

impl DataKey {
    pub fn as_bytes(&self) -> &[u8; KEY_LEN] {
        &self.key
    }

    /// Reconstruct from a byte slice. Panics if not exactly `KEY_LEN`.
    pub fn from_bytes(bytes: &[u8]) -> Self {
        let key: [u8; KEY_LEN] = bytes
            .try_into()
            .expect("DataKey::from_bytes requires exactly 32 bytes");
        Self { key }
    }
}

// ---------------------------------------------------------------------------
// Master key bootstrap
// ---------------------------------------------------------------------------

/// First boot: generate master key, encrypt with IRONDRIVE_SECRET_KEY, store in DB.
/// Subsequent boots: load from DB and decrypt.
pub async fn bootstrap_master_key(
    pool: &DbPool,
    secret_key_b64: &str,
) -> Result<MasterKey, AppError> {
    /// Drop guard that zeroizes the wrapping key even on early `?` returns.
    struct WrappingKey([u8; KEY_LEN]);
    impl Drop for WrappingKey {
        fn drop(&mut self) {
            self.0.zeroize();
        }
    }

    let wk = WrappingKey(decode_secret_key(secret_key_b64)?);

    match load_encrypted_master_key(pool).await? {
        Some(blob) => {
            tracing::info!("Master key found in database — decrypting");
            let raw = aes_gcm_unwrap(&wk.0, &blob)?;
            Ok(MasterKey { key: raw })
        }
        None => {
            tracing::info!("No master key in database — generating a new one");
            let key = generate_master_key();
            let blob = aes_gcm_wrap(&wk.0, &key.key)?;
            store_encrypted_master_key(pool, &blob).await?;
            tracing::info!("Master key generated and stored");
            Ok(key)
        }
    }
}

// ---------------------------------------------------------------------------
// Data key operations
// ---------------------------------------------------------------------------

/// Generate a random 256-bit data key for a new library or space.
pub fn generate_data_key() -> DataKey {
    let mut key = [0u8; KEY_LEN];
    OsRng.fill_bytes(&mut key);
    DataKey { key }
}

/// Encrypt a data key with the master key. Returns nonce ‖ ciphertext ‖ tag.
pub fn wrap_data_key(master_key: &MasterKey, data_key: &DataKey) -> Result<Vec<u8>, AppError> {
    aes_gcm_wrap(&master_key.key, &data_key.key)
}

/// Decrypt a wrapped data key blob using the master key.
pub fn unwrap_data_key(master_key: &MasterKey, blob: &[u8]) -> Result<DataKey, AppError> {
    let raw = aes_gcm_unwrap(&master_key.key, blob)?;
    Ok(DataKey { key: raw })
}

// ---------------------------------------------------------------------------
// Generic AES-256-GCM key wrap/unwrap
// ---------------------------------------------------------------------------

/// AES-256-GCM encrypt a 32-byte key. Returns nonce ‖ ciphertext ‖ tag.
fn aes_gcm_wrap(
    wrapping_key: &[u8; KEY_LEN],
    plaintext: &[u8; KEY_LEN],
) -> Result<Vec<u8>, AppError> {
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(wrapping_key));

    let mut nonce_bytes = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, plaintext.as_slice())
        .map_err(|e| AppError::Internal(format!("AES-256-GCM encrypt failed: {e}")))?;

    let mut blob = Vec::with_capacity(NONCE_LEN + ciphertext.len());
    blob.extend_from_slice(&nonce_bytes);
    blob.extend_from_slice(&ciphertext);

    Ok(blob)
}

/// AES-256-GCM decrypt a wrapped 32-byte key from nonce ‖ ciphertext ‖ tag.
fn aes_gcm_unwrap(wrapping_key: &[u8; KEY_LEN], blob: &[u8]) -> Result<[u8; KEY_LEN], AppError> {
    if blob.len() != WRAPPED_KEY_LEN {
        return Err(AppError::Internal(format!(
            "Wrapped key blob has wrong size ({} bytes, expected exactly {WRAPPED_KEY_LEN})",
            blob.len(),
        )));
    }

    let (nonce_bytes, ciphertext) = blob.split_at(NONCE_LEN);
    let nonce = Nonce::from_slice(nonce_bytes);
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(wrapping_key));

    let mut plaintext = cipher.decrypt(nonce, ciphertext).map_err(|_| {
        AppError::Internal("AES-256-GCM decrypt failed — wrong key or corrupt data".to_string())
    })?;

    if plaintext.len() != KEY_LEN {
        let len = plaintext.len();
        plaintext.zeroize();
        return Err(AppError::Internal(format!(
            "Unwrapped key has wrong length: expected {KEY_LEN}, got {}",
            len
        )));
    }

    let mut key = [0u8; KEY_LEN];
    key.copy_from_slice(&plaintext);
    plaintext.zeroize();
    Ok(key)
}

// ---------------------------------------------------------------------------
// DB helpers
// ---------------------------------------------------------------------------

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

async fn load_encrypted_master_key(pool: &DbPool) -> Result<Option<Vec<u8>>, AppError> {
    let row = sqlx::query("SELECT value FROM server_config WHERE key = ?")
        .bind(MASTER_KEY_DB_KEY)
        .fetch_optional(pool)
        .await?;

    Ok(row.map(|r| r.get("value")))
}

/// Uses INSERT OR IGNORE + verify to handle concurrent first boots.
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

// ---------------------------------------------------------------------------
// File encryption / decryption
// ---------------------------------------------------------------------------

/// Encrypt plaintext and return the on-disk format:
/// `SINGLE_MAGIC (3) ‖ nonce (12) ‖ ciphertext+tag (N+16) ‖ file_hash (32)`.
///
/// file_hash = SHA-256(magic ‖ nonce ‖ ciphertext+tag).
/// No plaintext hash stored — AES-GCM tag already authenticates plaintext.
#[cfg_attr(not(test), allow(dead_code))]
pub fn encrypt_file_bytes(data_key: &DataKey, plaintext: &[u8]) -> Result<Vec<u8>, AppError> {
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(data_key.as_bytes()));

    let mut nonce_bytes = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext_and_tag = cipher
        .encrypt(nonce, plaintext)
        .map_err(|e| AppError::Internal(format!("File encryption failed: {e}")))?;

    // Build blob without the trailing hash first.
    let content_len = MAGIC_LEN + NONCE_LEN + ciphertext_and_tag.len();
    let mut blob = Vec::with_capacity(content_len + FILE_HASH_LEN);
    blob.extend_from_slice(&SINGLE_MAGIC);
    blob.extend_from_slice(&nonce_bytes);
    blob.extend_from_slice(&ciphertext_and_tag);

    // Hash everything so far, append as trailer.
    let file_hash = sha256_bytes(&blob);
    blob.extend_from_slice(&file_hash);

    Ok(blob)
}

/// Outcome of `decrypt_file_bytes_inner` — lets `verify_file_integrity`
/// tell apart file-hash failures from GCM failures without string matching.
enum DecryptOutcome {
    Ok(Vec<u8>),
    DecryptionFailed(String),
    FileHashMismatch,
}

/// Core decrypt logic for single-shot files (SINGLE_MAGIC format).
///
/// Layout: `SINGLE_MAGIC(3) | nonce(12) | ciphertext+tag(N+16) | file_hash(32)`
///
/// 1. Check file_hash (key-free — catches disk corruption).
/// 2. AES-GCM decrypt (key-required — GCM tag authenticates plaintext).
fn decrypt_file_bytes_inner(data_key: &DataKey, blob: &[u8]) -> DecryptOutcome {
    if blob.len() < MIN_SINGLE_FILE_LEN {
        return DecryptOutcome::DecryptionFailed(format!(
            "Encrypted file too small ({} bytes, minimum {MIN_SINGLE_FILE_LEN})",
            blob.len(),
        ));
    }

    // Verify magic prefix.
    if blob[..MAGIC_LEN] != SINGLE_MAGIC {
        return DecryptOutcome::DecryptionFailed(
            "Not a single-shot encrypted file (bad magic bytes)".to_string(),
        );
    }

    // Key-free check: hash everything before the trailing 32 bytes.
    let content = &blob[..blob.len() - FILE_HASH_LEN];
    let stored_hash = &blob[blob.len() - FILE_HASH_LEN..];

    let computed_hash = sha256_bytes(content);
    if computed_hash.as_slice() != stored_hash {
        return DecryptOutcome::FileHashMismatch;
    }

    // Parse nonce and ciphertext from the content (after magic).
    let nonce_bytes = &content[MAGIC_LEN..MAGIC_LEN + NONCE_LEN];
    let ciphertext_and_tag = &content[MAGIC_LEN + NONCE_LEN..];

    let nonce = Nonce::from_slice(nonce_bytes);
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(data_key.as_bytes()));

    let plaintext = match cipher.decrypt(nonce, ciphertext_and_tag) {
        Ok(pt) => pt,
        Err(_) => {
            return DecryptOutcome::DecryptionFailed(
                "File decryption failed — wrong key or tampered ciphertext".to_string(),
            );
        }
    };

    DecryptOutcome::Ok(plaintext)
}

/// Decrypt a single-shot encrypted file blob. Checks file hash first (key-free),
/// then AES-GCM decrypts.
pub fn decrypt_file_bytes(data_key: &DataKey, blob: &[u8]) -> Result<Vec<u8>, AppError> {
    match decrypt_file_bytes_inner(data_key, blob) {
        DecryptOutcome::Ok(plaintext) => Ok(plaintext),
        DecryptOutcome::FileHashMismatch => Err(AppError::Internal(
            "File hash mismatch — data on disk may be corrupted".to_string(),
        )),
        DecryptOutcome::DecryptionFailed(msg) => Err(AppError::Internal(msg)),
    }
}

/// Result of integrity verification against an encrypted file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IntegrityStatus {
    Ok,
    FileHashMismatch,
    DecryptionFailed(String),
}

/// Verify the integrity of a single-shot encrypted file without returning plaintext.
pub fn verify_file_integrity(data_key: &DataKey, blob: &[u8]) -> IntegrityStatus {
    match decrypt_file_bytes_inner(data_key, blob) {
        DecryptOutcome::Ok(_) => IntegrityStatus::Ok,
        DecryptOutcome::FileHashMismatch => IntegrityStatus::FileHashMismatch,
        DecryptOutcome::DecryptionFailed(msg) => IntegrityStatus::DecryptionFailed(msg),
    }
}

// ---------------------------------------------------------------------------
// SHA-256 helpers
// ---------------------------------------------------------------------------

/// SHA-256 of an in-memory byte slice.
pub fn sha256_bytes(data: &[u8]) -> [u8; FILE_HASH_LEN] {
    Sha256::digest(data).into()
}

/// SHA-256 of a file on disk via streaming reads. Avoids loading the entire
/// file into memory.
#[cfg_attr(not(test), allow(dead_code))]
pub async fn sha256_file(path: &Path) -> Result<[u8; FILE_HASH_LEN], AppError> {
    let mut file = tokio::fs::File::open(path)
        .await
        .map_err(|e| AppError::Internal(format!("Failed to open file for hashing: {e}")))?;

    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; HASH_BUF_SIZE];

    loop {
        let n = file
            .read(&mut buf)
            .await
            .map_err(|e| AppError::Internal(format!("Failed to read file for hashing: {e}")))?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }

    Ok(hasher.finalize().into())
}

// ---------------------------------------------------------------------------
// Key-free file integrity verification
// ---------------------------------------------------------------------------

/// Check the trailing SHA-256 hash of an in-memory encrypted blob.
/// Hashes `blob[0..len-32]` and compares to the last 32 bytes.
/// No encryption key needed.
pub fn verify_file_hash_bytes(blob: &[u8]) -> Result<(), AppError> {
    if blob.len() < MAGIC_LEN + FILE_HASH_LEN {
        return Err(AppError::Internal(format!(
            "File too small for integrity check ({} bytes, need at least {})",
            blob.len(),
            MAGIC_LEN + FILE_HASH_LEN,
        )));
    }

    let content = &blob[..blob.len() - FILE_HASH_LEN];
    let stored_hash = &blob[blob.len() - FILE_HASH_LEN..];

    let computed: [u8; 32] = Sha256::digest(content).into();
    if computed.as_slice() != stored_hash {
        return Err(AppError::Internal(
            "File hash mismatch — data on disk may be corrupted".to_string(),
        ));
    }

    Ok(())
}

/// Same as `verify_file_hash_bytes` but streams from disk so we don't
/// load the whole file into memory. Reads everything except the last 32
/// bytes through a SHA-256 hasher, then compares to the stored hash.
pub async fn verify_file_hash(path: &Path) -> Result<(), AppError> {
    let meta = tokio::fs::metadata(path)
        .await
        .map_err(|e| AppError::Internal(format!("Failed to stat file for integrity check: {e}")))?;

    let file_len = meta.len() as usize;
    if file_len < MAGIC_LEN + FILE_HASH_LEN {
        return Err(AppError::Internal(format!(
            "File too small for integrity check ({file_len} bytes, need at least {})",
            MAGIC_LEN + FILE_HASH_LEN,
        )));
    }

    let content_len = file_len - FILE_HASH_LEN;

    let mut file = tokio::fs::File::open(path)
        .await
        .map_err(|e| AppError::Internal(format!("Failed to open file for integrity check: {e}")))?;

    // Stream-hash everything except the trailing FILE_HASH_LEN bytes.
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; HASH_BUF_SIZE];
    let mut remaining = content_len;

    while remaining > 0 {
        let to_read = remaining.min(HASH_BUF_SIZE);
        let n = file
            .read(&mut buf[..to_read])
            .await
            .map_err(|e| AppError::Internal(format!("Failed to read file for integrity check: {e}")))?;
        if n == 0 {
            return Err(AppError::Internal(
                "Unexpected EOF during integrity check".to_string(),
            ));
        }
        hasher.update(&buf[..n]);
        remaining -= n;
    }

    let computed: [u8; 32] = hasher.finalize().into();

    // Read the stored hash from the tail of the file.
    let mut stored_hash = [0u8; FILE_HASH_LEN];
    file.read_exact(&mut stored_hash)
        .await
        .map_err(|e| AppError::Internal(format!("Failed to read file hash tail: {e}")))?;

    if computed != stored_hash {
        return Err(AppError::Internal(
            "File hash mismatch — data on disk may be corrupted".to_string(),
        ));
    }

    Ok(())
}

/// Encrypt plaintext and write to disk with an optional write-verify pass.
#[cfg_attr(not(test), allow(dead_code))]
pub async fn encrypt_and_write_file(
    data_key: &DataKey,
    plaintext: &[u8],
    dest: &Path,
    write_verify: bool,
) -> Result<(), AppError> {
    encrypt_and_write_file_owned(data_key, plaintext.to_vec(), dest, write_verify).await
}

/// Encrypt owned plaintext in place and write the encrypted payload to disk.
///
/// Uses in-place encryption to avoid allocating a second full-size buffer.
/// On-disk: `SINGLE_MAGIC(3) | nonce(12) | ciphertext+tag(N+16) | file_hash(32)`.
/// Feeds all bytes through a SHA-256 hasher while writing, then appends the hash.
pub async fn encrypt_and_write_file_owned(
    data_key: &DataKey,
    mut plaintext: Vec<u8>,
    dest: &Path,
    write_verify: bool,
) -> Result<(), AppError> {
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(data_key.as_bytes()));

    let mut nonce_bytes = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let tag = cipher
        .encrypt_in_place_detached(nonce, b"", &mut plaintext)
        .map_err(|e| AppError::Internal(format!("File encryption failed: {e}")))?;

    // Build a hasher that covers magic + nonce + ciphertext + tag.
    let mut hasher = Sha256::new();

    let mut file = tokio::fs::File::create(dest)
        .await
        .map_err(|e| AppError::Internal(format!("Failed to write encrypted file: {e}")))?;

    // Write magic.
    file.write_all(&SINGLE_MAGIC)
        .await
        .map_err(|e| AppError::Internal(format!("Failed to write encrypted file magic: {e}")))?;
    hasher.update(SINGLE_MAGIC);

    // Write nonce.
    file.write_all(&nonce_bytes)
        .await
        .map_err(|e| AppError::Internal(format!("Failed to write encrypted file nonce: {e}")))?;
    hasher.update(nonce_bytes);

    // Write ciphertext (plaintext buffer is now encrypted in-place).
    file.write_all(&plaintext)
        .await
        .map_err(|e| AppError::Internal(format!("Failed to write encrypted file body: {e}")))?;
    hasher.update(&plaintext);

    // Write GCM tag.
    file.write_all(tag.as_slice())
        .await
        .map_err(|e| AppError::Internal(format!("Failed to write encrypted file tag: {e}")))?;
    hasher.update(tag.as_slice());

    // Write file hash (SHA-256 of everything above).
    let file_hash: [u8; 32] = hasher.finalize().into();
    file.write_all(&file_hash)
        .await
        .map_err(|e| AppError::Internal(format!("Failed to write encrypted file hash: {e}")))?;

    file.flush()
        .await
        .map_err(|e| AppError::Internal(format!("Failed to flush encrypted file: {e}")))?;
    file.sync_data()
        .await
        .map_err(|e| AppError::Internal(format!("Failed to sync encrypted file to disk: {e}")))?;

    if write_verify {
        // Key-free check: re-read and verify the file hash.
        verify_file_hash(dest).await.map_err(|e| {
            AppError::Internal(format!("Write-verify failed: {e}"))
        })?;

        // Key check: decrypt to confirm GCM tag passes.
        let readback = tokio::fs::read(dest).await.map_err(|e| {
            AppError::Internal(format!("Write-verify: failed to read back file: {e}"))
        })?;
        decrypt_file_bytes(data_key, &readback)?;
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// STREAM encrypt / decrypt (chunk-file streaming, O(segment) RAM)
// ---------------------------------------------------------------------------

/// Encrypt ordered chunk files into a single STREAM-format file on disk.
///
/// On-disk layout:
///   [STREAM_MAGIC 3B] [stream_nonce 7B]
///   per segment: [seg_len 4B LE] [ciphertext+tag]
///   [file_hash 32B]   ← SHA-256(everything before this)
///
/// Chunks are read one at a time so peak RAM is bounded to one chunk buffer.
/// `write_verify` re-reads the file and checks the file hash (no key needed).
pub async fn stream_encrypt_chunks_to_file(
    data_key: &DataKey,
    chunk_paths: &[std::path::PathBuf],
    total_plaintext_bytes: u64,
    dest: &Path,
    write_verify: bool,
) -> Result<(), AppError> {
    // Random 7-byte external stream nonce.
    let mut stream_nonce = [0u8; STREAM_NONCE_LEN];
    OsRng.fill_bytes(&mut stream_nonce);

    let mut out = tokio::fs::File::create(dest)
        .await
        .map_err(|e| AppError::Internal(format!("Failed to create encrypted file: {e}")))?;

    // We hash everything we write so we can append the file hash at the end.
    let mut hasher = Sha256::new();

    // Header: magic (3) + stream nonce (7).
    out.write_all(&STREAM_MAGIC)
        .await
        .map_err(|e| AppError::Internal(format!("Failed to write STREAM magic: {e}")))?;
    hasher.update(STREAM_MAGIC);
    out.write_all(&stream_nonce)
        .await
        .map_err(|e| AppError::Internal(format!("Failed to write STREAM nonce: {e}")))?;
    hasher.update(stream_nonce);

    // Build the STREAM encryptor.
    let key = Key::<Aes256Gcm>::from_slice(data_key.as_bytes());
    let nonce_ga = aes_gcm::aead::generic_array::GenericArray::from_slice(&stream_nonce);
    let mut encryptor: Option<EncryptorBE32<Aes256Gcm>> =
        Some(EncryptorBE32::<Aes256Gcm>::new(key, nonce_ga));

    let mut bytes_read: u64 = 0;
    let total = chunk_paths.len();
    for (i, path) in chunk_paths.iter().enumerate() {
        let mut buf = tokio::fs::read(path)
            .await
            .map_err(|_| AppError::Validation(format!("Missing chunk {}.", i)))?;
        bytes_read += buf.len() as u64;

        let is_last = i + 1 == total;
        if is_last {
            encryptor
                .take()
                .expect("encryptor consumed before last chunk")
                .encrypt_last_in_place(b"", &mut buf)
                .map_err(|e| AppError::Internal(format!("STREAM encrypt last segment failed: {e}")))?;
        } else {
            encryptor
                .as_mut()
                .expect("encryptor already consumed")
                .encrypt_next_in_place(b"", &mut buf)
                .map_err(|e| AppError::Internal(format!("STREAM encrypt segment {i} failed: {e}")))?;
        }

        // Write 4-byte LE segment length then the ciphertext+tag.
        let seg_len = buf.len() as u32;
        let seg_len_bytes = seg_len.to_le_bytes();
        out.write_all(&seg_len_bytes)
            .await
            .map_err(|e| AppError::Internal(format!("Failed to write segment header: {e}")))?;
        hasher.update(seg_len_bytes);
        out.write_all(&buf)
            .await
            .map_err(|e| AppError::Internal(format!("Failed to write segment body: {e}")))?;
        hasher.update(&buf);
    }

    if bytes_read != total_plaintext_bytes {
        return Err(AppError::Internal(format!(
            "Chunk size mismatch: expected {total_plaintext_bytes} bytes, read {bytes_read}"
        )));
    }

    // Append the file hash (SHA-256 of everything written so far).
    let file_hash: [u8; FILE_HASH_LEN] = hasher.finalize().into();
    out.write_all(&file_hash)
        .await
        .map_err(|e| AppError::Internal(format!("Failed to write file hash: {e}")))?;

    out.flush()
        .await
        .map_err(|e| AppError::Internal(format!("Failed to flush encrypted file: {e}")))?;
    out.sync_data()
        .await
        .map_err(|e| AppError::Internal(format!("Failed to sync encrypted file to disk: {e}")))?;
    drop(out);

    // Write-verify: re-read and check the file hash. No key needed.
    if write_verify {
        verify_file_hash(dest).await?;
    }

    Ok(())
}

/// Read and decrypt a STREAM-encrypted file, returning all plaintext.
/// The file hash is checked first (key-free), then GCM tags validate each segment.
pub async fn stream_decrypt_file(
    data_key: &DataKey,
    path: &Path,
) -> Result<Vec<u8>, AppError> {
    stream_decrypt_file_inner(data_key, path).await
}

/// Verify a STREAM file's GCM tags without keeping the plaintext.
///
/// Decrypts each segment to check its auth tag, then drops the plaintext
/// immediately — peak RAM is one segment buffer. The file hash is checked
/// first (key-free), so disk corruption is caught before any decryption.
pub async fn stream_verify_decryption(
    data_key: &DataKey,
    path: &Path,
) -> Result<(), AppError> {
    use tokio::io::AsyncReadExt;

    let file = tokio::fs::File::open(path)
        .await
        .map_err(|e| AppError::Internal(format!("Failed to open STREAM file for verify: {e}")))?;

    let file_len = file.metadata().await
        .map_err(|e| AppError::Internal(format!("Failed to stat STREAM file: {e}")))?.len() as usize;

    // File hash check first (key-free).
    drop(file);
    verify_file_hash(path).await?;

    // Re-open and parse header: magic(3) + nonce(7) = 10 bytes.
    let mut file = tokio::fs::File::open(path)
        .await
        .map_err(|e| AppError::Internal(format!("Failed to re-open STREAM file: {e}")))?;

    let header_len = MAGIC_LEN + STREAM_NONCE_LEN;
    let mut header_buf = vec![0u8; header_len];
    file.read_exact(&mut header_buf)
        .await
        .map_err(|_| AppError::Internal("STREAM file too small to contain header".into()))?;

    if header_buf[..MAGIC_LEN] != STREAM_MAGIC {
        return Err(AppError::Internal("STREAM file has wrong magic bytes".into()));
    }

    let stream_nonce = &header_buf[MAGIC_LEN..MAGIC_LEN + STREAM_NONCE_LEN];
    let key = Key::<Aes256Gcm>::from_slice(data_key.as_bytes());
    let nonce_ga = aes_gcm::aead::generic_array::GenericArray::from_slice(stream_nonce);
    let mut decryptor = DecryptorBE32::<Aes256Gcm>::new(key, nonce_ga);

    // Segments live between header and trailing file_hash.
    let segments_end = file_len - FILE_HASH_LEN;
    let mut pos = header_len;
    let mut pending: Option<Vec<u8>> = None;
    let mut seg_len_buf = [0u8; 4];

    while pos < segments_end {
        file.read_exact(&mut seg_len_buf)
            .await
            .map_err(|e| AppError::Internal(format!("STREAM verify: truncated segment header: {e}")))?;
        pos += 4;

        let seg_len = u32::from_le_bytes(seg_len_buf) as usize;
        let mut seg_data = vec![0u8; seg_len];
        file.read_exact(&mut seg_data)
            .await
            .map_err(|e| AppError::Internal(format!("STREAM verify: truncated segment body: {e}")))?;
        pos += seg_len;

        // Decrypt the previously pending segment as non-last.
        if let Some(mut prev) = pending.take() {
            decryptor
                .decrypt_next_in_place(b"", &mut prev)
                .map_err(|_| AppError::Internal(
                    "STREAM verify: decrypt segment failed".into(),
                ))?;
            // drop plaintext
        }

        pending = Some(seg_data);
    }

    // Flush the last segment.
    if let Some(mut seg) = pending.take() {
        decryptor
            .decrypt_last_in_place(b"", &mut seg)
            .map_err(|_| AppError::Internal(
                "STREAM verify: decrypt last segment failed".into(),
            ))?;
    }

    Ok(())
}

/// Internal: parse and decrypt a STREAM file, returning plaintext.
/// Checks file hash (key-free) first, then decrypts all segments.
async fn stream_decrypt_file_inner(
    data_key: &DataKey,
    path: &Path,
) -> Result<Vec<u8>, AppError> {
    let raw = tokio::fs::read(path)
        .await
        .map_err(|e| AppError::Internal(format!("Failed to read STREAM encrypted file: {e}")))?;

    if raw.len() < MIN_STREAM_FILE_LEN {
        return Err(AppError::Internal(
            "STREAM file too small to contain header + file hash".into(),
        ));
    }

    // Key-free file hash check.
    verify_file_hash_bytes(&raw)?;

    if raw[..MAGIC_LEN] != STREAM_MAGIC {
        return Err(AppError::Internal(
            "STREAM file has wrong magic bytes".into(),
        ));
    }

    let stream_nonce = &raw[MAGIC_LEN..MAGIC_LEN + STREAM_NONCE_LEN];

    let key = Key::<Aes256Gcm>::from_slice(data_key.as_bytes());
    let nonce_ga = aes_gcm::aead::generic_array::GenericArray::from_slice(stream_nonce);
    let mut decryptor = DecryptorBE32::<Aes256Gcm>::new(key, nonce_ga);

    // Segments live between header and trailing file_hash.
    let header_len = MAGIC_LEN + STREAM_NONCE_LEN;
    let segments_end = raw.len() - FILE_HASH_LEN;
    let mut plaintext = Vec::new();
    let mut pos = header_len;
    let mut pending: Option<Vec<u8>> = None;

    while pos < segments_end {
        if pos + STREAM_SEGMENT_HEADER_LEN > segments_end {
            return Err(AppError::Internal(
                "STREAM file truncated inside segment header".into(),
            ));
        }
        let seg_len = u32::from_le_bytes(
            raw[pos..pos + 4].try_into().expect("slice is 4 bytes"),
        ) as usize;
        pos += STREAM_SEGMENT_HEADER_LEN;

        if pos + seg_len > segments_end {
            return Err(AppError::Internal(
                "STREAM file truncated inside segment body".into(),
            ));
        }
        let seg_data = raw[pos..pos + seg_len].to_vec();
        pos += seg_len;

        // Decrypt the previously pending segment as non-last.
        if let Some(mut prev) = pending.take() {
            decryptor
                .decrypt_next_in_place(b"", &mut prev)
                .map_err(|_| AppError::Internal(
                    "STREAM decrypt segment failed — wrong key or tampered data".into(),
                ))?;
            plaintext.extend_from_slice(&prev);
        }

        pending = Some(seg_data);
    }

    // Flush the last segment.
    if let Some(mut seg) = pending.take() {
        decryptor
            .decrypt_last_in_place(b"", &mut seg)
            .map_err(|_| AppError::Internal(
                "STREAM decrypt last segment failed — wrong key or tampered data".into(),
            ))?;
        plaintext.extend_from_slice(&seg);
    }

    Ok(plaintext)
}

/// Check whether a file on disk uses the STREAM format (magic = 0x49 0x44 0x02).
pub async fn is_stream_format(path: &Path) -> bool {
    let mut file = match tokio::fs::File::open(path).await {
        Ok(f) => f,
        Err(_) => return false,
    };
    let mut magic = [0u8; 3];
    (file.read_exact(&mut magic).await).is_ok() && magic == STREAM_MAGIC
}

/// Verify integrity of any encrypted file (single-shot or STREAM).
///
/// Two tiers:
///  1. File hash check (key-free) — catches disk corruption on any file.
///  2. Full decrypt / GCM tag check (needs key) — catches wrong-key or
///     encryption-level issues.
///
/// If no key is provided, only tier 1 runs.
pub async fn verify_file_integrity_async(
    data_key: Option<&DataKey>,
    path: &Path,
) -> IntegrityStatus {
    // Tier 1: file hash — no key needed.
    if verify_file_hash(path).await.is_err() {
        return IntegrityStatus::FileHashMismatch;
    }

    // Tier 2: full decrypt (GCM tags) — only if we have a key.
    let Some(dk) = data_key else {
        return IntegrityStatus::Ok; // file hash passed, no key to go deeper
    };

    if is_stream_format(path).await {
        match stream_verify_decryption(dk, path).await {
            Ok(_) => IntegrityStatus::Ok,
            Err(e) => IntegrityStatus::DecryptionFailed(format!("{e}")),
        }
    } else {
        match tokio::fs::read(path).await {
            Ok(blob) => verify_file_integrity(dk, &blob),
            Err(e) => IntegrityStatus::DecryptionFailed(format!("read error: {e}")),
        }
    }
}

/// Read and decrypt any encrypted file (single-shot or STREAM).
pub async fn read_and_decrypt_file(data_key: &DataKey, path: &Path) -> Result<Vec<u8>, AppError> {
    if is_stream_format(path).await {
        stream_decrypt_file(data_key, path).await
    } else {
        let blob = tokio::fs::read(path)
            .await
            .map_err(|e| AppError::Internal(format!("Failed to read encrypted file: {e}")))?;
        decrypt_file_bytes(data_key, &blob)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write as _;
    use std::path::PathBuf;
    use tempfile::NamedTempFile;

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

    // -- decode_secret_key --

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
        assert!(decode_secret_key("not-valid-base64!!!").is_err());
    }

    #[test]
    fn decode_secret_key_rejects_wrong_length() {
        let short = base64::engine::general_purpose::STANDARD.encode([0u8; 16]);
        assert!(decode_secret_key(&short).is_err());

        let long = base64::engine::general_purpose::STANDARD.encode([0u8; 64]);
        assert!(decode_secret_key(&long).is_err());
    }

    // -- aes_gcm_wrap / aes_gcm_unwrap --

    #[test]
    fn wrap_unwrap_roundtrip() {
        let mut wrapping_key = [0u8; KEY_LEN];
        OsRng.fill_bytes(&mut wrapping_key);

        let mut plaintext = [0u8; KEY_LEN];
        OsRng.fill_bytes(&mut plaintext);

        let blob = aes_gcm_wrap(&wrapping_key, &plaintext).unwrap();
        assert_eq!(blob.len(), WRAPPED_KEY_LEN);

        let recovered = aes_gcm_unwrap(&wrapping_key, &blob).unwrap();
        assert_eq!(recovered, plaintext);
    }

    #[test]
    fn unwrap_with_wrong_key_fails() {
        let mut wrapping_key = [0u8; KEY_LEN];
        OsRng.fill_bytes(&mut wrapping_key);

        let mut plaintext = [0u8; KEY_LEN];
        OsRng.fill_bytes(&mut plaintext);

        let blob = aes_gcm_wrap(&wrapping_key, &plaintext).unwrap();

        let mut wrong_key = [0u8; KEY_LEN];
        OsRng.fill_bytes(&mut wrong_key);

        assert!(aes_gcm_unwrap(&wrong_key, &blob).is_err());
    }

    #[test]
    fn unwrap_with_tampered_blob_fails() {
        let mut wrapping_key = [0u8; KEY_LEN];
        OsRng.fill_bytes(&mut wrapping_key);

        let mut plaintext = [0u8; KEY_LEN];
        OsRng.fill_bytes(&mut plaintext);

        let mut blob = aes_gcm_wrap(&wrapping_key, &plaintext).unwrap();
        blob[NONCE_LEN + 5] ^= 0xFF;

        assert!(aes_gcm_unwrap(&wrapping_key, &blob).is_err());
    }

    #[test]
    fn unwrap_rejects_truncated_blob() {
        assert!(aes_gcm_unwrap(&[0u8; KEY_LEN], &[0u8; 10]).is_err());
    }

    #[test]
    fn unwrap_rejects_oversized_blob() {
        assert!(aes_gcm_unwrap(&[0u8; KEY_LEN], &[0u8; WRAPPED_KEY_LEN + 1]).is_err());
    }

    #[test]
    fn wrap_produces_unique_blobs_for_same_key() {
        let mut wrapping_key = [0u8; KEY_LEN];
        OsRng.fill_bytes(&mut wrapping_key);

        let mut plaintext = [0u8; KEY_LEN];
        OsRng.fill_bytes(&mut plaintext);

        let blob1 = aes_gcm_wrap(&wrapping_key, &plaintext).unwrap();
        let blob2 = aes_gcm_wrap(&wrapping_key, &plaintext).unwrap();
        assert_ne!(blob1, blob2);

        assert_eq!(aes_gcm_unwrap(&wrapping_key, &blob1).unwrap(), plaintext);
        assert_eq!(aes_gcm_unwrap(&wrapping_key, &blob2).unwrap(), plaintext);
    }

    // -- data key generate / wrap / unwrap --

    #[test]
    fn generated_data_keys_are_unique() {
        let k1 = generate_data_key();
        let k2 = generate_data_key();
        assert_ne!(k1.as_bytes(), k2.as_bytes());
    }

    #[test]
    fn data_key_wrap_unwrap_roundtrip() {
        let master = generate_master_key();
        let data = generate_data_key();
        let original = *data.as_bytes();

        let blob = wrap_data_key(&master, &data).unwrap();
        assert_eq!(blob.len(), WRAPPED_KEY_LEN);

        let recovered = unwrap_data_key(&master, &blob).unwrap();
        assert_eq!(*recovered.as_bytes(), original);
    }

    #[test]
    fn data_key_unwrap_with_wrong_master_fails() {
        let master1 = generate_master_key();
        let master2 = generate_master_key();
        let data = generate_data_key();

        let blob = wrap_data_key(&master1, &data).unwrap();
        assert!(unwrap_data_key(&master2, &blob).is_err());
    }

    #[test]
    fn data_key_unwrap_with_tampered_blob_fails() {
        let master = generate_master_key();
        let data = generate_data_key();

        let mut blob = wrap_data_key(&master, &data).unwrap();
        blob[NONCE_LEN + 2] ^= 0xFF;

        assert!(unwrap_data_key(&master, &blob).is_err());
    }

    // -- bootstrap --

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

    // -- File encrypt / decrypt --

    #[test]
    fn file_encrypt_decrypt_roundtrip_empty() {
        let key = generate_data_key();
        let plaintext = b"";

        let blob = encrypt_file_bytes(&key, plaintext).unwrap();
        // magic(3) + nonce(12) + tag(16) + file_hash(32) = 63
        assert_eq!(blob.len(), MIN_SINGLE_FILE_LEN);
        assert_eq!(&blob[..MAGIC_LEN], &SINGLE_MAGIC);

        let recovered = decrypt_file_bytes(&key, &blob).unwrap();
        assert_eq!(recovered, plaintext);
    }

    #[test]
    fn file_encrypt_decrypt_roundtrip_small() {
        let key = generate_data_key();
        let plaintext = b"Hello, IronDrive!";

        let blob = encrypt_file_bytes(&key, plaintext).unwrap();
        assert_eq!(
            blob.len(),
            MAGIC_LEN + NONCE_LEN + plaintext.len() + TAG_LEN + FILE_HASH_LEN
        );
        assert_eq!(&blob[..MAGIC_LEN], &SINGLE_MAGIC);

        let recovered = decrypt_file_bytes(&key, &blob).unwrap();
        assert_eq!(recovered, plaintext);
    }

    #[test]
    fn file_encrypt_decrypt_roundtrip_large() {
        let key = generate_data_key();
        let mut plaintext = vec![0u8; 1024 * 1024];
        OsRng.fill_bytes(&mut plaintext);

        let blob = encrypt_file_bytes(&key, &plaintext).unwrap();
        let recovered = decrypt_file_bytes(&key, &blob).unwrap();
        assert_eq!(recovered, plaintext);
    }

    #[test]
    fn file_decrypt_wrong_key_fails() {
        let key1 = generate_data_key();
        let key2 = generate_data_key();
        let plaintext = b"secret data";

        let blob = encrypt_file_bytes(&key1, plaintext).unwrap();
        assert!(decrypt_file_bytes(&key2, &blob).is_err());
    }

    #[test]
    fn file_decrypt_tampered_ciphertext_fails() {
        let key = generate_data_key();
        let plaintext = b"secret data";

        let mut blob = encrypt_file_bytes(&key, plaintext).unwrap();
        // Tamper with a byte in the ciphertext area (after magic + nonce).
        blob[MAGIC_LEN + NONCE_LEN + 3] ^= 0xFF;

        let err = decrypt_file_bytes(&key, &blob).unwrap_err();
        let msg = format!("{err}");
        // File hash check catches this before GCM even runs.
        assert!(
            msg.contains("hash mismatch") || msg.contains("decryption failed") || msg.contains("tampered"),
            "Expected integrity failure, got: {msg}"
        );
    }

    #[test]
    fn file_decrypt_tampered_file_hash_detected() {
        let key = generate_data_key();
        let plaintext = b"secret data";

        let mut blob = encrypt_file_bytes(&key, plaintext).unwrap();
        let last = blob.len() - 1;
        blob[last] ^= 0xFF;

        // Tampered file hash → caught by key-free check.
        let err = decrypt_file_bytes(&key, &blob);
        assert!(err.is_err(), "Should have detected tampered file hash");
        let msg = format!("{}", err.unwrap_err());
        assert!(
            msg.contains("hash mismatch"),
            "Expected file hash mismatch, got: {msg}"
        );
    }

    #[test]
    fn file_decrypt_truncated_blob_rejected() {
        let key = generate_data_key();
        let tiny = vec![0u8; MIN_SINGLE_FILE_LEN - 1];
        assert!(decrypt_file_bytes(&key, &tiny).is_err());
    }

    #[test]
    fn file_encrypt_produces_unique_blobs() {
        let key = generate_data_key();
        let plaintext = b"same content";

        let blob1 = encrypt_file_bytes(&key, plaintext).unwrap();
        let blob2 = encrypt_file_bytes(&key, plaintext).unwrap();

        // Different nonces → different blobs.
        assert_ne!(blob1, blob2);

        assert_eq!(decrypt_file_bytes(&key, &blob1).unwrap(), plaintext);
        assert_eq!(decrypt_file_bytes(&key, &blob2).unwrap(), plaintext);
    }

    // -- Integrity verification --

    #[test]
    fn verify_integrity_ok() {
        let key = generate_data_key();
        let blob = encrypt_file_bytes(&key, b"valid").unwrap();
        assert_eq!(verify_file_integrity(&key, &blob), IntegrityStatus::Ok);
    }

    #[test]
    fn verify_integrity_tampered_file_hash() {
        let key = generate_data_key();
        let mut blob = encrypt_file_bytes(&key, b"valid").unwrap();
        let last = blob.len() - 1;
        blob[last] ^= 0xFF;
        assert_eq!(
            verify_file_integrity(&key, &blob),
            IntegrityStatus::FileHashMismatch
        );
    }

    #[test]
    fn verify_integrity_tampered_ciphertext() {
        let key = generate_data_key();
        let mut blob = encrypt_file_bytes(&key, b"valid").unwrap();
        // Tamper ciphertext body (after magic + nonce).
        blob[MAGIC_LEN + NONCE_LEN + 2] ^= 0xFF;
        // File hash check catches this before GCM.
        assert_eq!(
            verify_file_integrity(&key, &blob),
            IntegrityStatus::FileHashMismatch
        );
    }

    // -- SHA-256 helpers --

    #[test]
    fn sha256_bytes_known_vector() {
        let hash = sha256_bytes(b"");
        assert_eq!(
            hex::encode(hash),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn sha256_bytes_hello() {
        let hash = sha256_bytes(b"hello");
        assert_eq!(
            hex::encode(hash),
            "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
        );
    }

    #[tokio::test]
    async fn sha256_file_matches_sha256_bytes() {
        let data = b"The quick brown fox jumps over the lazy dog";
        let expected = sha256_bytes(data);

        let mut tmp = NamedTempFile::new().unwrap();
        tmp.write_all(data).unwrap();
        tmp.flush().unwrap();

        let file_hash = sha256_file(tmp.path()).await.unwrap();
        assert_eq!(file_hash, expected);
    }

    #[tokio::test]
    async fn sha256_file_empty() {
        let tmp = NamedTempFile::new().unwrap();
        let hash = sha256_file(tmp.path()).await.unwrap();
        assert_eq!(hash, sha256_bytes(b""));
    }

    #[tokio::test]
    async fn sha256_file_large() {
        // Larger than HASH_BUF_SIZE to exercise the streaming loop.
        let mut data = vec![0u8; HASH_BUF_SIZE * 3 + 42];
        OsRng.fill_bytes(&mut data);
        let expected = sha256_bytes(&data);

        let mut tmp = NamedTempFile::new().unwrap();
        tmp.write_all(&data).unwrap();
        tmp.flush().unwrap();

        let file_hash = sha256_file(tmp.path()).await.unwrap();
        assert_eq!(file_hash, expected);
    }

    // -- verify_file_hash (key-free integrity) --

    /// Helper: build a blob with a valid trailing file hash.
    fn make_hashed_blob(content: &[u8]) -> Vec<u8> {
        let hash: [u8; 32] = Sha256::digest(content).into();
        let mut blob = Vec::with_capacity(content.len() + FILE_HASH_LEN);
        blob.extend_from_slice(content);
        blob.extend_from_slice(&hash);
        blob
    }

    #[test]
    fn verify_file_hash_bytes_valid() {
        // 3-byte magic + some payload → meets minimum size with hash appended
        let content = b"IDX_some_encrypted_payload_here_";
        let blob = make_hashed_blob(content);
        assert!(verify_file_hash_bytes(&blob).is_ok());
    }

    #[test]
    fn verify_file_hash_bytes_tampered_body() {
        let content = b"IDX_some_encrypted_payload_here_";
        let mut blob = make_hashed_blob(content);
        // Flip a byte in the body
        blob[5] ^= 0xFF;
        assert!(verify_file_hash_bytes(&blob).is_err());
    }

    #[test]
    fn verify_file_hash_bytes_tampered_hash() {
        let content = b"IDX_some_encrypted_payload_here_";
        let mut blob = make_hashed_blob(content);
        // Flip a byte in the trailing hash
        let last = blob.len() - 1;
        blob[last] ^= 0xFF;
        assert!(verify_file_hash_bytes(&blob).is_err());
    }

    #[test]
    fn verify_file_hash_bytes_truncated() {
        // Too small to contain magic + file_hash
        let tiny = vec![0u8; MAGIC_LEN + FILE_HASH_LEN - 1];
        assert!(verify_file_hash_bytes(&tiny).is_err());
    }

    #[test]
    fn verify_file_hash_bytes_minimum_size() {
        // Exactly MAGIC_LEN content bytes + FILE_HASH_LEN = valid
        let content = &[0x49u8, 0x44, 0x03]; // 3-byte "content" (the magic)
        let blob = make_hashed_blob(content);
        assert!(verify_file_hash_bytes(&blob).is_ok());
    }

    #[tokio::test]
    async fn verify_file_hash_valid_on_disk() {
        let content = b"IDX_streaming_verification_test_";
        let blob = make_hashed_blob(content);

        let mut tmp = NamedTempFile::new().unwrap();
        tmp.write_all(&blob).unwrap();
        tmp.flush().unwrap();

        assert!(verify_file_hash(tmp.path()).await.is_ok());
    }

    #[tokio::test]
    async fn verify_file_hash_tampered_on_disk() {
        let content = b"IDX_streaming_verification_test_";
        let mut blob = make_hashed_blob(content);
        blob[10] ^= 0xFF;

        let mut tmp = NamedTempFile::new().unwrap();
        tmp.write_all(&blob).unwrap();
        tmp.flush().unwrap();

        assert!(verify_file_hash(tmp.path()).await.is_err());
    }

    #[tokio::test]
    async fn verify_file_hash_large_file() {
        // Larger-than-buffer file to exercise the streaming loop
        let mut content = vec![0u8; HASH_BUF_SIZE * 2 + 77];
        OsRng.fill_bytes(&mut content);
        let blob = make_hashed_blob(&content);

        let mut tmp = NamedTempFile::new().unwrap();
        tmp.write_all(&blob).unwrap();
        tmp.flush().unwrap();

        assert!(verify_file_hash(tmp.path()).await.is_ok());
    }

    #[tokio::test]
    async fn verify_file_hash_truncated_on_disk() {
        let tiny = vec![0u8; MAGIC_LEN + FILE_HASH_LEN - 1];
        let mut tmp = NamedTempFile::new().unwrap();
        tmp.write_all(&tiny).unwrap();
        tmp.flush().unwrap();

        assert!(verify_file_hash(tmp.path()).await.is_err());
    }

    // -- File encrypt/decrypt via disk --

    #[tokio::test]
    async fn encrypt_write_read_decrypt_roundtrip() {
        let key = generate_data_key();
        let plaintext = b"round-trip through disk";

        let tmp = NamedTempFile::new().unwrap();
        encrypt_and_write_file(&key, plaintext, tmp.path(), false)
            .await
            .unwrap();

        let recovered = read_and_decrypt_file(&key, tmp.path()).await.unwrap();
        assert_eq!(recovered, plaintext);
    }

    #[tokio::test]
    async fn encrypt_write_with_verify() {
        let key = generate_data_key();
        let plaintext = b"verified write";

        let tmp = NamedTempFile::new().unwrap();
        encrypt_and_write_file(&key, plaintext, tmp.path(), true)
            .await
            .unwrap();

        let recovered = read_and_decrypt_file(&key, tmp.path()).await.unwrap();
        assert_eq!(recovered, plaintext);
    }

    #[tokio::test]
    async fn read_decrypt_nonexistent_file_fails() {
        let key = generate_data_key();
        let result =
            read_and_decrypt_file(&key, Path::new("/tmp/nonexistent_irondrive_test_file")).await;
        assert!(result.is_err());
    }

    // -- Key-free integrity on real encrypted blobs --

    #[test]
    fn verify_file_hash_passes_on_real_encrypted_blob() {
        let key = generate_data_key();
        let blob = encrypt_file_bytes(&key, b"real encrypted content").unwrap();
        // The blob has a valid trailing file hash — key-free check should pass.
        assert!(verify_file_hash_bytes(&blob).is_ok());
    }

    #[test]
    fn verify_file_hash_catches_tampered_encrypted_blob_without_key() {
        let key = generate_data_key();
        let mut blob = encrypt_file_bytes(&key, b"real encrypted content").unwrap();
        // Tamper ciphertext — the file hash (last 32 bytes) is now wrong.
        blob[MAGIC_LEN + NONCE_LEN + 2] ^= 0xFF;
        assert!(verify_file_hash_bytes(&blob).is_err());
    }

    // -- verify_file_integrity_async (two-tier) --

    #[tokio::test]
    async fn integrity_async_key_free_valid_single_shot() {
        let key = generate_data_key();
        let blob = encrypt_file_bytes(&key, b"async check").unwrap();

        let mut tmp = NamedTempFile::new().unwrap();
        tmp.write_all(&blob).unwrap();
        tmp.flush().unwrap();

        // No key provided — only file hash check runs.
        let status = verify_file_integrity_async(None, tmp.path()).await;
        assert_eq!(status, IntegrityStatus::Ok);
    }

    #[tokio::test]
    async fn integrity_async_key_free_corrupted_single_shot() {
        let key = generate_data_key();
        let mut blob = encrypt_file_bytes(&key, b"async check").unwrap();
        blob[MAGIC_LEN + NONCE_LEN + 1] ^= 0xFF; // tamper ciphertext

        let mut tmp = NamedTempFile::new().unwrap();
        tmp.write_all(&blob).unwrap();
        tmp.flush().unwrap();

        let status = verify_file_integrity_async(None, tmp.path()).await;
        assert_eq!(status, IntegrityStatus::FileHashMismatch);
    }

    #[tokio::test]
    async fn integrity_async_wrong_key_single_shot() {
        let key1 = generate_data_key();
        let key2 = generate_data_key();
        let blob = encrypt_file_bytes(&key1, b"wrong key test").unwrap();

        let mut tmp = NamedTempFile::new().unwrap();
        tmp.write_all(&blob).unwrap();
        tmp.flush().unwrap();

        // File hash passes (blob is intact), but GCM decrypt fails.
        let status = verify_file_integrity_async(Some(&key2), tmp.path()).await;
        assert!(
            matches!(status, IntegrityStatus::DecryptionFailed(_)),
            "Expected DecryptionFailed, got: {:?}",
            status
        );
    }

    #[tokio::test]
    async fn integrity_async_correct_key_single_shot() {
        let key = generate_data_key();
        let blob = encrypt_file_bytes(&key, b"correct key test").unwrap();

        let mut tmp = NamedTempFile::new().unwrap();
        tmp.write_all(&blob).unwrap();
        tmp.flush().unwrap();

        let status = verify_file_integrity_async(Some(&key), tmp.path()).await;
        assert_eq!(status, IntegrityStatus::Ok);
    }

    // -- STREAM format unit tests --

    /// Helper: write chunk data to temp files and return paths.
    fn write_chunk_files(chunks: &[&[u8]]) -> (tempfile::TempDir, Vec<PathBuf>) {
        let dir = tempfile::tempdir().unwrap();
        let mut paths = Vec::new();
        for (i, chunk) in chunks.iter().enumerate() {
            let path = dir.path().join(format!("{i:08}.chunk"));
            std::fs::write(&path, chunk).unwrap();
            paths.push(path);
        }
        (dir, paths)
    }

    #[tokio::test]
    async fn stream_encrypt_decrypt_roundtrip() {
        let key = generate_data_key();
        let data = b"hello stream encryption";
        let (_chunk_dir, chunk_paths) = write_chunk_files(&[data]);

        let dest = NamedTempFile::new().unwrap();
        stream_encrypt_chunks_to_file(
            &key,
            &chunk_paths,
            data.len() as u64,
            dest.path(),
            false,
        )
        .await
        .unwrap();

        // Should be identified as STREAM format.
        assert!(is_stream_format(dest.path()).await);

        // Decrypt and verify content.
        let recovered = stream_decrypt_file(&key, dest.path()).await.unwrap();
        assert_eq!(recovered, data);
    }

    #[tokio::test]
    async fn stream_encrypt_decrypt_multi_chunk_roundtrip() {
        let key = generate_data_key();
        let chunk1 = vec![0xAAu8; 1024];
        let chunk2 = vec![0xBBu8; 512];
        let total = (chunk1.len() + chunk2.len()) as u64;
        let (_chunk_dir, chunk_paths) =
            write_chunk_files(&[&chunk1, &chunk2]);

        let dest = NamedTempFile::new().unwrap();
        stream_encrypt_chunks_to_file(&key, &chunk_paths, total, dest.path(), false)
            .await
            .unwrap();

        let recovered = stream_decrypt_file(&key, dest.path()).await.unwrap();
        let mut expected = chunk1.clone();
        expected.extend_from_slice(&chunk2);
        assert_eq!(recovered, expected);
    }

    #[tokio::test]
    async fn stream_encrypt_with_write_verify() {
        let key = generate_data_key();
        let data = b"verified stream write";
        let (_chunk_dir, chunk_paths) = write_chunk_files(&[data]);

        let dest = NamedTempFile::new().unwrap();
        stream_encrypt_chunks_to_file(
            &key,
            &chunk_paths,
            data.len() as u64,
            dest.path(),
            true, // write-verify enabled
        )
        .await
        .unwrap();

        let recovered = stream_decrypt_file(&key, dest.path()).await.unwrap();
        assert_eq!(recovered, data);
    }

    #[tokio::test]
    async fn stream_file_hash_valid_without_key() {
        let key = generate_data_key();
        let data = b"key-free stream check";
        let (_chunk_dir, chunk_paths) = write_chunk_files(&[data]);

        let dest = NamedTempFile::new().unwrap();
        stream_encrypt_chunks_to_file(
            &key,
            &chunk_paths,
            data.len() as u64,
            dest.path(),
            false,
        )
        .await
        .unwrap();

        // Key-free file hash check should pass.
        assert!(verify_file_hash(dest.path()).await.is_ok());
    }

    #[tokio::test]
    async fn stream_file_hash_catches_corruption_without_key() {
        let key = generate_data_key();
        let data = b"corrupt stream check";
        let (_chunk_dir, chunk_paths) = write_chunk_files(&[data]);

        let dest = NamedTempFile::new().unwrap();
        stream_encrypt_chunks_to_file(
            &key,
            &chunk_paths,
            data.len() as u64,
            dest.path(),
            false,
        )
        .await
        .unwrap();

        // Tamper a byte in the encrypted segment area.
        let mut raw = std::fs::read(dest.path()).unwrap();
        raw[MAGIC_LEN + STREAM_NONCE_LEN + 6] ^= 0xFF;
        std::fs::write(dest.path(), &raw).unwrap();

        assert!(verify_file_hash(dest.path()).await.is_err());
    }

    #[tokio::test]
    async fn stream_decrypt_wrong_key_fails() {
        let key1 = generate_data_key();
        let key2 = generate_data_key();
        let data = b"stream wrong key";
        let (_chunk_dir, chunk_paths) = write_chunk_files(&[data]);

        let dest = NamedTempFile::new().unwrap();
        stream_encrypt_chunks_to_file(
            &key1,
            &chunk_paths,
            data.len() as u64,
            dest.path(),
            false,
        )
        .await
        .unwrap();

        assert!(stream_decrypt_file(&key2, dest.path()).await.is_err());
    }

    #[tokio::test]
    async fn integrity_async_key_free_valid_stream() {
        let key = generate_data_key();
        let data = b"stream integrity async";
        let (_chunk_dir, chunk_paths) = write_chunk_files(&[data]);

        let dest = NamedTempFile::new().unwrap();
        stream_encrypt_chunks_to_file(
            &key,
            &chunk_paths,
            data.len() as u64,
            dest.path(),
            false,
        )
        .await
        .unwrap();

        let status = verify_file_integrity_async(None, dest.path()).await;
        assert_eq!(status, IntegrityStatus::Ok);
    }

    #[tokio::test]
    async fn integrity_async_key_free_corrupted_stream() {
        let key = generate_data_key();
        let data = b"stream tamper async";
        let (_chunk_dir, chunk_paths) = write_chunk_files(&[data]);

        let dest = NamedTempFile::new().unwrap();
        stream_encrypt_chunks_to_file(
            &key,
            &chunk_paths,
            data.len() as u64,
            dest.path(),
            false,
        )
        .await
        .unwrap();

        let mut raw = std::fs::read(dest.path()).unwrap();
        raw[MAGIC_LEN + STREAM_NONCE_LEN + 4] ^= 0xFF;
        std::fs::write(dest.path(), &raw).unwrap();

        let status = verify_file_integrity_async(None, dest.path()).await;
        assert_eq!(status, IntegrityStatus::FileHashMismatch);
    }

    #[tokio::test]
    async fn integrity_async_wrong_key_stream() {
        let key1 = generate_data_key();
        let key2 = generate_data_key();
        let data = b"stream wrong key async";
        let (_chunk_dir, chunk_paths) = write_chunk_files(&[data]);

        let dest = NamedTempFile::new().unwrap();
        stream_encrypt_chunks_to_file(
            &key1,
            &chunk_paths,
            data.len() as u64,
            dest.path(),
            false,
        )
        .await
        .unwrap();

        // File hash passes, GCM tags fail.
        let status = verify_file_integrity_async(Some(&key2), dest.path()).await;
        assert!(
            matches!(status, IntegrityStatus::DecryptionFailed(_)),
            "Expected DecryptionFailed, got: {:?}",
            status
        );
    }

    #[tokio::test]
    async fn integrity_async_correct_key_stream() {
        let key = generate_data_key();
        let data = b"stream correct key async";
        let (_chunk_dir, chunk_paths) = write_chunk_files(&[data]);

        let dest = NamedTempFile::new().unwrap();
        stream_encrypt_chunks_to_file(
            &key,
            &chunk_paths,
            data.len() as u64,
            dest.path(),
            false,
        )
        .await
        .unwrap();

        let status = verify_file_integrity_async(Some(&key), dest.path()).await;
        assert_eq!(status, IntegrityStatus::Ok);
    }
}
