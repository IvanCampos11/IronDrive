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
const CHECKSUM_LEN: usize = 32;
const WRAPPED_KEY_LEN: usize = NONCE_LEN + KEY_LEN + TAG_LEN;

/// Minimum valid encrypted file: nonce (12) + tag (16) + checksum (32) = 60 bytes.
const MIN_ENCRYPTED_FILE_LEN: usize = NONCE_LEN + TAG_LEN + CHECKSUM_LEN;

/// Buffer size for streaming SHA-256 reads.
const HASH_BUF_SIZE: usize = 64 * 1024;

// ---------------------------------------------------------------------------
// V2 STREAM format constants
// ---------------------------------------------------------------------------
//
// On-disk layout for chunk-assembled (large) files:
//
//  [magic: 3 bytes 0x49 0x44 0x02] [stream_nonce: 7 bytes]
//  [plaintext_sha256: 32 bytes]
//  repeated per segment:
//    [seg_payload_len: 4 bytes LE]  -- length of ciphertext+tag = plaintext_chunk_len + 16
//    [ciphertext+tag: seg_payload_len bytes]
//
// The STREAM construction is STREAM-BE32 over AES-256-GCM.
// Each segment is independently authenticated; replay/reorder attacks are
// prevented by the BE32 counter embedded in each per-segment nonce.
// The external nonce is 7 bytes (AES-GCM 12-byte nonce minus 5 bytes of BE32 overhead).

/// Magic prefix that identifies a V2 STREAM-encrypted file.
const STREAM_MAGIC: [u8; 3] = [0x49, 0x44, 0x02]; // "ID\x02"
/// External nonce length for STREAM-BE32 over AES-256-GCM (12 - 5 = 7).
const STREAM_NONCE_LEN: usize = 7;
/// Fixed overhead per segment on disk: 4-byte length prefix.
const STREAM_SEGMENT_HEADER_LEN: usize = 4;

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
/// `nonce (12) ‖ ciphertext+tag (N+16) ‖ SHA-256(plaintext) (32)`.
pub fn encrypt_file_bytes(data_key: &DataKey, plaintext: &[u8]) -> Result<Vec<u8>, AppError> {
    let checksum = sha256_bytes(plaintext);

    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(data_key.as_bytes()));

    let mut nonce_bytes = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext_and_tag = cipher
        .encrypt(nonce, plaintext)
        .map_err(|e| AppError::Internal(format!("File encryption failed: {e}")))?;

    let total_len = NONCE_LEN + ciphertext_and_tag.len() + CHECKSUM_LEN;
    let mut blob = Vec::with_capacity(total_len);
    blob.extend_from_slice(&nonce_bytes);
    blob.extend_from_slice(&ciphertext_and_tag);
    blob.extend_from_slice(&checksum);

    Ok(blob)
}

/// Outcome of `decrypt_file_bytes_inner` — used by `verify_file_integrity`
/// to distinguish checksum failures from decryption failures without string matching.
enum DecryptOutcome {
    Ok(Vec<u8>),
    DecryptionFailed(String),
    ChecksumMismatch,
}

/// Core decrypt logic returning a typed outcome for precise error discrimination.
fn decrypt_file_bytes_inner(data_key: &DataKey, blob: &[u8]) -> DecryptOutcome {
    if blob.len() < MIN_ENCRYPTED_FILE_LEN {
        return DecryptOutcome::DecryptionFailed(format!(
            "Encrypted file too small ({} bytes, minimum {MIN_ENCRYPTED_FILE_LEN})",
            blob.len(),
        ));
    }

    let checksum_start = blob.len() - CHECKSUM_LEN;
    let nonce_bytes = &blob[..NONCE_LEN];
    let ciphertext_and_tag = &blob[NONCE_LEN..checksum_start];
    let stored_checksum = &blob[checksum_start..];

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

    let computed_checksum = sha256_bytes(&plaintext);
    if computed_checksum != stored_checksum {
        return DecryptOutcome::ChecksumMismatch;
    }

    DecryptOutcome::Ok(plaintext)
}

/// Decrypt an on-disk encrypted file blob and verify its SHA-256 checksum.
pub fn decrypt_file_bytes(data_key: &DataKey, blob: &[u8]) -> Result<Vec<u8>, AppError> {
    match decrypt_file_bytes_inner(data_key, blob) {
        DecryptOutcome::Ok(plaintext) => Ok(plaintext),
        DecryptOutcome::ChecksumMismatch => Err(AppError::Internal(
            "File checksum mismatch after decryption — data corrupted".to_string(),
        )),
        DecryptOutcome::DecryptionFailed(msg) => Err(AppError::Internal(msg)),
    }
}

/// Result of integrity verification against an encrypted file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IntegrityStatus {
    Ok,
    ChecksumMismatch,
    DecryptionFailed(String),
}

/// Verify the integrity of an encrypted file without returning the plaintext.
/// Used by the background integrity scanner.
pub fn verify_file_integrity(data_key: &DataKey, blob: &[u8]) -> IntegrityStatus {
    match decrypt_file_bytes_inner(data_key, blob) {
        DecryptOutcome::Ok(_) => IntegrityStatus::Ok,
        DecryptOutcome::ChecksumMismatch => IntegrityStatus::ChecksumMismatch,
        DecryptOutcome::DecryptionFailed(msg) => IntegrityStatus::DecryptionFailed(msg),
    }
}

// ---------------------------------------------------------------------------
// SHA-256 helpers
// ---------------------------------------------------------------------------

/// SHA-256 of an in-memory byte slice.
pub fn sha256_bytes(data: &[u8]) -> [u8; CHECKSUM_LEN] {
    Sha256::digest(data).into()
}

/// SHA-256 of a file on disk via streaming reads. Avoids loading the entire
/// file into memory.
pub async fn sha256_file(path: &Path) -> Result<[u8; CHECKSUM_LEN], AppError> {
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

/// Encrypt plaintext and write to disk with an optional write-verify pass.
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
/// This avoids allocating a second full-size buffer for ciphertext, which is
/// critical for large chunk-assembled uploads.
pub async fn encrypt_and_write_file_owned(
    data_key: &DataKey,
    mut plaintext: Vec<u8>,
    dest: &Path,
    write_verify: bool,
) -> Result<(), AppError> {
    let checksum = sha256_bytes(&plaintext);

    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(data_key.as_bytes()));

    let mut nonce_bytes = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let tag = cipher
        .encrypt_in_place_detached(nonce, b"", &mut plaintext)
        .map_err(|e| AppError::Internal(format!("File encryption failed: {e}")))?;

    let mut file = tokio::fs::File::create(dest)
        .await
        .map_err(|e| AppError::Internal(format!("Failed to write encrypted file: {e}")))?;

    file.write_all(&nonce_bytes)
        .await
        .map_err(|e| AppError::Internal(format!("Failed to write encrypted file nonce: {e}")))?;
    file.write_all(&plaintext)
        .await
        .map_err(|e| AppError::Internal(format!("Failed to write encrypted file body: {e}")))?;
    file.write_all(tag.as_slice())
        .await
        .map_err(|e| AppError::Internal(format!("Failed to write encrypted file tag: {e}")))?;
    file.write_all(&checksum)
        .await
        .map_err(|e| AppError::Internal(format!("Failed to write encrypted file checksum: {e}")))?;
    file.flush()
        .await
        .map_err(|e| AppError::Internal(format!("Failed to flush encrypted file: {e}")))?;
    file.sync_data()
        .await
        .map_err(|e| AppError::Internal(format!("Failed to sync encrypted file to disk: {e}")))?;

    if write_verify {
        let readback = tokio::fs::read(dest).await.map_err(|e| {
            AppError::Internal(format!("Write-verify: failed to read back file: {e}"))
        })?;

        // Validate by decrypting and comparing checksums instead of allocating
        // a second expected encrypted blob of the same size.
        let decrypted = decrypt_file_bytes(data_key, &readback)?;
        let readback_checksum = sha256_bytes(&decrypted);
        if readback_checksum != checksum {
            return Err(AppError::Internal(
                "Write-verify failed: decrypted checksum mismatch after write".to_string(),
            ));
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// V2 STREAM encrypt / decrypt (chunk-file streaming, O(segment) RAM)
// ---------------------------------------------------------------------------

/// Encrypt a sequence of on-disk chunk files into a single V2 STREAM file.
///
/// Each chunk file is read one at a time, encrypted with a fresh STREAM segment,
/// and written to `dest` before the next chunk is loaded. Peak RAM usage is
/// bounded by a single chunk buffer plus one segment's tag overhead.
///
/// `total_plaintext_bytes` is the expected total across all chunks and is used
/// only for a size sanity check.
///
/// `write_verify` causes a full streaming re-decrypt of the written file and
/// compares the SHA-256 against `expected_checksum`.
pub async fn stream_encrypt_chunks_to_file(
    data_key: &DataKey,
    chunk_paths: &[std::path::PathBuf],
    total_plaintext_bytes: u64,
    expected_checksum: Option<&[u8; CHECKSUM_LEN]>,
    dest: &Path,
    write_verify: bool,
) -> Result<[u8; CHECKSUM_LEN], AppError> {
    // Generate a random 7-byte external stream nonce.
    let mut stream_nonce = [0u8; STREAM_NONCE_LEN];
    OsRng.fill_bytes(&mut stream_nonce);

    // We need the plaintext SHA-256 before we begin writing (it goes in the
    // header). We compute it by streaming through the chunk files once first.
    // This costs one extra sequential disk I/O pass but no extra RAM.
    let plaintext_checksum = sha256_chunks(chunk_paths, total_plaintext_bytes).await?;

    if let Some(expected) = expected_checksum {
        if &plaintext_checksum != expected {
            return Err(AppError::Validation(
                "Assembled file checksum mismatch; upload rejected.".into(),
            ));
        }
    }

    // Open the output file.
    let mut out = tokio::fs::File::create(dest)
        .await
        .map_err(|e| AppError::Internal(format!("Failed to create encrypted file: {e}")))?;

    // Write header: magic (3) + stream nonce (7) + plaintext SHA-256 (32).
    out.write_all(&STREAM_MAGIC)
        .await
        .map_err(|e| AppError::Internal(format!("Failed to write STREAM magic: {e}")))?;
    out.write_all(&stream_nonce)
        .await
        .map_err(|e| AppError::Internal(format!("Failed to write STREAM nonce: {e}")))?;
    out.write_all(&plaintext_checksum)
        .await
        .map_err(|e| AppError::Internal(format!("Failed to write STREAM checksum: {e}")))?;

    // Build the STREAM encryptor.
    let key = Key::<Aes256Gcm>::from_slice(data_key.as_bytes());
    let nonce_ga = aes_gcm::aead::generic_array::GenericArray::from_slice(&stream_nonce);
    // Wrap in Option so we can move out of it for encrypt_last_in_place (which takes self).
    let mut encryptor: Option<EncryptorBE32<Aes256Gcm>> =
        Some(EncryptorBE32::<Aes256Gcm>::new(key, nonce_ga));

    let total = chunk_paths.len();
    for (i, path) in chunk_paths.iter().enumerate() {
        let mut buf = tokio::fs::read(path)
            .await
            .map_err(|_| AppError::Validation(format!("Missing chunk {}.", i)))?;

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
        out.write_all(&seg_len.to_le_bytes())
            .await
            .map_err(|e| AppError::Internal(format!("Failed to write segment header: {e}")))?;
        out.write_all(&buf)
            .await
            .map_err(|e| AppError::Internal(format!("Failed to write segment body: {e}")))?;
    }

    out.flush()
        .await
        .map_err(|e| AppError::Internal(format!("Failed to flush encrypted file: {e}")))?;
    out.sync_data()
        .await
        .map_err(|e| AppError::Internal(format!("Failed to sync encrypted file to disk: {e}")))?;
    drop(out);

    if write_verify {
        let verified_checksum = stream_decrypt_file_checksum_only(data_key, dest).await?;
        if verified_checksum != plaintext_checksum {
            return Err(AppError::Internal(
                "Write-verify failed: decrypted checksum mismatch after STREAM write".to_string(),
            ));
        }
    }

    Ok(plaintext_checksum)
}

/// Read and decrypt a V2 STREAM-encrypted file, returning all plaintext.
pub async fn stream_decrypt_file(
    data_key: &DataKey,
    path: &Path,
) -> Result<Vec<u8>, AppError> {
    let (plaintext, stored_checksum) = stream_decrypt_file_inner(data_key, path).await?;

    let computed = sha256_bytes(&plaintext);
    if computed != stored_checksum {
        return Err(AppError::Internal(
            "STREAM file checksum mismatch after decryption — data corrupted".to_string(),
        ));
    }

    Ok(plaintext)
}

/// Verify a V2 STREAM file's integrity without materialising the full plaintext.
///
/// Decrypts each segment, feeds it into a SHA-256 hasher, and immediately
/// drops the plaintext — so peak RAM is bounded to one segment buffer.
/// Returns the computed checksum so callers can compare it if needed.
pub async fn stream_decrypt_file_checksum_only(
    data_key: &DataKey,
    path: &Path,
) -> Result<[u8; CHECKSUM_LEN], AppError> {
    use tokio::io::AsyncReadExt;

    let mut file = tokio::fs::File::open(path)
        .await
        .map_err(|e| AppError::Internal(format!("Failed to open STREAM file for verify: {e}")))?;

    let header_len = STREAM_MAGIC.len() + STREAM_NONCE_LEN + CHECKSUM_LEN;
    let mut header_buf = vec![0u8; header_len];
    file.read_exact(&mut header_buf)
        .await
        .map_err(|_| AppError::Internal("STREAM file too small to contain header".into()))?;

    if header_buf[..3] != STREAM_MAGIC {
        return Err(AppError::Internal("STREAM file has wrong magic bytes".into()));
    }

    let stream_nonce = &header_buf[3..3 + STREAM_NONCE_LEN];
    let stored_checksum: [u8; CHECKSUM_LEN] = header_buf[3 + STREAM_NONCE_LEN..header_len]
        .try_into()
        .expect("slice length guaranteed by header_len check");

    let key = Key::<Aes256Gcm>::from_slice(data_key.as_bytes());
    let nonce_ga = aes_gcm::aead::generic_array::GenericArray::from_slice(stream_nonce);
    let mut decryptor = DecryptorBE32::<Aes256Gcm>::new(key, nonce_ga);

    let mut hasher = Sha256::new();
    let mut pending: Option<Vec<u8>> = None;
    let mut seg_len_buf = [0u8; 4];

    loop {
        // Try to read the next segment header (4 bytes).
        match file.read_exact(&mut seg_len_buf).await {
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                // End of file — flush pending segment as last.
                if let Some(mut seg) = pending.take() {
                    decryptor
                        .decrypt_last_in_place(b"", &mut seg)
                        .map_err(|_| AppError::Internal(
                            "STREAM verify: decrypt last segment failed".into(),
                        ))?;
                    hasher.update(&seg);
                }
                break;
            }
            Err(e) => {
                return Err(AppError::Internal(format!(
                    "STREAM verify: failed to read segment header: {e}"
                )));
            }
        }

        let seg_len = u32::from_le_bytes(seg_len_buf) as usize;
        let mut seg_data = vec![0u8; seg_len];
        file.read_exact(&mut seg_data)
            .await
            .map_err(|e| AppError::Internal(format!(
                "STREAM verify: truncated segment body: {e}"
            )))?;

        // Decrypt the previously pending segment as a non-last segment.
        if let Some(mut prev) = pending.take() {
            decryptor
                .decrypt_next_in_place(b"", &mut prev)
                .map_err(|_| AppError::Internal(
                    "STREAM verify: decrypt segment failed".into(),
                ))?;
            hasher.update(&prev);
        }

        pending = Some(seg_data);
    }

    let computed: [u8; CHECKSUM_LEN] = hasher.finalize().into();
    if computed != stored_checksum {
        return Err(AppError::Internal(
            "STREAM file checksum mismatch — data corrupted".to_string(),
        ));
    }

    Ok(computed)
}

/// Internal: parse and decrypt a V2 STREAM file, returning `(plaintext, stored_checksum)`.
async fn stream_decrypt_file_inner(
    data_key: &DataKey,
    path: &Path,
) -> Result<(Vec<u8>, [u8; CHECKSUM_LEN]), AppError> {
    let raw = tokio::fs::read(path)
        .await
        .map_err(|e| AppError::Internal(format!("Failed to read STREAM encrypted file: {e}")))?;

    let header_len = STREAM_MAGIC.len() + STREAM_NONCE_LEN + CHECKSUM_LEN;
    if raw.len() < header_len {
        return Err(AppError::Internal(
            "STREAM file too small to contain header".into(),
        ));
    }

    if raw[..3] != STREAM_MAGIC {
        return Err(AppError::Internal(
            "STREAM file has wrong magic bytes".into(),
        ));
    }

    let stream_nonce = &raw[3..3 + STREAM_NONCE_LEN];
    let stored_checksum: [u8; CHECKSUM_LEN] = raw
        [3 + STREAM_NONCE_LEN..header_len]
        .try_into()
        .expect("slice length guaranteed by header_len check");

    let key = Key::<Aes256Gcm>::from_slice(data_key.as_bytes());
    let nonce_ga = aes_gcm::aead::generic_array::GenericArray::from_slice(stream_nonce);
    let mut decryptor = DecryptorBE32::<Aes256Gcm>::new(key, nonce_ga);

    // Walk the segment list and accumulate plaintext.
    let mut plaintext = Vec::new();
    let mut pos = header_len;

    // We track whether we've seen any segment at all so we can call
    // decrypt_last on the final one.
    let mut pending: Option<Vec<u8>> = None;
    let mut is_first_iter = true;

    loop {
        if pos == raw.len() {
            // End of file — flush the pending segment as the last.
            if let Some(mut seg) = pending.take() {
                decryptor
                    .decrypt_last_in_place(b"", &mut seg)
                    .map_err(|_| AppError::Internal(
                        "STREAM decrypt last segment failed — wrong key or tampered data".into(),
                    ))?;
                plaintext.extend_from_slice(&seg);
            } else if is_first_iter {
                // Zero-segment file — unusual but valid (empty upload).
            }
            break;
        }
        is_first_iter = false;

        if pos + STREAM_SEGMENT_HEADER_LEN > raw.len() {
            return Err(AppError::Internal(
                "STREAM file truncated inside segment header".into(),
            ));
        }
        let seg_len = u32::from_le_bytes(
            raw[pos..pos + 4].try_into().expect("slice is 4 bytes"),
        ) as usize;
        pos += STREAM_SEGMENT_HEADER_LEN;

        if pos + seg_len > raw.len() {
            return Err(AppError::Internal(
                "STREAM file truncated inside segment body".into(),
            ));
        }
        let seg_data = raw[pos..pos + seg_len].to_vec();
        pos += seg_len;

        // Decrypt the previously pending segment as a non-last segment.
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

    Ok((plaintext, stored_checksum))
}

/// Check whether a file on disk uses the V2 STREAM format.
pub async fn is_stream_format(path: &Path) -> bool {
    let mut file = match tokio::fs::File::open(path).await {
        Ok(f) => f,
        Err(_) => return false,
    };
    let mut magic = [0u8; 3];
    matches!(file.read_exact(&mut magic).await, Ok(_)) && magic == STREAM_MAGIC
}

/// Compute SHA-256 over a sequence of chunk files without loading them all at once.
async fn sha256_chunks(
    paths: &[std::path::PathBuf],
    total_plaintext_bytes: u64,
) -> Result<[u8; CHECKSUM_LEN], AppError> {
    let mut hasher = Sha256::new();
    let mut total_read: u64 = 0;

    for path in paths {
        let mut file = tokio::fs::File::open(path)
            .await
            .map_err(|e| AppError::Internal(format!("Failed to open chunk for hashing: {e}")))?;

        let mut buf = vec![0u8; HASH_BUF_SIZE];
        loop {
            let n = file.read(&mut buf).await.map_err(|e| {
                AppError::Internal(format!("Failed to read chunk for hashing: {e}"))
            })?;
            if n == 0 {
                break;
            }
            hasher.update(&buf[..n]);
            total_read += n as u64;
        }
    }

    if total_read != total_plaintext_bytes {
        return Err(AppError::Internal(format!(
            "Checksum pass size mismatch: expected {total_plaintext_bytes} bytes, read {total_read}"
        )));
    }

    Ok(hasher.finalize().into())
}

/// Verify integrity of any encrypted file (V1 or V2 STREAM) without returning plaintext.
pub async fn verify_file_integrity_async(
    data_key: &DataKey,
    path: &Path,
) -> IntegrityStatus {
    if is_stream_format(path).await {
        match stream_decrypt_file_checksum_only(data_key, path).await {
            Ok(_) => IntegrityStatus::Ok,
            Err(e) => {
                let msg = format!("{e}");
                if msg.contains("checksum mismatch") {
                    IntegrityStatus::ChecksumMismatch
                } else {
                    IntegrityStatus::DecryptionFailed(msg)
                }
            }
        }
    } else {
        match tokio::fs::read(path).await {
            Ok(blob) => verify_file_integrity(data_key, &blob),
            Err(e) => IntegrityStatus::DecryptionFailed(format!("read error: {e}")),
        }
    }
}

/// Read and decrypt any encrypted file (V1 monolithic or V2 STREAM).
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
        assert_eq!(blob.len(), MIN_ENCRYPTED_FILE_LEN);

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
            NONCE_LEN + plaintext.len() + TAG_LEN + CHECKSUM_LEN
        );

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
        blob[NONCE_LEN + 3] ^= 0xFF;

        let err = decrypt_file_bytes(&key, &blob).unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("decryption failed") || msg.contains("tampered"),
            "Expected decryption failure, got: {msg}"
        );
    }

    #[test]
    fn file_decrypt_tampered_checksum_detected() {
        let key = generate_data_key();
        let plaintext = b"secret data";

        let mut blob = encrypt_file_bytes(&key, plaintext).unwrap();
        let last = blob.len() - 1;
        blob[last] ^= 0xFF;

        // Checksum is outside the GCM-authenticated envelope, so GCM decryption
        // succeeds but the SHA-256 comparison catches the tampering.
        let err = decrypt_file_bytes(&key, &blob);
        assert!(err.is_err(), "Should have detected tampered checksum");
        let msg = format!("{}", err.unwrap_err());
        assert!(
            msg.contains("checksum mismatch"),
            "Expected checksum mismatch, got: {msg}"
        );
    }

    #[test]
    fn file_decrypt_truncated_blob_rejected() {
        let key = generate_data_key();
        let tiny = vec![0u8; MIN_ENCRYPTED_FILE_LEN - 1];
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
    fn verify_integrity_tampered_checksum() {
        let key = generate_data_key();
        let mut blob = encrypt_file_bytes(&key, b"valid").unwrap();
        let last = blob.len() - 1;
        blob[last] ^= 0xFF;
        assert_eq!(
            verify_file_integrity(&key, &blob),
            IntegrityStatus::ChecksumMismatch
        );
    }

    #[test]
    fn verify_integrity_tampered_ciphertext() {
        let key = generate_data_key();
        let mut blob = encrypt_file_bytes(&key, b"valid").unwrap();
        blob[NONCE_LEN + 2] ^= 0xFF;
        match verify_file_integrity(&key, &blob) {
            IntegrityStatus::DecryptionFailed(_) => {}
            other => panic!("Expected DecryptionFailed, got {other:?}"),
        }
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
}
