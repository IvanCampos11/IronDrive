use std::env;
use std::fs;
use std::path::Path;

use rand::RngCore;

/// Application configuration loaded from environment variables.
/// The server can now start with zero config — a secret key will be
/// auto-generated and persisted to `{data_dir}/.secret_key` on first boot.
#[derive(Debug, Clone)]
pub struct AppConfig {
    /// Master encryption key passphrase — encrypts the master key in the DB.
    /// Resolved from (in priority order):
    ///   1. `IRONDRIVE_SECRET_KEY` env var (if set to a real value)
    ///   2. `{data_dir}/.secret_key` file (auto-generated on first boot)
    pub secret_key: String,

    /// Root directory for file storage and the SQLite database.
    pub data_dir: String,

    /// Default disk quota for new users (bytes). Default: 5 GB.
    pub default_quota_bytes: u64,

    /// Maximum single-request upload size (bytes). Default: 5 GB.
    pub max_upload_bytes: u64,

    /// Session token lifetime (hours). Default: 168 (7 days).
    pub session_expiry_hours: u64,

    /// Chunk size for chunked transfers (bytes). Default: 8 MiB.
    pub chunk_size_bytes: u64,

    /// Hours before incomplete chunked uploads are cleaned up. Default: 24.
    pub chunk_upload_expiry_hours: u64,

    /// Suggested max parallel chunks per session. Default: 4.
    pub max_parallel_chunks: u32,

    /// Whether periodic integrity scanning is enabled. Default: true.
    pub integrity_scan_enabled: bool,

    /// Integrity scan interval (hours). Default: 168 (weekly).
    pub integrity_scan_interval_hours: u64,
}

const PLACEHOLDER_KEY: &str = "CHANGE-ME-generate-a-random-256-bit-key-here";
const SECRET_KEY_FILENAME: &str = ".secret_key";

impl AppConfig {
    /// Load configuration from environment variables (including `.env` via dotenvy).
    ///
    /// Secret key resolution order:
    ///   1. `IRONDRIVE_SECRET_KEY` env var (if present and not the placeholder)
    ///   2. Existing `{data_dir}/.secret_key` file
    ///   3. Auto-generate a new key → write to `{data_dir}/.secret_key`
    pub fn from_env() -> Self {
        let data_dir = env_or("IRONDRIVE_DATA_DIR", "./data");
        let secret_key = resolve_secret_key(&data_dir);

        Self {
            secret_key,
            data_dir,
            default_quota_bytes: env_parse("IRONDRIVE_DEFAULT_QUOTA_BYTES", 5_368_709_120),
            max_upload_bytes: env_parse("IRONDRIVE_MAX_UPLOAD_BYTES", 5_368_709_120),
            session_expiry_hours: env_parse("IRONDRIVE_SESSION_EXPIRY_HOURS", 168),
            chunk_size_bytes: env_parse("IRONDRIVE_CHUNK_SIZE_BYTES", 8_388_608),
            chunk_upload_expiry_hours: env_parse("IRONDRIVE_CHUNK_UPLOAD_EXPIRY_HOURS", 24),
            max_parallel_chunks: env_parse("IRONDRIVE_MAX_PARALLEL_CHUNKS", 4),
            integrity_scan_enabled: env_parse("IRONDRIVE_INTEGRITY_SCAN_ENABLED", true),
            integrity_scan_interval_hours: env_parse(
                "IRONDRIVE_INTEGRITY_SCAN_INTERVAL_HOURS",
                168,
            ),
        }
    }

    /// Returns the path to the libraries storage directory.
    pub fn libraries_dir(&self) -> String {
        format!("{}/libraries", self.data_dir)
    }

    /// Returns the path to the spaces storage directory.
    pub fn spaces_dir(&self) -> String {
        format!("{}/spaces", self.data_dir)
    }

    /// Returns the path to the chunks staging directory.
    pub fn chunks_dir(&self) -> String {
        format!("{}/.chunks", self.data_dir)
    }
}

/// Resolve the secret key using the priority chain:
///   1. `IRONDRIVE_SECRET_KEY` env var (if set to a real, non-placeholder value)
///   2. Existing `{data_dir}/.secret_key` file on disk
///   3. Auto-generate → persist to `{data_dir}/.secret_key`
fn resolve_secret_key(data_dir: &str) -> String {
    // 1. Check env var first — it always wins if it's a real value.
    if let Ok(key) = env::var("IRONDRIVE_SECRET_KEY") {
        let trimmed = key.trim().to_string();
        if !trimmed.is_empty() && trimmed != PLACEHOLDER_KEY {
            tracing::info!("Using secret key from IRONDRIVE_SECRET_KEY environment variable");
            return trimmed;
        }
        // If it's the placeholder or empty, fall through to file / auto-generate.
        tracing::warn!("IRONDRIVE_SECRET_KEY is set to the placeholder value — ignoring it");
    }

    // 2. Try loading from the persisted key file.
    let key_path = Path::new(data_dir).join(SECRET_KEY_FILENAME);

    if key_path.exists() {
        match fs::read_to_string(&key_path) {
            Ok(contents) => {
                let trimmed = contents.trim().to_string();
                if !trimmed.is_empty() {
                    tracing::info!(
                        path = %key_path.display(),
                        "Loaded secret key from file"
                    );
                    return trimmed;
                }
                tracing::warn!(
                    path = %key_path.display(),
                    "Secret key file exists but is empty — regenerating"
                );
            }
            Err(e) => {
                tracing::warn!(
                    path = %key_path.display(),
                    error = %e,
                    "Failed to read secret key file — regenerating"
                );
            }
        }
    }

    // 3. Auto-generate a new key and persist it.
    let key = generate_secret_key();
    persist_secret_key(data_dir, &key_path, &key);

    tracing::warn!("==========================================================");
    tracing::warn!("  AUTO-GENERATED a new IRONDRIVE_SECRET_KEY.");
    tracing::warn!("  Saved to: {}", key_path.display());
    tracing::warn!("");
    tracing::warn!("  *** BACK UP THIS FILE! ***");
    tracing::warn!("  If you lose it, ALL server-encrypted data becomes");
    tracing::warn!("  permanently inaccessible.");
    tracing::warn!("");
    tracing::warn!("  To use your own key instead, set the");
    tracing::warn!("  IRONDRIVE_SECRET_KEY environment variable.");
    tracing::warn!("==========================================================");

    key
}

/// Generate a cryptographically random 32-byte key, returned as base64.
fn generate_secret_key() -> String {
    use base64::Engine;
    let mut bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut bytes);
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

/// Persist the secret key to `{data_dir}/.secret_key`, creating the data
/// directory if it doesn't already exist.
///
/// # Panics
/// Panics if the directory can't be created or the file can't be written —
/// there's no sane way to continue without a persisted key.
fn persist_secret_key(data_dir: &str, key_path: &Path, key: &str) {
    // Ensure the data directory exists (it might not on very first boot,
    // since the Rocket fairing that creates subdirs hasn't run yet).
    fs::create_dir_all(data_dir)
        .unwrap_or_else(|e| panic!("Failed to create data directory '{}': {}", data_dir, e));

    // Write the key with a trailing newline for readability.
    let contents = format!("{key}\n");
    fs::write(key_path, contents).unwrap_or_else(|e| {
        panic!(
            "Failed to write secret key to '{}': {}",
            key_path.display(),
            e
        )
    });

    // Best-effort: restrict file permissions to owner-only on Unix.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::Permissions::from_mode(0o600);
        let _ = fs::set_permissions(key_path, perms);
    }
}

/// Read an env var or return a default string.
fn env_or(key: &str, default: &str) -> String {
    env::var(key).unwrap_or_else(|_| default.to_string())
}

/// Read an env var, parse it to `T`, or return a default.
///
/// # Panics
/// Panics if the env var is set but cannot be parsed into `T`.
fn env_parse<T>(key: &str, default: T) -> T
where
    T: std::str::FromStr,
    T::Err: std::fmt::Display,
{
    match env::var(key) {
        Ok(val) => val
            .parse()
            .unwrap_or_else(|e| panic!("{key} is set but could not be parsed: {e}")),
        Err(_) => default,
    }
}
