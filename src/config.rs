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

    /// Root directory for file storage (libraries, spaces, chunks).
    pub data_dir: String,

    /// Directory for the SQLite database (separate from file storage).
    pub db_dir: String,

    /// Default disk quota for new users (bytes internally). Default: 5 GB.
    /// Set via `IRONDRIVE_DEFAULT_QUOTA` — accepts human sizes like `"5 GB"`.
    pub default_quota_bytes: u64,

    /// Maximum single-request upload size (bytes internally). Default: 5 GB.
    /// Set via `IRONDRIVE_MAX_UPLOAD` — accepts human sizes like `"5 GB"`.
    pub max_upload_bytes: u64,

    /// Session token lifetime (hours). Default: 168 (7 days).
    pub session_expiry_hours: u64,

    /// Chunk size for chunked transfers (bytes internally). Default: 8 MiB.
    /// Set via `IRONDRIVE_CHUNK_SIZE` — accepts human sizes like `"8 MiB"`.
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
        let db_dir = env_or("IRONDRIVE_DB_DIR", "./db");
        let secret_key = resolve_secret_key(&data_dir);

        Self {
            secret_key,
            data_dir,
            db_dir,
            default_quota_bytes: env_size("IRONDRIVE_DEFAULT_QUOTA", 5_368_709_120),
            max_upload_bytes: env_size("IRONDRIVE_MAX_UPLOAD", 5_368_709_120),
            session_expiry_hours: env_parse("IRONDRIVE_SESSION_EXPIRY_HOURS", 168),
            chunk_size_bytes: env_size("IRONDRIVE_CHUNK_SIZE", 8_388_608),
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

    /// Returns the SQLite connection URL for the database.
    pub fn db_url(&self) -> String {
        format!("sqlite:{}/irondrive.db?mode=rwc", self.db_dir)
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

/// Read an env var as a human-friendly size string and return bytes, or use
/// a default (already in bytes).
///
/// Accepted formats (case-insensitive, optional space between number and unit):
///   - Plain number: `"8388608"` → parsed as bytes
///   - Bytes:   `"500 B"`
///   - KB / KiB: `"500 KB"`, `"512 KiB"`
///   - MB / MiB: `"100 MB"`, `"8 MiB"`
///   - GB / GiB: `"5 GB"`, `"2 GiB"`
///   - TB / TiB: `"1 TB"`, `"1 TiB"`
///
/// `KB`, `MB`, `GB`, `TB` use **binary** (1024-based) multipliers — matching
/// how virtually every OS, tool, and config file uses them in practice.
/// The explicit `KiB`/`MiB`/`GiB`/`TiB` forms also work and are identical.
///
/// # Panics
/// Panics if the env var is set but the value cannot be parsed.
fn env_size(key: &str, default: u64) -> u64 {
    match env::var(key) {
        Ok(val) => {
            parse_size(&val).unwrap_or_else(|| panic!("{key}={val} — could not parse as a size"))
        }
        Err(_) => default,
    }
}

/// Parse a human-readable size string into bytes.
///
/// Returns `None` if the string is not a valid size.
fn parse_size(s: &str) -> Option<u64> {
    let s = s.trim();

    // Fast path: plain integer (raw bytes).
    if let Ok(n) = s.parse::<u64>() {
        return Some(n);
    }

    // Split into numeric part and unit suffix.
    let pos = s
        .find(|c: char| !c.is_ascii_digit() && c != '.')
        .unwrap_or(s.len());

    let num_str = s[..pos].trim();
    let unit_str = s[pos..].trim();

    let num: f64 = num_str.parse().ok()?;
    if num < 0.0 {
        return None;
    }

    let multiplier: u64 = match unit_str.to_ascii_lowercase().as_str() {
        "" | "b" => 1,
        "kb" | "kib" | "k" => 1024,
        "mb" | "mib" | "m" => 1024 * 1024,
        "gb" | "gib" | "g" => 1024 * 1024 * 1024,
        "tb" | "tib" | "t" => 1024 * 1024 * 1024 * 1024,
        _ => return None,
    };

    Some((num * multiplier as f64) as u64)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_size_plain_bytes() {
        assert_eq!(parse_size("8388608"), Some(8_388_608));
        assert_eq!(parse_size("0"), Some(0));
    }

    #[test]
    fn parse_size_with_units() {
        assert_eq!(parse_size("5 GB"), Some(5 * 1024 * 1024 * 1024));
        assert_eq!(parse_size("5GB"), Some(5 * 1024 * 1024 * 1024));
        assert_eq!(parse_size("5 GiB"), Some(5 * 1024 * 1024 * 1024));
        assert_eq!(parse_size("8 MiB"), Some(8 * 1024 * 1024));
        assert_eq!(parse_size("8MiB"), Some(8 * 1024 * 1024));
        assert_eq!(parse_size("8 MB"), Some(8 * 1024 * 1024));
        assert_eq!(parse_size("512 KB"), Some(512 * 1024));
        assert_eq!(parse_size("1 TB"), Some(1024 * 1024 * 1024 * 1024));
    }

    #[test]
    fn parse_size_case_insensitive() {
        assert_eq!(parse_size("5 gb"), Some(5 * 1024 * 1024 * 1024));
        assert_eq!(parse_size("5 Gb"), Some(5 * 1024 * 1024 * 1024));
        assert_eq!(parse_size("8 mib"), Some(8 * 1024 * 1024));
    }

    #[test]
    fn parse_size_fractional() {
        assert_eq!(
            parse_size("1.5 GB"),
            Some((1.5 * 1024.0 * 1024.0 * 1024.0) as u64)
        );
        assert_eq!(parse_size("0.5 MB"), Some((0.5 * 1024.0 * 1024.0) as u64));
    }

    #[test]
    fn parse_size_invalid() {
        assert_eq!(parse_size(""), None);
        assert_eq!(parse_size("abc"), None);
        assert_eq!(parse_size("5 XB"), None);
    }
}
