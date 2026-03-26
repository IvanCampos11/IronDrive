use std::env;
use std::fs;
use std::path::Path;

use rand::RngCore;

/// Application configuration loaded from environment variables.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct AppConfig {
    pub secret_key: String,
    pub data_dir: String,
    pub db_dir: String,
    pub default_quota_bytes: u64,
    pub max_upload_bytes: u64,
    pub session_expiry_hours: u64,
    pub chunk_size_bytes: u64,
    pub chunk_upload_expiry_hours: u64,
    pub max_parallel_chunks: u32,
    pub integrity_scan_enabled: bool,
    pub integrity_scan_interval_hours: u64,
}

const PLACEHOLDER_KEY: &str = "CHANGE-ME-generate-a-random-256-bit-key-here";
const SECRET_KEY_FILENAME: &str = ".secret_key";

#[allow(dead_code)]
impl AppConfig {
    /// Load configuration from environment variables.
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

    pub fn libraries_dir(&self) -> String {
        format!("{}/libraries", self.data_dir)
    }

    pub fn spaces_dir(&self) -> String {
        format!("{}/spaces", self.data_dir)
    }

    pub fn chunks_dir(&self) -> String {
        format!("{}/.chunks", self.data_dir)
    }

    pub fn db_url(&self) -> String {
        format!("sqlite:{}/irondrive.db?mode=rwc", self.db_dir)
    }
}

/// Resolve the secret key: env var → file on disk → auto-generate.
fn resolve_secret_key(data_dir: &str) -> String {
    if let Ok(key) = env::var("IRONDRIVE_SECRET_KEY") {
        let trimmed = key.trim().to_string();
        if !trimmed.is_empty() && trimmed != PLACEHOLDER_KEY {
            tracing::info!("Using secret key from IRONDRIVE_SECRET_KEY environment variable");
            return trimmed;
        }
        tracing::warn!("IRONDRIVE_SECRET_KEY is set to the placeholder value — ignoring it");
    }

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

/// Generate a random 32-byte key, returned as base64.
fn generate_secret_key() -> String {
    use base64::Engine;
    let mut bytes = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

/// Write the secret key to `{data_dir}/.secret_key`. Panics on failure.
fn persist_secret_key(data_dir: &str, key_path: &Path, key: &str) {
    fs::create_dir_all(data_dir)
        .unwrap_or_else(|e| panic!("Failed to create data directory '{}': {}", data_dir, e));

    let contents = format!("{key}\n");
    fs::write(key_path, contents).unwrap_or_else(|e| {
        panic!(
            "Failed to write secret key to '{}': {}",
            key_path.display(),
            e
        )
    });

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::Permissions::from_mode(0o600);
        let _ = fs::set_permissions(key_path, perms);
    }
}

/// Read an env var or return a default.
fn env_or(key: &str, default: &str) -> String {
    env::var(key).unwrap_or_else(|_| default.to_string())
}

/// Read an env var, parse it to `T`, or return a default. Panics on bad input.
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

/// Read an env var as a human-friendly size string (e.g. `"5 GB"`) and return
/// bytes. All units use 1024-based multipliers. Panics on bad input.
fn env_size(key: &str, default: u64) -> u64 {
    match env::var(key) {
        Ok(val) => {
            parse_size(&val).unwrap_or_else(|| panic!("{key}={val} — could not parse as a size"))
        }
        Err(_) => default,
    }
}

/// Parse a human-readable size string into bytes. Returns `None` on invalid input.
fn parse_size(s: &str) -> Option<u64> {
    let s = s.trim();

    if let Ok(n) = s.parse::<u64>() {
        return Some(n);
    }

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
