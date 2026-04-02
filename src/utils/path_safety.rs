use std::path::{Path, PathBuf};

use crate::errors::AppError;

/// Maximum byte length for a single path component (file or directory name).
/// Linux ext4/btrfs/xfs all cap at 255 bytes; macOS HFS+/APFS likewise.
const MAX_COMPONENT_BYTES: usize = 255;

/// Maximum total byte length for the user-supplied path string.
/// Linux `PATH_MAX` is 4096; we leave headroom for the root prefix.
const MAX_PATH_BYTES: usize = 4096;

/// Maximum nesting depth (number of `/`-separated components).
/// Prevents degenerate inputs from causing excessive iteration.
const MAX_DEPTH: usize = 128;

/// Returns a safe, canonical path within `root`.
///
/// This is the **most critical security function** in the codebase. Every
/// user-supplied path must pass through here before touching the filesystem.
///
/// # Rejected inputs
///
/// - Empty paths
/// - Absolute paths (`/`, `\`, Windows drive letters like `C:`)
/// - `..` and `.` components
/// - Dot-prefixed components (`.hidden`, `.irondrive.meta`, etc.)
/// - Components containing null bytes or ASCII control characters
/// - Components exceeding [`MAX_COMPONENT_BYTES`] (255)
/// - Total path length exceeding [`MAX_PATH_BYTES`] (4096)
/// - Nesting depth exceeding [`MAX_DEPTH`] (128)
/// - Whitespace-only or trailing-whitespace component names
/// - Symlinks that resolve outside the root directory
///
/// # Symlink handling
///
/// For every existing path component we call `symlink_metadata` exactly once
/// (avoiding TOCTOU gaps between `exists()` → `metadata()` → `canonicalize()`).
/// If the component is a symlink, or if it resolves outside `root`, the path
/// is rejected.
///
/// # Errors
///
/// Returns [`AppError::Validation`] for all rejected inputs.
pub fn safe_join(root: &Path, user_path: &str) -> Result<PathBuf, AppError> {
    // ── 1. Reject empty ──────────────────────────────────────────────────
    if user_path.is_empty() {
        return Err(AppError::Validation("Path must not be empty.".into()));
    }

    // ── 2. Reject oversized total path ───────────────────────────────────
    if user_path.len() > MAX_PATH_BYTES {
        return Err(AppError::Validation(format!(
            "Path exceeds maximum length of {MAX_PATH_BYTES} bytes."
        )));
    }

    // ── 3. Reject absolute paths ─────────────────────────────────────────
    //    Unix `/`, Windows `\` prefix, or drive letters like `C:`
    if user_path.starts_with('/') || user_path.starts_with('\\') || user_path.contains(':') {
        return Err(AppError::Validation(
            "Absolute paths are not allowed.".into(),
        ));
    }

    // ── 4. Split on `/` and `\` and validate every component ─────────────
    let components: Vec<&str> = user_path.split(['/', '\\']).collect();

    if components.len() > MAX_DEPTH {
        return Err(AppError::Validation(format!(
            "Path exceeds maximum nesting depth of {MAX_DEPTH}."
        )));
    }

    for component in &components {
        validate_component(component)?;
    }

    // ── 5. Canonicalize root (must exist) ────────────────────────────────
    let canonical_root = std::fs::canonicalize(root)
        .map_err(|e| AppError::Validation(format!("Root path cannot be resolved: {e}")))?;

    // ── 6. Walk components, checking existing entries for symlink escape ─
    //
    // For each component we attempt `symlink_metadata` on the accumulated
    // path. This is a *single* syscall per component, avoiding the classic
    // TOCTOU gap that arises from separate `exists()` + `metadata()` +
    // `canonicalize()` calls.
    //
    // • If the metadata call succeeds → the entry exists on disk.
    //   – If it's a symlink, resolve and verify it stays within root.
    //   – Otherwise, canonicalize and verify.
    //   – In both cases, continue walking from the *resolved* location so
    //     that nested symlinks are caught.
    //
    // • If the metadata call fails with `NotFound` → the rest of the path
    //   doesn't exist yet. That's fine for uploads/mkdir — we've already
    //   validated the component names above. Append remaining components
    //   to the last known-good prefix and break.
    //
    // • Any other I/O error → propagate.

    let mut current = canonical_root.clone();

    for (i, component) in components.iter().enumerate() {
        current.push(component);

        match std::fs::symlink_metadata(&current) {
            Ok(meta) => {
                // Entry exists. Resolve to a canonical path and ensure it's
                // still under the root.  `canonicalize` follows symlinks
                // recursively, so it covers both the symlink and non-symlink
                // cases in a single shot.
                let resolved = std::fs::canonicalize(&current).map_err(|e| {
                    AppError::Validation(format!("Cannot resolve path component: {e}"))
                })?;

                if !resolved.starts_with(&canonical_root) {
                    // Emit a specific message when we know it was a symlink.
                    if meta.file_type().is_symlink() {
                        return Err(AppError::Validation(
                            "Path escapes the root directory via symlink.".into(),
                        ));
                    }
                    return Err(AppError::Validation(
                        "Path escapes the root directory.".into(),
                    ));
                }

                // Continue walking from the resolved (canonical) path so that
                // subsequent components are validated against the real location.
                current = resolved;
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                // This component doesn't exist on disk yet.  Append the
                // remaining (already-validated) components and stop walking.
                for remaining in &components[i + 1..] {
                    current.push(remaining);
                }
                break;
            }
            Err(e) => {
                return Err(AppError::Validation(format!(
                    "Cannot read metadata for path component: {e}"
                )));
            }
        }
    }

    // ── 7. Belt-and-suspenders: final starts_with check ──────────────────
    if !current.starts_with(&canonical_root) {
        return Err(AppError::Validation(
            "Path escapes the root directory.".into(),
        ));
    }

    Ok(current)
}

/// Validate a single path component (file or directory name).
///
/// Extracted so the rules are in one place and easy to audit.
fn validate_component(component: &str) -> Result<(), AppError> {
    // Empty (double slashes, trailing slash)
    if component.is_empty() {
        return Err(AppError::Validation(
            "Path contains empty components (double slashes or trailing slash).".into(),
        ));
    }

    // Byte length
    if component.len() > MAX_COMPONENT_BYTES {
        return Err(AppError::Validation(format!(
            "Path component exceeds maximum length of {MAX_COMPONENT_BYTES} bytes."
        )));
    }

    // Null bytes
    if component.contains('\0') {
        return Err(AppError::Validation("Path contains null bytes.".into()));
    }

    // ASCII control characters (0x01–0x1F, 0x7F). Null is already caught
    // above but the range includes it for completeness.
    if component.bytes().any(|b| b < 0x20 || b == 0x7F) {
        return Err(AppError::Validation(
            "Path contains control characters.".into(),
        ));
    }

    // `.` current-dir
    if component == "." {
        return Err(AppError::Validation("Path contains '.' component.".into()));
    }

    // `..` parent-dir traversal
    if component == ".." {
        return Err(AppError::Validation(
            "Path traversal ('..') is not allowed.".into(),
        ));
    }

    // Dot-prefixed (hidden files, `.irondrive.meta`, etc.)
    if component.starts_with('.') {
        return Err(AppError::Validation(
            "Dot-prefixed path components are not allowed.".into(),
        ));
    }

    // Whitespace-only or trailing whitespace. Leading whitespace is also
    // rejected because many filesystems silently strip it, creating
    // confusing name mismatches.
    if component != component.trim() {
        return Err(AppError::Validation(
            "Path component has leading or trailing whitespace.".into(),
        ));
    }
    if component.chars().all(char::is_whitespace) {
        return Err(AppError::Validation(
            "Path component is whitespace-only.".into(),
        ));
    }

    Ok(())
}

// ═══════════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    /// Create a fresh temporary directory (caller holds the `TempDir` guard).
    fn make_root() -> TempDir {
        TempDir::new().expect("failed to create temp dir")
    }

    /// Assert that `safe_join` returns `Err(AppError::Validation(_))` whose
    /// message contains `needle`.
    fn assert_validation_err(root: &Path, user_path: &str, needle: &str) {
        let err = safe_join(root, user_path)
            .expect_err(&format!("expected Err for user_path={user_path:?}"));
        match err {
            AppError::Validation(msg) => {
                assert!(
                    msg.contains(needle),
                    "expected message containing {needle:?}, got: {msg:?}"
                );
            }
            other => panic!("expected Validation, got: {other:?}"),
        }
    }

    // ─── Valid paths ───────────────────────────────────────────────────

    #[test]
    fn valid_simple_filename() {
        let root = make_root();
        let result = safe_join(root.path(), "hello.txt").unwrap();
        assert!(result.ends_with("hello.txt"));
    }

    #[test]
    fn valid_nested_path() {
        let root = make_root();
        let result = safe_join(root.path(), "a/b/c/file.txt").unwrap();
        assert!(result.ends_with("a/b/c/file.txt"));
    }

    #[test]
    fn valid_single_component() {
        let root = make_root();
        assert!(safe_join(root.path(), "documents").is_ok());
    }

    #[test]
    fn valid_existing_directory() {
        let root = make_root();
        std::fs::create_dir(root.path().join("subdir")).unwrap();
        let result = safe_join(root.path(), "subdir/newfile.txt").unwrap();
        assert!(result.ends_with("subdir/newfile.txt"));
    }

    #[test]
    fn valid_deeply_nested() {
        let root = make_root();
        assert!(safe_join(root.path(), "a/b/c/d/e/f/g.txt").is_ok());
    }

    #[test]
    fn valid_existing_file() {
        let root = make_root();
        std::fs::write(root.path().join("existing.txt"), b"data").unwrap();
        assert!(safe_join(root.path(), "existing.txt").is_ok());
    }

    #[test]
    fn valid_multiple_components_existing() {
        let root = make_root();
        std::fs::create_dir_all(root.path().join("a/b")).unwrap();
        std::fs::write(root.path().join("a/b/file.txt"), b"content").unwrap();
        assert!(safe_join(root.path(), "a/b/file.txt").is_ok());
    }

    #[test]
    fn valid_path_with_spaces_and_unicode() {
        let root = make_root();
        assert!(safe_join(root.path(), "my folder/日本語/file 名前.txt").is_ok());
    }

    #[test]
    fn valid_path_with_dashes_and_underscores() {
        let root = make_root();
        assert!(safe_join(root.path(), "my-folder/sub_dir/file-name_v2.tar.gz").is_ok());
    }

    // ─── Empty path ────────────────────────────────────────────────────

    #[test]
    fn reject_empty_path() {
        let root = make_root();
        assert_validation_err(root.path(), "", "must not be empty");
    }

    // ─── Overall length limit ──────────────────────────────────────────

    #[test]
    fn reject_overly_long_path() {
        let root = make_root();
        // 4097 bytes of `a` exceeds MAX_PATH_BYTES (4096)
        let long = "a".repeat(MAX_PATH_BYTES + 1);
        assert_validation_err(root.path(), &long, "maximum length");
    }

    #[test]
    fn accept_path_at_max_length() {
        let root = make_root();
        // Exactly MAX_PATH_BYTES should be fine (single component ≤ 255).
        // Build a path of 128 components of 31 chars each + 127 slashes = 4095
        let comp = "a".repeat(31);
        let path = std::iter::repeat(comp.as_str())
            .take(MAX_DEPTH)
            .collect::<Vec<_>>()
            .join("/");
        assert!(path.len() <= MAX_PATH_BYTES);
        assert!(safe_join(root.path(), &path).is_ok());
    }

    // ─── Component length limit ────────────────────────────────────────

    #[test]
    fn reject_overly_long_component() {
        let root = make_root();
        let long_name = "a".repeat(MAX_COMPONENT_BYTES + 1);
        assert_validation_err(root.path(), &long_name, "maximum length");
    }

    #[test]
    fn accept_component_at_max_length() {
        let root = make_root();
        let name = "a".repeat(MAX_COMPONENT_BYTES);
        assert!(safe_join(root.path(), &name).is_ok());
    }

    // ─── Depth limit ───────────────────────────────────────────────────

    #[test]
    fn reject_excessive_depth() {
        let root = make_root();
        let deep = std::iter::repeat("d")
            .take(MAX_DEPTH + 1)
            .collect::<Vec<_>>()
            .join("/");
        assert_validation_err(root.path(), &deep, "nesting depth");
    }

    // ─── Dot-dot traversal ─────────────────────────────────────────────

    #[test]
    fn reject_dotdot_simple() {
        let root = make_root();
        assert_validation_err(root.path(), "..", "..");
    }

    #[test]
    fn reject_dotdot_prefix() {
        let root = make_root();
        assert_validation_err(root.path(), "../etc/passwd", "..");
    }

    #[test]
    fn reject_dotdot_middle() {
        let root = make_root();
        assert_validation_err(root.path(), "a/../b", "..");
    }

    #[test]
    fn reject_dotdot_suffix() {
        let root = make_root();
        assert_validation_err(root.path(), "a/b/..", "..");
    }

    #[test]
    fn reject_dotdot_repeated() {
        let root = make_root();
        assert_validation_err(root.path(), "a/../../..", "..");
    }

    // ─── Dot components ────────────────────────────────────────────────

    #[test]
    fn reject_single_dot() {
        let root = make_root();
        assert_validation_err(root.path(), ".", "'.'");
    }

    #[test]
    fn reject_dot_in_middle() {
        let root = make_root();
        assert_validation_err(root.path(), "a/./b", "'.'");
    }

    // ─── Dot-prefixed components (hidden files) ────────────────────────

    #[test]
    fn reject_dot_hidden_file() {
        let root = make_root();
        assert_validation_err(root.path(), ".hidden", "Dot-prefixed");
    }

    #[test]
    fn reject_irondrive_meta() {
        let root = make_root();
        assert_validation_err(root.path(), ".irondrive.meta", "Dot-prefixed");
    }

    #[test]
    fn reject_dot_prefixed_nested() {
        let root = make_root();
        assert_validation_err(root.path(), "a/.secret/b", "Dot-prefixed");
    }

    #[test]
    fn reject_dot_gitignore() {
        let root = make_root();
        assert_validation_err(root.path(), "dir/.gitignore", "Dot-prefixed");
    }

    // ─── Absolute paths ────────────────────────────────────────────────

    #[test]
    fn reject_absolute_unix() {
        let root = make_root();
        assert_validation_err(root.path(), "/etc/passwd", "Absolute");
    }

    #[test]
    fn reject_absolute_backslash() {
        let root = make_root();
        assert_validation_err(root.path(), "\\windows\\system32", "Absolute");
    }

    #[test]
    fn reject_windows_drive_letter() {
        let root = make_root();
        assert_validation_err(root.path(), "C:\\Users", "Absolute");
    }

    #[test]
    fn reject_drive_colon_only() {
        let root = make_root();
        assert_validation_err(root.path(), "D:file.txt", "Absolute");
    }

    // ─── Null bytes ────────────────────────────────────────────────────

    #[test]
    fn reject_null_byte_in_name() {
        let root = make_root();
        assert_validation_err(root.path(), "file\0.txt", "null");
    }

    #[test]
    fn reject_null_byte_in_component() {
        let root = make_root();
        assert_validation_err(root.path(), "a/b\0c/d", "null");
    }

    // ─── Control characters ────────────────────────────────────────────

    #[test]
    fn reject_tab_in_name() {
        let root = make_root();
        assert_validation_err(root.path(), "file\tname.txt", "control");
    }

    #[test]
    fn reject_newline_in_name() {
        let root = make_root();
        assert_validation_err(root.path(), "file\nname.txt", "control");
    }

    #[test]
    fn reject_carriage_return_in_name() {
        let root = make_root();
        assert_validation_err(root.path(), "file\rname.txt", "control");
    }

    #[test]
    fn reject_bell_character() {
        let root = make_root();
        assert_validation_err(root.path(), "file\x07name.txt", "control");
    }

    #[test]
    fn reject_escape_character() {
        let root = make_root();
        assert_validation_err(root.path(), "file\x1Bname.txt", "control");
    }

    #[test]
    fn reject_del_character() {
        let root = make_root();
        assert_validation_err(root.path(), "file\x7Fname.txt", "control");
    }

    // ─── Whitespace edge cases ─────────────────────────────────────────

    #[test]
    fn reject_leading_whitespace() {
        let root = make_root();
        assert_validation_err(root.path(), " leading.txt", "whitespace");
    }

    #[test]
    fn reject_trailing_whitespace() {
        let root = make_root();
        assert_validation_err(root.path(), "trailing.txt ", "whitespace");
    }

    #[test]
    fn reject_whitespace_only_component() {
        let root = make_root();
        assert_validation_err(root.path(), "a/   /b", "whitespace");
    }

    #[test]
    fn allow_interior_spaces() {
        let root = make_root();
        // Interior spaces are fine: "my file.txt"
        assert!(safe_join(root.path(), "my file.txt").is_ok());
    }

    #[test]
    fn reject_leading_whitespace_in_nested_component() {
        let root = make_root();
        assert_validation_err(root.path(), "a/ b/c", "whitespace");
    }

    #[test]
    fn reject_trailing_whitespace_in_nested_component() {
        let root = make_root();
        assert_validation_err(root.path(), "a/b /c", "whitespace");
    }

    // ─── Double slashes / empty components ─────────────────────────────

    #[test]
    fn reject_double_slash() {
        let root = make_root();
        assert_validation_err(root.path(), "a//b", "empty components");
    }

    #[test]
    fn reject_trailing_slash() {
        let root = make_root();
        assert_validation_err(root.path(), "a/b/", "empty components");
    }

    #[test]
    fn reject_leading_slash_variation() {
        let root = make_root();
        // Leading slash is caught by the absolute-path check first.
        assert_validation_err(root.path(), "/a/b", "Absolute");
    }

    // ─── Creative encoding / evasion attempts ──────────────────────────

    #[test]
    fn reject_backslash_dotdot() {
        let root = make_root();
        assert_validation_err(root.path(), "a\\..\\b", "..");
    }

    #[test]
    fn reject_mixed_separators_with_dotdot() {
        let root = make_root();
        assert_validation_err(root.path(), "a/b\\..\\..\\c", "..");
    }

    #[test]
    fn reject_double_backslash() {
        let root = make_root();
        assert_validation_err(root.path(), "a\\\\b", "empty components");
    }

    // ─── Symlink escape detection (Unix only) ──────────────────────────

    #[cfg(unix)]
    #[test]
    fn reject_symlink_escaping_root() {
        let root = make_root();
        let outside = make_root();

        std::fs::write(outside.path().join("secret.txt"), b"secret data").unwrap();

        let link_path = root.path().join("escape_link");
        std::os::unix::fs::symlink(outside.path(), &link_path).unwrap();

        assert_validation_err(root.path(), "escape_link/secret.txt", "escapes");
    }

    #[cfg(unix)]
    #[test]
    fn reject_symlink_to_parent() {
        let root = make_root();

        let link_path = root.path().join("parent_link");
        std::os::unix::fs::symlink(root.path().parent().unwrap(), &link_path).unwrap();

        assert_validation_err(root.path(), "parent_link/etc/passwd", "escapes");
    }

    #[cfg(unix)]
    #[test]
    fn allow_symlink_within_root() {
        let root = make_root();

        let subdir = root.path().join("real_dir");
        std::fs::create_dir(&subdir).unwrap();
        std::fs::write(subdir.join("file.txt"), b"data").unwrap();

        let link_path = root.path().join("internal_link");
        std::os::unix::fs::symlink(&subdir, &link_path).unwrap();

        let result = safe_join(root.path(), "internal_link/file.txt");
        assert!(result.is_ok(), "Expected Ok, got: {result:?}");
    }

    #[cfg(unix)]
    #[test]
    fn reject_nested_symlink_escape() {
        let root = make_root();
        let outside = make_root();

        let subdir = root.path().join("subdir");
        std::fs::create_dir(&subdir).unwrap();

        let link_path = subdir.join("evil_link");
        std::os::unix::fs::symlink(outside.path(), &link_path).unwrap();

        assert_validation_err(root.path(), "subdir/evil_link/file.txt", "escapes");
    }

    #[cfg(unix)]
    #[test]
    fn reject_symlink_pointing_to_absolute() {
        let root = make_root();

        let link_path = root.path().join("tmp_link");
        std::os::unix::fs::symlink("/tmp", &link_path).unwrap();

        assert_validation_err(root.path(), "tmp_link/something", "escapes");
    }

    #[cfg(unix)]
    #[test]
    fn reject_symlink_chain_escape() {
        // link_a → real_dir (inside root), then real_dir/link_b → outside
        let root = make_root();
        let outside = make_root();

        let real_dir = root.path().join("real_dir");
        std::fs::create_dir(&real_dir).unwrap();

        // link_a → real_dir (safe)
        let link_a = root.path().join("link_a");
        std::os::unix::fs::symlink(&real_dir, &link_a).unwrap();

        // real_dir/link_b → outside (unsafe)
        let link_b = real_dir.join("link_b");
        std::os::unix::fs::symlink(outside.path(), &link_b).unwrap();

        assert_validation_err(root.path(), "link_a/link_b/secret.txt", "escapes");
    }

    // ─── Root doesn't exist ────────────────────────────────────────────

    #[test]
    fn reject_nonexistent_root() {
        let path = Path::new("/nonexistent_root_dir_12345");
        assert_validation_err(path, "file.txt", "Root path");
    }

    // ─── Return-value properties ───────────────────────────────────────

    #[test]
    fn result_starts_with_canonical_root() {
        let root = make_root();
        let result = safe_join(root.path(), "some/path/file.txt").unwrap();
        let canonical_root = std::fs::canonicalize(root.path()).unwrap();
        assert!(
            result.starts_with(&canonical_root),
            "Result {result:?} does not start with root {canonical_root:?}"
        );
    }

    #[test]
    fn result_preserves_filename() {
        let root = make_root();
        let result = safe_join(root.path(), "my_file.txt").unwrap();
        assert_eq!(result.file_name().unwrap().to_str().unwrap(), "my_file.txt");
    }

    #[test]
    fn result_uses_canonical_root_not_original() {
        // Even if root contains a `..` or a symlink, the returned path
        // should be anchored at the *canonical* root.
        let root = make_root();
        let canonical = std::fs::canonicalize(root.path()).unwrap();
        let result = safe_join(root.path(), "file.txt").unwrap();
        assert!(result.starts_with(&canonical));
    }

    // ─── validate_component unit tests ─────────────────────────────────

    #[test]
    fn component_valid_simple() {
        assert!(validate_component("hello.txt").is_ok());
    }

    #[test]
    fn component_reject_empty() {
        assert!(validate_component("").is_err());
    }

    #[test]
    fn component_reject_dot() {
        assert!(validate_component(".").is_err());
    }

    #[test]
    fn component_reject_dotdot() {
        assert!(validate_component("..").is_err());
    }

    #[test]
    fn component_reject_dot_prefix() {
        assert!(validate_component(".hidden").is_err());
    }

    #[test]
    fn component_reject_null() {
        assert!(validate_component("a\0b").is_err());
    }

    #[test]
    fn component_reject_control() {
        assert!(validate_component("a\x01b").is_err());
    }

    #[test]
    fn component_reject_too_long() {
        let long = "x".repeat(MAX_COMPONENT_BYTES + 1);
        assert!(validate_component(&long).is_err());
    }

    #[test]
    fn component_accept_max_length() {
        let name = "x".repeat(MAX_COMPONENT_BYTES);
        assert!(validate_component(&name).is_ok());
    }

    #[test]
    fn component_reject_leading_space() {
        assert!(validate_component(" file").is_err());
    }

    #[test]
    fn component_reject_trailing_space() {
        assert!(validate_component("file ").is_err());
    }

    #[test]
    fn component_reject_whitespace_only() {
        assert!(validate_component("   ").is_err());
    }

    #[test]
    fn component_accept_interior_space() {
        assert!(validate_component("my file").is_ok());
    }

    #[test]
    fn component_accept_unicode() {
        assert!(validate_component("日本語ファイル").is_ok());
    }

    #[test]
    fn component_accept_dashes_underscores() {
        assert!(validate_component("my-file_v2").is_ok());
    }
}
