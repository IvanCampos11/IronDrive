//! Trash: deleted files and folders kept for a while so they can be restored.
//!
//! Deleting moves the item to `<root>/.trash/<id>/<name>` — a rename on the
//! same filesystem, so it's instant and keeps the encrypted bytes untouched —
//! and records it in `trash_items`. Dot-prefixed paths can't be reached
//! through the file APIs and are skipped by listings, usage walks and the
//! integrity scanner, so trashed items stay out of sight. Trash counts toward
//! the owner's quota via `size_bytes`.

use std::path::{Path, PathBuf};

use serde::Serialize;
use tokio::fs;
use uuid::Uuid;

use crate::config::AppConfig;
use crate::db::DbPool;
use crate::errors::AppError;
use crate::services::fs_service::{self, TargetKind};

/// Hidden directory at the root of each library/space holding trashed items.
pub const TRASH_DIR: &str = ".trash";

#[derive(Debug, Clone, Serialize, sqlx::FromRow)]
pub struct TrashItem {
    pub id: String,
    pub target_type: String,
    pub target_id: String,
    pub original_path: String,
    pub is_dir: bool,
    pub size_bytes: i64,
    pub file_count: i64,
    pub deleted_by: Option<String>,
    pub deleted_at: String,
}

impl TrashItem {
    pub fn name(&self) -> &str {
        self.original_path
            .rsplit('/')
            .next()
            .unwrap_or(&self.original_path)
    }

    /// Folder the item was deleted from ("" for the root).
    pub fn parent(&self) -> &str {
        self.original_path
            .rsplit_once('/')
            .map(|(p, _)| p)
            .unwrap_or("")
    }
}

fn item_dir(root: &Path, id: &str) -> PathBuf {
    root.join(TRASH_DIR).join(id)
}

fn validate_id(id: &str) -> Result<(), AppError> {
    Uuid::parse_str(id)
        .map(|_| ())
        .map_err(|_| AppError::NotFound)
}

/// Move a file or folder into the trash. Returns the new trash entry.
pub async fn move_to_trash(
    pool: &DbPool,
    config: &AppConfig,
    kind: TargetKind,
    target_id: &str,
    user_path: &str,
    deleted_by: Option<&str>,
) -> Result<TrashItem, AppError> {
    if user_path.is_empty() {
        return Err(AppError::Validation(
            "Can't delete the top-level folder.".into(),
        ));
    }

    let root = fs_service::root_of(config, kind, target_id);
    let source = fs_service::safe_join_async(root.clone(), user_path.to_string()).await?;
    let meta = fs::metadata(&source).await.map_err(|e| {
        if e.kind() == std::io::ErrorKind::NotFound {
            AppError::NotFound
        } else {
            AppError::Internal(format!("Cannot read entry metadata: {e}"))
        }
    })?;

    // Same belt-and-braces check as permanent delete: never move the root.
    let canonical_root = fs_service::canonicalize_async(root.clone()).await?;
    let canonical_source = fs_service::canonicalize_async(source.clone()).await?;
    if !canonical_source.starts_with(&canonical_root) || canonical_source == canonical_root {
        return Err(AppError::Validation("Path escapes the root.".into()));
    }

    let usage = match kind {
        TargetKind::Library => fs_service::calculate_usage(config, target_id, user_path).await?,
        TargetKind::Space => {
            fs_service::calculate_space_usage(config, target_id, user_path).await?
        }
    };

    let id = Uuid::new_v4().to_string();
    let name = canonical_source
        .file_name()
        .ok_or_else(|| AppError::Internal("Entry has no name".into()))?
        .to_owned();
    let dir = item_dir(&canonical_root, &id);
    fs::create_dir_all(&dir)
        .await
        .map_err(|e| AppError::Internal(format!("Failed to create trash directory: {e}")))?;
    fs::rename(&canonical_source, dir.join(&name))
        .await
        .map_err(|e| AppError::Internal(format!("Failed to move entry to trash: {e}")))?;

    // Store the path as the user sees it (normalized separators).
    let original_path = user_path.replace('\\', "/");
    let inserted = sqlx::query_as::<_, TrashItem>(
        "INSERT INTO trash_items (id, target_type, target_id, original_path, is_dir, size_bytes, file_count, deleted_by)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)
         RETURNING id, target_type, target_id, original_path, is_dir, size_bytes, file_count, deleted_by, deleted_at",
    )
    .bind(&id)
    .bind(kind.as_str())
    .bind(target_id)
    .bind(&original_path)
    .bind(meta.is_dir())
    .bind(usage.disk_bytes as i64)
    .bind(usage.file_count as i64)
    .bind(deleted_by)
    .fetch_one(pool)
    .await;

    match inserted {
        Ok(item) => {
            tracing::info!(target_id, path = user_path, trash_id = %id, "Moved to trash");
            Ok(item)
        }
        Err(e) => {
            // Put it back so nothing goes missing without a record.
            let _ = fs::rename(dir.join(&name), &canonical_source).await;
            let _ = fs::remove_dir(&dir).await;
            Err(e.into())
        }
    }
}

/// Items in the trash of one library or space, newest first.
pub async fn list(
    pool: &DbPool,
    kind: TargetKind,
    target_id: &str,
) -> Result<Vec<TrashItem>, AppError> {
    Ok(sqlx::query_as::<_, TrashItem>(
        "SELECT id, target_type, target_id, original_path, is_dir, size_bytes, file_count, deleted_by, deleted_at
         FROM trash_items WHERE target_type = ? AND target_id = ?
         ORDER BY deleted_at DESC, rowid DESC",
    )
    .bind(kind.as_str())
    .bind(target_id)
    .fetch_all(pool)
    .await?)
}

async fn get(
    pool: &DbPool,
    kind: TargetKind,
    target_id: &str,
    id: &str,
) -> Result<TrashItem, AppError> {
    validate_id(id)?;
    sqlx::query_as::<_, TrashItem>(
        "SELECT id, target_type, target_id, original_path, is_dir, size_bytes, file_count, deleted_by, deleted_at
         FROM trash_items WHERE id = ? AND target_type = ? AND target_id = ?",
    )
    .bind(id)
    .bind(kind.as_str())
    .bind(target_id)
    .fetch_optional(pool)
    .await?
    .ok_or(AppError::NotFound)
}

/// A name that's free in `dir`: `name`, then `name (restored)`,
/// `name (restored 2)`, ... keeping the extension at the end.
async fn free_name(dir: &Path, name: &str, is_dir: bool) -> String {
    if !fs::try_exists(dir.join(name)).await.unwrap_or(true) {
        return name.to_string();
    }
    let (stem, ext) = match name.rfind('.') {
        Some(i) if i > 0 && !is_dir => (&name[..i], &name[i..]),
        _ => (name, ""),
    };
    for n in 1..1000 {
        let suffix = if n == 1 {
            " (restored)".to_string()
        } else {
            format!(" (restored {n})")
        };
        let candidate = format!("{stem}{suffix}{ext}");
        if !fs::try_exists(dir.join(&candidate)).await.unwrap_or(true) {
            return candidate;
        }
    }
    format!("{stem} ({}){ext}", Uuid::new_v4())
}

/// Put an item back where it was deleted from. Missing parent folders are
/// recreated; if the name is taken, the item is restored as "name (restored)".
/// Returns the path it was restored to.
pub async fn restore(
    pool: &DbPool,
    config: &AppConfig,
    kind: TargetKind,
    target_id: &str,
    id: &str,
) -> Result<String, AppError> {
    let item = get(pool, kind, target_id, id).await?;
    let root = fs_service::canonicalize_async(fs_service::root_of(config, kind, target_id)).await?;
    let source = item_dir(&root, id).join(item.name());
    if !fs::try_exists(&source).await.unwrap_or(false) {
        // The files are gone (e.g. removed by hand); drop the stale record.
        forget(pool, id).await?;
        return Err(AppError::NotFound);
    }

    // Recreate the parent folder if needed. If that's impossible (a file now
    // sits where a folder was), restore into the top level instead.
    let mut parent = item.parent().to_string();
    let parent_dir = if parent.is_empty() {
        root.clone()
    } else {
        match fs_service::safe_join_async(root.clone(), parent.clone()).await {
            Ok(dir) if fs::create_dir_all(&dir).await.is_ok() => dir,
            _ => {
                parent.clear();
                root.clone()
            }
        }
    };

    let name = free_name(&parent_dir, item.name(), item.is_dir).await;
    fs::rename(&source, parent_dir.join(&name))
        .await
        .map_err(|e| AppError::Internal(format!("Failed to restore from trash: {e}")))?;
    let _ = fs::remove_dir_all(item_dir(&root, id)).await;
    forget(pool, id).await?;

    let restored = if parent.is_empty() {
        name
    } else {
        format!("{parent}/{name}")
    };
    tracing::info!(target_id, path = %restored, trash_id = id, "Restored from trash");
    Ok(restored)
}

async fn forget(pool: &DbPool, id: &str) -> Result<(), AppError> {
    sqlx::query("DELETE FROM trash_items WHERE id = ?")
        .bind(id)
        .execute(pool)
        .await?;
    Ok(())
}

/// Remove one item from the trash permanently.
pub async fn delete_forever(
    pool: &DbPool,
    config: &AppConfig,
    kind: TargetKind,
    target_id: &str,
    id: &str,
) -> Result<(), AppError> {
    let item = get(pool, kind, target_id, id).await?;
    let root = fs_service::root_of(config, kind, target_id);
    remove_item_files(&root, &item.id).await?;
    forget(pool, &item.id).await
}

async fn remove_item_files(root: &Path, id: &str) -> Result<(), AppError> {
    match fs::remove_dir_all(item_dir(root, id)).await {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(AppError::Internal(format!(
            "Failed to delete trash item: {e}"
        ))),
    }
}

/// Permanently delete everything in one library's or space's trash.
/// Returns how many items were removed.
pub async fn empty(
    pool: &DbPool,
    config: &AppConfig,
    kind: TargetKind,
    target_id: &str,
) -> Result<usize, AppError> {
    let items = list(pool, kind, target_id).await?;
    let root = fs_service::root_of(config, kind, target_id);
    for item in &items {
        remove_item_files(&root, &item.id).await?;
        forget(pool, &item.id).await?;
    }
    Ok(items.len())
}

/// Drop the trash records of a space that is being deleted (its directory,
/// trash included, is removed by the caller).
pub async fn forget_space(pool: &DbPool, space_id: &str) -> Result<(), AppError> {
    sqlx::query("DELETE FROM trash_items WHERE target_type = 'space' AND target_id = ?")
        .bind(space_id)
        .execute(pool)
        .await?;
    Ok(())
}

/// Permanently delete items that have been in the trash longer than
/// `retention_days` (0 disables). Returns how many were removed.
pub async fn purge_expired(
    pool: &DbPool,
    config: &AppConfig,
    retention_days: u64,
) -> Result<usize, AppError> {
    if retention_days == 0 {
        return Ok(0);
    }
    let expired: Vec<TrashItem> = sqlx::query_as(
        "SELECT id, target_type, target_id, original_path, is_dir, size_bytes, file_count, deleted_by, deleted_at
         FROM trash_items WHERE deleted_at < datetime('now', ?)",
    )
    .bind(format!("-{retention_days} days"))
    .fetch_all(pool)
    .await?;

    let mut removed = 0;
    for item in &expired {
        let Some(kind) = TargetKind::parse(&item.target_type) else {
            continue;
        };
        let root = fs_service::root_of(config, kind, &item.target_id);
        match remove_item_files(&root, &item.id).await {
            Ok(()) => {
                forget(pool, &item.id).await?;
                removed += 1;
            }
            Err(e) => tracing::warn!(trash_id = %item.id, error = %e, "Could not purge trash item"),
        }
    }
    Ok(removed)
}

#[cfg(test)]
mod tests {
    //! Model-based test: random sequences of writes, deletes, restores and
    //! permanent deletes, checked after every step against a plain in-memory
    //! model of what should be on disk and in the trash.

    use super::*;
    use crate::services::crypto_service::{generate_data_key, read_and_decrypt_file};
    use crate::services::unlock_state::UnlockState;
    use proptest::prelude::*;
    use std::collections::{BTreeMap, BTreeSet};

    const LIB: &str = "lib-under-test";
    /// Files the test writes; "d" doubles as a folder that can be trashed.
    const PATHS: [&str; 5] = ["a.txt", "b.txt", "d/a.txt", "d/c.txt", "d"];

    #[derive(Debug, Clone)]
    enum Op {
        Write(usize, u8),
        Trash(usize),
        Restore(usize),
        Forget(usize),
    }

    fn op() -> impl Strategy<Value = Op> {
        prop_oneof![
            3 => (0..4usize, any::<u8>()).prop_map(|(i, b)| Op::Write(i, b)),
            3 => (0..5usize).prop_map(Op::Trash),
            2 => (0..4usize).prop_map(Op::Restore),
            1 => (0..4usize).prop_map(Op::Forget),
        ]
    }

    struct Env {
        _tmp: tempfile::TempDir,
        config: AppConfig,
        unlock: UnlockState,
        pool: DbPool,
        root: PathBuf,
    }

    async fn env() -> Env {
        let tmp = tempfile::tempdir().unwrap();
        let config = AppConfig {
            secret_key: "dGVzdC1rZXk=".into(),
            data_dir: tmp.path().to_string_lossy().to_string(),
            db_dir: tmp.path().to_string_lossy().to_string(),
            default_quota_bytes: 1 << 30,
            max_upload_bytes: 1 << 30,
            session_expiry_hours: 1,
            chunk_size_bytes: 1 << 20,
            chunk_upload_expiry_hours: 1,
            max_parallel_chunks: 1,
            integrity_scan_enabled: false,
            integrity_scan_interval_hours: 1,
            registration_enabled: true,
            secure_cookies: false,
            trash_retention_days: 30,
        };
        let root = tmp.path().join("libraries").join(LIB);
        fs::create_dir_all(&root).await.unwrap();
        let root = fs::canonicalize(&root).await.unwrap();
        let unlock = UnlockState::new();
        unlock.insert_library_key(LIB, &generate_data_key());
        let url = format!("sqlite:{}/t.db?mode=rwc", tmp.path().display());
        let pool = crate::db::init_pool(&url).await.unwrap();
        crate::db::run_migrations(&pool).await.unwrap();
        Env {
            _tmp: tmp,
            config,
            unlock,
            pool,
            root,
        }
    }

    /// A trashed item in the model: (trash id, original path, files under it
    /// keyed relative to it, folders likewise).
    type TrashedItem = (String, String, BTreeMap<String, Vec<u8>>, BTreeSet<String>);

    #[derive(Default, Debug)]
    struct Model {
        files: BTreeMap<String, Vec<u8>>,
        dirs: BTreeSet<String>,
        trash: Vec<TrashedItem>,
    }

    impl Model {
        fn exists(&self, path: &str) -> bool {
            self.files.contains_key(path) || self.dirs.contains(path)
        }

        /// Take everything at `path` (a file, or a folder and its contents)
        /// out of the tree, keyed relative to `path`.
        fn take(&mut self, path: &str) -> (BTreeMap<String, Vec<u8>>, BTreeSet<String>) {
            let prefix = format!("{path}/");
            let mut files = BTreeMap::new();
            for k in self.files.keys().cloned().collect::<Vec<_>>() {
                if k == path {
                    files.insert(String::new(), self.files.remove(&k).unwrap());
                } else if let Some(rest) = k.strip_prefix(&prefix) {
                    files.insert(rest.to_string(), self.files.remove(&k).unwrap());
                }
            }
            let mut dirs = BTreeSet::new();
            for d in self.dirs.iter().cloned().collect::<Vec<_>>() {
                if d == path {
                    self.dirs.remove(&d);
                    dirs.insert(String::new());
                } else if let Some(rest) = d.strip_prefix(&prefix) {
                    self.dirs.remove(&d);
                    dirs.insert(rest.to_string());
                }
            }
            (files, dirs)
        }

        fn put(&mut self, at: &str, files: BTreeMap<String, Vec<u8>>, dirs: BTreeSet<String>) {
            let join = |rel: &str| {
                if rel.is_empty() {
                    at.to_string()
                } else {
                    format!("{at}/{rel}")
                }
            };
            for (rel, data) in files {
                self.files.insert(join(&rel), data);
            }
            for rel in dirs {
                self.dirs.insert(join(&rel));
            }
            // Parents of whatever was put back exist again.
            let mut p = at;
            while let Some((parent, _)) = p.rsplit_once('/') {
                self.dirs.insert(parent.to_string());
                p = parent;
            }
        }
    }

    /// What's actually on disk (hidden entries skipped), decrypted.
    async fn snapshot(env: &Env) -> (BTreeMap<String, Vec<u8>>, BTreeSet<String>) {
        let key = env.unlock.get_library_key(LIB).unwrap();
        let mut files = BTreeMap::new();
        let mut dirs = BTreeSet::new();
        let mut stack = vec![(env.root.clone(), String::new())];
        while let Some((dir, rel)) = stack.pop() {
            let mut rd = fs::read_dir(&dir).await.unwrap();
            while let Some(e) = rd.next_entry().await.unwrap() {
                let name = e.file_name().to_string_lossy().to_string();
                if name.starts_with('.') {
                    continue;
                }
                let child = if rel.is_empty() {
                    name
                } else {
                    format!("{rel}/{name}")
                };
                if e.file_type().await.unwrap().is_dir() {
                    dirs.insert(child.clone());
                    stack.push((e.path(), child));
                } else {
                    let data = read_and_decrypt_file(&key, &e.path()).await.unwrap();
                    files.insert(child, data);
                }
            }
        }
        (files, dirs)
    }

    async fn run(ops: Vec<Op>) -> Result<(), TestCaseError> {
        let env = env().await;
        let mut model = Model::default();
        let kind = TargetKind::Library;

        for op in ops {
            match op {
                Op::Write(i, b) => {
                    let path = PATHS[i];
                    // Can't write a file where a folder of that name exists.
                    if model.dirs.contains(path) {
                        continue;
                    }
                    let data = vec![b; b as usize + 1];
                    fs_service::upload_file_owned(
                        &env.config,
                        &env.unlock,
                        LIB,
                        path,
                        data.clone(),
                        false,
                    )
                    .await
                    .unwrap();
                    model.put(
                        path,
                        BTreeMap::from([(String::new(), data)]),
                        BTreeSet::new(),
                    );
                }
                Op::Trash(i) => {
                    let path = PATHS[i];
                    let result = move_to_trash(&env.pool, &env.config, kind, LIB, path, None).await;
                    if model.exists(path) {
                        let item = result.unwrap();
                        let (files, dirs) = model.take(path);
                        model.trash.push((item.id, path.to_string(), files, dirs));
                    } else {
                        prop_assert!(matches!(result, Err(AppError::NotFound)), "{result:?}");
                    }
                }
                Op::Restore(k) => {
                    if k >= model.trash.len() {
                        continue;
                    }
                    let (id, original, files, dirs) = model.trash.remove(k);
                    let restored = restore(&env.pool, &env.config, kind, LIB, &id)
                        .await
                        .unwrap();

                    // Same folder; same name unless that name was taken.
                    let parent = |p: &str| {
                        p.rsplit_once('/')
                            .map(|(a, _)| a.to_string())
                            .unwrap_or_default()
                    };
                    prop_assert_eq!(parent(&restored), parent(&original));
                    if restored != original {
                        prop_assert!(
                            model.exists(&original),
                            "renamed although {original} was free"
                        );
                        prop_assert!(restored.contains("(restored"), "{restored}");
                    }
                    prop_assert!(!model.exists(&restored), "restored over {restored}");
                    model.put(&restored, files, dirs);
                }
                Op::Forget(k) => {
                    if k >= model.trash.len() {
                        continue;
                    }
                    let (id, ..) = model.trash.remove(k);
                    delete_forever(&env.pool, &env.config, kind, LIB, &id)
                        .await
                        .unwrap();
                }
            }

            let (files, dirs) = snapshot(&env).await;
            prop_assert_eq!(&files, &model.files);
            prop_assert_eq!(&dirs, &model.dirs);
            let mut listed: Vec<String> = list(&env.pool, kind, LIB)
                .await
                .unwrap()
                .into_iter()
                .map(|t| t.id)
                .collect();
            let mut expected: Vec<String> = model.trash.iter().map(|t| t.0.clone()).collect();
            listed.sort();
            expected.sort();
            prop_assert_eq!(listed, expected);
        }
        Ok(())
    }

    proptest! {
        #![proptest_config(ProptestConfig { cases: 96, ..ProptestConfig::default() })]

        #[test]
        fn trash_matches_model(ops in prop::collection::vec(op(), 1..30)) {
            let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
            rt.block_on(run(ops))?;
        }
    }
}
