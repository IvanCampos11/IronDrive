-- Deleted files and folders, kept for a while so they can be restored.
-- The item itself is moved to `<root>/.trash/<id>/<name>` (dot-prefixed paths
-- are unreachable through the file APIs and hidden from listings).
CREATE TABLE trash_items (
    id              TEXT PRIMARY KEY,
    target_type     TEXT NOT NULL,            -- 'library' | 'space'
    target_id       TEXT NOT NULL,            -- library or space id
    original_path   TEXT NOT NULL,            -- where it was, relative to the root
    is_dir          INTEGER NOT NULL,
    size_bytes      INTEGER NOT NULL,         -- on-disk bytes (counts toward quota)
    file_count      INTEGER NOT NULL,         -- files inside (1 for a file)
    deleted_by      TEXT REFERENCES users(id) ON DELETE SET NULL,
    deleted_at      TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX idx_trash_target ON trash_items(target_type, target_id, deleted_at);
CREATE INDEX idx_trash_deleted_at ON trash_items(deleted_at);
