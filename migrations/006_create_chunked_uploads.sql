-- One row per in-progress chunked upload session.
CREATE TABLE chunked_uploads (
    id              TEXT PRIMARY KEY,         -- upload session UUID
    user_id         TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    target_type     TEXT NOT NULL,            -- 'library' | 'space'
    target_id       TEXT NOT NULL,            -- library or space id
    target_path     TEXT NOT NULL,            -- destination relative path
    filename        TEXT NOT NULL,            -- original filename
    total_chunks    INTEGER NOT NULL,         -- expected number of chunks
    received_chunks INTEGER NOT NULL DEFAULT 0,
    total_bytes     INTEGER NOT NULL,         -- expected total file size (plaintext)
    checksum        TEXT,                     -- expected SHA-256 of complete plaintext (optional, client-supplied)
    expires_at      TEXT NOT NULL,            -- auto-cleanup deadline
    created_at      TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX idx_chunked_uploads_user ON chunked_uploads(user_id);
CREATE INDEX idx_chunked_uploads_expires ON chunked_uploads(expires_at);
