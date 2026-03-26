-- Detected file corruption / integrity failures.
-- Surfaced to users via the notifications API.
CREATE TABLE integrity_events (
    id              TEXT PRIMARY KEY,
    target_type     TEXT NOT NULL,            -- 'library' | 'space'
    target_id       TEXT NOT NULL,            -- library or space id
    file_path       TEXT NOT NULL,            -- relative path of the affected file
    event_type      TEXT NOT NULL,            -- 'checksum_mismatch' | 'decrypt_failed' | 'file_truncated'
    details         TEXT,                     -- human-readable description
    detected_by     TEXT NOT NULL,            -- 'download' | 'background_scan' | 'upload_verify'
    acknowledged    INTEGER NOT NULL DEFAULT 0,
    created_at      TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX idx_integrity_target ON integrity_events(target_type, target_id, acknowledged);
