-- Append-only log of admin recovery events. Never delete rows from this.
-- Users must be able to see their own entries.
CREATE TABLE IF NOT EXISTS recovery_audit_log (
    id              TEXT PRIMARY KEY,
    target_type     TEXT NOT NULL,      -- 'library' | 'space'
    target_id       TEXT NOT NULL,      -- library or space id
    target_user_id  TEXT NOT NULL,      -- user who owns the library/space
    recovered_by    TEXT NOT NULL REFERENCES users(id),  -- admin who triggered recovery
    reason          TEXT,               -- optional admin-provided reason
    acknowledged    INTEGER NOT NULL DEFAULT 0,  -- user has dismissed the notification
    created_at      TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_recovery_audit_user ON recovery_audit_log(target_user_id, acknowledged);
