CREATE TABLE spaces (
    id                  TEXT PRIMARY KEY,
    name                TEXT NOT NULL,
    owner_type          TEXT NOT NULL,     -- 'user' | 'group'
    owner_id            TEXT NOT NULL,
    encryption_mode     TEXT NOT NULL DEFAULT 'server',

    -- Same key material pattern as personal_libraries
    encrypted_data_key  BLOB NOT NULL,
    salt                BLOB,
    verify_blob         BLOB,
    recovery_blob       BLOB,

    created_at          TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE space_access (
    space_id     TEXT NOT NULL REFERENCES spaces(id) ON DELETE CASCADE,
    grantee_type TEXT NOT NULL,        -- 'user' | 'group'
    grantee_id   TEXT NOT NULL,
    permission   TEXT NOT NULL DEFAULT 'read',  -- 'read' | 'write' | 'admin'
    granted_at   TEXT NOT NULL DEFAULT (datetime('now')),
    PRIMARY KEY (space_id, grantee_type, grantee_id)
);

-- Reverse lookup: find all spaces a specific user or group can access.
-- Covers the permission-resolution CTEs in models/space.rs.
CREATE INDEX idx_space_access_grantee
    ON space_access(grantee_type, grantee_id);
