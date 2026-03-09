CREATE TABLE personal_libraries (
    id                  TEXT PRIMARY KEY,
    user_id             TEXT NOT NULL UNIQUE REFERENCES users(id),  -- exactly ONE per user
    encryption_mode     TEXT NOT NULL,  -- 'server' | 'failsafe_user' | 'pure_user'

    -- Server encryption fields
    encrypted_data_key  BLOB NOT NULL,  -- data key encrypted by master key (server mode)
                                        -- OR by user key (user modes)

    -- User encryption fields (NULL for server mode)
    salt                BLOB,           -- Argon2 salt for key derivation
    verify_blob         BLOB,           -- "IRONDRIVE_VERIFY" encrypted with user key

    -- Recovery fields (NULL for server and pure_user modes)
    recovery_blob       BLOB,           -- data key encrypted by master key (failsafe only)

    created_at          TEXT NOT NULL DEFAULT (datetime('now'))
);
