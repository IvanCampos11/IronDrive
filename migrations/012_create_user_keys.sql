-- User-managed encryption tiers.
--
-- Every user who has finished setup has an X25519 key pair. The private key is
-- wrapped by the server master key (tier 'server') or by a key derived from a
-- password (tiers 'failsafe_user' and 'pure_user'). 'failsafe_user' also keeps
-- a master-key-wrapped copy that is only used by an audited admin recovery.
--
-- password_mode 'single': the login password unlocks the keys at sign-in.
-- password_mode 'separate': a second encryption password unlocks them.
CREATE TABLE user_keys (
    user_id              TEXT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    tier                 TEXT NOT NULL DEFAULT 'server',
    password_mode        TEXT NOT NULL DEFAULT 'single',
    public_key           BLOB NOT NULL,
    wrapped_private_key  BLOB NOT NULL,
    kdf_salt             BLOB,
    recovery_private_key BLOB,
    updated_at           TEXT NOT NULL DEFAULT (datetime('now'))
);

-- Space data keys sealed to each member's public key. Used by spaces whose
-- encryption_mode is 'members' (no server-held copy). sealed_key is NULL while
-- the grant is pending: nobody who could open the key was online when access
-- was given, so it is sealed the next time the space is unlocked.
--
-- spaces.encryption_mode is now one of:
--   'server'   data key wrapped by the master key (always available)
--   'members'  data key only in member envelopes below
--   'password' data key wrapped by a key derived from the space password
CREATE TABLE space_key_envelopes (
    space_id    TEXT NOT NULL REFERENCES spaces(id) ON DELETE CASCADE,
    user_id     TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    sealed_key  BLOB,
    created_at  TEXT NOT NULL DEFAULT (datetime('now')),
    PRIMARY KEY (space_id, user_id)
);

CREATE INDEX idx_space_key_envelopes_user ON space_key_envelopes(user_id);

-- One-time password reset codes issued by an admin. Only the hash is stored.
CREATE TABLE password_resets (
    id          TEXT PRIMARY KEY,
    user_id     TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    code_hash   TEXT NOT NULL,
    issued_by   TEXT NOT NULL REFERENCES users(id),
    reason      TEXT,
    expires_at  TEXT NOT NULL,
    used_at     TEXT,
    created_at  TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX idx_password_resets_user ON password_resets(user_id);
