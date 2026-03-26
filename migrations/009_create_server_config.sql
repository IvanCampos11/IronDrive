-- Master encryption key storage.
-- Single row: key = 'master_key_encrypted'
-- Value = master key encrypted with IRONDRIVE_SECRET_KEY from environment.
-- IRONDRIVE_SECRET_KEY is NEVER stored in the database.

CREATE TABLE IF NOT EXISTS server_config (
    key   TEXT PRIMARY KEY,
    value BLOB NOT NULL
);
