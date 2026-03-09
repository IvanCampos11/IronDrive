# IronDrive — TODO

> **Last Updated:** 2025-01-09
> See [ARCHITECTURE.md](ARCHITECTURE.md) for the full design.

---

## Table of Contents

1. [Progress Tracker](#progress-tracker)
2. [Status Key](#status-key)
3. [Milestone Details](#milestone-details)
4. [Future Roadmap (v2+)](#future-roadmap-v2)

---

## Progress Tracker

| Phase | Milestone | What | Status |
|---|---|---|---|
| **M1** | Project Scaffold | `Cargo.toml`, `Rocket.toml`, DB pool, migrations, `/health` | ✅ Complete |
| **M2** | Authentication | Register, login, logout, session tokens, `AuthenticatedUser` guard | ⬜ Not started |
| **M3** | Server Encryption Core | Master key bootstrap, data key gen, AES-256-GCM encrypt/decrypt + SHA-256, `UnlockState` | ⬜ Not started |
| **M4** | Setup Wizard + Library | `POST /auth/setup-library`, personal library creation (server mode), `SetupGuard` | ⬜ Not started |
| **M5** | Filesystem Service | `fs_service` + library routes — browse, upload, download, mkdir, rename, delete (all encrypted + checksummed) | ⬜ Not started |
| **M5.5** | Chunked Transfers | Chunked upload/download endpoints, `chunk_service`, staging dir management | ⬜ Not started |
| **M5.6** | Data Integrity | `integrity_service`, integrity events table, corruption detection + notifications | ⬜ Not started |
| **M5.7** | Background Services | `BackgroundRunner`, integrity scanner, session cleanup, chunk cleanup | ⬜ Not started |
| **M6** | Groups | Group CRUD + membership | ⬜ Not started |
| **M7** | Spaces | Space CRUD, access control, filesystem routes (reuses `fs_service`) | ⬜ Not started |
| **M8** | User Encryption Tiers | Failsafe + pure user: passphrase-derived keys, lock/unlock, recovery, audit log | ⬜ Not started |
| **M9** | Quotas | Disk usage calculation + enforcement on upload | ⬜ Not started |
| **M10** | Polish | CORS, request logging, error consistency, integration tests | ⬜ Not started |

---

## Status Key

| Icon | Meaning |
|---|---|
| ⬜ | Not started |
| 🔨 | In progress |
| ✅ | Complete |
| ⏸️ | Blocked / paused |

---

## Milestone Details

### M1 — Project Scaffold

- [x] Init Cargo project
- [x] `Cargo.toml` with all deps
- [x] `Rocket.toml` with sensible defaults
- [x] `.env.example` with `IRONDRIVE_SECRET_KEY` placeholder
- [x] `src/main.rs` — Rocket launch
- [x] `src/config.rs` — load config from env + Rocket.toml
- [x] `src/db.rs` — SQLx pool init
- [x] Create all migration SQL files
- [x] Run migrations on startup
- [x] `GET /health` endpoint
- [x] Create `data/libraries/`, `data/spaces/`, `data/.chunks/` dirs on startup
- [x] `src/errors.rs` — `AppError` + `Responder` impl
- [x] Verify server starts and `/health` returns 200

### M2 — Authentication

- [ ] `src/models/user.rs` — User struct, create, find by username/email
- [ ] `src/models/session.rs` — Session struct, create, validate, delete
- [ ] `src/utils/crypto.rs` — Argon2 password hash + verify
- [ ] `src/services/auth_service.rs` — register, login, logout
- [ ] `src/guards/auth_guard.rs` — `AuthenticatedUser` request guard
- [ ] `src/guards/admin_guard.rs` — `AdminUser` request guard
- [ ] `src/routes/auth.rs` — register, login, logout endpoints
- [ ] Integration tests for auth flow

### M3 — Server Encryption Core

- [ ] Master key bootstrap in `src/services/crypto_service.rs`:
  - [ ] First boot: generate master key, encrypt with `IRONDRIVE_SECRET_KEY`, store in `server_config`
  - [ ] Subsequent boots: load + decrypt master key into memory
- [ ] Per-library/space data key generation
- [ ] Data key wrapping: encrypt data key with master key → `encrypted_data_key`
- [ ] Data key unwrapping: decrypt `encrypted_data_key` with master key
- [ ] AES-256-GCM file encryption (nonce + ciphertext + tag + checksum format)
- [ ] AES-256-GCM file decryption with checksum verification
- [ ] SHA-256 checksum computation (streaming, async)
- [ ] `src/services/unlock_state.rs` — in-memory key store (dashmap)
- [ ] Unit tests: encrypt → decrypt roundtrip
- [ ] Unit tests: key wrapping/unwrapping
- [ ] Unit tests: checksum generation + verification
- [ ] Unit tests: corruption detection (tampered file → checksum mismatch)

### M4 — Setup Wizard + Library

- [ ] `src/models/library.rs` — PersonalLibrary struct, create, find by user
- [ ] `src/services/library_service.rs`:
  - [ ] Setup: create library with `server` mode (default)
  - [ ] Generate data key, wrap with master key, store `encrypted_data_key`
  - [ ] Create dir on disk + `.irondrive.meta`
  - [ ] Load data key into `UnlockState` right away (server mode = always unlocked)
- [ ] `src/guards/setup_guard.rs` — reject requests if `setup_complete == false`
- [ ] `POST /api/v1/auth/setup-library` endpoint (server mode only for now)
- [ ] Integration tests for setup flow

### M5 — Filesystem Service

- [ ] `src/utils/path_safety.rs` — `safe_join()` with all the traversal checks
- [ ] `src/utils/mime.rs` — MIME type detection from extension
- [ ] `src/services/fs_service.rs`:
  - [ ] `list_directory()` — read real filesystem, return `Vec<FsEntry>` (includes integrity status)
  - [ ] `create_directory()` — mkdir with parent creation
  - [ ] `upload_file()` — encrypt, compute checksum, write to disk, verify write
  - [ ] `download_file()` — read, decrypt, verify checksum, set integrity header
  - [ ] `delete_entry()` — remove file or dir (recursive)
  - [ ] `rename_entry()` — rename or move within same root
  - [ ] `get_entry_info()` — stat a single file/folder (with integrity status)
  - [ ] `calculate_usage()` — walk dir tree, sum sizes
- [ ] `src/routes/library.rs` — personal library filesystem endpoints
- [ ] File upload via Rocket's `Data` type (multipart)
- [ ] File download with streaming response + `X-IronDrive-Integrity` header
- [ ] Integration tests for all fs operations
- [ ] Integration tests for checksum verification on download
- [ ] **Security**: fuzz `safe_join()` with adversarial paths — this is the most critical function in the codebase

### M5.5 — Chunked Transfers

- [ ] Create `data/.chunks/` staging dir on startup
- [ ] `src/services/chunk_service.rs`:
  - [ ] `init_upload()` — create `chunked_uploads` row + staging dir, return `upload_id`
  - [ ] `receive_chunk()` — validate index + size, encrypt chunk, write to staging
  - [ ] `complete_upload()` — assemble chunks → single encrypted file with checksum, verify, move to target, clean up staging
  - [ ] `cancel_upload()` — nuke staging dir + DB row
  - [ ] `init_download()` — stat file, compute chunk boundaries, generate short-lived token
  - [ ] `serve_chunk()` — read chunk range from encrypted file, decrypt, stream
- [ ] `006_create_chunked_uploads.sql` migration
- [ ] Chunked upload/download routes in `src/routes/library.rs`
- [ ] Chunked upload/download routes in `src/routes/spaces.rs`
- [ ] Tests:
  - [ ] Chunked upload → download roundtrip
  - [ ] Parallel chunk upload ordering
  - [ ] Incomplete upload → cancel → verify cleanup happened
  - [ ] Checksum mismatch on assembly → reject
  - [ ] Small file falls through to single-request path

### M5.6 — Data Integrity

- [ ] `src/services/integrity_service.rs`:
  - [ ] `verify_file()` — decrypt + recompute SHA-256 + compare
  - [ ] `record_event()` — insert into `integrity_events`
  - [ ] `list_events()` — query for a library/space (unacknowledged first)
  - [ ] `acknowledge_event()` — mark as acknowledged
  - [ ] `scan_library()` — walk all files, verify each, record failures
  - [ ] `scan_space()` — same but for spaces
- [ ] `007_create_integrity_events.sql` migration
- [ ] Integrity routes in `src/routes/library.rs` and `src/routes/spaces.rs`
- [ ] Wire into `GET /api/v1/users/me/notifications`
- [ ] Admin integrity endpoints in `src/routes/admin.rs`
- [ ] Tests:
  - [ ] Upload → corrupt on disk → download → integrity event created
  - [ ] Scan finds corrupted file → event created
  - [ ] Acknowledge → gone from unacknowledged list
  - [ ] Truncated file → caught as `file_truncated`

### M5.7 — Background Services

- [ ] `src/services/background/mod.rs` — `BackgroundRunner`
- [ ] `src/services/background/integrity_scan.rs`:
  - [ ] Periodic loop, configurable interval
  - [ ] Skip locked libraries/spaces (no key = can't verify)
  - [ ] Throttle I/O between files so we don't starve request handling
  - [ ] Log via `tracing`
- [ ] `src/services/background/session_cleanup.rs`:
  - [ ] Hourly loop, prune expired sessions
- [ ] `src/services/background/chunk_cleanup.rs`:
  - [ ] Every 30min, delete expired incomplete uploads
  - [ ] Remove staging dir + DB row
- [ ] `src/fairings/background.rs` — launch `BackgroundRunner` on liftoff
- [ ] Config env vars: `IRONDRIVE_INTEGRITY_SCAN_INTERVAL_HOURS`, `IRONDRIVE_INTEGRITY_SCAN_ENABLED`
- [ ] Tests:
  - [ ] Session cleanup actually removes expired sessions
  - [ ] Chunk cleanup removes expired staging
  - [ ] Integrity scanner catches corrupted file
  - [ ] Scanner skips locked libraries

### M6 — Groups

- [ ] `src/models/group.rs` — Group, GroupMember structs + queries
- [ ] `src/services/group_service.rs` — create, update, delete, add/remove members
- [ ] `src/routes/groups.rs` — all group endpoints
- [ ] Integration tests

### M7 — Spaces

- [ ] `src/models/space.rs` — Space, SpaceAccess structs + queries
- [ ] `src/services/space_service.rs`:
  - [ ] Create space (DB row + dir + data key, server mode)
  - [ ] Delete space (DB row + dir)
  - [ ] Permission resolution (owner → group → direct grant)
  - [ ] Grant/revoke access
  - [ ] Load all server-mode space keys into `UnlockState` at boot
- [ ] `src/guards/space_guard.rs` — permission check guard
- [ ] `src/routes/spaces.rs` — all space endpoints (CRUD + filesystem + access)
- [ ] Integration tests

### M8 — User Encryption Tiers

- [ ] Extend `crypto_service.rs`:
  - [ ] Argon2 key derivation from passphrase + salt
  - [ ] Wrap data key with user-derived key → `encrypted_data_key`
  - [ ] Unwrap data key with user-derived key
  - [ ] Verify passphrase via `verify_blob`
  - [ ] Recovery blob creation (failsafe mode): wrap data key with master key
- [ ] Extend `library_service.rs` for `failsafe_user` and `pure_user` setup
- [ ] Extend `space_service.rs` for `failsafe_user` and `pure_user` creation
- [ ] Lock/unlock endpoints for libraries and spaces
- [ ] `src/services/recovery_service.rs`:
  - [ ] Admin triggers recovery: unwrap data key from `recovery_blob` via master key
  - [ ] Re-wrap with new user-derived key
  - [ ] Write to `recovery_audit_log`
  - [ ] Reject recovery for `pure_user` (no recovery blob exists, that's the whole point)
- [ ] `src/models/recovery_log.rs` — audit log queries
- [ ] Recovery notification in `GET /api/v1/users/me/notifications`
- [ ] Notification acknowledge endpoint
- [ ] `src/routes/admin.rs` — recovery endpoints (admin only)
- [ ] Update setup wizard for all three encryption modes
- [ ] Tests:
  - [ ] Failsafe: setup → lock → unlock → file roundtrip
  - [ ] Failsafe: recovery → notification → acknowledge
  - [ ] Pure: setup → lock → unlock → file roundtrip
  - [ ] Pure: recovery attempt → rejected
  - [ ] Bad passphrase → rejected
  - [ ] Onboarding covers all three modes + pure mode warning

### M9 — Quotas

- [ ] `src/services/quota_service.rs`:
  - [ ] Real disk usage per library (encrypted sizes on disk)
  - [ ] Real disk usage per space (attributed to owner)
  - [ ] Total usage per user (library + owned spaces)
- [ ] Quota check before file upload
- [ ] Usage info in `GET /api/v1/users/me` response
- [ ] Usage info in `GET /api/v1/library/status` response
- [ ] Tests for quota enforcement

### M10 — Polish

- [ ] `src/fairings/cors.rs` — configurable CORS
- [ ] `src/fairings/request_logger.rs` — structured request logging
- [ ] Go through all error responses for consistency
- [ ] `tracing` spans on all service functions
- [ ] Make sure crypto errors never leak key material into logs
- [ ] Big integration test pass:
  - [ ] Full lifecycle: register → setup (server) → upload → download
  - [ ] Full lifecycle: register → setup (failsafe) → unlock → upload → lock → unlock → download
  - [ ] Full lifecycle: register → setup (pure) → unlock → upload → lock → unlock → download
  - [ ] Group creation + space sharing
  - [ ] Encrypted space full cycle (all three tiers)
  - [ ] Permission denials
  - [ ] Path traversal attacks
  - [ ] Recovery end-to-end with notification
  - [ ] Chunked upload → download with checksum verification
  - [ ] Background integrity scanner catches corruption
  - [ ] Background chunk cleanup reclaims space
  - [ ] Server restart: server-mode auto-unlocks, user-mode needs re-unlock
- [ ] README with setup instructions
- [ ] Test single-binary deployment
- [ ] Document `IRONDRIVE_SECRET_KEY` backup procedures

---

## Future Roadmap (v2+)

Not happening in v1, but the architecture shouldn't make any of these painful to add later.

### Zero-Knowledge E2EE

The big one. Full client-side encryption where the server never sees plaintext.

| Component | Description |
|---|---|
| **Browser client (WebCrypto)** | All encrypt/decrypt happens in the browser. Server never sees plaintext or keys. |
| **Desktop / mobile clients** | Native clients doing all crypto locally, syncing encrypted blobs. |
| **Key exchange** | Asymmetric key pairs (X25519 or similar) for sharing space keys between users without the server knowing. |
| **Server role** | Becomes a dumb storage + access-control relay. Stores encrypted blobs, can't read anything. |

This is compatible with v1 — chunked transfers, checksums, and the file format all work fine with opaque blobs. The real work is building client-side crypto and key distribution.

### Other v2+ Ideas

| Feature | Notes |
|---|---|
| **Filename encryption** | v1 only encrypts contents. Filename encryption needs an encrypted name→real name mapping somewhere (DB or sidecar file). |
| **File versioning** | Previous versions in `.versions/` subdirs per space/library. |
| **Trash / recycle bin** | Soft delete to `.trash/`, auto-purge after N days via background service. |
| **Thumbnails & previews** | Decrypt in memory, generate thumbnail, encrypt and cache. Server-mode only (obviously not possible with E2EE). |
| **Full-text search** | Index decrypted contents with tantivy. Server-mode only, or while unlocked for user modes. |
| **WebDAV** | Mount spaces as network drives. Big feature, probably a separate binary. |
| **Public share links** | Public URLs for space files. Needs careful key management for encrypted spaces. |
| **S3 backend** | Make `fs_service` trait-based. Current approach becomes `LocalBackend`. |
| **Rate limiting** | Rocket fairing. |
| **2FA** | TOTP via `totp-rs`. |
| **General audit logging** | Who accessed/modified what and when. Broader than recovery audit log. |
| **Desktop sync client** | Rust client that syncs a local folder with a library/space. Uses chunked transfers for delta sync. |
| **Admin dashboard** | Web UI for user/quota management, system health, recovery triggers, integrity events. |
| **Key rotation** | Re-encrypt all data keys with a new master key. Critical for key compromise scenarios. |
| **Memory key zeroization** | `zeroize` crate to wipe keys from memory on lock/drop. |
| **Encryption mode migration** | Upgrade a library/space from server → failsafe → pure (re-encrypt data key, files stay as-is). |

---

*Living document — update as things get built.*