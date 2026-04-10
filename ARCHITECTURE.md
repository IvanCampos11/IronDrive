# IronDrive Architecture

> Version: 0.6.0  
> Last updated: 2026-04-10 

## 1) Current State

IronDrive is a Rust self-hosted file storage app with encrypted-at-rest file data, session auth, personal libraries, collaborative spaces, groups, and a server-rendered web UI.

## 2) What Is Implemented

- Auth
  - Register, login, logout.
  - Session token model with hashed token storage.
  - Setup gating for first-login flow.
- Personal library
  - One library per user.
  - Browse, upload, download, rename/move, mkdir, delete.
  - Chunked upload/download (API and page flows).
- Spaces
  - Space CRUD.
  - User/group access grants with read/write/admin permissions.
  - File operations parity with libraries.
  - Chunked upload/download in page routes.
  - Non-chunked file API routes are complete.
- Groups
  - Group CRUD, membership management, member role updates.
- Integrity
  - File-hash verification and integrity status.
  - Integrity events + acknowledge.
  - User notifications endpoint for unacknowledged integrity events.
  - Admin scan and admin event listing.
- Background jobs
  - Integrity scanning.
  - Expired session cleanup.
  - Expired chunked upload cleanup.
- Frontend
  - Rocket + Tera pages for auth, setup, files, groups, spaces, settings.
  - HTMX interactions and progressive enhancement with vanilla JS.
  - CSRF protection for state-changing operations.

## 3) What Is Not Implemented Yet

- User-managed encryption tiers are not active in runtime flows.
  - `failsafe_user` and `pure_user` exist in schema/model shape but setup currently creates server mode only.
  - No active lock/unlock passphrase flow in API or pages.
- Quota enforcement is not complete.
  - Quota values are stored and usage is displayed in UI.
  - Upload/complete paths are not consistently blocked by quota checks.
- Chunked spaces API parity
  - Chunked space operations exist in page routes.
  - API route module does not currently expose chunked space endpoints.

## 4) Architecture Principles

- Filesystem is source of truth for files/folders.
- Database stores identity, auth, ownership, access, key metadata, and events.
- Service layer holds business logic; route layer stays thin.
- Keep changes local and explicit: minimal indirection, straightforward modules.

## 5) Runtime Layout

### App bootstrap

On startup, the server:

1. Loads config and secret key.
2. Ensures data and DB directories exist.
3. Opens SQLite pool and runs migrations.
4. Bootstraps master encryption key.
5. Loads server-mode library and space keys into `UnlockState`.
6. Starts background workers.

### Core state in Rocket

- `AppConfig`
- `SqlitePool`
- `MasterKey`
- `UnlockState`
- `RateLimiter`

## 6) Data Ownership Split

### Database (SQLite)

- Users, sessions.
- Personal library and space records.
- Group and membership tables.
- Space access grants.
- Chunked upload sessions.
- Integrity events.
- Recovery audit schema (reserved for future tier/recovery flows).
- Server config key-value table (master key envelope).

### Filesystem (`data/`)

- `data/libraries/<library_id>/...`
- `data/spaces/<space_id>/...`
- `data/.chunks/<upload_id>/...`

Disk files are encrypted blobs. Directory and file names are currently plaintext.

## 7) Encryption and Integrity

### Active mode

- Server-managed encryption mode is the active mode.
- Per-library/space data keys are wrapped by a server master key.

### File format and checks

- AES-256-GCM encryption per file.
- Hash footer is stored with encrypted payload for key-free corruption checks.
- Optional deeper integrity checks use data key when available.

### Key cache

- `UnlockState` stores currently available decrypted data keys.
- Server-mode keys are loaded at boot.

## 8) Layering

- Routes: HTTP contract and request/response mapping.
- Guards: auth/session/setup/space-permission/CSRF gatekeeping.
- Services: business logic.
- Models: SQLx-backed DB access.
- Utils: stateless helpers (path safety, mime, crypto helpers).

## 9) API Surface (Current)

### Core API modules

- Auth: `/api/v1/auth/*`
- Library files + chunked: `/api/v1/library/*`
- Integrity + notifications: `/api/v1/library/integrity/*`, `/api/v1/users/me/notifications`, `/api/v1/admin/integrity/*`
- Groups: `/api/v1/groups/*`
- Spaces + access + files: `/api/v1/spaces/*`

### Page modules

- Auth/setup pages: `/`, `/login`, `/register`, `/setup`
- Library pages: `/files*`, `/usage*`, `/settings`
- Group pages: `/groups*`
- Space pages: `/spaces*` (including chunked flows in page routes)

## 10) Background Jobs

- Integrity scanner: periodic scan + event recording.
- Session cleanup: removes expired sessions.
- Chunk cleanup: removes expired chunk uploads and staging directories.

## 11) Security Model (Current)

- Passwords: Argon2.
- Sessions: token hashed before DB storage.
- CSRF: cookie + token validation on state-changing page actions.
- Path traversal defense: centralized safe-join checks.
- Security headers and CSP in global fairings.

## 12) Repository Map

- `src/main.rs`: bootstrap, fairings, state wiring.
- `src/routes/`: API + page handlers.
- `src/services/`: core business logic.
- `src/models/`: persistence queries/structs.
- `src/guards/`: request guards.
- `src/tests/`: integration tests.
- `migrations/`: SQLite schema evolution.
- `templates/`, `static/`: server-rendered UI assets.

## 14) Immediate Cleanup Priorities

- Add server-side quota enforcement in upload and chunk completion paths.
- Decide on chunked space endpoint parity between API and page layers.
- Implement user-tier encryption flows end-to-end, or remove dormant schema paths until ready.
