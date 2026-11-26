# IronDrive Architecture

> Version: 0.7.0  
> Last updated: 2026-11-26

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
  - File operations parity with libraries, including chunked upload/download
    in both the API and the browser.
- Storage
  - Quotas enforced on every write path (see "Quotas" below).
  - Trash with restore; deleted items are kept for
    `IRONDRIVE_TRASH_RETENTION_DAYS` (default 30).
  - Streaming downloads with HTTP Range support; folders and multi-item
    selections download as a streamed zip.
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
- Group-owned spaces have no quota (they aren't charged to any user).

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
- `<library or space root>/.trash/<trash_id>/<name>`: trashed items. Dot-prefixed
  paths can't be addressed through any file route and are skipped by listings,
  usage walks and the integrity scanner.

Disk files are encrypted blobs. Directory and file names are currently plaintext.

## 7) Encryption and Integrity

### Active mode

- Server-managed encryption mode is the active mode.
- Per-library/space data keys are wrapped by a server master key.

### File format and checks

- AES-256-GCM encryption per file.
- Hash footer is stored with encrypted payload for key-free corruption checks.
- Optional deeper integrity checks use data key when available.

### Downloads

- `crypto_service::open_plaintext_stream` decrypts a byte range one STREAM
  segment at a time; memory stays bounded by the chunk size.
- A segment that fails authentication ends the stream with an error, so the
  HTTP response aborts (clients see a failed transfer, never a short "success")
  and an integrity alert is recorded.
- Full downloads of small single-piece files also carry `X-IronDrive-Integrity`
  (plaintext SHA-256). Streamed (chunked) files don't, since the hash isn't
  known until the end.

### Quotas

- A user's quota covers their library, spaces they own, their trash and their
  in-progress chunked uploads (which reserve space at init).
- Checked before every write: direct uploads, chunked init, chunked complete.
  Exceeding it returns 507 with how much space is left.

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

### Which routes to use

`/api/v1/*` is the API: bearer-token auth (`Authorization: Bearer <token>` from
`POST /api/v1/auth/login`), JSON in and out, errors as
`{"error": {"status", "reason", "description"}}`. Libraries and spaces expose the same set of
file operations, including chunked transfers and trash.

Everything else is the browser UI's own surface: session cookie plus CSRF
token, HTML or ad-hoc JSON shaped for the pages. It changes with the UI and
isn't a supported integration point.

### Core API modules

- Auth: `/api/v1/auth/*`
- Library files: `/api/v1/library/{list,mkdir,upload,download,delete,rename,info,usage,zip}`
- Library chunked transfers: `/api/v1/library/chunked/*`
- Library trash: `/api/v1/library/trash*`
- Integrity + notifications: `/api/v1/library/integrity/*`, `/api/v1/users/me/notifications`, `/api/v1/admin/integrity/*`
- Groups: `/api/v1/groups/*`
- Spaces + access: `/api/v1/spaces/*`
- Space files: `/api/v1/spaces/<id>/files/*` (same operations as the library,
  including `chunked/*` and `zip`), trash at `/api/v1/spaces/<id>/trash*`

Notes:

- `DELETE .../delete` moves to the trash and returns `trash_id`; pass
  `permanent=true` to delete outright.
- `GET .../download` streams and honours `Range`; `GET .../zip?path=a&path=b`
  streams a zip.

### Page modules

- Auth/setup pages: `/`, `/login`, `/register`, `/setup`
- Library pages: `/files*`, `/usage*`, `/settings`, `/trash*`
- Group pages: `/groups*`
- Space pages: `/spaces*`
- Admin and UI partials: `/admin*`, `/notifications*`, `/nav/extra`

## 10) Background Jobs

- Integrity scanner: periodic scan + event recording.
- Session cleanup: removes expired sessions.
- Chunk cleanup: removes expired chunk uploads and staging directories.
- Trash cleanup: permanently deletes items older than the retention period.

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

- Implement user-tier encryption flows end-to-end, or remove dormant schema paths until ready.
- Decide how group-owned spaces should be limited (group quotas, or charge the group's owner).
