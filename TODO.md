# IronDrive — TODO

> **Last Updated:** 2026-04-07
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
| **M2** | Authentication | Register, login, logout, session tokens, `AuthenticatedUser` guard | ✅ Complete |
| **M3** | Server Encryption Core | Master key bootstrap, data key gen, AES-256-GCM encrypt/decrypt + SHA-256, `UnlockState` | ✅ Complete |
| **M4** | Setup Wizard + Library | `POST /auth/setup-library`, personal library creation (server mode), `SetupGuard` | ✅ Complete |
| **M5** | Filesystem Service | `fs_service` + library routes — browse, upload, download, mkdir, rename, delete (all encrypted + checksummed) | ✅ Complete |
| **M5F** | Frontend (Tera + HTMX) | Server-rendered UI — auth flows, setup wizard, file browser, upload/download, settings, sidebar nav | ✅ Complete |
| **M5.5** | Chunked Transfers | Chunked upload/download endpoints, `chunk_service`, staging dir management | ✅ Complete |
| **M5.6** | Data Integrity | New on-disk format (file hash), key-free `verify_file_hash()`, two-tier integrity, corruption detection | ✅ Complete |
| **M5.7** | Background Services | `BackgroundRunner`, integrity scanner, session cleanup, chunk cleanup | ✅ Complete |
| **M6** | Groups | Group CRUD + membership + group management UI | ✅ Complete |
| **M7** | Spaces | Space CRUD, access control, filesystem routes (reuses `fs_service`) + space browser & sharing UI | 🔨 In progress |
| **M8** | User Encryption Tiers | Passphrase-derived keys, lock/unlock, recovery, audit log + setup wizard modes, lock/unlock UI, recovery alerts | ⬜ Not started |
| **M9** | Quotas | Disk usage calculation + enforcement on upload + quota display, usage breakdown, warning banners | ⬜ Not started |
| **M10** | Polish | CORS, request logging, error consistency, integration tests + UI/UX audit, responsive/a11y/dark mode pass | ⬜ Not started |

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

- [x] `src/models/user.rs` — User struct, create, find by username/email
- [x] `src/models/session.rs` — Session struct, create, validate, delete
- [x] `src/utils/crypto.rs` — Argon2 password hash + verify
- [x] `src/services/auth_service.rs` — register, login, logout
- [x] `src/guards/auth_guard.rs` — `AuthenticatedUser` request guard
- [x] `src/guards/admin_guard.rs` — `AdminUser` request guard
- [x] `src/routes/auth.rs` — register, login, logout endpoints

### M3 — Server Encryption Core

- [x] Master key bootstrap in `src/services/crypto_service.rs`:
  - [x] First boot: generate master key, encrypt with `IRONDRIVE_SECRET_KEY`, store in `server_config`
  - [x] Subsequent boots: load + decrypt master key into memory
  - [x] `MasterKey` managed as Rocket state, zeroized on drop via `zeroize` crate
  - [x] Race-safe first boot (`INSERT OR IGNORE` + verify)
- [x] Per-library/space data key generation
- [x] Data key wrapping: encrypt data key with master key → `encrypted_data_key`
- [x] Data key unwrapping: decrypt `encrypted_data_key` with master key
- [x] AES-256-GCM file encryption (nonce + ciphertext + tag + checksum format)
  - [x] `encrypt_file_bytes()` — in-memory encrypt to on-disk format
  - [x] `encrypt_and_write_file()` — encrypt + write to disk with optional write-verify pass
- [x] AES-256-GCM file decryption with checksum verification
  - [x] `decrypt_file_bytes()` — in-memory decrypt with SHA-256 checksum verification
  - [x] `read_and_decrypt_file()` — read from disk + decrypt
  - [x] `verify_file_integrity()` — returns `IntegrityStatus` enum (Ok / ChecksumMismatch / DecryptionFailed)
- [x] SHA-256 checksum computation (streaming, async)
  - [x] `sha256_bytes()` — in-memory hash
  - [x] `sha256_file()` — streaming async file hash (64 KiB buffer)
- [x] `src/services/unlock_state.rs` — in-memory key store (dashmap)
  - [x] Separate `DashMap` for libraries and spaces
  - [x] Insert / get / remove / is_unlocked / count for both
  - [x] `clear_all()` for shutdown
  - [x] `ZeroVec` wrapper zeroizes key bytes on drop
  - [x] Integrated into Rocket managed state at startup
- [x] Unit tests: encrypt → decrypt roundtrip
- [x] Unit tests: key wrapping/unwrapping
- [x] Unit tests: checksum generation + verification
- [x] Unit tests: corruption detection (tampered file → checksum mismatch)

### M4 — Setup Wizard + Library

- [x] `src/models/library.rs` — PersonalLibrary struct, create, find by user
- [x] `src/services/library_service.rs`:
  - [x] Setup: create library with `server` mode (default)
  - [x] Generate data key, wrap with master key, store `encrypted_data_key`
  - [x] Create dir on disk + `.irondrive.meta`
  - [x] Load data key into `UnlockState` right away (server mode = always unlocked)
- [x] `src/guards/setup_guard.rs` — reject requests if `setup_complete == false`
- [x] `POST /api/v1/auth/setup-library` endpoint (server mode only for now)
- [x] Integration tests for setup flow

### M5 — Filesystem Service

- [x] `src/utils/path_safety.rs` — `safe_join()` with all the traversal checks
- [x] `src/utils/mime.rs` — MIME type detection from extension
- [x] `src/services/fs_service.rs`:
  - [x] `list_directory()` — read real filesystem, return `Vec<FsEntry>` (includes integrity status)
  - [x] `create_directory()` — mkdir with parent creation
  - [x] `upload_file()` — encrypt, compute checksum, write to disk, verify write
  - [x] `download_file()` — read, decrypt, verify checksum, set integrity header
  - [x] `delete_entry()` — remove file or dir (recursive)
  - [x] `rename_entry()` — rename or move within same root
  - [x] `get_entry_info()` — stat a single file/folder (with integrity status)
  - [x] `calculate_usage()` — walk dir tree, sum sizes
- [x] `src/routes/library.rs` — personal library filesystem endpoints (list, mkdir, upload, download, delete, rename, info, usage)
- [x] File upload via Rocket's `Data` type (with configurable size limit from `max_upload_bytes`)
- [x] File download with streaming response + `X-IronDrive-Integrity` header (SHA-256 hex digest)
- [x] Integration tests for all fs operations (48 HTTP-level integration tests)
- [x] Integration tests for checksum verification on download (known-vector SHA-256 + upload/download roundtrip)
- [ ] **Security**: fuzz `safe_join()` with adversarial paths — this is the most critical function in the codebase

### M5F — Frontend (Tera + HTMX + Tailwind)

Server-rendered UI served directly by Rocket. Stack: `rocket_dyn_templates` (Tera) + HTMX + vanilla JS + Tailwind CSS.

- [x] **Setup & Infrastructure**
  - [x] Add `rocket_dyn_templates` with Tera to `Cargo.toml`
  - [x] Configure template dir in `Rocket.toml` (`templates/`)
  - [x] `src/routes/pages.rs` — page-serving routes (HTML responses, separate from `/api/v1/` JSON routes)
  - [x] Wire `Template::fairing()` into Rocket launch
  - [x] Serve static assets via `FileServer` from `static/`
  - [x] Download HTMX (~14KB) into `static/vendor/`
  - [x] Tailwind CSS build (standalone CLI) → `static/css/style.css`
  - [x] `Makefile`: `build-css`, `watch-css`, `dev` targets
- [x] **Base Layout & Shared Components**
  - [x] `templates/base.html.tera` — HTML shell (head, sidebar, footer, HTMX + Tailwind includes, `static/js/app.js`)
  - [x] `templates/partials/nav.html.tera` — left sidebar nav (logo, Files/Shares/Spaces/Trash links, storage usage, user menu with settings/dark mode/logout)
  - [x] `templates/partials/flash.html.tera` — toast notification component (fixed top-right overlay, auto-dismiss)
  - [x] `templates/partials/breadcrumb.html.tera` — path breadcrumbs for file browser
  - [x] `templates/partials/confirm_modal.html.tera` — reusable confirmation dialog (vanilla JS)
  - [x] `templates/partials/empty_state.html.tera` — empty folder / no results placeholder
  - [x] `templates/partials/sidebar_usage.html.tera` — HTMX-loaded storage bar in sidebar
- [x] **Auth Pages**
  - [x] `GET /login` → `templates/auth/login.html.tera` — login form
  - [x] `GET /register` → `templates/auth/register.html.tera` — registration form
  - [x] `POST /login` — form submit → call `auth_service::login()` → set session cookie → redirect
  - [x] `POST /register` — form submit → call `auth_service::register()` → redirect to login
  - [x] `POST /logout` — destroy session → redirect to login
  - [x] Flash messages for errors (bad password, username taken, etc.)
  - [x] Redirect authenticated users away from login/register
  - [x] Redirect unauthenticated users to login from protected pages
- [x] **Setup Wizard Page**
  - [x] `GET /setup` → `templates/setup/wizard.html.tera` — library setup form
  - [x] `POST /setup` — create personal library (server mode) → redirect to file browser
  - [x] Guard: redirect to `/setup` if `setup_complete == false`
  - [x] Guard: redirect to `/files` if setup already complete
- [x] **File Browser (core feature)**
  - [x] `GET /files` → `templates/files/browser.html.tera` — main file browser view
  - [x] `GET /files?path=subdir/` — directory navigation via query param
  - [x] `templates/partials/file_list.html.tera` — table of `FsEntry` items (HTMX partial for swapping)
  - [x] HTMX-powered directory navigation (`hx-get="/files/partial?path=..."` → swap file list without full reload)
  - [x] File icons by type/extension (folder icon, document icon, image icon, etc.) via `partials/file_icon.html.tera`
  - [x] File size formatting (human-readable: KB, MB, GB)
  - [x] Last modified timestamp display
  - [x] Sort by name / size / date (vanilla JS client-side sorting)
  - [x] Breadcrumb navigation (clickable path segments)
- [x] **File Operations UI**
  - [x] **Upload**: drag-and-drop zone + file input button
    - [x] `POST /files/upload?path=...` — raw body upload via XHR
    - [x] **Upload progress panel** (`static/js/upload.js` + `templates/partials/upload_panel.html.tera`):
      - [x] Collapsible panel listing active uploads (fixed bottom-right)
      - [x] Per-file progress bar driven by `XMLHttpRequest` `upload.onprogress`
      - [x] States per file: uploading → processing ("Encrypting…") → complete / failed
      - [x] Panel auto-opens when upload starts
      - [x] Multiple concurrent uploads shown as stacked rows
      - [x] Minimize / expand toggle
      - [x] "Clear completed" button
    - [x] **Placeholder row in file list** while server is processing (ghost row with pulsing indicator)
    - [x] Error flash on failure (size limit, conflict, etc.)
  - [x] **Download**: click file name or download button → `GET /files/download?path=...` (direct browser download)
  - [x] **Create Folder**: button → modal → `POST /files/mkdir` → redirect with flash
  - [x] **Rename**: click rename action → modal → `POST /files/rename` → redirect with flash
  - [x] **Delete**: click delete action → confirmation modal → `POST /files/delete` → redirect with flash
  - [ ] Multi-select with checkboxes → bulk delete (stretch goal)
- [x] **Usage / Storage Page**
  - [x] `GET /usage` → `templates/files/usage.html.tera`
  - [x] Display total usage (from `calculate_usage()`)
  - [x] Visual bar / progress indicator for used space
  - [x] `GET /usage/sidebar` — HTMX partial for permanent sidebar storage indicator
- [x] **Settings Page**
  - [x] `GET /settings` → `templates/settings/index.html.tera`
  - [x] Display current user info (username, email)
  - [x] Library info (encryption mode, created date)
  - [x] Placeholder sections for future features (encryption tier, quotas)
- [x] **Error Pages**
  - [x] `templates/errors/404.html.tera` — not found
  - [x] `templates/errors/500.html.tera` — internal error
  - [x] `templates/errors/403.html.tera` — forbidden / locked
  - [x] Rocket catcher routes → render error templates (400, 401, 403, 404, 409, 422, 500)
- [x] **Responsive Design**
  - [x] Mobile sidebar (slide-out drawer with overlay, hamburger button in mobile top bar)
  - [x] File browser works on mobile (columns hidden on small screens: `hidden sm:table-cell`)
  - [x] Upload works on mobile (file picker + drag-and-drop)
- [x] **Accessibility & UX Polish** (partial)
  - [x] Semantic HTML throughout (nav, main, aside, etc.)
  - [x] ARIA labels on icon-only buttons (upload, delete, rename, etc.)
  - [x] Visible focus rings on interactive elements (`focus-visible:ring`)
  - [x] `aria-live="polite"` region for flash messages
  - [x] Disable submit buttons during in-flight requests to prevent double-submit
  - [x] Keyboard navigation: ArrowUp/Down through file list, Enter to open folder / download file
  - [x] Focus management after HTMX swaps (re-init keyboard nav on `htmx:afterSwap`)
  - [x] Loading states: animated progress bar during HTMX requests (`hx-indicator`)
- [x] **Security Hardening (frontend)** (partial)
  - [x] CSP Rocket fairing: restrict `script-src`, `style-src`, `connect-src`, `font-src`
  - [x] `SameSite=Lax` + `HttpOnly` on session cookie
  - [x] `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy`, `Permissions-Policy` response headers
  - [x] Tera auto-escapes all user-supplied values (no `| safe` on user data)
  - [x] CSRF tokens on all state-changing forms (double-submit cookie + hidden field + `X-CSRF-Token` header for XHR)
  - [x] Rate-limit login / register form submissions (in-memory sliding window: 10 login/15min, 5 register/15min)
- [x] **Performance & Caching** (partial)
  - [x] Cache-bust static assets (version query param `?v=0.1.0` on CSS/JS URLs)
  - [x] `Cache-Control` headers: `immutable` for `/static/*`, `no-cache, no-store` for HTML
  - [ ] Gzip / Brotli compression fairing for responses
- [x] **Dark Mode**
  - [x] Tailwind `dark:` variant support (`darkMode: "class"`)
  - [x] Toggle in user menu panel (vanilla JS, persist choice in `localStorage`)
  - [x] Consistent dark palette across all pages and components
  - [x] OS preference detection via `prefers-color-scheme`
- [x] **Favicon & Branding**
  - [x] `static/favicon.svg`
  - [x] `<meta>` tags: `theme-color`
  - [x] App title / logo in sidebar and login page
- [x] **SEO & Meta (minimal)**
  - [x] `<meta name="robots" content="noindex, nofollow">`
  - [x] Proper `<title>` on every page
  - [x] `<meta name="description">`
- [x] **Tests**
  - [x] Page-level integration tests: unauthenticated → redirects to login
  - [x] Page-level integration tests: authenticated → renders file browser
  - [x] Page-level integration tests: setup guard redirects correctly
  - [x] Upload via XHR → file appears in listing
  - [x] Create folder → appears in listing
  - [x] Delete → removed from listing
  - [x] Rename → updated in listing
  - [x] CSRF token present on all forms
  - [x] CSRF rejection test (POST without token → 422)
  - [x] Cache-Control header test (HTML → no-cache)
  - [x] CSP header present on all responses
  - [x] Error pages render correctly (404, 403, 500)

### M5.5 — Chunked Transfers

- [x] Create `data/.chunks/` staging dir on startup
- [x] `src/services/chunk_service.rs`:
  - [x] `init_upload()` — create `chunked_uploads` row + staging dir, return `upload_id`
  - [x] `receive_chunk()` — validate index + size, write to staging
  - [x] `complete_upload()` — assemble chunks, verify checksum, persist encrypted file, clean up staging
  - [x] `cancel_upload()` — nuke staging dir + DB row
  - [x] `init_download()` — resolve file/chunks and generate short-lived token
  - [x] `serve_chunk()` — token-validated chunk serving from decrypted payload
- [x] `006_create_chunked_uploads.sql` migration
- [x] Chunked upload/download routes in `src/routes/library.rs`
- [ ] Chunked upload/download routes in `src/routes/spaces.rs`
- [x] Tests:
  - [x] Chunked upload → download roundtrip
  - [x] Parallel chunk upload ordering
  - [x] Incomplete upload → cancel → verify cleanup happened
  - [x] Checksum field on assembly is advisory-only (mismatch no longer rejected server-side)
  - [x] Small file falls through to single-request path

### M5.6 — Data Integrity

- [x] `verify_file_hash()` + `verify_file_hash_bytes()` — streaming key-free integrity check. Constants: `SINGLE_MAGIC`, `STREAM_MAGIC`, `FILE_HASH_LEN`, `MIN_SINGLE_FILE_LEN`, `MIN_STREAM_FILE_LEN`. 9 unit tests.
- [x] Single-shot encrypt/decrypt rewrite — `encrypt_file_bytes()`, `encrypt_and_write_file_owned()`, `decrypt_file_bytes_inner()` now produce `[SINGLE_MAGIC | nonce | ciphertext+tag | file_hash]`. Renamed `ChecksumMismatch` → `FileHashMismatch`. `ENCRYPTION_OVERHEAD = 63`.
- [x] STREAM encrypt/decrypt rewrite — `stream_encrypt_chunks_to_file()` hashes while writing, appends file hash at end. Removed `sha256_chunks()` pre-pass and `expected_checksum` param. Stream decrypt checks file hash first (key-free), then GCM tags per segment.
- [x] Two-tier `verify_file_integrity_async(data_key: Option<&DataKey>, path)` — tier 1: file hash (no key), tier 2: full GCM decrypt (with key). Falls back gracefully when library is locked.
- [x] Caller updates — `list_directory()` and `get_entry_info()` use `try_data_key()` so integrity checks work even when library is locked (key-free fallback instead of erroring). `chunk_service` checksum field is advisory-only. `routes/library.rs` response structs documented.
- [x] 16 new crypto_service tests (key-free checks on real blobs, two-tier async for single-shot + STREAM, roundtrips, corruption detection). Full suite: **450 tests passing**.

### M5.7 — Background Services & Integrity Events

- [x] `src/services/integrity_service.rs`:
  - [x] `record_event()` — insert into `integrity_events`
  - [x] `list_events()` — query for a library/space (unacknowledged first)
  - [x] `acknowledge_event()` — mark as acknowledged
  - [x] `scan_library()` — walk all files, `verify_file_hash()` each, record failures
  - [x] `scan_space()` — same for spaces
- [x] `007_create_integrity_events.sql` migration
- [x] Integrity routes in `src/routes/integrity.rs`
- [x] Wire into `GET /api/v1/users/me/notifications`
- [x] Admin integrity endpoints in `src/routes/integrity.rs`
- [x] `src/services/background/mod.rs` — `BackgroundRunner`
- [x] `src/services/background/integrity_scan.rs`:
  - [x] Periodic loop, configurable interval
  - [x] Skip locked libraries/spaces for GCM check (key-free file hash still runs)
  - [x] Throttle I/O between files so we don't starve request handling
  - [x] Log via `tracing`
- [x] `src/services/background/session_cleanup.rs`:
  - [x] Hourly loop, prune expired sessions
- [x] `src/services/background/chunk_cleanup.rs`:
  - [x] Every 30min, delete expired incomplete uploads
  - [x] Remove staging dir + DB row
- [x] `on_liftoff` fairing in `main.rs` — launch `BackgroundRunner`
- [x] Config env vars: `IRONDRIVE_INTEGRITY_SCAN_INTERVAL_HOURS`, `IRONDRIVE_INTEGRITY_SCAN_ENABLED`
- [x] Tests:
  - [x] Upload → corrupt on disk → `verify_file_hash()` catches it without key
  - [x] Scan finds corrupted file → event created
  - [x] Acknowledge → gone from unacknowledged list
  - [x] Truncated file → caught
  - [x] Session cleanup actually removes expired sessions
  - [x] Chunk cleanup removes expired staging
  - [x] Integrity scanner catches corrupted file
  - [x] Scanner skips locked libraries (key-free check only, no GCM)

### M6 — Groups

- [x] `migrations/003_create_groups.sql` — `groups` + `group_members` tables (cascade delete, composite PK)
- [x] `src/models/group.rs` — Group, GroupMember, GroupMemberDetail, GroupWithMeta structs + queries
  - [x] `Group::create()`, `find_by_id()`, `find_by_name()`, `find_for_user()`, `find_all_for_user()`, `update()`, `delete_by_id()`
  - [x] `GroupMember::add()`, `remove()`, `find()`, `is_member()`, `list_with_details()`, `update_role()`
  - [x] Race-safe UNIQUE constraint handling on group names and member inserts
  - [x] Owner-first member sort order (`CASE WHEN` on role)
  - [x] 10 unit tests (create, find, duplicate, update, delete cascade, list for user, add/remove member, role update, list with details)
- [x] `src/services/group_service.rs` — business logic
  - [x] `create_group()` — create + auto-add creator as owner
  - [x] `get_group()` — single targeted query (not full-list scan)
  - [x] `list_user_groups()` — all groups user belongs to with meta
  - [x] `update_group()` — requires owner/manager role
  - [x] `delete_group()` — owner (creator) only
  - [x] `list_members()` — requires membership
  - [x] `add_member()` — by username, owner/manager only, cannot assign owner role
  - [x] `remove_member()` — owner/manager remove others, self-leave, owner protected
  - [x] `update_member_role()` — owner only, cannot change owner's role
  - [x] Input validation: name 1-100 chars (trimmed), description max 500 chars, role whitelist
  - [x] Structured `tracing` logging on all mutations
- [x] `src/routes/groups.rs` — 9 JSON API endpoints
  - [x] `POST /api/v1/groups` — create group
  - [x] `GET /api/v1/groups` — list user's groups
  - [x] `GET /api/v1/groups/<id>` — get single group
  - [x] `PUT /api/v1/groups/<id>` — update group
  - [x] `DELETE /api/v1/groups/<id>` — delete group
  - [x] `GET /api/v1/groups/<id>/members` — list members
  - [x] `POST /api/v1/groups/<id>/members` — add member by username
  - [x] `DELETE /api/v1/groups/<id>/members/<user_id>` — remove member
  - [x] `PUT /api/v1/groups/<id>/members/<user_id>` — update member role
- [x] **Frontend**
  - [x] `templates/groups/index.html.tera` — group list page (responsive card grid, empty state, create modal)
  - [x] `templates/groups/detail.html.tera` — group detail page (info card, member table, edit/delete/add-member modals)
  - [x] `templates/partials/member_list.html.tera` — member table partial (avatar, username, email, role badges, remove button)
  - [x] `static/js/groups.js` — modal logic for create group (CSP-compliant, no inline JS)
  - [x] `static/js/group_detail.js` — modal logic for edit/delete/add-member + confirm-before-remove
  - [x] `GET /groups` page route — list groups with flash messages
  - [x] `GET /groups/<id>` page route — group detail with member list
  - [x] `POST /groups/create` — form submit with CSRF → create group → redirect with flash
  - [x] `POST /groups/<id>/edit` — form submit with CSRF → update group → redirect with flash
  - [x] `POST /groups/<id>/delete` — form submit with CSRF → delete group → redirect with flash
  - [x] `POST /groups/<id>/members/add` — form submit with CSRF → add member → redirect with flash
  - [x] `POST /groups/<id>/members/<user_id>/remove` — form submit with CSRF → remove member → redirect with flash
  - [x] Updated sidebar nav: "Groups" link with users icon between Shares and Spaces
  - [x] Role badges: owner (blue), manager (amber), member (gray)
  - [x] Empty state for no groups
  - [x] Responsive layout, dark mode support, accessibility (aria-modal, aria-label)
  - [x] All modals: open/close via external JS, Escape key dismiss, backdrop click dismiss
- [x] Integration tests (`src/tests/groups.rs`) — 20 tests
  - [x] Create group → appears in list
  - [x] Duplicate group name → 409 Conflict
  - [x] Get group detail → correct response
  - [x] Update group name/description → updated
  - [x] Delete group → removed
  - [x] Add member → appears in member list
  - [x] Remove member → gone from list
  - [x] Owner cannot be removed
  - [x] Non-member cannot access group
  - [x] Member cannot add/remove members or edit/delete group
  - [x] Manager can add members and edit but not delete
  - [x] Update member role (promote to manager)
  - [x] Duplicate member → 409 Conflict
  - [x] Add nonexistent user → 404
  - [x] Member can self-leave
  - [x] Unauthenticated API → 401
  - [x] Groups page renders for authenticated user
  - [x] Group detail page renders with group name and owner
  - [x] Unauthenticated groups page → redirect
  - [x] CSRF required on form POSTs (missing → 422)

### M7 — Spaces

- [x] `src/models/space.rs` — Space, SpaceAccess structs + queries
- [x] `src/services/space_service.rs`:
  - [x] Create space (DB row + dir + data key, server mode)
  - [x] Delete space (DB row + dir)
  - [x] Permission resolution (owner → group → direct grant)
  - [x] Grant/revoke access
  - [x] Load all server-mode space keys into `UnlockState` at boot
- [x] `src/guards/space_guard.rs` — permission check guard
- [x] `src/routes/spaces.rs` — all space endpoints (CRUD + filesystem + access)
- [ ] **Frontend**
  - [ ] `templates/spaces/index.html.tera` — space list page (cards showing name, owner, member count, usage)
  - [ ] `templates/spaces/browser.html.tera` — space file browser (reuse `file_list.html.tera` partial with space context)
  - [ ] `templates/spaces/settings.html.tera` — space settings (rename, delete, manage access)
  - [ ] `templates/partials/space_card.html.tera` — reusable space card component
  - [ ] `templates/partials/access_list.html.tera` — member/group access list with role badges
  - [ ] `GET /spaces` page route — list all spaces the user has access to
  - [ ] `GET /spaces/:id` page route — space file browser (same UX as personal library browser)
  - [ ] `GET /spaces/:id/settings` page route — space settings & access management
  - [ ] Create space modal (name) → `POST /spaces` → redirect to new space browser
  - [ ] Delete space → confirmation modal → `POST /spaces/:id/delete` → redirect with flash
  - [ ] Share space: grant access to user or group → role selector (viewer/editor/admin) → HTMX swap access list
  - [ ] Revoke access → confirmation modal → HTMX swap access list
  - [ ] Space file operations: reuse upload, download, mkdir, rename, delete UI (same partials, scoped to space)
  - [ ] Breadcrumb shows space name as root instead of "My Library"
  - [ ] Update sidebar nav: add "Spaces" link with icon + list of user's spaces
  - [ ] Empty state for no spaces
  - [ ] Permission-aware UI: hide edit/delete/upload buttons if user is viewer-only
  - [ ] Responsive layout for space pages
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
- [ ] **Frontend**
  - [ ] Update `templates/setup/wizard.html.tera` — encryption mode selector (server / failsafe / pure)
    - [ ] Mode cards with descriptions and security trade-off explanation
    - [ ] Passphrase input fields for failsafe/pure modes (with strength indicator)
    - [ ] Pure mode warning dialog ("no recovery possible — are you sure?")
    - [ ] Confirm passphrase field with match validation
  - [ ] `templates/partials/lock_banner.html.tera` — banner shown when library/space is locked ("Enter passphrase to unlock")
  - [ ] `templates/partials/unlock_modal.html.tera` — passphrase entry modal for unlocking
  - [ ] Lock/unlock UI in file browser:
    - [ ] Lock button in toolbar/nav when library/space is unlocked
    - [ ] Locked state: show lock banner instead of file list, hide upload/mkdir/rename/delete buttons
    - [ ] `POST /files/unlock` → submit passphrase → unlock → redirect to file browser
    - [ ] `POST /files/lock` → lock → redirect with flash
  - [ ] Lock/unlock UI for spaces:
    - [ ] Same lock banner + unlock modal scoped to `/spaces/:id`
    - [ ] `POST /spaces/:id/unlock` / `POST /spaces/:id/lock`
  - [ ] Update `templates/settings/index.html.tera`:
    - [ ] Display current encryption tier (server / failsafe / pure) with explanation
    - [ ] Change passphrase form (current passphrase + new passphrase + confirm)
  - [ ] Recovery notification UI:
    - [ ] `templates/partials/recovery_alert.html.tera` — dismissible alert banner ("Admin recovered your library on <date>")
    - [ ] Show in nav or top-of-page when unacknowledged recovery exists
    - [ ] Acknowledge button → `POST /notifications/:id/acknowledge` → HTMX remove alert
  - [ ] Admin recovery page:
    - [ ] `templates/admin/recovery.html.tera` — list users, trigger recovery for failsafe users
    - [ ] Confirmation modal before triggering recovery
    - [ ] Recovery audit log table
  - [ ] Responsive layout for all new modals and pages
- [ ] Tests:
  - [ ] Failsafe: setup → lock → unlock → file roundtrip
  - [ ] Failsafe: recovery → notification → acknowledge
  - [ ] Pure: setup → lock → unlock → file roundtrip
  - [ ] Pure: recovery attempt → rejected
  - [ ] Bad passphrase → rejected
  - [ ] Onboarding covers all three modes + pure mode warning
  - [ ] Setup wizard renders all three mode options
  - [ ] Lock/unlock UI state transitions (locked → unlock form → unlocked file browser)
  - [ ] Recovery alert appears after admin recovery, disappears after acknowledge

### M9 — Quotas

- [ ] `src/services/quota_service.rs`:
  - [ ] Real disk usage per library (encrypted sizes on disk)
  - [ ] Real disk usage per space (attributed to owner)
  - [ ] Total usage per user (library + owned spaces)
- [ ] Quota check before file upload
- [ ] Usage info in `GET /api/v1/users/me` response
- [ ] Usage info in `GET /api/v1/library/status` response
- [ ] **Frontend**
  - [ ] Update `templates/files/usage.html.tera` — show quota limit alongside current usage
    - [ ] Progress bar: used / quota (color changes: green → yellow → red as approaching limit)
    - [ ] Breakdown: library usage + per-space usage table
  - [ ] Update `templates/partials/sidebar_usage.html.tera` — show quota fraction (e.g., "3.2 GB / 10 GB")
    - [ ] Warning color when usage > 80% of quota
    - [ ] Critical color when usage > 95% of quota
  - [ ] Upload rejection feedback: flash message when upload is rejected due to quota ("Storage full — free up space or contact admin")
  - [ ] Quota warning banner on file browser when near limit (> 90%)
  - [ ] Admin quota management (if admin UI exists by this point):
    - [ ] Set per-user quota in admin settings
    - [ ] View all users' usage vs quota
  - [ ] Update space settings page: show space-specific usage
  - [ ] Responsive layout for updated usage page
- [ ] Tests for quota enforcement
  - [ ] Upload rejected when over quota → correct flash message shown
  - [ ] Sidebar usage reflects quota fraction
  - [ ] Warning banner appears when near limit

### M10 — Polish

- [ ] `src/fairings/cors.rs` — configurable CORS
- [ ] `src/fairings/request_logger.rs` — structured request logging
- [ ] Go through all error responses for consistency
- [ ] `tracing` spans on all service functions
- [ ] Make sure crypto errors never leak key material into logs
- [ ] **Frontend**
  - [ ] Consistent error page styling across all error codes (400, 401, 403, 404, 409, 422, 500)
  - [ ] Gzip / Brotli compression fairing for responses (moved from M5F)
  - [ ] UI audit: verify all flash messages have consistent styling and auto-dismiss behavior
  - [ ] UI audit: verify all modals have consistent close behavior (Escape key, click outside, X button)
  - [ ] UI audit: verify all forms disable submit button during in-flight requests
  - [ ] UI audit: verify CSRF tokens present on all new forms added in M6–M9
  - [ ] Responsive design pass: verify all M6–M9 pages work on mobile
  - [ ] Accessibility pass: ARIA labels on all new interactive elements from M6–M9
  - [ ] Dark mode pass: verify all new M6–M9 components have proper `dark:` variants
  - [ ] Loading states: verify HTMX indicators on all new HTMX-powered interactions
  - [ ] Navigation: verify sidebar active state highlights correctly on all pages
  - [ ] Breadcrumb consistency across library browser, space browser, group pages
  - [ ] Cache-bust updated CSS/JS assets (bump version query param)
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
| ~~**Memory key zeroization**~~ | ~~`zeroize` crate to wipe keys from memory on lock/drop.~~ Done in v1 (M3). |
| **Encryption mode migration** | Upgrade a library/space from server → failsafe → pure (re-encrypt data key, files stay as-is). |

---

*Living document — update as things get built.*
