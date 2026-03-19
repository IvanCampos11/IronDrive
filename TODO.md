# IronDrive — TODO

> **Last Updated:** 2026-03-17
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
| **M5F** | Frontend (Tera + HTMX) | Server-rendered UI — auth flows, setup wizard, file browser, upload/download, settings | ⬜ Not started |
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

- [ ] **Setup & Infrastructure**
  - [ ] Add `rocket_dyn_templates` with Tera to `Cargo.toml`
  - [ ] Configure template dir in `Rocket.toml` (`templates/`)
  - [ ] `src/routes/pages.rs` — page-serving routes (HTML responses, separate from `/api/v1/` JSON routes)
  - [ ] Wire `Template::fairing()` into Rocket launch
  - [ ] Serve static assets via `FileServer` from `static/`
  - [ ] Download HTMX (~14KB) into `static/vendor/`
  - [ ] Tailwind CSS build (standalone CLI or npm script) → `static/css/style.css`
  - [ ] `Makefile` / script: `build-css` target for Tailwind rebuild
- [ ] **Base Layout & Shared Components**
  - [ ] `templates/base.html.tera` — HTML shell (head, nav, footer, HTMX + Tailwind includes, `static/js/app.js`)
  - [ ] `templates/partials/nav.html.tera` — top nav bar (logo, user menu, logout)
  - [ ] `templates/partials/flash.html.tera` — flash message / toast component
  - [ ] `templates/partials/breadcrumb.html.tera` — path breadcrumbs for file browser
  - [ ] `templates/partials/confirm_modal.html.tera` — reusable confirmation dialog (vanilla JS)
  - [ ] `templates/partials/empty_state.html.tera` — empty folder / no results placeholder
- [ ] **Auth Pages**
  - [ ] `GET /login` → `templates/auth/login.html.tera` — login form
  - [ ] `GET /register` → `templates/auth/register.html.tera` — registration form
  - [ ] `POST /login` — form submit → call `auth_service::login()` → set session cookie → redirect
  - [ ] `POST /register` — form submit → call `auth_service::register()` → redirect to login
  - [ ] `POST /logout` — destroy session → redirect to login
  - [ ] Flash messages for errors (bad password, username taken, etc.)
  - [ ] Redirect authenticated users away from login/register
  - [ ] Redirect unauthenticated users to login from protected pages
- [ ] **Setup Wizard Page**
  - [ ] `GET /setup` → `templates/setup/wizard.html.tera` — library setup form
  - [ ] `POST /setup` — create personal library (server mode) → redirect to file browser
  - [ ] Guard: redirect to `/setup` if `setup_complete == false`
  - [ ] Guard: redirect to `/files` if setup already complete
- [ ] **File Browser (core feature)**
  - [ ] `GET /files` → `templates/files/browser.html.tera` — main file browser view
  - [ ] `GET /files?path=subdir/` — directory navigation via query param
  - [ ] `templates/partials/file_list.html.tera` — table/grid of `FsEntry` items (HTMX partial for swapping)
  - [ ] HTMX-powered directory navigation (`hx-get="/files?path=..."` → swap file list without full reload)
  - [ ] File icons by type/extension (folder icon, document icon, image icon, etc.)
  - [ ] File size formatting (human-readable: KB, MB, GB)
  - [ ] Last modified timestamp display
  - [ ] Sort by name / size / date (HTMX swap or vanilla JS client-side)
  - [ ] Breadcrumb navigation (clickable path segments)
- [ ] **File Operations UI**
  - [ ] **Upload**: drag-and-drop zone + file input button
    - [ ] `POST /files/upload?path=...` — multipart or raw body upload
    - [ ] **Upload progress panel** (fixed bottom-right, vanilla JS component):
      - [ ] `templates/partials/upload_panel.html.tera` — collapsible panel listing active uploads
      - [ ] Per-file progress bar driven by `XMLHttpRequest` `upload.onprogress` (percentage + bytes sent)
      - [ ] States per file: uploading → processing (server encrypting) → complete / failed
      - [ ] Panel auto-opens when upload starts, stays visible until dismissed or all complete
      - [ ] Multiple concurrent uploads shown as stacked rows in the panel
      - [ ] Minimize / expand toggle so panel doesn't block the file browser
      - [ ] "Clear completed" button to dismiss finished items
    - [ ] **Placeholder row in file list** while server is processing:
      - [ ] After browser upload finishes (100%), inject a ghost/placeholder row into the file list via vanilla JS DOM manipulation
      - [ ] Placeholder shows filename + spinning/pulsing indicator + "Encrypting…" status text
      - [ ] Row styled distinctly (muted/translucent) so it's clearly not a real entry yet
      - [ ] On upload success → HTMX refresh replaces placeholder with real `FsEntry` row
      - [ ] On upload failure → placeholder turns into error state with retry/dismiss action
      - [ ] Handles edge case: user navigates away from target folder → placeholder only shown when viewing that folder
    - [ ] Error flash on failure (size limit, conflict, etc.)
  - [ ] **Download**: click file name or download button → `GET /files/download?path=...` (direct browser download)
  - [ ] **Create Folder**: button → inline input or modal → `POST /files/mkdir?path=...` → HTMX refresh
  - [ ] **Rename**: click rename action → inline edit or modal → `POST /files/rename` → HTMX refresh
  - [ ] **Delete**: click delete action → confirmation modal (vanilla JS) → `DELETE /files/delete?path=...` → HTMX refresh
  - [ ] Multi-select with checkboxes → bulk delete (stretch goal)
- [ ] **Usage / Storage Page**
  - [ ] `GET /usage` → `templates/files/usage.html.tera`
  - [ ] Display total usage (from `calculate_usage()`)
  - [ ] Visual bar / progress indicator for used space
- [ ] **Settings Page**
  - [ ] `GET /settings` → `templates/settings/index.html.tera`
  - [ ] Display current user info (username, email)
  - [ ] Library info (encryption mode, created date)
  - [ ] Placeholder sections for future features (encryption tier, quotas)
- [ ] **Error Pages**
  - [ ] `templates/errors/404.html.tera` — not found
  - [ ] `templates/errors/500.html.tera` — internal error
  - [ ] `templates/errors/403.html.tera` — forbidden / locked
  - [ ] Rocket catcher routes → render error templates
- [ ] **Responsive Design**
  - [ ] Mobile-friendly nav (hamburger menu via vanilla JS)
  - [ ] File browser works on mobile (card layout or compact table)
  - [ ] Upload works on mobile (file picker, no drag-and-drop)
- [ ] **Accessibility & UX Polish**
  - [ ] Semantic HTML throughout (nav, main, section, article, etc.)
  - [ ] ARIA labels on icon-only buttons (upload, delete, rename, etc.)
  - [ ] Keyboard navigation: tab through file list, Enter to open folder / download file
  - [ ] Focus management after HTMX swaps (focus first item or flash message)
  - [ ] Visible focus rings on all interactive elements (Tailwind `focus-visible:ring`)
  - [ ] `aria-live="polite"` region for flash messages / HTMX swap notifications
  - [ ] Sufficient color contrast (WCAG AA minimum)
  - [ ] Loading states: skeleton / spinner shown during HTMX requests (`hx-indicator`)
  - [ ] Disable submit buttons during in-flight requests to prevent double-submit
- [ ] **Security Hardening (frontend)**
  - [ ] CSP meta tag or Rocket fairing: restrict `script-src`, `style-src`, `connect-src`
  - [ ] CSRF tokens on all state-changing forms (Rocket `CsrfToken` cookie + hidden field)
  - [ ] `SameSite=Lax` (or `Strict`) + `HttpOnly` + `Secure` on session cookie
  - [ ] `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY` response headers
  - [ ] Sanitize / escape all user-supplied values rendered in templates (Tera auto-escapes by default — verify no `| safe` on user data)
  - [ ] Rate-limit login / register form submissions (Rocket fairing or middleware)
- [ ] **Performance & Caching**
  - [ ] Cache-bust static assets (append hash or version query param to CSS/JS URLs)
  - [ ] `Cache-Control` headers: long cache for versioned static assets, no-cache for HTML
  - [ ] Gzip / Brotli compression fairing for responses (`rocket_compression` or reverse proxy note)
  - [ ] Lazy-load file icons / thumbnails for large directories (if applicable)
- [ ] **Dark Mode**
  - [ ] Tailwind `dark:` variant support (OS preference via `prefers-color-scheme`)
  - [ ] Toggle button in nav (vanilla JS, persist choice in `localStorage`)
  - [ ] Consistent dark palette across all pages and components
- [ ] **Favicon & Branding**
  - [ ] `static/favicon.ico` + `static/favicon.svg`
  - [ ] `<meta>` tags: `og:title`, `og:description`, `theme-color`
  - [ ] App title / logo in nav bar and login page
- [ ] **SEO & Meta (minimal)**
  - [ ] `<meta name="robots" content="noindex, nofollow">` (private app — don't index)
  - [ ] Proper `<title>` on every page (`IronDrive — Login`, `IronDrive — Files`, etc.)
  - [ ] `<meta name="description">` on login page (for bookmarks / link previews)
- [ ] **Tests**
  - [ ] Page-level integration tests: unauthenticated → redirects to login
  - [ ] Page-level integration tests: authenticated → renders file browser
  - [ ] Page-level integration tests: setup guard redirects correctly
  - [ ] Upload via HTML form → file appears in listing
  - [ ] Create folder → appears in listing
  - [ ] Delete → removed from listing
  - [ ] Rename → updated in listing
  - [ ] CSRF token present on all forms
  - [ ] CSP header present on all responses
  - [ ] Error pages render correctly (404, 403, 500)

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
| ~~**Memory key zeroization**~~ | ~~`zeroize` crate to wipe keys from memory on lock/drop.~~ Done in v1 (M3). |
| **Encryption mode migration** | Upgrade a library/space from server → failsafe → pure (re-encrypt data key, files stay as-is). |

---

*Living document — update as things get built.*
