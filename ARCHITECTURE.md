# IronDrive — Architecture Guide

> **Version:** 0.1.0
> **Last Updated:** 2025-07-14
> **Status:** Active development — core features implemented and tested

---

## Table of Contents

1. [Project Overview](#1-project-overview)
2. [Core Concepts](#2-core-concepts)
3. [Storage Philosophy](#3-storage-philosophy)
4. [Encryption Model](#4-encryption-model)
5. [User Onboarding Flow](#5-user-onboarding-flow)
6. [Directory Structure](#6-directory-structure)
7. [Data Layout on Disk](#7-data-layout-on-disk)
8. [Database Schema](#8-database-schema)
9. [Layer Architecture](#9-layer-architecture)
10. [API Surface](#10-api-surface)
11. [Chunked Transfers](#11-chunked-transfers)
12. [Data Integrity](#12-data-integrity)
13. [Background Services](#13-background-services)
14. [Key Design Patterns](#14-key-design-patterns)
15. [Dependencies](#15-dependencies)
16. [Security Considerations](#16-security-considerations)

> **Development milestones and future roadmap** are tracked in **[TODO.md](TODO.md)**.

---

## 1. Project Overview

IronDrive is a self-hosted file storage and sharing platform — basically a Google Drive / nextcloud / opencloud alternative, written in **Rust** with **Rocket**.

### Design Principles

- **Filesystem-as-truth** — The real filesystem is the source of truth for files and folders. No file metadata in the DB. If it's on disk, it exists. If it's not, it doesn't.
- **Keep it maintainable** — Flat module hierarchy, clear layers, no unnecessary abstractions.
- **Encrypted by default** — Every file is encrypted at rest via server-managed keys. Users don't have to think about it. If they want more control, they can opt into user-managed encryption.
- **Async all the way** — All I/O, all services, all background work. Nothing blocks.
- **Data integrity** — SHA-256 checksum on every file at write time, verified on read. Corruption gets caught and surfaced.
- **Single binary** — `cargo build --release` gives you one binary. Add a SQLite file and a data directory and you're done.

### Tech Stack

| Component | Choice | Why |
|---|---|---|
| Language | Rust | Performance, safety, single binary output |
| Web framework | Rocket 0.5.1 | Ergonomic, mature, async-native |
| Database | SQLite via SQLx | Zero-config, embedded, can swap to Postgres later |
| Password hashing | Argon2 | OWASP recommendation |
| Encryption | AES-256-GCM | Authenticated encryption, hardware-accelerated on most CPUs |
| Checksums | SHA-256 | Strong, fast with SHA-NI |
| Auth | Session tokens | Simpler than JWT for this use case |

---

## 2. Core Concepts

There are three main things users interact with:

```
┌──────────────────────────────────────────────────────────────┐
│                        IronDrive                             │
│                                                              │
│  ┌──────────────────┐          ┌──────────────────────────┐  │
│  │ Personal Library  │          │        Spaces            │  │
│  │ (one per user)    │          │  (collaborative areas)   │  │
│  │                   │          │                          │  │
│  │ - non-shareable   │          │  - owned by user/group   │  │
│  │ - non-deletable   │          │  - shareable             │  │
│  │ - private         │          │  - deletable             │  │
│  │ - created at      │          │  - permission levels:    │  │
│  │   first login     │          │    read / write / admin  │  │
│  └──────────────────┘          └──────────────────────────┘  │
│                                                              │
│  ┌──────────────────────────────────────────────────────────┐│
│  │                      Groups                              ││
│  │  Organize users → grant bulk access to Spaces            ││
│  └──────────────────────────────────────────────────────────┘│
└──────────────────────────────────────────────────────────────┘
```

### Personal Library

- **Exactly one** per user. Created during first-login setup wizard.
- **Cannot** be shared with other users.
- **Cannot** be deleted by the user (it exists as long as the account does).
- Encryption tier is chosen at setup and cannot be changed later.
- Always accessible at `/api/v1/library/...` (no ID needed — it's always *your* library).

### Spaces

- Collaborative shared storage areas.
- Owned by a **user** or a **group**.
- Can be shared with individual users or groups via `space_access`.
- Owner can delete the space.
- Each space has its own encryption tier (independent of the owner's library).

### Groups

- Named collections of users (e.g., "Engineering", "Design").
- Members have roles: `member` or `manager`.
- Groups can own spaces and be granted access to spaces.
- A user's effective permission on a space = highest permission from any grant (direct or via group).

### Permission Resolution (for Spaces)

```
Is user the space owner?              → admin
Is user in a group that owns space?   → admin
Does space_access have a direct grant?→ that permission level
Is user in a group that has a grant?  → that permission level (highest wins)
None of the above?                    → no access
```

---

## 3. Storage Philosophy

The short version: the DB knows about users, permissions, and keys. The filesystem knows about files. They don't overlap.

### What Lives Where

```
┌─────────────────────────┬────────────────────────────────────────┐
│ DATABASE (SQLite, db/)  │ FILESYSTEM (data/)                     │
├─────────────────────────┼────────────────────────────────────────┤
│ Users                   │ Actual files and folders               │
│ Personal library records│ File contents (always encrypted)       │
│ Groups + memberships    │ .irondrive.meta per library/space      │
│ Space registry:         │                                        │
│   - id, name, owner    │                                        │
│   - encryption_mode     │                                        │
│   - key material        │                                        │
│   - allowed groups/users│                                        │
│ Sessions / auth tokens  │                                        │
│ Quota limits            │                                        │
│ Recovery audit log      │                                        │
│ Chunked upload state    │                                        │
│ Integrity events        │                                        │
│                         │                                        │
│ NOT stored:             │ Source of truth for:                   │
│   - file names          │   - file names                         │
│   - folder structure    │   - folder structure                   │
│   - file sizes          │   - file sizes (of encrypted blobs)    │
│   - file contents       │   - file contents (encrypted)          │
│   - modification times  │   - modification times                 │
└─────────────────────────┴────────────────────────────────────────┘
```

### Why No File Database?

- **No sync headaches** — Can't have DB and disk disagree if only one of them tracks files.
- **Admin can browse** — The directory tree is visible (contents are encrypted, but structure is there).
- **No orphans** — No phantom DB records pointing to missing files or vice versa.
- **Dead-simple backups** — Copy `data/` and `db/`. That's the whole backup.

---

## 4. Encryption Model

Every file is always encrypted at rest. The tiers just determine who controls the decryption key.

### The Three Tiers

```
┌─────────────────────────────────────────────────────────────────┐
│                    ENCRYPTION TIERS                              │
│                                                                 │
│  ┌─────────────────────────────────────────────────────────┐    │
│  │ Tier 1: SERVER ENCRYPTION (default)                     │    │
│  │                                                         │    │
│  │  Server manages all keys. Users experience zero         │    │
│  │  friction. Files are encrypted at rest. Protects        │    │
│  │  against disk theft and backup leaks.                   │    │
│  │                                                         │    │
│  │  Key chain: IRONDRIVE_SECRET_KEY                        │    │
│  │             → master key (in DB, encrypted)             │    │
│  │               → per-library/space data key              │    │
│  │                 → AES-256-GCM file encryption           │    │
│  └─────────────────────────────────────────────────────────┘    │
│                                                                 │
│  ┌─────────────────────────────────────────────────────────┐    │
│  │ Tier 2: FAILSAFE USER ENCRYPTION                       │    │
│  │                                                         │    │
│  │  User sets a passphrase. Data key is wrapped by         │    │
│  │  BOTH the user-derived key AND the server master key    │    │
│  │  (recovery blob). Admin can recover on user request     │    │
│  │  — user is ALWAYS notified.                             │    │
│  │                                                         │    │
│  │  Key chain: user passphrase → Argon2 → user key         │    │
│  │             → unwrap data key → file decryption         │    │
│  │  Recovery:  master key → unwrap recovery blob           │    │
│  │             → data key → re-wrap with new passphrase    │    │
│  └─────────────────────────────────────────────────────────┘    │
│                                                                 │
│  ┌─────────────────────────────────────────────────────────┐    │
│  │ Tier 3: PURE USER ENCRYPTION                            │    │
│  │                                                         │    │
│  │  User sets a passphrase. Data key is wrapped ONLY by    │    │
│  │  the user-derived key. NO recovery blob exists.         │    │
│  │  If passphrase is lost, data is PERMANENTLY gone.       │    │
│  │                                                         │    │
│  │  Key chain: user passphrase → Argon2 → user key         │    │
│  │             → unwrap data key → file decryption         │    │
│  │  Recovery:  ❌ IMPOSSIBLE — by design                    │    │
│  └─────────────────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────────────────┘
```

### Tier 1: Server Encryption (Default)

**User experience**: Invisible. Files appear as if unencrypted.

**How it works**:

1. On first server boot, a **master key** (256-bit) is generated, encrypted with `IRONDRIVE_SECRET_KEY` from the environment, and stored in `server_config` table.
2. When a personal library or space is created:
   - A random **data key** (256-bit) is generated.
   - The data key is encrypted (wrapped) with the master key → stored as `encrypted_data_key` in the DB.
3. On server startup, the master key is loaded from DB and decrypted using `IRONDRIVE_SECRET_KEY`.
4. All server-mode data keys are unwrapped and held in memory (`UnlockState`).
5. Every file read/write uses the data key for AES-256-GCM encrypt/decrypt.

**Threat model**: Protects against:
- Physical disk theft
- Backup leaks
- Unauthorized direct filesystem access

Does **not** protect against: server compromise (admin/attacker with server access can read files).

### Tier 2: Failsafe User Encryption

**User experience**: Must enter passphrase each session to unlock library/space.

**How it works**:

1. User provides a passphrase during setup.
2. A random **salt** is generated and stored in the DB.
3. Argon2 derives a **user key** from passphrase + salt.
4. A random **data key** is generated.
5. The data key is wrapped with the user key → stored as `encrypted_data_key`.
6. The data key is ALSO wrapped with the master key → stored as `recovery_blob`.
7. A **verify blob** is created: encrypt the string `"IRONDRIVE_VERIFY"` with the user key. Used to quickly check if a passphrase is correct without attempting full decryption.

**Recovery flow** (admin-triggered):
1. Admin calls recovery endpoint with the user's ID.
2. Server unwraps data key from `recovery_blob` using master key.
3. User provides a new passphrase.
4. Data key is re-wrapped with the new user-derived key.
5. A **recovery audit log** entry is created (append-only, immutable).
6. User is **notified** via the notifications API and cannot miss it.

### Tier 3: Pure User Encryption

**User experience**: Must enter passphrase each session. **No safety net.**

**How it works**: Same as Tier 2, except:
- **No `recovery_blob`** is ever created.
- If the user forgets their passphrase, the data key is unrecoverable.
- The server explicitly refuses to create a recovery blob for this tier.
- Setup requires `acknowledge_no_recovery: true` in the API call.

### In-Memory Key Store

```rust
/// Holds decrypted data keys for currently unlocked libraries and spaces.
/// Server-mode keys are loaded automatically at boot.
/// User-mode keys are loaded when the user calls /unlock.
/// User-mode keys are removed when the user calls /lock or on session expiry.
/// All keys are zeroized on removal or drop.
///
/// Internally uses Arc<DashMap> so clones share the same key store.
/// This allows background tasks to hold a cheap handle to the live state.

#[derive(Clone)]
pub struct UnlockState {
    /// library_id → data key (decrypted, zeroized on drop)
    libraries: Arc<DashMap<String, ZeroVec>>,
    /// space_id → data key (decrypted, zeroized on drop)
    spaces: Arc<DashMap<String, ZeroVec>>,
}
```

### Encryption on Disk

Regardless of tier, encrypted files on disk have the same format:

```
┌──────────────┬───────────────────────────────┬──────────────────────┐
│ 12-byte      │ AES-256-GCM ciphertext        │ 32-byte              │
│ nonce        │ (includes 16-byte auth tag)    │ SHA-256 checksum     │
└──────────────┴───────────────────────────────┴──────────────────────┘
```

- Filenames and folder structure are **not encrypted** (visible on disk).
- Only file **contents** are encrypted.
- Each file gets its own random nonce.
- A SHA-256 checksum of the **original plaintext** is appended after the ciphertext+tag. This allows integrity verification after decryption (see [Data Integrity](#12-data-integrity)).
- Filename encryption is a potential v2 feature.

---

## 5. User Onboarding Flow

### Step 1: Registration

```
POST /api/v1/auth/register
{
  "username": "alice",
  "email": "alice@example.com",
  "password": "..."
}

Response:
{
  "user_id": "...",
  "setup_complete": false
}
```

### Step 2: Login

```
POST /api/v1/auth/login
{
  "username": "alice",
  "password": "..."
}

Response:
{
  "token": "...",
  "setup_complete": false    ← client should redirect to setup wizard
}
```

### Step 3: Setup Wizard (First Login Only)

```
┌────────────────────────────────────────────────────────┐
│          Welcome to IronDrive, Alice!                   │
│                                                        │
│   Your personal library will be created now.            │
│   All files are always encrypted at rest.               │
│                                                        │
│   Choose your encryption level:                         │
│                                                        │
│   ◉ Standard (recommended)                              │
│     Encryption is handled automatically by the          │
│     server. No passphrase needed. Nothing extra         │
│     to remember. Your files are encrypted at rest       │
│     and protected against disk theft.                   │
│                                                        │
│   ○ Enhanced — with recovery                            │
│     You set a passphrase to lock your library.          │
│     You must enter it each session to unlock.           │
│     The server admin CANNOT read your files.            │
│     If you forget your passphrase, the admin can        │
│     help you recover access (you will be notified).     │
│                                                        │
│   ○ Maximum — no recovery                               │
│     You set a passphrase to lock your library.          │
│     You must enter it each session to unlock.           │
│     ⚠️  NO ONE can recover your data if you forget      │
│     your passphrase. Not even the server admin.         │
│     Your data will be PERMANENTLY LOST.                 │
│                                                        │
│                               [ Continue → ]            │
└────────────────────────────────────────────────────────┘
```

If user selects "Enhanced" or "Maximum":

```
┌────────────────────────────────────────────────────────┐
│   Set your library passphrase                           │
│                                                        │
│   Passphrase:         [.........................]       │
│   Confirm passphrase: [.........................]       │
│                                                        │
│   ┌──────────────────────────────────────────────┐     │
│   │ ⚠️  (only for Maximum)                        │     │
│   │ This passphrase is the ONLY way to access    │     │
│   │ your files. If you lose it, your data is     │     │
│   │ gone FOREVER. There is no reset, no          │     │
│   │ recovery, no backdoor. This is by design.    │     │
│   │                                              │     │
│   │ ☐ I understand and accept this risk          │     │
│   └──────────────────────────────────────────────┘     │
│                                                        │
│                               [ Create Library → ]      │
└────────────────────────────────────────────────────────┘
```

### Step 3 API Call

```
POST /api/v1/auth/setup-library
{
  "encryption_mode": "server"
}

--- OR ---

POST /api/v1/auth/setup-library
{
  "encryption_mode": "failsafe_user",
  "passphrase": "my-secret-passphrase"
}

--- OR ---

POST /api/v1/auth/setup-library
{
  "encryption_mode": "pure_user",
  "passphrase": "my-secret-passphrase",
  "acknowledge_no_recovery": true        // REQUIRED — server rejects without this
}
```

Server creates:
- DB row in `personal_libraries` (with appropriate key material)
- Directory: `data/libraries/<user_id>/`
- `.irondrive.meta` file in the directory
- Sets `user.setup_complete = true`
- For `server` mode: data key is immediately cached in `UnlockState`
- For user modes: library starts locked, user must unlock

### Step 4: All Subsequent Requests

The `SetupGuard` request guard rejects API calls (except auth routes) if `setup_complete == false`. This ensures the user always completes setup before using the app.

---

## 6. Directory Structure

```
irondrive/
├── Cargo.toml
├── Rocket.toml                        # Rocket config (port, limits, TLS)
├── .env.example                       # Environment variable template
├── ARCHITECTURE.md                    # This document
├── TODO.md                            # Milestone tracker
├── Makefile                           # Build, test, run shortcuts
├── Dockerfile                         # Container build
├── docker-compose.yml                 # Docker Compose for local dev
├── tailwind.config.js                 # Tailwind CSS config
│
├── db/                                # SQLite database (gitignored)
│   └── irondrive.db                   # Main database file
│
├── migrations/                        # SQLx database migrations
│   ├── 001_create_users.sql
│   ├── 002_create_personal_libraries.sql
│   ├── 003_create_groups.sql
│   ├── 004_create_spaces.sql
│   ├── 005_create_sessions.sql
│   ├── 006_create_chunked_uploads.sql
│   ├── 007_create_integrity_events.sql
│   ├── 008_create_recovery_audit_log.sql
│   └── 009_create_server_config.sql
│
├── data/                              # File storage root (gitignored)
│   ├── libraries/                     # Personal libraries (one per user)
│   │   └── <library_uuid>/
│   │       ├── .irondrive.meta
│   │       └── ...user's files (encrypted on disk)...
│   ├── spaces/                        # Collaborative spaces
│   │   └── <space_uuid>/
│   │       ├── .irondrive.meta
│   │       └── ...space files (encrypted on disk)...
│   └── .chunks/                       # Temporary chunked upload staging
│       └── <upload_id>/
│           ├── .meta.json
│           └── ...numbered chunk files...
│
├── templates/                         # Tera HTML templates
│   ├── base.html.tera                 # Base layout (nav, flash, sidebar)
│   ├── auth/                          # Login, registration pages
│   ├── files/                         # File browser, usage display
│   ├── settings/                      # User settings
│   ├── setup/                         # First-run setup wizard
│   ├── errors/                        # 403, 404, 500 error pages
│   └── partials/                      # Reusable components (nav, breadcrumb, etc.)
│
├── static/                            # Static assets
│   ├── css/                           # Tailwind input + compiled CSS
│   ├── js/                            # App JS (upload panel, HTMX helpers)
│   └── vendor/                        # Third-party (htmx.min.js)
│
├── src/
│   ├── main.rs                        # Rocket launch, mount routes, attach fairings
│   ├── config.rs                      # AppConfig from env vars
│   ├── db.rs                          # SQLx pool init + migration runner
│   ├── errors.rs                      # Unified AppError type + Responder impl
│   │
│   ├── models/                        # DB-backed entities + queries
│   │   ├── mod.rs
│   │   ├── user.rs                    # User account CRUD
│   │   ├── library.rs                 # Personal library record + key material
│   │   └── session.rs                 # Auth sessions (create, validate, expire)
│   │
│   ├── routes/                        # Rocket route handlers (thin)
│   │   ├── mod.rs                     # Re-exports + all_routes()
│   │   ├── auth.rs                    # Register, login, logout, setup-library
│   │   ├── library.rs                 # Personal library filesystem routes
│   │   ├── integrity.rs               # Integrity events: list, acknowledge, admin scan
│   │   ├── pages.rs                   # HTML page routes (login, browser, settings)
│   │   └── health.rs                  # GET /health
│   │
│   ├── services/                      # Business logic (NO Rocket types)
│   │   ├── mod.rs
│   │   ├── auth_service.rs            # Registration, login, token management
│   │   ├── fs_service.rs              # Generic filesystem ops (list, upload, download, etc.)
│   │   ├── chunk_service.rs           # Chunked upload/download orchestration
│   │   ├── crypto_service.rs          # Key derivation, encrypt/decrypt, key wrapping
│   │   ├── integrity_service.rs       # Integrity scanning, event CRUD, corruption detection
│   │   ├── library_service.rs         # Personal library setup + server-mode key loading
│   │   ├── rate_limit.rs              # DashMap-based rate limiter
│   │   ├── unlock_state.rs            # In-memory key store (Arc<DashMap> + zeroize)
│   │   └── background/               # Background worker tasks
│   │       ├── mod.rs                 # BackgroundRunner — spawns all workers on liftoff
│   │       ├── integrity_scan.rs      # Periodic full-library integrity verification
│   │       ├── session_cleanup.rs     # Expired session pruning (hourly)
│   │       └── chunk_cleanup.rs       # Stale chunked upload cleanup (every 30 min)
│   │
│   ├── guards/                        # Rocket request guards
│   │   ├── mod.rs
│   │   ├── auth_guard.rs              # AuthenticatedUser (from session token)
│   │   ├── admin_guard.rs             # AdminUser (wraps AuthenticatedUser + role check)
│   │   ├── csrf_guard.rs              # CsrfXhr (cookie + header CSRF protection)
│   │   ├── session_guard.rs           # SessionUser (lower-level session validation)
│   │   └── setup_guard.rs             # SetupComplete (rejects if setup_complete == false)
│   │
│   ├── tests/                         # Integration tests (in-crate)
│   │   ├── mod.rs
│   │   ├── setup_flow.rs             # Registration, login, library setup tests
│   │   ├── library_fs.rs             # File upload, download, mkdir, rename, delete
│   │   ├── chunked_transfers.rs      # Chunked upload/download tests
│   │   ├── integrity.rs              # Integrity scanning, events, cleanup tests
│   │   └── page_routes.rs            # HTML page rendering tests
│   │
│   └── utils/                         # Shared stateless helpers
│       ├── mod.rs
│       ├── crypto.rs                  # Argon2 hashing, AES-256-GCM, key wrapping
│       ├── path_safety.rs             # Path traversal prevention (CRITICAL)
│       └── mime.rs                    # MIME type detection from extension
│
└── target/                            # Cargo build output (gitignored)
```

---

## 7. Data Layout on Disk

```
data/
├── libraries/                         # Personal libraries (one per user)
│   ├── a1b2c3d4-.../                  # user UUID as directory name
│   │   ├── .irondrive.meta            # encryption metadata (JSON)
│   │   ├── Documents/
│   │   │   ├── report.pdf             # encrypted contents on disk
│   │   │   └── notes.txt              # encrypted contents on disk
│   │   └── Photos/
│   │       └── vacation.jpg           # encrypted contents on disk
│   └── e5f6g7h8-.../
│       ├── .irondrive.meta
│       └── ...
│
├── spaces/                            # Collaborative spaces
│   ├── s1s2s3s4-.../                   # space UUID as directory name
│   │   ├── .irondrive.meta
│   │   ├── Project Files/
│   │   │   └── spec.docx              # encrypted contents on disk
│   │   └── Assets/
│   │       └── logo.png               # encrypted contents on disk
│   └── s5s6s7s8-.../
│       └── ...
│
└── .chunks/                           # Temporary chunked upload staging
    └── <upload_id>/                   # One directory per in-progress upload
        ├── .meta.json                 # Upload metadata (target path, expected chunks, checksum)
        ├── 0                          # Chunk 0 (raw encrypted bytes)
        ├── 1                          # Chunk 1
        └── ...
```

> Every file on disk is encrypted regardless of tier. The tiers only affect who can access the key, not whether encryption happens.

Chunk staging dirs get cleaned up after successful assembly, or by the background cleanup task if the upload is abandoned (default expiry: 24 hours).

### `.irondrive.meta`

```json
{
  "encryption_mode": "server",
  "version": 1
}
```

Valid `encryption_mode` values: `"server"`, `"failsafe_user"`, `"pure_user"`

> Key material (salts, encrypted blobs, recovery blobs) lives in the DB, not here. This file is just a lightweight marker so `fs_service` can figure out the encryption tier without hitting the DB on every operation.

---

## 8. Database Schema

### `001_create_users.sql`

```sql
CREATE TABLE users (
    id              TEXT PRIMARY KEY,
    username        TEXT NOT NULL UNIQUE,
    email           TEXT NOT NULL UNIQUE,
    password_hash   TEXT NOT NULL,
    role            TEXT NOT NULL DEFAULT 'user',     -- 'user' | 'admin'
    quota_bytes     INTEGER NOT NULL DEFAULT 5368709120,  -- 5 GB default
    is_active       INTEGER NOT NULL DEFAULT 1,
    setup_complete  INTEGER NOT NULL DEFAULT 0,       -- false until library created
    created_at      TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at      TEXT NOT NULL DEFAULT (datetime('now'))
);
```

### `002_create_personal_libraries.sql`

```sql
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
```

### `003_create_groups.sql`

```sql
CREATE TABLE groups (
    id          TEXT PRIMARY KEY,
    name        TEXT NOT NULL UNIQUE,
    description TEXT,
    created_by  TEXT NOT NULL REFERENCES users(id),
    created_at  TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE group_members (
    group_id  TEXT NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
    user_id   TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role      TEXT NOT NULL DEFAULT 'member',  -- 'member' | 'manager'
    joined_at TEXT NOT NULL DEFAULT (datetime('now')),
    PRIMARY KEY (group_id, user_id)
);
```

### `004_create_spaces.sql`

```sql
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
```

### `005_create_sessions.sql`

```sql
CREATE TABLE sessions (
    id         TEXT PRIMARY KEY,
    user_id    TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash TEXT NOT NULL UNIQUE,
    expires_at TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
```

### `006_create_chunked_uploads.sql`

```sql
-- One row per in-progress chunked upload session.
CREATE TABLE chunked_uploads (
    id              TEXT PRIMARY KEY,         -- upload session UUID
    user_id         TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    target_type     TEXT NOT NULL,            -- 'library' | 'space'
    target_id       TEXT NOT NULL,            -- library or space id
    target_path     TEXT NOT NULL,            -- destination relative path
    filename        TEXT NOT NULL,            -- original filename
    total_chunks    INTEGER NOT NULL,         -- expected number of chunks
    received_chunks INTEGER NOT NULL DEFAULT 0,
    total_bytes     INTEGER NOT NULL,         -- expected total file size (plaintext)
    checksum        TEXT,                     -- expected SHA-256 of complete plaintext (optional, client-supplied)
    expires_at      TEXT NOT NULL,            -- auto-cleanup deadline
    created_at      TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX idx_chunked_uploads_user ON chunked_uploads(user_id);
CREATE INDEX idx_chunked_uploads_expires ON chunked_uploads(expires_at);
```

### `007_create_integrity_events.sql`

```sql
-- Detected file corruption / integrity failures.
-- Surfaced to users via the notifications API.
CREATE TABLE integrity_events (
    id              TEXT PRIMARY KEY,
    target_type     TEXT NOT NULL,            -- 'library' | 'space'
    target_id       TEXT NOT NULL,            -- library or space id
    file_path       TEXT NOT NULL,            -- relative path of the affected file
    event_type      TEXT NOT NULL,            -- 'checksum_mismatch' | 'decrypt_failed' | 'file_truncated'
    details         TEXT,                     -- human-readable description
    detected_by     TEXT NOT NULL,            -- 'download' | 'background_scan' | 'upload_verify'
    acknowledged    INTEGER NOT NULL DEFAULT 0,
    created_at      TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX idx_integrity_target ON integrity_events(target_type, target_id, acknowledged);
```

### `008_create_recovery_audit_log.sql`

```sql
-- Append-only log of admin recovery events. Never delete rows from this.
-- Users must be able to see their own entries.
CREATE TABLE recovery_audit_log (
    id              TEXT PRIMARY KEY,
    target_type     TEXT NOT NULL,      -- 'library' | 'space'
    target_id       TEXT NOT NULL,      -- library or space id
    target_user_id  TEXT NOT NULL,      -- user who owns the library/space
    recovered_by    TEXT NOT NULL REFERENCES users(id),  -- admin who triggered recovery
    reason          TEXT,               -- optional admin-provided reason
    acknowledged    INTEGER NOT NULL DEFAULT 0,  -- user has dismissed the notification
    created_at      TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX idx_recovery_audit_user ON recovery_audit_log(target_user_id, acknowledged);
```

### Master Key Storage (`009_create_server_config.sql`)

The master encryption key is stored separately from the main tables:

```sql
-- Created automatically on first server boot
CREATE TABLE server_config (
    key   TEXT PRIMARY KEY,
    value BLOB NOT NULL
);

-- Single row: key = 'master_key_encrypted'
-- Value = master key encrypted with IRONDRIVE_SECRET_KEY from environment
-- IRONDRIVE_SECRET_KEY is NEVER stored in the database
```

---

## 9. Layer Architecture

Pretty standard layered setup. The key rule: only the top layer (routes/guards/fairings) touches Rocket. Everything below is plain Rust you can unit test without spinning up an HTTP server.

### Layer Responsibilities

| Layer | Location | Rocket Dependency | Responsibility |
|---|---|---|---|
| **Routes** | `src/routes/` | Yes | Parse request → call service → return JSON/status. As thin as possible. |
| **Guards** | `src/guards/` | Yes | Extract & validate auth tokens, check permissions, enforce setup completion, CSRF. |
| **Services** | `src/services/` | No | All business logic. Pure Rust. Takes `&DbPool` and plain args. |
| **Models** | `src/models/` | No | Data structs + SQL queries via SQLx. `Serialize`/`Deserialize`. |
| **Utils** | `src/utils/` | No | Stateless helper functions (crypto, path safety, MIME). |
| **Background** | `src/services/background/` | No | Spawned via `AdHoc::on_liftoff` fairing in `main.rs`. Pure async loops. |

### The Rule

**Only `routes/` and `guards/` import Rocket.** Everything else is framework-free. Fairings are defined inline in `main.rs` using `AdHoc` — no separate module.

### Data Flow

```
HTTP Request
    │
    ▼
┌─────────┐     ┌──────────┐
│ Fairing │────▶│  Guard   │  (auth, setup, CSRF checks)
│ (inline │     └──────────┘
│  AdHoc) │          │
└─────────┘          ▼
                ┌─────────┐
                │  Route   │  (thin: parse params, call service)
                └─────────┘
                     │
                     ▼
                ┌─────────┐
                │ Service  │  (business logic, calls models + utils)
                └─────────┘
                   │     │
                   ▼     ▼
             ┌───────┐ ┌───────┐
             │ Model │ │ Utils │
             │ (DB)  │ │(crypto│
             └───────┘ │ path) │
                       └───────┘
```

### Route Pattern: Library vs Spaces

Both use the same `fs_service` under the hood. The difference is just the root path, permission check, and where the key comes from:

```rust
// routes/library.rs — always scoped to authenticated user
// Root: data/libraries/<user_id>/
// No <id> in URL — there's only ever one library per user

#[get("/library/fs?<path>")]
pub async fn list(
    user: AuthenticatedUser,
    path: Option<&str>,
    pool: &State<DbPool>,
    unlock: &State<UnlockState>,
) -> Result<Json<Vec<FsEntry>>, AppError> {
    let library = library_service::get_for_user(&pool, &user.0.id).await?;
    let data_key = unlock.require_library_key(&library.id)?;
    let root = format!("data/libraries/{}", user.0.id);
    let entries = fs_service::list_directory(&root, path.unwrap_or(""), &data_key).await?;
    Ok(Json(entries))
}

// routes/spaces.rs — requires space ID + permission check
// Root: data/spaces/<space_id>/

#[get("/spaces/<space_id>/fs?<path>")]
pub async fn list(
    user: AuthenticatedUser,
    space_id: &str,
    path: Option<&str>,
    pool: &State<DbPool>,
    unlock: &State<UnlockState>,
) -> Result<Json<Vec<FsEntry>>, AppError> {
    space_service::check_permission(&pool, space_id, &user.0, "read").await?;
    let data_key = unlock.require_space_key(space_id)?;
    let root = format!("data/spaces/{}", space_id);
    let entries = fs_service::list_directory(&root, path.unwrap_or(""), &data_key).await?;
    Ok(Json(entries))
}
```

> For `server` mode, `require_library_key()` / `require_space_key()` always succeeds — the key is loaded at boot. For user modes, it returns `AppError::Locked` if the user hasn't unlocked yet.

---

## 10. API Surface

### Auth

| Method | Endpoint | Description | Auth Required |
|---|---|---|---|
| `POST` | `/api/v1/auth/register` | Create account | No |
| `POST` | `/api/v1/auth/login` | Login → session token + `setup_complete` flag | No |
| `POST` | `/api/v1/auth/logout` | Destroy session | Yes |
| `POST` | `/api/v1/auth/setup-library` | First-time setup: choose encryption tier, create personal library | Yes (setup_complete=false) |

### Personal Library

> No `<id>` in URLs — always scoped to the authenticated user's single library.

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/api/v1/library/status` | Encryption mode, locked/unlocked, disk usage, recovery notifications |
| `POST` | `/api/v1/library/unlock` | Unlock user-encrypted library (passphrase). No-op for server mode. |
| `POST` | `/api/v1/library/lock` | Lock user-encrypted library (wipe key). No-op for server mode. |
| `GET` | `/api/v1/library/fs?path=` | List directory contents |
| `GET` | `/api/v1/library/fs/download?path=` | Download file (single-request) |
| `POST` | `/api/v1/library/fs/upload?path=` | Upload file(s) (single-request) |
| `POST` | `/api/v1/library/fs/mkdir?path=` | Create folder |
| `PUT` | `/api/v1/library/fs/rename` | Rename / move file or folder |
| `DELETE` | `/api/v1/library/fs?path=` | Delete file or folder |
| `GET` | `/api/v1/library/fs/info?path=` | File/folder metadata |

### Spaces

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/api/v1/spaces` | List spaces user has access to |
| `POST` | `/api/v1/spaces` | Create a new space (choose encryption tier) |
| `GET` | `/api/v1/spaces/<id>` | Space details |
| `PUT` | `/api/v1/spaces/<id>` | Update space settings |
| `DELETE` | `/api/v1/spaces/<id>` | Delete space |
| `POST` | `/api/v1/spaces/<id>/unlock` | Unlock user-encrypted space |
| `POST` | `/api/v1/spaces/<id>/lock` | Lock user-encrypted space |
| **Filesystem (within a space)** | | |
| `GET` | `/api/v1/spaces/<id>/fs?path=` | List directory |
| `GET` | `/api/v1/spaces/<id>/fs/download?path=` | Download file (single-request) |
| `POST` | `/api/v1/spaces/<id>/fs/upload?path=` | Upload file(s) (single-request) |
| `POST` | `/api/v1/spaces/<id>/fs/mkdir?path=` | Create folder |
| `PUT` | `/api/v1/spaces/<id>/fs/rename` | Rename / move |
| `DELETE` | `/api/v1/spaces/<id>/fs?path=` | Delete file/folder |
| `GET` | `/api/v1/spaces/<id>/fs/info?path=` | File metadata |
| **Access Control** | | |
| `GET` | `/api/v1/spaces/<id>/access` | List who has access |
| `POST` | `/api/v1/spaces/<id>/access` | Grant access (user or group) |
| `DELETE` | `/api/v1/spaces/<id>/access/<grantee>` | Revoke access |

### Chunked Transfers

| Method | Endpoint | Description | Auth Required |
|---|---|---|---|
| `POST` | `/api/v1/library/fs/upload/init` | Initiate a chunked upload to personal library | Yes |
| `POST` | `/api/v1/library/fs/upload/chunk/<upload_id>/<index>` | Upload a single chunk | Yes |
| `POST` | `/api/v1/library/fs/upload/complete/<upload_id>` | Finalize chunked upload (assemble + verify) | Yes |
| `DELETE` | `/api/v1/library/fs/upload/<upload_id>` | Cancel an in-progress chunked upload | Yes |
| `GET` | `/api/v1/library/fs/download/chunked?path=&chunk_size=` | Download file in chunks (returns chunk manifest) | Yes |
| `GET` | `/api/v1/library/fs/download/chunk/<download_token>/<index>` | Download a specific chunk | Yes |
| `POST` | `/api/v1/spaces/<id>/fs/upload/init` | Initiate chunked upload to space | Yes |
| `POST` | `/api/v1/spaces/<id>/fs/upload/chunk/<upload_id>/<index>` | Upload a single chunk to space | Yes |
| `POST` | `/api/v1/spaces/<id>/fs/upload/complete/<upload_id>` | Finalize chunked upload to space | Yes |
| `DELETE` | `/api/v1/spaces/<id>/fs/upload/<upload_id>` | Cancel chunked upload to space | Yes |
| `GET` | `/api/v1/spaces/<id>/fs/download/chunked?path=&chunk_size=` | Chunked download manifest for space file | Yes |
| `GET` | `/api/v1/spaces/<id>/fs/download/chunk/<download_token>/<index>` | Download a specific chunk from space | Yes |

### Integrity

| Method | Endpoint | Description | Auth Required |
|---|---|---|---|
| `GET` | `/api/v1/library/integrity/events` | List integrity events for personal library | Yes (SetupComplete) |
| `POST` | `/api/v1/library/integrity/events/<id>/acknowledge` | Acknowledge/dismiss an integrity event | Yes (SetupComplete + CSRF) |
| `GET` | `/api/v1/users/me/notifications` | Unacknowledged integrity events for current user | Yes (SetupComplete) |
| `GET` | `/api/v1/admin/integrity/events?target_type&target_id` | List integrity events for any target (admin only) | Yes (AdminUser) |
| `POST` | `/api/v1/admin/integrity/scan?target_type&target_id` | Trigger manual scan on a library or space | Yes (AdminUser + CSRF) |

### Groups

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/api/v1/groups` | List groups user belongs to |
| `POST` | `/api/v1/groups` | Create group |
| `GET` | `/api/v1/groups/<id>` | Group details + member list |
| `PUT` | `/api/v1/groups/<id>` | Update group info |
| `DELETE` | `/api/v1/groups/<id>` | Delete group |
| `POST` | `/api/v1/groups/<id>/members` | Add member |
| `DELETE` | `/api/v1/groups/<id>/members/<uid>` | Remove member |

### Users

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/api/v1/users/me` | Current user profile + quota + usage |
| `PUT` | `/api/v1/users/me` | Update profile |
| `GET` | `/api/v1/users/me/notifications` | Recovery notifications + integrity alerts + other alerts |
| `POST` | `/api/v1/users/me/notifications/<id>/ack` | Acknowledge/dismiss a notification |
| `GET` | `/api/v1/users` | List all users (admin only) |

### Admin

| Method | Endpoint | Description |
|---|---|---|
| `POST` | `/api/v1/admin/recovery/library/<user_id>` | Trigger recovery for a user's library (failsafe only) |
| `POST` | `/api/v1/admin/recovery/space/<space_id>` | Trigger recovery for a space (failsafe only) |
| `GET` | `/api/v1/admin/recovery/log` | View all recovery audit log entries |
| `GET` | `/api/v1/admin/integrity/events?target_type&target_id` | View integrity events for a specific target |
| `POST` | `/api/v1/admin/integrity/scan?target_type&target_id` | Trigger integrity scan on a specific library or space |

### Health

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/health` | Health check |

---

## 11. Chunked Transfers

Large files get split into chunks for upload and download. This buys us:

- **Resumability** — Connection drops? Retry the failed chunk, not the whole file.
- **Memory** — Server never holds a full file in memory. Each chunk is processed independently.
- **Parallelism** — Client can push/pull multiple chunks at once.
- **Progress** — Accurate progress bars based on chunk completion.

### Chunked Upload Flow

```
Client                                  Server
  │                                       │
  │  POST /fs/upload/init                 │
  │  { filename, total_size,              │
  │    total_chunks, checksum? }          │
  │──────────────────────────────────────▶│
  │                                       │  Create chunked_uploads row
  │  { upload_id, chunk_size }            │  Create data/.chunks/<upload_id>/
  │◀──────────────────────────────────────│
  │                                       │
  │  POST /fs/upload/chunk/<id>/0         │
  │  [raw bytes — chunk 0]                │
  │──────────────────────────────────────▶│  Encrypt chunk, write to staging
  │  { received: 0, status: "ok" }        │
  │◀──────────────────────────────────────│
  │                                       │
  │  POST /fs/upload/chunk/<id>/1         │  (can be parallel with chunk 0)
  │  [raw bytes — chunk 1]                │
  │──────────────────────────────────────▶│  Encrypt chunk, write to staging
  │  { received: 1, status: "ok" }        │
  │◀──────────────────────────────────────│
  │                                       │
  │  ... (repeat for all chunks) ...      │
  │                                       │
  │  POST /fs/upload/complete/<id>        │
  │──────────────────────────────────────▶│  Assemble chunks → single encrypted file
  │                                       │  Verify checksum (if provided)
  │                                       │  Write final file to library/space
  │                                       │  Clean up staging directory
  │  { path, size, checksum }             │  Delete chunked_uploads row
  │◀──────────────────────────────────────│
```

### Chunked Download Flow

```
Client                                  Server
  │                                       │
  │  GET /fs/download/chunked?path=X      │
  │      &chunk_size=8388608              │
  │──────────────────────────────────────▶│  Stat file, compute chunk count
  │                                       │  Generate short-lived download_token
  │  { download_token, total_size,        │
  │    total_chunks, chunk_size,          │
  │    checksum }                         │
  │◀──────────────────────────────────────│
  │                                       │
  │  GET /fs/download/chunk/<token>/0     │
  │──────────────────────────────────────▶│  Read chunk range, decrypt, stream
  │  [raw bytes — chunk 0]                │
  │◀──────────────────────────────────────│
  │                                       │
  │  GET /fs/download/chunk/<token>/1     │  (can be parallel)
  │──────────────────────────────────────▶│  Read chunk range, decrypt, stream
  │  [raw bytes — chunk 1]                │
  │◀──────────────────────────────────────│
  │                                       │
  │  ... (client reassembles + verifies   │
  │       checksum locally) ...           │
```

### Chunk Configuration

| Setting | Default | Description |
|---|---|---|
| `IRONDRIVE_CHUNK_SIZE` | `8 MiB` | Default chunk size for uploads/downloads |
| `IRONDRIVE_CHUNK_UPLOAD_EXPIRY_HOURS` | `24` | Incomplete uploads are auto-cleaned after this |
| `IRONDRIVE_MAX_PARALLEL_CHUNKS` | `4` | Suggested max parallel chunk uploads per session |

### Small File Optimization

Files smaller than the chunk size just go through the normal single-request upload/download endpoints. The client checks file size and picks the right path. The server accepts single-request uploads for any size up to the Rocket data limit — chunking is optional, but you probably want it for anything over the chunk size.

### Chunk-Level Encryption

Each chunk gets encrypted independently with AES-256-GCM (its own random nonce). During assembly (`/upload/complete`), the server:

1. Decrypts each chunk in order into a streaming plaintext buffer
2. Computes SHA-256 of the full plaintext as it streams through
3. Re-encrypts the whole thing as a single file (nonce + ciphertext + tag + checksum)
4. Checks the computed checksum against the client-supplied one (if provided)
5. Writes the final encrypted file to its destination

The result is that the on-disk format is always the same single-file format, regardless of how the upload happened.

---

## 12. Data Integrity

Every file gets a SHA-256 checksum so we can catch disk corruption, bad writes, and storage failures.

### Checksum Strategy

- **Algorithm**: SHA-256 — strong enough, fast with hardware acceleration
- **What's checksummed**: The **original plaintext** (before encryption)
- **Where it lives**: Last 32 bytes of the on-disk file, appended after the ciphertext+tag

```
On-disk file format:
┌──────────┬──────────────────────────────┬──────────────────────┐
│ 12-byte  │ AES-256-GCM ciphertext       │ 32-byte              │
│ nonce    │ (payload + 16-byte auth tag)  │ SHA-256 checksum     │
│          │                              │ (of plaintext)       │
└──────────┴──────────────────────────────┴──────────────────────┘
```

### When Verification Happens

| Trigger | What Happens |
|---|---|
| **File download** | After decryption, compute SHA-256 of plaintext and compare to stored checksum. If mismatch → return file with a `X-IronDrive-Integrity: failed` header + create integrity event. |
| **Upload complete** | After writing the encrypted file, immediately read-back and verify as a write-verify pass. |
| **Chunked upload assembly** | Checksum is computed during streaming assembly and compared to the client-supplied value (if any). |
| **Background integrity scan** | A background service periodically walks all files in unlocked libraries/spaces, decrypts, and verifies checksums. |
| **On-demand scan** | Users or admins can trigger a manual scan via the API. |

### Integrity Event Types

| Event Type | Description |
|---|---|
| `checksum_mismatch` | Stored checksum doesn't match recomputed plaintext hash. File contents may be corrupted. |
| `decrypt_failed` | AES-256-GCM authentication tag verification failed. File has been tampered with or corrupted. |
| `file_truncated` | File is shorter than the minimum valid size (12 nonce + 16 tag + 32 checksum = 60 bytes). |

### Corruption Notification Flow

```
Background scan or download detects corruption
    │
    ▼
Create integrity_events row
    │
    ▼
User sees event in:
  - GET /api/v1/library/integrity
  - GET /api/v1/users/me/notifications (aggregated)
  - Response header on affected file downloads
    │
    ▼
User acknowledges via POST .../integrity/<event_id>/ack
```

> AES-GCM already gives us tamper detection via the auth tag. The SHA-256 checksum is a second, independent layer. It can also catch issues even when the decryption key isn't available (e.g., locked user-encrypted library — the checksum bytes sit in the clear after the ciphertext). But the main use case is plaintext-level verification after a successful decrypt.

### Integrity in `FsEntry` Response

File listings include an integrity field:

```rust
pub struct FsEntry {
    pub name: String,
    pub is_dir: bool,
    pub size_bytes: u64,
    pub modified: String,
    pub mime_type: Option<String>,
    pub path: String,
    pub integrity: Option<String>,  // "ok" | "failed" | "unchecked"
}
```

- `"ok"` — Last verification passed
- `"failed"` — An unacknowledged integrity event exists for this file
- `"unchecked"` — File has not been verified yet (or library is locked)
- `None` — Directories don't have integrity status

---

## 13. Background Services

A few housekeeping tasks run in the background as `tokio::spawn`'d tasks. They share the same async runtime as Rocket — no separate processes or threads needed.

### Architecture

```
Server Startup
    │
    ▼
┌─────────────────────────────────┐
│        BackgroundRunner         │
│  (spawns + supervises tasks)    │
├─────────────────────────────────┤
│                                 │
│  ┌─────────────────────────┐    │
│  │ Integrity Scanner       │    │  Periodic full-library/space checksum verification
│  │ (configurable interval) │    │
│  └─────────────────────────┘    │
│                                 │
│  ┌─────────────────────────┐    │
│  │ Session Cleanup         │    │  Prune expired sessions from DB
│  │ (every 1 hour)          │    │
│  └─────────────────────────┘    │
│                                 │
│  ┌─────────────────────────┐    │
│  │ Chunk Cleanup           │    │  Delete expired incomplete uploads
│  │ (every 30 min)          │    │
│  └─────────────────────────┘    │
│                                 │
└─────────────────────────────────┘
```

### BackgroundRunner

```rust
/// Spawns background worker loops on the Tokio runtime.
/// Each worker runs in its own `tokio::spawn` task and loops forever.
pub struct BackgroundRunner;

impl BackgroundRunner {
    /// Launch all background workers. Called from the `on_liftoff` fairing.
    ///
    /// `unlock_state` is cloned from Rocket managed state — because
    /// `UnlockState` uses `Arc<DashMap>` internally, the clone shares
    /// the same live key store as the request handlers.
    pub fn start(pool: SqlitePool, config: AppConfig, unlock_state: UnlockState) {
        tokio::spawn(integrity_scan::integrity_scan_loop(
            pool.clone(), config.clone(), unlock_state,
        ));
        tokio::spawn(session_cleanup::session_cleanup_loop(pool.clone()));
        tokio::spawn(chunk_cleanup::chunk_cleanup_loop(pool, config));

        tracing::info!("BackgroundRunner: all workers launched");
    }
}
```

Note: tasks are fire-and-forget. If a worker panics, it dies silently — acceptable for a solo deployment where you're watching the logs. A production multi-tenant setup would want supervision/restart logic here.

### Service Details

#### Integrity Scanner (`integrity_scan.rs`)

- **Interval**: Configurable via `IRONDRIVE_INTEGRITY_SCAN_INTERVAL_HOURS` (default: `168` = weekly)
- Walks all libraries and spaces, skips locked ones (no key = can't verify)
- For each unlocked library/space: decrypt every file, recompute SHA-256, compare to stored checksum
- Mismatches create an `integrity_events` row with `detected_by = 'background_scan'`
- Logs progress via `tracing`
- Sleeps briefly between files (`tokio::time::sleep`) so we don't starve request handling of I/O

#### Session Cleanup (`session_cleanup.rs`)

- **Interval**: Every hour
- Just runs `DELETE FROM sessions WHERE expires_at < datetime('now')` to keep the table from growing forever

#### Chunk Cleanup (`chunk_cleanup.rs`)

- **Interval**: Every 30 minutes
- Finds expired `chunked_uploads` rows, deletes the staging directory + DB row
- Reclaims disk space from abandoned/failed uploads

### Configuration

| Setting | Default | Description |
|---|---|---|
| `IRONDRIVE_INTEGRITY_SCAN_INTERVAL_HOURS` | `168` (weekly) | How often the background integrity scanner runs |
| `IRONDRIVE_INTEGRITY_SCAN_ENABLED` | `true` | Enable/disable the background scanner |
| `IRONDRIVE_CHUNK_UPLOAD_EXPIRY_HOURS` | `24` | Incomplete uploads cleaned after this duration |

### Integration with Rocket

Background workers are launched via an inline `AdHoc::on_liftoff` fairing in `main.rs` — no separate fairing struct needed:

```rust
// In main.rs
.attach(AdHoc::on_liftoff("Background Workers", |rocket| {
    Box::pin(async move {
        let pool = rocket.state::<SqlitePool>().unwrap().clone();
        let config = rocket.state::<AppConfig>().unwrap().clone();
        let unlock_state = rocket.state::<UnlockState>().unwrap().clone();
        BackgroundRunner::start(pool, config, unlock_state);
    })
}))
```

`UnlockState` uses `Arc<DashMap>` internally, so `.clone()` gives the background tasks a cheap handle to the same live key store. When a user unlocks their library via the API, background workers see the key immediately.

---

## 14. Key Design Patterns

### Unified Error Type

```rust
#[derive(Debug, thiserror::Error)]
pub enum AppError {
    // Client errors
    #[error("not found")]
    NotFound,

    #[error("unauthorized")]
    Unauthorized,

    #[error("forbidden")]
    Forbidden,

    #[error("conflict: {0}")]
    Conflict(String),

    #[error("quota exceeded")]
    QuotaExceeded,

    #[error("library/space is locked — unlock first")]
    Locked,

    #[error("recovery not available for this encryption mode")]
    RecoveryNotAvailable,

    #[error("validation error: {0}")]
    Validation(String),

    #[error("incorrect passphrase")]
    BadPassphrase,

    // Server errors
    #[error("internal error: {0}")]
    Internal(String),

    #[error(transparent)]
    Sqlx(#[from] sqlx::Error),

    #[error(transparent)]
    Io(#[from] std::io::Error),
}
```

Every variant maps to an HTTP status code. The `Responder` implementation converts each variant to a JSON error response with the appropriate status code. Sensitive details (e.g., SQL errors, key material) are logged but **never** exposed to the client.

### Auth Guard

```rust
pub struct AuthenticatedUser(pub User);

#[rocket::async_trait]
impl<'r> FromRequest<'r> for AuthenticatedUser {
    type Error = AppError;

    async fn from_request(request: &'r Request<'_>) -> Outcome<Self, Self::Error> {
        // 1. Extract Bearer token from Authorization header
        // 2. Hash the token
        // 3. Look up token_hash in sessions table
        // 4. Check expiry
        // 5. Load user from users table
        // 6. Return AuthenticatedUser(user)
    }
}
```

### Admin Guard

```rust
pub struct AdminUser(pub User);

#[rocket::async_trait]
impl<'r> FromRequest<'r> for AdminUser {
    type Error = AppError;

    async fn from_request(request: &'r Request<'_>) -> Outcome<Self, Self::Error> {
        // 1. Run AuthenticatedUser guard first
        // 2. Check user.role == "admin"
        // 3. Return AdminUser(user) or Forbidden
    }
}
```

### Path Safety (this is the big one)

```rust
/// Returns a safe, canonical path within `root`.
/// Rejects: absolute paths, "..", ".", dot-prefixed components, symlink escape.
pub fn safe_join(root: &Path, user_path: &str) -> Result<PathBuf, AppError> {
    // 1. Reject empty or absolute user_path
    // 2. Split on '/' and reject any component that is "..", ".", or starts with '.'
    // 3. Join root + user_path
    // 4. Canonicalize and verify it starts with canonical root
    // 5. Return the safe path
}
```

### Filesystem Entry Response

```rust
pub struct FsEntry {
    pub name: String,
    pub is_dir: bool,
    pub size_bytes: u64,
    pub modified: String,
    pub mime_type: Option<String>,
    pub path: String,
    pub integrity: Option<String>,  // "ok" | "failed" | "unchecked" | None (dirs)
}
```

---

## 15. Dependencies

### `Cargo.toml`

```toml
[package]
name = "irondrive"
version = "0.1.0"
edition = "2021"
license = "AGPL-3.0-only"

[dependencies]
# Web framework
rocket = { version = "0.5.1", features = ["json", "secrets"] }
rocket_dyn_templates = { version = "0.2.0", features = ["tera"] }

# Database
sqlx = { version = "0.8", features = ["runtime-tokio", "sqlite", "migrate", "chrono", "uuid"] }

# Auth & crypto
argon2 = "0.5"                   # Password hashing + key derivation
aes-gcm = { version = "0.10", features = ["stream"] }
sha2 = "0.10"                    # SHA-256 checksums for data integrity
hmac = "0.12"                    # HMAC-SHA256 signing for download tokens
hex = "0.4"                      # Hex encoding for token hashes
rand = "0.8"                     # Secure random generation
base64 = "0.22"                  # Base64 encoding for key material

# Serialization
serde = { version = "1", features = ["derive"] }
serde_json = "1"

# Utilities
chrono = { version = "0.4", features = ["serde"] }
uuid = { version = "1", features = ["v4", "serde"] }
tokio = { version = "1", features = ["fs", "io-util", "time", "rt", "sync"] }
thiserror = "2"                  # Ergonomic error types
tracing = "0.1"                  # Structured logging
tracing-subscriber = { version = "0.3", features = ["env-filter"] }
mime_guess = "2"                 # MIME type from file extension
dotenvy = "0.15"                 # Load .env files
async-trait = "0.1"              # Async trait support
dashmap = "6"                    # Concurrent map for UnlockState
zeroize = { version = "1.8", features = ["zeroize_derive"] }

[dev-dependencies]
tempfile = "3"
```

### Why These Choices

| Crate | Why |
|---|---|
| `sqlx` (not Diesel, not SeaORM) | Compile-time checked raw SQL. No ORM magic — you see exactly what runs. |
| `argon2` (not bcrypt) | Current OWASP recommendation. Does double duty for password hashing and key derivation. |
| `aes-gcm` (not chacha20) | Hardware-accelerated on most CPUs (AES-NI). Used for both file encryption and key wrapping. |
| `sha2` | SHA-256 checksums. Hardware-accelerated (SHA-NI). Same RustCrypto family as `aes-gcm`. |
| `thiserror` (not anyhow) | Structured error variants — much better for API responses than opaque errors. |
| `tracing` (not log) | Structured, async-aware. The standard choice in Rust at this point. |
| `tokio` (extended features) | `time` for background intervals, `sync` for shared state, `rt` for spawning tasks. |
| `dashmap` | Lock-free concurrent hashmap. `UnlockState` gets hit from both request handlers and background tasks. |
| `zeroize` | Wipes key bytes from memory on drop. Wraps all in-memory data keys in `ZeroVec`. |
| `rocket_dyn_templates` | Tera templates for server-rendered HTML pages (login, file browser, settings). |
| SQLite (not Postgres) | Zero-config, embedded. Right choice for single-server self-hosted. One feature flag swap to Postgres if needed later. |

---

## 16. Security Considerations

### Path Traversal
- **Every** user-supplied path goes through `safe_join()` before touching the filesystem.
- No `..`, no absolute paths, no `.`-prefixed components, no symlink escape.
- This is the most important security function in the entire codebase. Get it wrong and everything else is moot.

### Password Storage
- Argon2id with recommended params (19 MiB memory, 2 iterations, 1 parallelism).
- Passwords never appear in plaintext anywhere — not in the DB, not in logs, not in error messages.

### Session Tokens
- Random 256-bit values.
- Only the **hash** is stored in the DB (`token_hash`).
- Expiration enforced. Logout kills the session server-side.
- Background cleanup prunes expired sessions.

### Encryption Keys
- All files encrypted at rest, always.
- `IRONDRIVE_SECRET_KEY` env var is the root of trust. Guard it.
- Master key is encrypted in the DB by `IRONDRIVE_SECRET_KEY`.
- Data keys are encrypted by master key (server mode) or user-derived key (user modes).
- Keys only live in memory while needed.
- On restart: server-mode keys auto-reload, user-mode keys need re-unlock.
- `zeroize` crate wipes key bytes from memory on drop — all `UnlockState` keys are wrapped in `ZeroVec`.

### Recovery Audit Trail
- Every admin recovery goes into `recovery_audit_log`. Append-only — never delete rows.
- Users see their own recovery events via the notifications API.
- Notifications stick around until explicitly acknowledged.
- Bottom line: an admin *can* recover failsafe-mode data, but they *can't* do it quietly.

### IRONDRIVE_SECRET_KEY
- Set it in the environment (or `.env`).
- Needs at least 256 bits of entropy (44+ chars base64, or 64+ hex).
- Lose it → all server-mode data and failsafe recovery blobs are gone.
- Compromise it → all server-mode data and failsafe recovery paths are exposed (pure_user data is fine though).
- **Back it up. Separately from the database. Seriously.**

### File Uploads
- Max file size enforced by Rocket's data limits (`Rocket.toml`).
- MIME type detected from file extension (not magic bytes — encrypted files don't have valid magic bytes).
- Files only get written after permission checks pass.
- Chunked uploads validate chunk indices, total counts, and sizes before accepting anything.
- Abandoned chunks are cleaned up by the background service.

### Data Integrity
- SHA-256 checksum appended to every file on disk (after the encrypted payload).
- Verified on every download + periodically by the background scanner.
- Failures go into `integrity_events` and surface via the notifications API.
- GCM auth tags are the first line of defense; checksums are a second independent layer.
- Integrity events can't be silently dismissed — visible to owners and admins.

### Rate Limiting
- Not in v1. Rocket fairing in v2 if needed.

---

## Appendix A: Spaces + Groups Example

```
Users:  alice, bob, charlie, dave
Groups: engineering (alice, bob), design (charlie, dave)

┌──────────────────────────────────────────────────────────┐
│ PERSONAL LIBRARIES (never shared, always encrypted)      │
│                                                          │
│ alice's library    → server mode (default)               │
│   Appears as plain text to alice. Always accessible.     │
│                                                          │
│ bob's library      → failsafe_user mode                  │
│   Bob enters passphrase each session. Admin can recover  │
│   if he forgets. Bob is notified on recovery.            │
│                                                          │
│ charlie's library  → pure_user mode                      │
│   Charlie enters passphrase each session. NO recovery.   │
│   If Charlie forgets his passphrase, data is GONE.       │
│                                                          │
│ dave's library     → server mode (default)               │
│   Same as alice — zero friction.                         │
├──────────────────────────────────────────────────────────┤
│ SPACES (collaborative)                                   │
│                                                          │
│ "Engineering Docs"   owner: group/engineering            │
│   encryption: server (default)                           │
│   → alice + bob auto-access via group                    │
│   → charlie granted read via space_access                │
│   → Everyone uses it like plain text — no passphrase     │
│                                                          │
│ "Secret Project"     owner: user/alice                   │
│   encryption: failsafe_user                              │
│   → alice owns it, shared with group/engineering         │
│   → Anyone with access needs the space passphrase        │
│   → Passphrase shared out-of-band (Slack, in person)     │
│   → If passphrase lost, admin can recover + users know   │
│                                                          │
│ "Company Assets"     owner: group/design                 │
│   encryption: server (default)                           │
│   → design team has full access                          │
│   → space_access grants read to group/engineering        │
│   → No passphrase needed by anyone                       │
└──────────────────────────────────────────────────────────┘
```

---

## Appendix B: Configuration

### `Rocket.toml`

```toml
[default]
address = "0.0.0.0"
port = 8000

[default.limits]
file = "5 GiB"
data-form = "5 GiB"

[default.databases.irondrive]
url = "sqlite:db/irondrive.db?mode=rwc"
```

### `.env.example`

```env
# IronDrive Configuration
#
# CRITICAL: This key encrypts the master encryption key in the database.
# If you lose this key, ALL server-mode data and failsafe recovery blobs
# become permanently inaccessible. BACK THIS UP SECURELY.
#
# Generate with: openssl rand -base64 44
IRONDRIVE_SECRET_KEY=CHANGE-ME-generate-a-random-256-bit-key-here

# Data directory (where files are stored)
IRONDRIVE_DATA_DIR=./data

# Database directory (where the SQLite DB is stored, separate from file storage)
IRONDRIVE_DB_DIR=./db

# Default quota for new users (default 5 GB)
# Accepts human-friendly sizes: "5 GB", "500 MB", "1.5 TB", etc.
IRONDRIVE_DEFAULT_QUOTA=5 GB

# Maximum single file upload size (default 5 GB)
IRONDRIVE_MAX_UPLOAD=5 GB

# Session expiry (in hours, default 7 days)
IRONDRIVE_SESSION_EXPIRY_HOURS=168

# Chunked transfer settings
IRONDRIVE_CHUNK_SIZE=8 MiB                  # Default chunk size for uploads/downloads
IRONDRIVE_CHUNK_UPLOAD_EXPIRY_HOURS=24       # Incomplete uploads cleaned after 24h
IRONDRIVE_MAX_PARALLEL_CHUNKS=4              # Suggested max parallel chunks per session

# Background services
IRONDRIVE_INTEGRITY_SCAN_ENABLED=true        # Enable periodic integrity scanning
IRONDRIVE_INTEGRITY_SCAN_INTERVAL_HOURS=168  # Scan interval (default: weekly)
```

---

## Appendix C: On-Disk File Format Reference

```
Every stored file on disk:

Offset  Length   Field
──────  ───────  ─────────────────────────────────
0       12       Nonce (random, unique per file)
12      N        AES-256-GCM ciphertext
12+N    16       AES-256-GCM auth tag
12+N+16 32       SHA-256 checksum (of original plaintext)

Overhead: 60 bytes per file (nonce + tag + checksum)
Minimum valid file: 60 bytes (empty plaintext)
```

### Reading:
1. First 12 bytes → nonce
2. Bytes 12..(len-48) → ciphertext + auth tag
3. Last 32 bytes → expected SHA-256
4. Decrypt with nonce + data key → plaintext (GCM verifies the tag)
5. SHA-256 the plaintext, compare to stored checksum
6. Mismatch → corrupted → create integrity event

### Writing:
1. SHA-256 the plaintext
2. Generate random 12-byte nonce
3. Encrypt with nonce + data key → ciphertext + tag
4. Write: nonce ‖ ciphertext ‖ tag ‖ checksum
5. Optional: read-back and verify (write-verify pass)

---

## Appendix D: Encryption Tier Decision Guide

Quick guide for users picking a tier:

```
Do you want maximum convenience with zero friction?
  YES → Server encryption (default)
        Files are encrypted at rest. You'll never notice.
        Admin can technically access files.

Do you want admin-proof privacy but still want a safety net?
  YES → Failsafe user encryption
        You set a passphrase. Admin can't read files.
        If you forget your passphrase, admin can help recover.
        You'll always be notified if recovery is used.

Do you want absolute privacy with no possible backdoor?
  YES → Pure user encryption
        You set a passphrase. Nobody else can ever read your files.
        ⚠️  If you forget your passphrase, your data is GONE FOREVER.
        Not even the server admin can help. This is by design.
```

---

*Living document — updated as things get built. Current through M5.7.*
