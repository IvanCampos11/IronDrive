# IronDrive

Self-hosted encrypted file storage in Rust.

IronDrive is a web app that gives you personal libraries, shared spaces, groups, and encrypted-at-rest file handling with integrity checks.

## What Works Today

- Auth and sessions
  - Register, login, logout
  - Session token model with hashed token storage
  - Setup gating for first login
- Personal libraries
  - One library per user
  - Browse, upload, download, mkdir, rename/move, delete
  - Chunked upload/download
- Spaces
  - Space CRUD
  - Access control for users and groups (`read`, `write`, `admin`)
  - File operation parity with personal libraries
  - Chunked upload/download in page flows
- Groups
  - Group CRUD
  - Membership and role management
- Integrity and background services
  - File hash checks and integrity events
  - User notifications endpoint for integrity events
  - Background workers for integrity scan, expired sessions, and chunk cleanup
- Frontend
  - Server-rendered pages with Tera + HTMX
  - CSRF protection for state-changing actions

## Not Done Yet

- User-managed encryption tiers are not active in runtime setup/lock/unlock flows.
- Quota enforcement is not complete on all write paths.
- Space chunked API parity is incomplete (page flows exist; API route parity still pending).

## Quick Start

### Requirements

- Rust (stable)
- OpenSSL (for generating a secret key)

### Setup

```bash
git clone https://github.com/IvanCampos11/IronDrive.git
cd IronDrive
cp .env.example .env

# Required: root secret for server-managed encryption key material.
echo "IRONDRIVE_SECRET_KEY=$(openssl rand -base64 44)" >> .env

# Start the app
cargo run
```

Then open `http://localhost:8000`.

First boot will:

1. Create data directories.
2. Initialize SQLite and run migrations.
3. Bootstrap/load encryption key state.
4. Start background workers.

### Optional Dev Command

If you want Tailwind watch + server in one command:

```bash
make dev
```

## Configuration

See [.env.example](.env.example) for all settings.

Most important variables:

- `IRONDRIVE_SECRET_KEY` (required)
- `IRONDRIVE_DATA_DIR`
- `IRONDRIVE_DB_DIR`
- `IRONDRIVE_MAX_UPLOAD`
- `IRONDRIVE_DEFAULT_QUOTA`
- `IRONDRIVE_CHUNK_SIZE`
- `IRONDRIVE_INTEGRITY_SCAN_ENABLED`

## Security Note

`IRONDRIVE_SECRET_KEY` is the root secret for server-managed encryption state.

- If you lose it, server-managed encrypted data becomes unreadable.
- Back it up securely and separately from the server.

## Project Layout

```text
src/
  routes/      HTTP routes (API + pages)
  guards/      request guards (auth, setup, space permissions, csrf)
  services/    business logic
  models/      SQLx models/queries
  utils/       shared helpers
  tests/       integration tests
migrations/    SQLite schema migrations
templates/     Tera templates
static/        CSS/JS/vendor assets
data/          runtime storage (created automatically)
```

## Documentation

- Architecture and current capability map: [ARCHITECTURE.md](ARCHITECTURE.md)
- Prioritized backlog: [TODO.md](TODO.md)

## License

AGPL-3.0
