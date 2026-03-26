# IronDrive

Self-hosted encrypted cloud file storage. Nextcloud/Google Drive but written in Rust.

> **Heads up:** This is a work in progress. I'm building this for myself and learning a ton along the way. Don't put anything important on it yet.

## What works right now

- User registration and login (session-based auth, Argon2 password hashing)
- Personal libraries — each user gets their own encrypted storage space on setup
- File operations — upload, download, browse, mkdir, rename, delete
- Everything encrypted with AES-256-GCM before it touches disk
- SHA-256 integrity checks on every file
- Multi-user support (each user's files are fully isolated)
- Server-rendered frontend with Tera templates + HTMX (in progress)

## What's planned but not done yet

- Chunked uploads for large files
- Shared spaces (like shared folders with permissions)
- Groups
- User encryption tiers (passphrase-protected libraries where even the server admin can't read your files)
- Background integrity scanning
- Quotas
- Eventually, full client-side E2EE — the architecture is designed to support it later without rewriting everything

See [TODO.md](TODO.md) for the full roadmap.

## Tech stack

- **Rust** with **Rocket 0.5** for the web framework
- **SQLite** via SQLx (no database server needed)
- **AES-256-GCM** for file encryption, **SHA-256** for checksums
- **Argon2** for password hashing
- **Tera + HTMX + Tailwind** for the frontend (served by Rocket, no separate JS build)

One binary, one SQLite file, one data directory. That's the whole deployment.

## Encryption

Every file is encrypted at rest, always. The on-disk format is `nonce || ciphertext || checksum` — there's no plaintext on disk, ever.

Right now only "server mode" is implemented: the server manages the keys automatically, and encryption is invisible to the user. This protects against disk theft, backup leaks, that kind of thing.

Two more tiers are planned:

| Mode | What it means |
|---|---|
| **Server** (current) | Automatic. Admin can read files. No passphrase needed. |
| **Failsafe User** (planned) | User sets a passphrase. Admin can trigger recovery if the passphrase is lost, but the user gets notified. |
| **Pure User** (planned) | User sets a passphrase. No recovery, period. Forget it and your data is gone. |

The full encryption design is in [ARCHITECTURE.md](ARCHITECTURE.md).

## Running it

### You'll need

- Rust stable (1.75+)
- SQLite3

### Setup

```sh
git clone https://github.com/yourusername/irondrive.git
cd irondrive
cp .env.example .env

# Generate a secret key. This protects all encryption keys.
# Back this up somewhere safe — lose it and server-mode data is gone.
echo "IRONDRIVE_SECRET_KEY=$(openssl rand -base64 44)" >> .env

cargo run
```

First run creates the data directories, runs migrations, generates the master key, and starts listening on `http://localhost:8000`.

### About `IRONDRIVE_SECRET_KEY`

This is the root of trust for all server-managed encryption. If you lose it, all server-mode files become unreadable. Generate it once, back it up, and don't lose it. I mean it.

See `.env.example` for all config options.

## Project structure

```
src/
  config.rs          — env/config loading
  db.rs              — SQLite pool
  errors.rs          — error types
  main.rs            — Rocket launch
  guards/            — request guards (auth, setup, admin)
  models/            — database models (users, sessions, libraries)
  routes/            — HTTP route handlers
  services/          — business logic (auth, crypto, filesystem, etc.)
  utils/             — path safety, MIME detection, crypto helpers
migrations/          — SQLite migrations
templates/           — Tera HTML templates
static/              — CSS, JS, vendor files
data/                — created at runtime (libraries, spaces, chunks)
```

## Docs

[ARCHITECTURE.md](ARCHITECTURE.md) has the full design — encryption model, key hierarchy, API surface, database schema, everything.

[TODO.md](TODO.md) has the milestone tracker.

## License

TBD
