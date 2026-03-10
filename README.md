# IronDrive

Self-hosted file storage and sharing, think Google Drive / ownCloud / Seafile, but built in **Rust** on top of **Rocket**.

> ⚠️ **This project is in very early development.** Things will break, APIs will change, and nothing is production-ready. Don't run this with data you care about yet.

## What It Does (Planned)

- **Personal Libraries** — Each user gets their own private storage, created on first login. Can't be shared, can't be deleted.
- **Spaces** — Shared folders with granular permissions (`read`, `write`, `admin`). Owned by a user or a group.
- **Groups** — Organize users for bulk access control on spaces.
- **Everything Encrypted at Rest** — AES-256-GCM. No plaintext ever hits the disk. Period.
- **Three Encryption Tiers:**
  - **Server (default)** — Automatic, invisible. Zero friction. Protects against disk theft / backup leaks.
  - **Failsafe User** — User sets a passphrase. Admin can't read files. If the passphrase is forgotten, admin can trigger recovery (user always gets notified).
  - **Pure User** — User sets a passphrase. No recovery. Forget it and your data is gone forever. That's the point.
- **Chunked Uploads & Downloads** — Large files get split into chunks for parallel transfer and resumability. Small files just go through in a single request, no ceremony.
- **Data Integrity** — SHA-256 checksum on every file at write time, verified on every read. Disk corruption or bad writes get caught automatically and the user gets notified.
- **Background Services** — Async background tasks for periodic integrity scanning, session cleanup, and stale chunk cleanup. They share the tokio runtime with Rocket, no extra processes.
- **Async All the Way Down** — All I/O, all service logic, all background work. Nothing blocks.
- **Filesystem-as-Truth** — No DB entries for files. The actual filesystem is the source of truth. The DB handles users, groups, permissions, encryption keys, and operational state.
- **Single Binary** — One Rust binary + a SQLite file + a data directory. That's the whole deployment.
- **E2EE (Future)** — The architecture is set up so we can bolt on full client-side end-to-end encryption later without tearing everything apart.

## Tech Stack

| Component | Choice |
|---|---|
| Language | Rust |
| Web Framework | [Rocket 0.5.1](https://rocket.rs) |
| Database | SQLite via [SQLx](https://github.com/launchbadge/sqlx) |
| Password Hashing | Argon2 |
| File Encryption | AES-256-GCM |
| Data Integrity | SHA-256 checksums |
| Key Derivation | Argon2 (for user encryption tiers) |
| Async Runtime | Tokio (requests + background services) |

## Encryption Model

Every file is always encrypted at rest. The only question is who holds the key.

| Tier | UX | Admin Can Read? | Password Lost? |
|---|---|---|---|
| **Server** (default) | Invisible — feels like plaintext | Yes (key is server-managed) | N/A — no password involved |
| **Failsafe User** | Passphrase required each session | Only via recovery (user notified) | Admin can recover |
| **Pure User** | Passphrase required each session | Never | **Data gone forever** |

Full details in **[ARCHITECTURE.md](ARCHITECTURE.md)** — key hierarchy, recovery flows, the whole thing.

## Docs

**[ARCHITECTURE.md](ARCHITECTURE.md)** covers everything:

- Core concepts (Libraries vs Spaces vs Groups)
- Three-tier encryption model with detailed flows
- Chunked transfer protocol (upload/download, parallel chunks)
- Data integrity (checksums, corruption detection, notifications)
- Background services (integrity scanner, session cleanup, chunk cleanup)
- Database schema
- Full API surface (60+ endpoints)
- On-disk file format
- Security considerations

## Status

**Pre-development** — still in the architecture/planning phase. See **[TODO.md](TODO.md)** for milestones and progress.

## Getting Started

> Not runnable yet — this is still pre-dev.

### Prerequisites

- Rust (stable, 1.75+)
- SQLite3

### Build & Run

```sh
git clone https://github.com/yourusername/irondrive.git
cd irondrive

cp .env.example .env

# Generate a real secret key — this protects all server-managed encryption.
# Back it up somewhere safe.
echo "IRONDRIVE_SECRET_KEY=$(openssl rand -base64 44)" >> .env

cargo run
```

On first run the server will:
1. Create `data/` directory structure (`data/libraries/`, `data/spaces/`).
2. Run SQLite migrations.
3. Generate the master encryption key (encrypted by `IRONDRIVE_SECRET_KEY`, stored in DB).
4. Start listening on `http://localhost:8000`.

## Configuration

Copy `.env.example` to `.env` and tweak as needed. See [Appendix B in ARCHITECTURE.md](ARCHITECTURE.md#appendix-b-configuration) for all options.

### About `IRONDRIVE_SECRET_KEY`

This env var is the **root of trust** for all server-managed encryption. If you lose it:
- All **server-mode** data becomes permanently unreadable.
- All **failsafe user** recovery blobs become useless (users can still unlock with their own passphrase though).
- **Pure user** data is unaffected (it never touches the server key).

**Generate it properly and back it up separately from the database.** Seriously.

## License

TBD
