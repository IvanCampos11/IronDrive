# IronDrive TODO

## Status Snapshot

- Current version: 0.7.0
- Working areas: auth, personal libraries, groups, spaces, integrity, background jobs, server-rendered UI, quotas, trash, streaming downloads
- Biggest gaps: user-managed encryption tiers, quotas for group-owned spaces

## Priority Rules

1. Security and data safety first.
2. Features users touch every day second.
3. New capabilities only after reliability debt is handled.

## (P0/P1)

- [x] Enforce quota checks server-side on all write paths.
  - [x] library upload
  - [x] space upload
  - [x] chunked init and complete (library + space); in-progress uploads reserve space
  - [x] consistent `QuotaExceeded` (507) with a user-facing message
- [x] Add missing chunked space API endpoints (canonical API documented in ARCHITECTURE.md §9).
- [x] Property tests for path safety (random traversal inputs + symlink escape) and a model-based test for trash operations.
- [x] Tighten memory for large transfers: downloads stream segment by segment, direct uploads share a 50 MiB cap without extra copies, chunked completes already stream.
- [x] Trash with undo instead of permanent deletes.
- [ ] Decide quotas for group-owned spaces (currently uncharged).

## (P2)

- [ ] Implement real user-managed encryption tiers end-to-end.
  - [ ] setup flow for `server` / `failsafe_user` / `pure_user`
  - [ ] unlock/lock routes and page UX
  - [ ] passphrase verification and key lifecycle
- [ ] Implement recovery flow for failsafe mode.
  - [ ] admin trigger
  - [ ] audit log lifecycle
  - [ ] user-visible notification handling
- [ ] Add structured request logging and stronger operational diagnostics.

## (P3)

- [x] Quota/admin management UI (admin page: users, quotas, enable/disable, scan).
- [ ] API-level polish pass (consistent errors, docs, and status semantics).
- [ ] Optional compression strategy for large responses.
- [ ] Storage backend abstraction (local first, others later).
- [ ] Client-side E2EE research branch (non-blocking, design-only stage).

## UI/UX Cleanup Queue

- [ ] Keep forms and modal behaviors consistent across files/groups/spaces pages.
- [ ] Accessibility pass on recently added interactive controls.
- [ ] Improve empty/error states to reduce user confusion during setup and sharing flows.

## Test/Quality Queue

- [ ] Add full lifecycle integration tests for:
  - [ ] group + space sharing and revocation
  - [ ] chunked flows under permission boundaries
  - [ ] startup/restart behavior with key loading and cleanup
- [x] Add regressions for integrity event acknowledge + notifications.

## Done (Condensed)

- [x] Core app scaffold and migrations
- [x] Registration/login/logout + setup gating
- [x] Server-managed encryption at rest
- [x] Personal library file operations
- [x] Chunked library transfers
- [x] Integrity events + admin scan + notifications endpoint
- [x] Background workers (integrity/session/chunk cleanup)
- [x] Groups (API + pages)
- [x] Spaces (API + pages + access model + file ops)
- [x] Server-rendered frontend with Tera + HTMX

