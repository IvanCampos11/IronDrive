# IronDrive TODO

> Last updated: 2026-04-10  
> Scope: practical solo-maintainer backlog, not historical milestone narration.

## Status Snapshot

- Current version: 0.6.0
- Working areas: auth, personal libraries, groups, spaces, integrity, background jobs, server-rendered UI
- Biggest gaps: quota enforcement, user-managed encryption tiers, API/page parity for some chunked space flows

## Priority Rules

1. Security and data safety first.
2. Features users touch every day second.
3. New capabilities only after reliability debt is handled.

## Now (P0/P1)

- [ ] Enforce quota checks server-side on all write paths.
  - [ ] library upload
  - [ ] space upload
  - [ ] chunked complete (library + space)
  - [ ] return consistent `QuotaExceeded` behavior and UI feedback
- [ ] Add missing chunked space API endpoints or intentionally remove page/API split.
  - [ ] decide contract
  - [ ] implement or deprecate
  - [ ] document one canonical path
- [ ] Add focused fuzz/property tests around path safety and file operation edge cases.
- [ ] Tighten upload memory behavior for large completes (reduce peak RAM where feasible).

## Next (P2)

- [ ] Implement real user-managed encryption tiers end-to-end.
  - [ ] setup flow for `server` / `failsafe_user` / `pure_user`
  - [ ] unlock/lock routes and page UX
  - [ ] passphrase verification and key lifecycle
- [ ] Implement recovery flow for failsafe mode.
  - [ ] admin trigger
  - [ ] audit log lifecycle
  - [ ] user-visible notification handling
- [ ] Add structured request logging and stronger operational diagnostics.

## Later (P3)

- [ ] Full quota/admin management UI.
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
- [ ] Add regressions for integrity event acknowledge + notifications.

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

## Backlog Hygiene

- Removed from this file:
  - huge historical milestone checklists that are already complete
  - speculative implementation details that belong in design notes
  - duplicate task statements across API and UI sections

Keep this TODO short. If a section stops being actionable, delete or rewrite it.
