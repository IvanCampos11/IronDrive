# Releasing IronDrive

Releases are automatic. You choose the version bump with a PR label and write
the release notes in the PR description; CI does the rest.

## The flow

```
feature PR ──merge──▶ dev ──▶ v0.8.0-rc.1   pre-release, image :edge
feature PR ──merge──▶ dev ──▶ v0.8.0-rc.2
dev ──────── merge ─▶ main ─▶ v0.8.0        stable release, images :latest :0.8 :0.8.0
```

1. **Open a PR into `dev`** and give it one version label:
   `semver-major`/`major`, `semver-minor`/`minor` or `semver-patch`/`patch`.
   No label means merging won't cut a release (fine for small chores).
2. **Fill in "Release notes"** in the PR description: a sentence or two for
   users, plus bullets if useful. The *PR release notes* check shows a
   preview of how the entry will look in the release.
3. **Merge.** A pre-release tag `vX.Y.Z-rc.N` is created, which builds
   binaries, a Docker image (`:edge`) and a GitHub pre-release.
4. **When dev is ready, open a PR from `dev` into `main`** (no label needed) and
   merge it. The pending version is released as stable `vX.Y.Z`. The
   "Release notes" section of *this* PR becomes the release's introduction,
   so it's a good place for a short overview of the whole release.

Hotfix: a PR straight into `main` with `semver-patch` releases `vX.Y.(Z+1)`.
Merge `main` back into `dev` afterwards.

## Labels that shape the notes

| Label | Effect |
| --- | --- |
| `highlight` | Shown in full under **Highlights** at the top. Use for the 1–3 changes worth talking about. |
| `breaking` / major | **Breaking changes** |
| `feature`, `enhancement` / minor | **New** |
| `bug`, `fix` / patch | **Fixes** |
| `security`, `performance`, `documentation` | Their own sections |
| `chore`, `dependencies`, `refactor`, `test`, `ci`, `build` | Folded into **Maintenance** |
| `skip-changelog` | Left out |

Anything in a PR's **Upgrade notes** section is collected under
**Before you upgrade** at the top of the release.

## What each release publishes

- `ghcr.io/<owner>/irondrive` images for amd64 and arm64, with SBOM and
  build provenance.
- `irondrive-<tag>-<target>.tar.gz` for Linux (x86_64, arm64) and macOS
  (Apple Silicon, Intel), with `SHA256SUMS` and provenance attestations
  (`gh attestation verify <file> --repo <owner>/IronDrive`).

The version shown on `/health` and in Settings comes from the tag: release
builds stamp it into `Cargo.toml` before compiling. The version committed
in `Cargo.toml` is only used for local builds.

## Setup (once)

- Secret `RELEASE_TOKEN`: a fine-grained personal access token for this repo
  with **Contents: read and write**. Tags pushed with the default token don't
  trigger the release workflow, so this one is needed.
- Create the labels above if they don't exist.
- Optional: in branch protection for `dev` and `main`, require the CI checks
  *Format*, *Clippy*, *Test* and *Compiled CSS is up to date*.

## Trying the notes locally

```sh
python3 .github/scripts/release_notes.py --repo <owner>/IronDrive --tag v0.7.0
python3 .github/scripts/release_notes.py --repo <owner>/IronDrive --pr 42
```
