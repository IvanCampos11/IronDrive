#!/usr/bin/env python3
"""Work out the next release tag from existing git tags.

  dev  merges: vX.Y.Z-rc.N  (pre-release; X.Y.Z = latest stable + the PR's bump,
               or the version an earlier rc already targets if that is higher)
  main merges: vX.Y.Z       (promotes the pending rc version; a hotfix PR straight
               into main with a semver label bumps the latest stable instead)

Prints `key=value` lines for $GITHUB_OUTPUT: tag, already_tagged, should_tag.
"""
import argparse
import re
import subprocess
import sys
from pathlib import Path

STABLE = re.compile(r"^v(\d+)\.(\d+)\.(\d+)$")
RC = re.compile(r"^v(\d+)\.(\d+)\.(\d+)-rc\.(\d+)$")


def git(*args):
    return subprocess.run(["git", *args], check=True, capture_output=True, text=True).stdout


def cargo_version():
    text = Path("Cargo.toml").read_text()
    m = re.search(r'^version\s*=\s*"(\d+)\.(\d+)\.(\d+)"', text, re.M)
    return tuple(map(int, m.groups())) if m else (0, 0, 0)


def bump(v, kind):
    major, minor, patch = v
    if kind == "major":
        return (major + 1, 0, 0)
    if kind == "minor":
        return (major, minor + 1, 0)
    if kind == "patch":
        return (major, minor, patch + 1)
    raise SystemExit(f"unknown bump: {kind}")


def fmt(v):
    return "v%d.%d.%d" % v


def plan(tags, head_tags, mode, kind, fallback):
    """Pure decision logic, separated out so it can be tested without git."""
    for t in head_tags:
        if STABLE.match(t) or RC.match(t):
            return {"should_tag": "true", "already_tagged": "true", "tag": t}

    stables = [tuple(map(int, m.groups())) for t in tags if (m := STABLE.match(t))]
    stable = max(stables) if stables else fallback
    rcs = [(tuple(map(int, m.groups()[:3])), int(m.group(4))) for t in tags if (m := RC.match(t))]
    pending = max((base for base, _ in rcs if base > stable), default=None)

    if mode == "dev":
        if not kind:
            return {"should_tag": "false"}
        target = bump(stable, kind)
        if pending and pending > target:
            target = pending
        n = 1 + max((num for base, num in rcs if base == target), default=0)
        return {"should_tag": "true", "already_tagged": "false", "tag": f"{fmt(target)}-rc.{n}"}

    if pending:
        return {"should_tag": "true", "already_tagged": "false", "tag": fmt(pending)}
    if kind:
        return {"should_tag": "true", "already_tagged": "false", "tag": fmt(bump(stable, kind))}
    return {"should_tag": "false"}


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--mode", choices=["dev", "main"], required=True)
    p.add_argument("--bump", choices=["major", "minor", "patch", ""], default="")
    a = p.parse_args()
    tags = git("tag", "-l", "v*").split()
    head_tags = git("tag", "--points-at", "HEAD").split()
    for k, v in plan(tags, head_tags, a.mode, a.bump, cargo_version()).items():
        print(f"{k}={v}")


if __name__ == "__main__":
    sys.exit(main())
