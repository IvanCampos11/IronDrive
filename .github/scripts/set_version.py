#!/usr/bin/env python3
"""Stamp a release version into Cargo.toml and Cargo.lock.

Usage: set_version.py v1.2.3[-rc.1]

The binary reports CARGO_PKG_VERSION (on /health and the settings page), so
release builds write the tag's version in before compiling. Both files are
updated so `cargo build --locked` still accepts the lockfile.
"""
import re
import sys
from pathlib import Path

version = sys.argv[1].removeprefix("v")
if not re.fullmatch(r"\d+\.\d+\.\d+(-[0-9A-Za-z.]+)?", version):
    sys.exit(f"not a semver version: {version}")

toml = Path("Cargo.toml")
text, n = re.subn(r'(?m)^(version\s*=\s*)"[^"]*"', rf'\g<1>"{version}"', toml.read_text(), count=1)
if n != 1:
    sys.exit("no version line in Cargo.toml")
toml.write_text(text)

lock = Path("Cargo.lock")
text, n = re.subn(r'(name = "irondrive"\nversion = )"[^"]*"', rf'\g<1>"{version}"', lock.read_text())
if n != 1:
    sys.exit("irondrive package not found in Cargo.lock")
lock.write_text(text)

print(f"version set to {version}")
