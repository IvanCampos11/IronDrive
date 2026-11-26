#!/usr/bin/env python3
"""Build release notes from the pull requests merged since the previous release.

Each PR's "Release notes" and "Upgrade notes" sections (see
.github/pull_request_template.md) become the user-facing text; PRs without them
fall back to their title. Labels decide the grouping:

  highlight            -> "Highlights", rendered in full at the top
  breaking / major     -> "Breaking changes"
  feature / minor      -> "New"
  bug / fix / patch    -> "Fixes"
  security, performance, docs -> their own groups
  chore / dependencies / refactor / test / ci / build -> collapsed "Maintenance"
  skip-changelog       -> left out

A dev -> main promotion PR is not listed; its "Release notes" become the
release's opening paragraph instead.

Usage:
  release_notes.py --tag v0.8.0 --repo owner/name          # full release notes
  release_notes.py --pr 42 --repo owner/name               # preview one PR's entry
Set GITHUB_TOKEN to avoid the API's anonymous rate limit.
"""
import argparse
import json
import os
import re
import subprocess
import sys
import urllib.request

TAG = re.compile(r"^v(\d+)\.(\d+)\.(\d+)(?:-rc\.(\d+))?$")
PROMOTION_HEADS = {"dev", "main"}

# (section title, labels), first match wins, in this order.
GROUPS = [
    ("skip", {"skip-changelog"}),
    ("Security", {"security"}),
    ("Breaking changes", {"breaking", "semver-major", "major"}),
    ("Performance", {"performance"}),
    ("Fixes", {"bug", "bugfix", "fix"}),
    ("New", {"feature", "enhancement"}),
    ("Documentation", {"documentation", "docs"}),
    ("Maintenance", {"chore", "dependencies", "refactor", "test", "ci", "build", "maintenance"}),
    ("New", {"semver-minor", "minor"}),
    ("Fixes", {"semver-patch", "patch"}),
]
ORDER = ["Breaking changes", "Security", "New", "Fixes", "Performance", "Documentation", "Other changes"]
EMPTY = {"", "n/a", "na", "none", "-", "nothing", "no"}


# ---------------------------------------------------------------- git + API

def git(*args):
    return subprocess.run(["git", *args], check=True, capture_output=True, text=True).stdout.strip()


def api(repo, path):
    req = urllib.request.Request(f"https://api.github.com/repos/{repo}{path}")
    req.add_header("Accept", "application/vnd.github+json")
    req.add_header("User-Agent", "release-notes-script")
    if os.environ.get("GITHUB_TOKEN"):
        req.add_header("Authorization", f"Bearer {os.environ['GITHUB_TOKEN']}")
    with urllib.request.urlopen(req, timeout=30) as r:
        return json.load(r)


def version_key(tag):
    m = TAG.match(tag)
    major, minor, patch, rc = m.groups()
    # A stable release sorts after all of its release candidates.
    return (int(major), int(minor), int(patch), int(rc) if rc else 10**9)


def previous_tag(tag):
    """Highest earlier tag that is an ancestor. Stable releases compare against
    the previous stable one so their notes cover every rc in between."""
    stable = "-" not in tag
    candidates = [
        t for t in git("tag", "-l", "v*").split()
        if TAG.match(t) and t != tag and version_key(t) < version_key(tag) and (not stable or "-" not in t)
    ]
    for t in sorted(candidates, key=version_key, reverse=True):
        if subprocess.run(["git", "merge-base", "--is-ancestor", t, tag]).returncode == 0:
            return t
    return None


def changes(prev, tag):
    """PR numbers merged in the range, plus commits that came in without a PR."""
    rng = f"{prev}..{tag}" if prev else tag
    prs, in_pr = [], set()
    for line in git("log", "--format=%H %P%x09%s", rng).splitlines():
        shas, subject = line.split("\t", 1)
        sha, *parents = shas.split()
        m = re.match(r"Merge pull request #(\d+)", subject) or re.search(r"\(#(\d+)\)$", subject)
        if not m:
            continue
        prs.append(int(m.group(1)))
        in_pr.add(sha)
        if len(parents) == 2 and subject.startswith("Merge pull request"):
            in_pr.update(git("rev-list", f"{parents[0]}..{parents[1]}").split())
    direct = []
    for line in git("log", "--no-merges", "--format=%H%x09%an%x09%s", rng).splitlines():
        sha, author, subject = line.split("\t", 2)
        if sha not in in_pr:
            direct.append((sha, author, subject))
    return list(dict.fromkeys(prs)), direct


# ----------------------------------------------------------- PR body parsing

def section(body, name):
    """Text under a markdown heading called `name` (any level), up to the next heading."""
    body = re.sub(r"<!--.*?-->", "", body or "", flags=re.S).replace("\r\n", "\n")
    m = re.search(rf"^#+\s*{re.escape(name)}\s*$(.*?)(?=^#+\s|\Z)", body, re.M | re.S | re.I)
    text = m.group(1).strip() if m else ""
    return "" if text.lower().strip(" .") in EMPTY else text


def group_for(labels):
    for title, names in GROUPS:
        if labels & names:
            return title
    return "Other changes"


def entry(pr, repo):
    """One bullet: the note's first paragraph (or the title), with any bullets
    or extra paragraphs from the note nested underneath."""
    link = f"([#{pr['number']}](https://github.com/{repo}/pull/{pr['number']}))"
    notes = pr["notes"]
    if not notes:
        return f"- {pr['title']} {link}"
    paras = [p.strip() for p in re.split(r"\n\s*\n", notes) if p.strip()]
    first = paras[0]
    rest = paras[1:]
    if first.lstrip().startswith(("- ", "* ")):
        lead, rest = f"**{pr['title']}**", paras
    else:
        lead = " ".join(line.strip() for line in first.splitlines())
    out = [f"- {lead} {link}"]
    for p in rest:
        for line in p.splitlines():
            line = line.rstrip()
            if line.lstrip().startswith(("- ", "* ")):
                out.append("  " + line.lstrip())
            elif line.strip():
                out.append("  " + line.strip())
        out.append("")
    return "\n".join(out).rstrip()


def load_pr(repo, number):
    raw = api(repo, f"/pulls/{number}")
    return {
        "number": number,
        "title": raw["title"].strip(),
        "author": raw["user"]["login"],
        "labels": {l["name"].lower() for l in raw["labels"]},
        "notes": section(raw["body"], "Release notes"),
        "upgrade": section(raw["body"], "Upgrade notes"),
        "promotion": raw["head"]["ref"] in PROMOTION_HEADS and raw["base"]["ref"] == "main",
        "merged": raw.get("merged_at") is not None,
    }


# ----------------------------------------------------------------- rendering

def render(tag, repo, prev, prs, direct):
    owner = repo.split("/")[0]
    out = []
    intro = [p for p in prs if p["promotion"] and p["notes"]]
    prs = [p for p in prs if not p["promotion"]]
    if "-" in tag:
        out.append(f"> **Pre-release** from the `dev` branch, for testing what's coming in "
                   f"{tag.split('-')[0]}. Use the `edge` image or wait for the stable release on `latest`.\n")
    for p in intro:
        out.append(p["notes"] + "\n")

    upgrades = [p for p in prs if p["upgrade"]]
    if upgrades:
        out.append("## Before you upgrade\n")
        for p in upgrades:
            out.append(f"**{p['title']}** ([#{p['number']}](https://github.com/{repo}/pull/{p['number']}))\n")
            out.append(p["upgrade"] + "\n")

    highlights = [p for p in prs if "highlight" in p["labels"] and p["notes"]]
    if highlights:
        out.append("## Highlights\n")
        for p in highlights:
            out.append(f"### {p['title']}\n")
            out.append(p["notes"] + "\n")
            out.append(f"<sub>[#{p['number']}](https://github.com/{repo}/pull/{p['number']})</sub>\n")

    groups = {}
    for p in prs:
        if p in highlights:
            continue
        groups.setdefault(group_for(p["labels"]), []).append(p)
    for title in ORDER:
        if groups.get(title):
            out.append(f"## {title}\n")
            out.extend(entry(p, repo) for p in groups[title])
            out.append("")

    maint = groups.get("Maintenance", [])
    if maint or direct:
        count = len(maint) + len(direct)
        out.append(f"<details>\n<summary>Maintenance and other commits ({count})</summary>\n")
        out.extend(entry(p, repo) for p in maint)
        for sha, _, subject in direct:
            out.append(f"- {subject} ([`{sha[:7]}`](https://github.com/{repo}/commit/{sha}))")
        out.append("\n</details>\n")

    if not any(groups.values()) and not direct and not highlights:
        out.append("No user-facing changes.\n")

    image = f"ghcr.io/{owner.lower()}/irondrive"
    out.append("## Install\n")
    out.append(f"```sh\ndocker pull {image}:{tag.removeprefix('v')}\n```\n")
    out.append("Or download an archive for your platform below, unpack it and run `./irondrive` "
               "from inside the folder (see `.env.example` for settings). "
               "Verify downloads with `sha256sum -c SHA256SUMS`.\n")

    others = sorted({p["author"] for p in prs if p["author"].lower() != owner.lower()})
    if others:
        out.append("Thanks to " + ", ".join(f"@{a}" for a in others) + " for contributing to this release.\n")
    if prev:
        out.append(f"**Full changelog:** https://github.com/{repo}/compare/{prev}...{tag}")
    return "\n".join(out).strip() + "\n"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--repo", required=True)
    ap.add_argument("--tag")
    ap.add_argument("--pr", type=int, help="preview the entry a single PR will produce")
    a = ap.parse_args()

    if a.pr:
        p = load_pr(a.repo, a.pr)
        where = "Highlights" if "highlight" in p["labels"] and p["notes"] else group_for(p["labels"])
        if p["promotion"]:
            where = "the release introduction"
        print(f"This PR will appear under **{where}**:\n")
        if where == "skip":
            print("_(left out of the release notes: `skip-changelog` label)_")
        elif where == "Highlights" or p["promotion"]:
            print(p["notes"])
        else:
            print(entry(p, a.repo))
        if not p["notes"]:
            print("\n_Tip: add a **Release notes** section to the PR description to describe this change "
                  "for users; otherwise the title is used._")
        if p["upgrade"]:
            print("\n**Before you upgrade:**\n\n" + p["upgrade"])
        return

    if not a.tag or not TAG.match(a.tag):
        sys.exit("--tag vX.Y.Z[-rc.N] is required")
    prev = previous_tag(a.tag)
    numbers, direct = changes(prev, a.tag)
    prs = [p for p in (load_pr(a.repo, n) for n in numbers) if p["merged"]]
    prs = [p for p in prs if group_for(p["labels"]) != "skip"]
    print(render(a.tag, a.repo, prev, prs, direct))


if __name__ == "__main__":
    main()
