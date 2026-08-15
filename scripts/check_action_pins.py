#!/usr/bin/env python3
"""Audit third-party GitHub Action references across a repository.

Two checks, with deliberately different severities.

PUBLISHER ALLOWLIST — blocking
    `uses: some-random/action@v1` runs arbitrary code with the job's token and access to its
    secrets. A pull request that adds one is asking for trust in a party nobody reviewed, and
    the review that should catch it is the one nobody performs on a green build. The
    allowlist makes adding a publisher a deliberate, visible change to this file.

SHA PINNING — reported, blocking only when --require-sha is set
    `actions/checkout@v4` resolves a MUTABLE tag. The owner can move `v4` to different code
    at any time, and a compromised popular action then runs in every job that references it.
    A 40-character commit SHA cannot be moved.

    This is not blocking yet, and the reason is honest rather than principled: pinning
    requires resolving every action to a current SHA, which needs network access, and STALE
    pinned SHAs are worse than tags because they silently miss security releases. Pinning is
    only safe once Dependabot is running to move the pins — which is why .github/dependabot.yml
    lands first. See docs/security.md.

    Run `scripts/pin_actions.sh` once Dependabot is confirmed working, then set
    --require-sha in CI to keep it that way.

Exit codes:
    0  no blocking findings
    1  a disallowed publisher, or an unpinned action when --require-sha is set
"""

from __future__ import annotations

import argparse
import re
import sys
from collections import defaultdict
from pathlib import Path

# Publishers permitted to run in this organisation's workflows.
#
# Enumerated, not pattern-matched. `aws-actions/*` is fine; `aws-actions-official/*` is a
# typosquat and would match a loose pattern.
ALLOWED_PUBLISHERS = {
    "actions",              # GitHub
    "github",               # GitHub
    "docker",               # Docker Inc
    "aws-actions",          # AWS
    "hashicorp",            # HashiCorp
    "aquasecurity",         # Trivy
    "anchore",              # Syft / Grype
    "sigstore",             # cosign
    "gitleaks",
    "terraform-linters",    # tflint
    "raven-actions",        # actionlint wrapper
    "open-policy-agent",    # OPA / conftest
    "kyverno",
    "peter-evans",          # create-pull-request
}

# `uses: owner/repo@ref` or `uses: owner/repo/path@ref`
USES_PATTERN = re.compile(
    r"^\s*-?\s*uses:\s*['\"]?"
    r"(?P<owner>[A-Za-z0-9._-]+)/(?P<repo>[A-Za-z0-9._/-]+?)"
    r"@(?P<ref>[A-Za-z0-9._-]+)['\"]?",
    re.MULTILINE,
)

SHA_PATTERN = re.compile(r"^[0-9a-f]{40}$")

# Refs that are branches rather than releases. Strictly worse than a version tag: a tag is
# mutable but is at least moved deliberately by the publisher, whereas a branch changes on
# every push. `uses: someone/action@master` runs whatever landed upstream minutes ago, with
# this job's token and secrets. Blocking, unconditionally.
BRANCH_REFS = {"master", "main", "develop", "latest", "HEAD"}


def audit(paths: list[Path], allowed: set[str]) -> tuple[list[str], list[str], dict]:
    """Return (blocking findings, pinning findings, usage summary)."""
    blocking: list[str] = []
    unpinned: list[str] = []
    usage: dict[str, set[str]] = defaultdict(set)

    for path in paths:
        text = path.read_text(encoding="utf-8")
        for match in USES_PATTERN.finditer(text):
            owner = match.group("owner")
            repo = match.group("repo")
            ref = match.group("ref")

            # A local or reusable-workflow reference inside this org is not a third-party
            # action. `./` paths never match the pattern in the first place.
            action = f"{owner}/{repo}"
            usage[action].add(ref)

            if owner == "Saikiran6650":
                continue

            if owner not in allowed:
                blocking.append(
                    f"{path.name}: '{action}@{ref}' — publisher '{owner}' is not on the "
                    f"allowlist. Adding it is a deliberate change to "
                    f"scripts/check_action_pins.py, reviewed on its own merits."
                )

            if ref in BRANCH_REFS:
                blocking.append(
                    f"{path.name}: '{action}@{ref}' pins a BRANCH. It changes on every "
                    f"upstream push and runs with this job's token. Use a release tag, or "
                    f"drop the action and invoke the tool directly."
                )
            elif not SHA_PATTERN.match(ref):
                unpinned.append(f"{path.name}: '{action}@{ref}' is a mutable tag")

    return blocking, unpinned, usage


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("paths", type=Path, nargs="*", default=[Path(".github/workflows")])
    parser.add_argument(
        "--require-sha",
        action="store_true",
        help="Fail when any action is referenced by tag rather than by commit SHA.",
    )
    args = parser.parse_args(argv)

    files: list[Path] = []
    for entry in args.paths:
        if entry.is_dir():
            files.extend(sorted(entry.rglob("*.yml")))
            files.extend(sorted(entry.rglob("*.yaml")))
        elif entry.exists():
            files.append(entry)

    if not files:
        print("no workflow files found", file=sys.stderr)
        return 1

    blocking, unpinned, usage = audit(files, ALLOWED_PUBLISHERS)

    print(f"scanned {len(files)} workflow file(s), {len(usage)} distinct action(s)\n")
    for action in sorted(usage):
        refs = ", ".join(sorted(usage[action]))
        pinned = all(SHA_PATTERN.match(r) for r in usage[action])
        marker = "sha" if pinned else "tag"
        print(f"  [{marker}] {action} @ {refs}")

    if blocking:
        print("\nBLOCKING — disallowed publisher:")
        for finding in blocking:
            print(f"  {finding}")

    if unpinned:
        severity = "BLOCKING" if args.require_sha else "ADVISORY"
        print(f"\n{severity} — {len(unpinned)} action(s) referenced by mutable tag:")
        for finding in unpinned[:20]:
            print(f"  {finding}")
        if len(unpinned) > 20:
            print(f"  ... and {len(unpinned) - 20} more")
        if not args.require_sha:
            print(
                "\n  Not blocking yet. Run scripts/pin_actions.sh (needs network) once\n"
                "  Dependabot is confirmed opening pull requests, then add --require-sha.\n"
                "  Stale pinned SHAs are worse than tags — see docs/security.md."
            )

    failed = bool(blocking) or (bool(unpinned) and args.require_sha)
    if not failed:
        print("\nno blocking findings.")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
