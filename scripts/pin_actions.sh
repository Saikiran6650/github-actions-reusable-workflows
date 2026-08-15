#!/usr/bin/env bash
#
# Pin every third-party action reference to a full commit SHA.
#
# REQUIRES NETWORK. This cannot be done offline: resolving a tag to a SHA means asking
# GitHub what that tag currently points at.
#
# RUN THIS ONLY AFTER Dependabot is confirmed opening pull requests against this repository.
#
# The order matters. A pinned SHA does not move, so a pinned repository with no Dependabot
# silently misses every security release — which is worse than tracking a tag, because it
# looks more secure while being less so. `.github/dependabot.yml` is already committed;
# confirm it has opened at least one pull request before running this.
#
# Afterwards, add --require-sha to the audit step in .github/workflows/ci.yml so the
# property is enforced rather than merely achieved once.

set -euo pipefail

if ! command -v ratchet >/dev/null 2>&1; then
  cat >&2 <<'MSG'
ratchet is not installed.

  go install github.com/sethvargo/ratchet@latest

ratchet is used rather than a hand-rolled script because it understands every form a `uses:`
reference can take — including Docker and container actions — and it writes the original tag
as a trailing comment, so a human reading the workflow can still see which version a SHA
corresponds to.
MSG
  exit 1
fi

repo_root="$(git rev-parse --show-toplevel)"
cd "$repo_root"

echo "pinning actions in .github/workflows/ ..."
for file in .github/workflows/*.yml actions/*/action.yml; do
  [ -e "$file" ] || continue
  echo "  $file"
  ratchet pin "$file"
done

echo
echo "done. Review the diff carefully:"
echo "  git diff --stat"
echo
echo "Then verify, and switch the audit to blocking:"
echo "  python3 scripts/check_action_pins.py .github/workflows --require-sha"
echo
echo "Finally, add --require-sha to the audit step in .github/workflows/ci.yml."
