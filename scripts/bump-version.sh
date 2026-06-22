#!/usr/bin/env bash
#
# Bump the crate version in every place it must stay in sync.
#
# Usage:
#   scripts/bump-version.sh <new-version>      # e.g. scripts/bump-version.sh 0.2.2
#
# The version lives in three places that have to agree or `cargo publish` (and
# the Docker/Homebrew artifacts) break: Cargo.toml, Cargo.lock and the git tag.
# Forgetting one of them is the usual cause of a failed release, so this script
# updates Cargo.toml and Cargo.lock together and prints the exact tag command to
# run afterwards. The Release workflow's verify-version job enforces the match.
set -euo pipefail

new="${1:-}"
if [ -z "$new" ]; then
  echo "usage: $0 <new-version>   (e.g. 0.2.2)" >&2
  exit 2
fi

# Accept a leading "v" (v0.2.2) but work with the bare version everywhere.
new="${new#v}"

# Validate semver: MAJOR.MINOR.PATCH (no leading zeros in the numeric parts)
# with optional -prerelease and +build metadata suffixes.
if ! printf '%s' "$new" | grep -Eq '^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-[0-9A-Za-z.-]+)?(\+[0-9A-Za-z.-]+)?$'; then
  echo "error: '$new' is not a valid semver version (expected e.g. 1.2.3)" >&2
  exit 2
fi

cd "$(git rev-parse --show-toplevel)"

current="$(grep -m1 '^version = ' Cargo.toml | sed -E 's/.*"([^"]+)".*/\1/')"
lock_current="$(awk '/^name = "shipsafe"$/{getline; print; exit}' Cargo.lock | sed -E 's/.*"([^"]+)".*/\1/')"

# Only a true no-op when BOTH files already match — otherwise a stale Cargo.lock
# (e.g. Cargo.toml bumped but the lock left behind) would never get repaired.
if [ "$current" = "$new" ] && [ "$lock_current" = "$new" ]; then
  echo "Cargo.toml and Cargo.lock are already at $new — nothing to do."
  exit 0
fi

# 1. Cargo.toml: only the first `version = ` line (the [package] one).
if [ "$current" != "$new" ]; then
  echo "Bumping Cargo.toml $current -> $new"
  perl -i -pe 'if (!$seen && /^version = /) { s/^version = ".*"/version = "'"$new"'"/; $seen = 1 }' Cargo.toml
fi

# 2. Cargo.lock: re-lock just the shipsafe entry. --offline keeps it from
#    touching unrelated dependency versions. Runs whenever the lock is out of
#    sync, so it also repairs a stale lock against an already-correct Cargo.toml.
if [ "$lock_current" != "$new" ]; then
  echo "Syncing Cargo.lock $lock_current -> $new"
fi
cargo update -p shipsafe --offline

echo
echo "Updated:"
echo "  Cargo.toml -> $(grep -m1 '^version = ' Cargo.toml | sed -E 's/.*"([^"]+)".*/\1/')"
echo "  Cargo.lock -> $(awk '/^name = "shipsafe"$/{getline; print; exit}' Cargo.lock | sed -E 's/.*"([^"]+)".*/\1/')"
echo
echo "Next steps:"
echo "  1. Update CHANGELOG.md for $new"
echo "  2. git switch -c release/$new"
echo "     git add Cargo.toml Cargo.lock CHANGELOG.md   # stage only the release files"
echo "     git commit -m \"chore: bump version to $new\""
echo "  3. Open a PR and merge it, then tag the merge commit:"
echo "       git tag v$new && git push origin v$new"
