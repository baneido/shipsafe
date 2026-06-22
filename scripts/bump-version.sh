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

# Validate semver: MAJOR.MINOR.PATCH with an optional -prerelease suffix.
if ! printf '%s' "$new" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$'; then
  echo "error: '$new' is not a valid semver version (expected e.g. 1.2.3)" >&2
  exit 2
fi

cd "$(git rev-parse --show-toplevel)"

current="$(grep -m1 '^version = ' Cargo.toml | sed -E 's/.*"([^"]+)".*/\1/')"
if [ "$current" = "$new" ]; then
  echo "Cargo.toml is already at $new — nothing to do."
  exit 0
fi

echo "Bumping $current -> $new"

# 1. Cargo.toml: only the first `version = ` line (the [package] one).
perl -i -pe 'if (!$seen && /^version = /) { s/^version = ".*"/version = "'"$new"'"/; $seen = 1 }' Cargo.toml

# 2. Cargo.lock: re-lock just the shipsafe entry. --offline keeps it from
#    touching unrelated dependency versions.
cargo update -p shipsafe --offline

echo
echo "Updated:"
echo "  Cargo.toml -> $(grep -m1 '^version = ' Cargo.toml | sed -E 's/.*"([^"]+)".*/\1/')"
echo "  Cargo.lock -> $(awk '/^name = "shipsafe"$/{getline; print; exit}' Cargo.lock | sed -E 's/.*"([^"]+)".*/\1/')"
echo
echo "Next steps:"
echo "  1. Update CHANGELOG.md for $new"
echo "  2. git switch -c release/$new && git commit -am \"chore: bump version to $new\""
echo "  3. Open a PR and merge it, then tag the merge commit:"
echo "       git tag v$new && git push origin v$new"
