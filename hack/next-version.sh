#!/usr/bin/env bash
# Prints the next release version (without "v") for HEAD, from the Conventional
# Commits since the latest vX.Y.Z tag reachable from HEAD:
#   BREAKING CHANGE / type!:  -> major
#   feat:                     -> minor
#   anything else             -> patch
# With no previous tag, prints INITIAL_VERSION (default 0.1.0). Prints nothing
# if HEAD is already tagged with a version.
set -euo pipefail

initial=${INITIAL_VERSION:-0.1.0}

last=$(git describe --tags --abbrev=0 --match 'v[0-9]*.[0-9]*.[0-9]*' --exclude '*-*' HEAD 2>/dev/null || true)
if [[ -z "$last" ]]; then
  echo "$initial"
  exit 0
fi
if [[ "$(git rev-parse "$last^{commit}")" == "$(git rev-parse HEAD)" ]]; then
  exit 0
fi

IFS=. read -r major minor patch <<<"${last#v}"
patch=${patch%%-*}

log=$(git log --format='%s%n%b%n--end--' "$last..HEAD")
if grep -qE '^BREAKING[ -]CHANGE:|^[a-z]+(\([^)]*\))?!:' <<<"$log"; then
  echo "$((major + 1)).0.0"
elif grep -qE '^feat(\([^)]*\))?:' <<<"$log"; then
  echo "$major.$((minor + 1)).0"
else
  echo "$major.$minor.$((patch + 1))"
fi
