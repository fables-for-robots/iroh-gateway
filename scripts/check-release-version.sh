#!/usr/bin/env bash
# Checks a release tag against the crates it releases: exits 0 when the tag is "v" followed by
# the version of both iroh-gateway-edge and iroh-gateway-operator, else prints the tag and both
# versions and exits 1. The versions come from cargo metadata. Needs cargo and jq on PATH.
# Usage: scripts/check-release-version.sh <tag>
set -euo pipefail

if [ "$#" -ne 1 ]; then
  echo "usage: $0 <tag>" >&2
  exit 2
fi
tag="$1"

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
metadata="$(cargo metadata --no-deps --format-version 1 --manifest-path "$root/Cargo.toml")"

# Prints the version of workspace crate $1, or nothing when there is no such crate.
version_of() {
  jq -r --arg name "$1" '.packages[] | select(.name == $name) | .version' <<<"$metadata"
}

edge="$(version_of iroh-gateway-edge)"
operator="$(version_of iroh-gateway-operator)"
if [ -z "$edge" ] || [ -z "$operator" ]; then
  echo "cargo metadata lists no version for iroh-gateway-edge or iroh-gateway-operator" >&2
  exit 1
fi

if [ "$tag" = "v$edge" ] && [ "$tag" = "v$operator" ]; then
  echo "ok tag $tag is the version of iroh-gateway-edge and iroh-gateway-operator"
  exit 0
fi
echo "tag $tag does not match the crates:" >&2
echo "  iroh-gateway-edge $edge" >&2
echo "  iroh-gateway-operator $operator" >&2
exit 1
