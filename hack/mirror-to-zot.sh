#!/usr/bin/env bash
# Copies a released image (all platforms) and Helm chart from GHCR to the Zot
# registry that highland pulls from. Run by CI after a release is pushed to
# GHCR; expects regctl to be logged in to both registries already.
#
# Zot is reached through a Cloudflare tunnel, which rejects request bodies
# over 100 MB, so blobs are uploaded in 50 MB chunks.
#
#   SRC=ghcr.io/ulfhedinn-dev DST=registry.ulfhedinn.net VERSION=0.1.1 \
#   EXTRA_TAGS="0.1 latest" hack/mirror-to-zot.sh
set -euo pipefail

: "${SRC:?SRC must be set, e.g. ghcr.io/ulfhedinn-dev}"
: "${DST:?DST must be set, e.g. registry.ulfhedinn.net}"
: "${VERSION:?VERSION must be set, e.g. 0.1.1}"

chunk=$((50 * 1024 * 1024))
regctl registry set "${DST%%/*}" --blob-max "$chunk" --blob-chunk "$chunk"

# Every tag is copied from the immutable X.Y.Z tag, so they all point at the
# same digest even if GHCR's moving tags change in the meantime.
for tag in "$VERSION" ${EXTRA_TAGS:-}; do
  regctl image copy "$SRC/heimdall:$VERSION" "$DST/heimdall:$tag"
done
regctl image copy "$SRC/charts/heimdall:$VERSION" "$DST/charts/heimdall:$VERSION"

for ref in heimdall charts/heimdall; do
  want=$(regctl image digest "$SRC/$ref:$VERSION")
  got=$(regctl image digest "$DST/$ref:$VERSION")
  if [[ "$want" != "$got" ]]; then
    echo "digest mismatch for $ref:$VERSION: $SRC has $want, $DST has $got" >&2
    exit 1
  fi
  echo "$DST/$ref:$VERSION $got"
done
