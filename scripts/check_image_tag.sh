#!/bin/sh
# Usage: check_image_tag.sh vX.Y.Z FILE...
# Fails unless every mcp-airlock image tag in the files is X.Y: a release must not ship docs that
# point at the previous image.
set -eu
tag=${1#v}
shift
want=${tag%.*}
for f in "$@"; do
  found=$(grep -o 'ghcr.io/shalimov04/mcp-airlock:[0-9][0-9.]*' "$f" | sed 's/.*://' | sort -u)
  if [ -z "$found" ]; then
    echo "$f: no ghcr.io/shalimov04/mcp-airlock:X.Y image tag found" >&2
    exit 1
  fi
  if [ "$found" != "$want" ]; then
    echo "$f: image tag is $(echo $found), the release tag needs $want" >&2
    exit 1
  fi
done
