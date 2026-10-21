#!/bin/bash
# The migrate runner on a host, under process-compose: the migrations the
# image carries as files arrive as arguments, in base64, are written where
# migrate.sh reads them, and it runs as it does in the image.
#
#   host.sh <baseline> [<name> <migration JSON in base64> ...]
set -euo pipefail

baseline=$1
shift
dir=$(mktemp -d)
trap 'rm -rf "$dir"' EXIT
while [ $# -gt 0 ]; do
	printf '%s' "$2" | base64 -d >"$dir/$1.json"
	shift 2
done
bash "$(dirname "$0")/migrate.sh" "$dir" "$baseline"
