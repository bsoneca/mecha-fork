#!/bin/bash
# What a host launch would otherwise compile (Electric's release, PLV8), fetched instead where mecha
# published a build of it for this platform: prebuilt.tsv names each by what it is, its cache key,
# the platform, where it is, and its sha256, which is checked before it is used. bsoneca/pronto-fork's
# prebuilt-mecha workflow builds them, from these same scripts.
#
#   prebuilt.sh <name> <key> <dest>
#
# Exits 0 once <dest> holds it; 1 when none is published for this platform or the fetch failed, for
# the caller to build it as before.
set -euo pipefail

name=$1
key=$2
dest=$3
here=$(cd "$(dirname "$0")" && pwd)

case "$(uname -s)-$(uname -m)" in
Linux-x86_64) platform=linux-x64 ;;
*) exit 1 ;;
esac
line=$(awk -F'\t' -v n="$name" -v k="$key" -v p="$platform" '$1 == n && $2 == k && $3 == p { print $4 " " $5 }' "$here/prebuilt.tsv")
[ -n "$line" ] || exit 1
read -r url sum <<<"$line"

mkdir -p "$(dirname "$dest")"
tmp=$(mktemp -d "$(dirname "$dest")/fetch.XXXXXX")
trap 'rm -rf "$tmp"' EXIT
echo "$name: fetching $key, built once for $platform" >&2
curl -fsSL --retry 3 -o "$tmp/build.tar.gz" "$url" || exit 1
if [ "$(sha256sum "$tmp/build.tar.gz" | cut -d' ' -f1)" != "$sum" ]; then
	echo "$name: $url is not the build mecha pins" >&2
	exit 1
fi
tar -xzf "$tmp/build.tar.gz" -C "$tmp"
[ -d "$tmp/$key" ] || exit 1
rm -rf "$dest"
mv "$tmp/$key" "$dest"
