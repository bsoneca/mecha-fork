#!/bin/bash
# PLV8 for the database a host runs (host.sh), at the version the image installs
# (.bayt's database-image: postgresql-18-plv8 3.2.5). No build of it ships for a
# host's PostgreSQL, so it is built from its source once per version and
# PostgreSQL major, into the cache, with the pg_config on PATH; PostgreSQL reads
# it from there (host.sh), never from its own installation.
#
#   plv8.sh build   builds it unless the cache holds it
#   plv8.sh dir     prints the directory it is in: lib/ and share/extension/
#
# The first build compiles V8 and takes the better part of an hour.
set -euo pipefail

version=3.2.5
major=$(pg_config --version | sed -E 's/^PostgreSQL ([0-9]+).*/\1/')
dir=${XDG_CACHE_HOME:-$HOME/.cache}/mecha/plv8/$version-pg$major

case ${1:-} in
dir) printf '%s\n' "$dir" ;;
build)
	[ -f "$dir/share/extension/plv8.control" ] && exit 0
	src=$(mktemp -d "${TMPDIR:-/tmp}/plv8.XXXXXX")
	trap 'rm -rf "$src"' EXIT
	git clone -q --depth 1 --branch "v$version" --recurse-submodules --shallow-submodules https://github.com/plv8/plv8.git "$src/plv8"
	echo "plv8 $version: building V8 and PLV8 for PostgreSQL $major (once)" >&2
	# A portable postgres names the SDK and the LLVM of the machine that built
	# it: this one's SDK instead, and no JIT bitcode, which PLV8 runs without.
	sysroot=()
	[ "$(uname)" = Darwin ] && sysroot=(PG_SYSROOT="$(xcrun --show-sdk-path)")
	make -C "$src/plv8" -s NUMPROC="$(getconf _NPROCESSORS_ONLN)" with_llvm=no ${sysroot[@]+"${sysroot[@]}"} >&2
	mkdir -p "$dir.part/lib" "$dir.part/share/extension"
	cp "$src"/plv8/plv8-"$version".{so,dylib} "$dir.part/lib/" 2>/dev/null || true
	cp "$src"/plv8/plv8.control "$src"/plv8/plv8--*.sql "$dir.part/share/extension/"
	ls "$dir.part/lib/"plv8-"$version".* >/dev/null
	rm -rf "$dir" && mv "$dir.part" "$dir"
	;;
*)
	echo "usage: plv8.sh build|dir" >&2
	exit 2
	;;
esac
