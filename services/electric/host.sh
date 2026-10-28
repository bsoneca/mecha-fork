#!/bin/bash
# Electric on a host, under process-compose. Electric publishes an image and
# its source, no binary, so the release the image ships is built here from the
# source commit its tag names, as its own Dockerfile builds it, and patched as
# the image is (patch.exs): once per version and patch, into a cache every app
# on the host shares. Each start then runs it over a fresh storage directory,
# as a recreated container starts.
#
#   host.sh build <version> <commit> <erlang> <elixir>
#   host.sh run <version> <commit> <erlang> <elixir>
#
# `build` puts the release in the cache if it lacks it: the build mecha published for this platform
# (../prebuilt.sh), or else built here; `run` starts it, reading
# what the image reads (DATABASE_URL, ELECTRIC_SECRET, ...) and ELECTRIC_PORT,
# the port the host moved it to. Building needs git, curl, a C compiler and
# the network; Erlang and Elixir come from mise at the versions electric's
# repository pins.
set -euo pipefail

mode=$1
version=$2
commit=$3
erlang=$4
elixir=$5
here=$(cd "$(dirname "$0")" && pwd)
patch=$here/patch.exs
key=$version-$(shasum -a 256 "$patch" | cut -c1-12)
root=${XDG_CACHE_HOME:-$HOME/.cache}/mecha/electric
release=$root/$key

build() {
	local work=$1
	git -C "$work" init -q src
	git -C "$work/src" remote add origin https://github.com/electric-sql/electric
	git -C "$work/src" fetch -q --depth 1 --filter=blob:none origin "$commit"
	git -C "$work/src" sparse-checkout set packages/sync-service packages/electric-telemetry
	git -C "$work/src" checkout -q FETCH_HEAD
	[ "$(git -C "$work/src" rev-parse HEAD)" = "$commit" ]
	(
		cd "$work/src/packages/sync-service"
		export MIX_ENV=prod MIX_TARGET=application ELECTRIC_VERSION=$version
		export MIX_HOME=$work/mix HEX_HOME=$work/hex
		mise x "erlang@$erlang" "elixir@$elixir" -- sh -c '
			set -e
			mix local.hex --force
			mix local.rebar --force
			mix deps.get
			mix deps.compile
			mix compile
			mix sentry.package_source_code
			mix release --overwrite'
	)
	local rel=$work/src/packages/sync-service/_build/application_prod/rel/electric
	DATABASE_URL=postgresql://compile:compile@localhost/compile ELECTRIC_SECRET=compile-only \
		"$rel/bin/electric" eval "Code.eval_file(\"$patch\")"
	mv "$rel" "$work/release"
}

if [ "$mode" = build ] && [ ! -x "$release/bin/electric" ]; then
	mkdir -p "$root"
	# One build at a time: another launch waits for it, then finds it built.
	until mkdir "$release.lock" 2>/dev/null; do
		echo "electric: waiting for another build of $key" >&2
		sleep 5
	done
	trap 'rm -rf "$release.lock"' EXIT
	if [ ! -x "$release/bin/electric" ] && ! bash "$here/../prebuilt.sh" electric "$key" "$release"; then
		echo "electric: building $version from its source (once per version)" >&2
		work=$(mktemp -d "$root/build.XXXXXX")
		build "$work" >&2
		mv "$work/release" "$release"
		rm -rf "$work"
	fi
	rm -rf "$release.lock"
	trap - EXIT
fi
[ "$mode" = build ] && exit 0
[ -x "$release/bin/electric" ] || { echo "electric: $key is not built" >&2; exit 1; }

storage=$(mktemp -d)
pid=
stop() {
	if [ -n "$pid" ]; then
		kill -TERM "$pid" 2>/dev/null || true
		wait "$pid" 2>/dev/null || true
	fi
	rm -rf "$storage"
}
trap stop EXIT
trap 'exit 143' TERM
trap 'exit 130' INT

# No Erlang distribution: two apps' electric would claim one node name.
ELECTRIC_STORAGE_DIR=$storage RELEASE_DISTRIBUTION=none "$release/bin/electric" start &
pid=$!
wait "$pid"
