#!/bin/bash
# The database on a host, under process-compose, as the image runs it in a
# container: a fresh data directory every start, initdb's steps applied in
# name order, then postgres in the foreground until it is told to stop, when
# the directory goes with it, as a recreated container's writable layer does.
#
#   host.sh <step> <file> [<step> <file> ...] -- <postgres arguments>
#
# A step is its initdb name (003_rls.sql); its file is a path from the working
# directory, the app's, or from this runtime's root when it opens with
# `{mecha}/`, and several files joined by `+` are one step, concatenated in
# order. A `.sh` step is sourced, as the image's entrypoint sources it, with
# its docker_process_sql. Reads what the image reads: POSTGRES_USER,
# POSTGRES_PASSWORD, POSTGRES_DB, POSTGRES_INITDB_ARGS, and PGPORT, the port
# the host moved it to.
set -euo pipefail

mecha=$(cd "$(dirname "$0")/../.." && pwd)
: "${POSTGRES_USER:=postgres}" "${POSTGRES_PASSWORD:=postgres}" "${POSTGRES_INITDB_ARGS:=}"
: "${POSTGRES_DB:?names the database the steps build}"
: "${PGPORT:?the port the database listens on}"

steps=()
files=()
while [ $# -gt 0 ] && [ "$1" != -- ]; do
	steps+=("$1")
	files+=("$2")
	shift 2
done
[ "${1:-}" = -- ] && shift

# A Unix socket's path is capped near 104 bytes on macOS, under a TMPDIR that
# alone takes half of it, so the directory hangs off /tmp.
dir=$(mktemp -d /tmp/mecha-pg.XXXXXX)
data=$dir/data
pid=
stop() {
	if [ -n "$pid" ]; then
		kill -INT "$pid" 2>/dev/null || true
		wait "$pid" 2>/dev/null || true
	elif [ -f "$data/postmaster.pid" ]; then
		# Stopped while the steps ran, against the socket-only server.
		pg_ctl -D "$data" -s -m immediate stop 2>/dev/null || true
	fi
	rm -rf "$dir"
}
trap stop EXIT
trap 'exit 143' TERM
trap 'exit 130' INT

# shellcheck disable=SC2086 # the image splits POSTGRES_INITDB_ARGS the same way
initdb -D "$data" -U "$POSTGRES_USER" $POSTGRES_INITDB_ARGS >/dev/null
# PLV8 from where plv8.sh built it, when it has: postgres reads extensions from
# its own installation and from there. In the configuration rather than on the
# command line, which pg_ctl hands a shell that would expand $system.
plv8=$(bash "$mecha/services/database/plv8.sh" dir)
if [ -f "$plv8/share/extension/plv8.control" ]; then
	printf "extension_control_path = '\$system:%s/share'\ndynamic_library_path = '\$libdir:%s/lib'\n" "$plv8" "$plv8" >>"$data/postgresql.conf"
fi

# The image's entrypoint runs the steps against a server only its socket
# reaches, so nothing connects to a half-built schema.
export PGHOST=$dir PGUSER=$POSTGRES_USER
pg_ctl -D "$data" -w -s -o "$* -c listen_addresses='' -k $dir" start
if [ "$POSTGRES_DB" != postgres ]; then
	psql -X -q -v ON_ERROR_STOP=1 -d postgres -v db="$POSTGRES_DB" <<<'CREATE DATABASE :"db";'
fi
docker_process_sql() {
	psql -X -q -v ON_ERROR_STOP=1 --no-password --no-psqlrc -d "$POSTGRES_DB" "$@"
}
export -f docker_process_sql
resolve() {
	case $1 in
	'{mecha}/'*) printf '%s/%s' "$mecha" "${1#\{mecha\}/}" ;;
	*) printf '%s' "$1" ;;
	esac
}
# Byte order, as the image's glob sorts them.
for i in $(for i in "${!steps[@]}"; do printf '%s %s\n' "${steps[$i]}" "$i"; done | LC_ALL=C sort | cut -d' ' -f2); do
	step=${steps[$i]}
	body=$dir/$step
	IFS=+ read -ra parts <<<"${files[$i]}"
	: >"$body"
	for p in "${parts[@]}"; do
		cat "$(resolve "$p")" >>"$body"
	done
	case $step in
	*.sh) (. "$body") ;;
	*.sql) docker_process_sql -f "$body" >/dev/null ;;
	*) echo "database: $step is neither .sql nor .sh" >&2; exit 1 ;;
	esac
done
pg_ctl -D "$data" -w -s -m fast stop

postgres -D "$data" -k "$dir" -c listen_addresses=localhost "$@" &
pid=$!
wait "$pid"
