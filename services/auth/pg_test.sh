#!/usr/bin/env bash
# main_test.ts and studio_test.ts against a throwaway Postgres on this host's own binaries (PG_BIN names the
# directory holding initdb, pg_ctl and psql; no Docker). The database is what the cluster's initdb steps give
# the tests: the extensions, the roles and the tenancy floor (mecha.rls_exempt among it); app_user and the
# rest the tests make themselves. The cluster is stopped and removed however this ends.
set -euo pipefail
: "${PG_BIN:?PG_BIN names the directory holding initdb and pg_ctl}"
here=$(cd "$(dirname "$0")" && pwd)
db=$(cd "$here/../database" && pwd)
dir=$(mktemp -d /tmp/authpg.XXXXXX)
stop() { "$PG_BIN/pg_ctl" -D "$dir/data" -m immediate stop >/dev/null 2>&1 || true; rm -rf "$dir"; }
trap stop EXIT
port=$(deno eval 'const l = Deno.listen({ port: 0 }); console.log(l.addr.port); l.close()')
"$PG_BIN/initdb" -D "$dir/data" -U postgres --auth=trust >/dev/null
"$PG_BIN/pg_ctl" -D "$dir/data" -o "-p $port -c listen_addresses=127.0.0.1 -c unix_socket_directories=$dir" -l "$dir/pg.log" -w start >/dev/null
psql=("$PG_BIN/psql" -h 127.0.0.1 -p "$port" -U postgres -v ON_ERROR_STOP=1 -q)
"${psql[@]}" -c "create database mecha"
for f in migrations/000_extensions.sql migrations/001_roles.sql rls/rls.sql; do
  "${psql[@]}" -d mecha -f "$db/$f" >/dev/null
done
export DATABASE_URL="postgres://postgres@127.0.0.1:$port/mecha"
export AUTH_STATEMENT_TIMEOUT_MS=5000 PGRST_JWT_SECRET=test-secret-test-secret-test-secret-1234
export WEBAUTHN_RP_ID=localhost WEBAUTHN_ORIGIN='https://localhost:*'
cd "$here"
# Not exec: the trap stops the cluster after.
deno test --frozen --allow-net --allow-env --allow-read --allow-run main_test.ts studio_test.ts
