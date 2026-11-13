// Where the auth tables live, as SQL both auth implementations run: the host
// service on Postgres (main.ts, migrate) and the edge cluster on PGlite
// (packages/mecha-edge/src/cluster.ts).
//
// The passkeys and links decide who signs in as whom, so they live in
// mecha_auth, a schema no app role may use. An app grants every table in
// public (mecha's 002_grants, pronto's emitted grants and default privileges)
// and the CRUD API serves public, BYPASSRLS roles included, so neither a
// revoke nor row security there outlasts the next such grant; nothing grants
// on mecha_auth, and sealAuthTables takes back whatever did at every start.
//
// A table an earlier release made in public moves with its rows, and a
// security_invoker view keeps the old name: an earlier release still running
// reads and writes through it, one starting again fails at its ALTER TABLE
// rather than making empty tables, and an app role reaching the view is
// refused at mecha_auth.
//
// The app's schema is `public` unless the cluster names its own (cluster.cue,
// meta.schema): app_user is there, and so are the tables an earlier release
// made on its search path and the views that keep their names. The audit's
// list is in mecha's schema.

export type AuthTable = "webauthn_credential" | "identity_link";
/** The app's schema and mecha's, each a plain identifier (main.ts checks the names it reads). */
export type AuthSchemas = { app: string; mecha: string };
const DEFAULT_SCHEMAS: AuthSchemas = { app: "public", mecha: "mecha" };

const columns = (app: string): Record<AuthTable, string> => ({
  webauthn_credential: `
    id text primary key,
    user_id uuid not null references ${app}.app_user(id) on delete cascade,
    public_key bytea not null,
    counter bigint not null default 0`,
  identity_link: `
    provider text not null,
    issuer text not null,
    sub text not null,
    user_id uuid not null unique references ${app}.app_user(id) on delete cascade,
    created_at timestamptz not null default now(),
    primary key (provider, issuer, sub)`,
});

const list = (tables: AuthTable[]) => `ARRAY[${tables.map((t) => `'${t}'`).join(", ")}]`;

/** Makes mecha_auth and the tables in it, moving any an earlier release left in the app's schema. */
export function prepareAuthTables(tables: AuthTable[], { app, mecha }: AuthSchemas = DEFAULT_SCHEMAS): string {
  return `
DO $auth$
DECLARE t text; kind "char";
BEGIN
  CREATE SCHEMA IF NOT EXISTS mecha_auth;
  FOREACH t IN ARRAY ${list(tables)} LOOP
    SELECT c.relkind INTO kind FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
      WHERE n.nspname = '${app}' AND c.relname = t;
    IF kind = 'r' THEN
      IF to_regclass('mecha_auth.' || t) IS NOT NULL THEN
        RAISE EXCEPTION '% is in both ${app} and mecha_auth: keep the one holding the live rows and drop the other', t;
      END IF;
      EXECUTE format('ALTER TABLE ${app}.%I SET SCHEMA mecha_auth', t);
      DELETE FROM ${mecha}.rls_exempt WHERE table_name = '${app}.' || t;
    ELSIF kind = 'v' THEN
      IF NOT EXISTS (SELECT 1 FROM pg_class WHERE oid = to_regclass('${app}.' || t) AND reloptions @> ARRAY['security_invoker=true']) THEN
        RAISE EXCEPTION '${app}.% is a view without security_invoker, not the auth service''s', t;
      END IF;
    ELSIF kind IS NOT NULL THEN
      RAISE EXCEPTION '${app}.% is a %, neither the table an earlier release made nor the auth service''s view', t, kind;
    END IF;
  END LOOP;
END $auth$;
${tables.map((t) => `CREATE TABLE IF NOT EXISTS mecha_auth.${t} (${columns(app)[t]}\n);`).join("\n")}
`;
}

/**
 * Takes back every privilege anyone but the owner holds on mecha_auth, on the
 * tables and on their columns, grant chains included, then names the old
 * views and tells the audit the tables are the service's own.
 */
export function sealAuthTables(tables: AuthTable[], { app, mecha }: AuthSchemas = DEFAULT_SCHEMAS): string {
  return `
DO $auth$
DECLARE t text; g record;
BEGIN
  FOR g IN
    SELECT 'SCHEMA mecha_auth' AS target, a.grantee
      FROM pg_namespace n, aclexplode(n.nspacl) a WHERE n.nspname = 'mecha_auth' AND a.grantee <> n.nspowner
    UNION SELECT format('mecha_auth.%I', c.relname), a.grantee
      FROM pg_class c, aclexplode(c.relacl) a
      WHERE c.relnamespace = 'mecha_auth'::regnamespace AND a.grantee <> c.relowner
    UNION SELECT format('(%I) ON mecha_auth.%I', at.attname, c.relname), a.grantee
      FROM pg_class c JOIN pg_attribute at ON at.attrelid = c.oid, aclexplode(at.attacl) a
      WHERE c.relnamespace = 'mecha_auth'::regnamespace AND at.attnum > 0 AND NOT at.attisdropped AND a.grantee <> c.relowner
  LOOP
    EXECUTE format('REVOKE ALL %s FROM %s CASCADE',
      CASE WHEN g.target LIKE '(%' THEN g.target ELSE 'ON ' || g.target END,
      CASE g.grantee WHEN 0 THEN 'PUBLIC' ELSE g.grantee::regrole::text END);
  END LOOP;
  FOREACH t IN ARRAY ${list(tables)} LOOP
    IF to_regclass('${app}.' || t) IS NULL THEN
      EXECUTE format('CREATE VIEW ${app}.%I WITH (security_invoker = true) AS SELECT * FROM mecha_auth.%I', t, t);
    END IF;
    INSERT INTO ${mecha}.rls_exempt VALUES ('mecha_auth.' || t, 'the auth service''s own table, in a schema no app role may use')
      ON CONFLICT DO NOTHING;
  END LOOP;
END $auth$;
`;
}

/**
 * API keys (PRONTO-312): an account's durable credential for a client that has no browser, exchanged
 * at POST /auth/key for a short user token. It lives in mecha_auth beside the passkeys and links, so
 * no app role reaches it and sealAuthTables takes back whatever was granted on it. Only the key's
 * SHA-256 is kept; the key itself is shown once, when it is made. Unlike the tables above, no earlier
 * release had it in public, so it gets no compatibility view there (an app may name its own
 * `api_key`). A key is read by its hash only through mecha_auth.api_key_owner, SECURITY DEFINER, the
 * one way a reader other than this service could be let at it: no service role, no table grant.
 */
export const API_KEYS_SQL = `
CREATE TABLE IF NOT EXISTS mecha_auth.api_key (
  id uuid primary key,
  owner uuid not null references public.app_user(id) on delete cascade,
  label text not null,
  scopes text[] not null,
  sha256 bytea not null unique,
  created_at timestamptz not null default now(),
  last_used timestamptz,
  revoked_at timestamptz
);
CREATE INDEX IF NOT EXISTS api_key_owner_live ON mecha_auth.api_key (owner) WHERE revoked_at IS NULL;
CREATE OR REPLACE FUNCTION mecha_auth.api_key_owner(hash bytea)
  RETURNS TABLE (id uuid, owner uuid, handle text, scopes text[])
  LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog AS $fn$
    SELECT k.id, k.owner, u.handle, k.scopes FROM mecha_auth.api_key k JOIN public.app_user u ON u.id = k.owner
      WHERE k.sha256 = hash AND k.revoked_at IS NULL
  $fn$;
REVOKE ALL ON FUNCTION mecha_auth.api_key_owner(bytea) FROM PUBLIC;
INSERT INTO mecha.rls_exempt VALUES ('mecha_auth.api_key', 'the auth service''s own table, in a schema no app role may use')
  ON CONFLICT DO NOTHING;
`;

/**
 * The native-app handoff codes spent (PRONTO-368): a row per code, written as the code is honoured
 * (POST /auth/oidc/session), so a code spent through one auth instance is refused by every other on the
 * same database. The primary key decides: the insert that lands honours the code, a second finds the row.
 * A row outlives its code by HANDOFF_SPENT_GRACE so a clock ahead of the database's cannot honour a code
 * whose row was pruned; rows past that are pruned as codes are spent. Only where provider sign-in is on.
 */
export const HANDOFF_SPENT_SQL = `
CREATE TABLE IF NOT EXISTS mecha_auth.handoff_spent (
  jti text primary key,
  expires_at timestamptz not null
);
CREATE INDEX IF NOT EXISTS handoff_spent_expires ON mecha_auth.handoff_spent (expires_at);
INSERT INTO mecha.rls_exempt VALUES ('mecha_auth.handoff_spent', 'the auth service''s own table, in a schema no app role may use')
  ON CONFLICT DO NOTHING;
`;
// How long a spent code's row outlives the code.
export const HANDOFF_SPENT_GRACE = "5 minutes";
