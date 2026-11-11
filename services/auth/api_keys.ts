// API keys (PRONTO-312): an account's durable credential for a client that has no browser, exchanged
// at POST /auth/key for a short user token (main.ts; README.md, "API keys"). Unlike the passkeys and
// links, which this line keeps in public, the keys live in mecha_auth, a schema no app role may use:
// an app grants every table in public, and the CRUD API serves it, so neither a revoke nor row security
// there would outlast the next such grant (the host line keeps all its auth tables there for that
// reason). Only the key's SHA-256 is kept; the key itself is shown once, when it is made. A key is read
// by its hash only through mecha_auth.api_key_owner, SECURITY DEFINER: no service role, no table grant.
export const API_KEYS_SQL = `
CREATE SCHEMA IF NOT EXISTS mecha_auth;
REVOKE ALL ON SCHEMA mecha_auth FROM PUBLIC;
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
