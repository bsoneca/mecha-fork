// Sign-in by a Studio play token (PRONTO-547; README.md, "Studio play tokens"): Studio signs a player in
// once and hands each game it opens a one-minute ES256 token for that game alone; POST /auth/studio
// (main.ts) trades it for the game's own session. This file is what needs no database: the keys Studio
// publishes, the token's claims and the per-IP limit. A key comes from STUDIO_JWKS_URL alone, never from
// anything the token says, so a token cannot point the service anywhere.
import { verifyJws } from "./oidc.ts";

/** Where a replayed token is caught: one row a token, in a schema no app role may use (as the API keys'),
 * and past its `exp` it is no use to anyone, since `exp` has no leeway. */
export const STUDIO_SQL = `
CREATE SCHEMA IF NOT EXISTS mecha_auth;
REVOKE ALL ON SCHEMA mecha_auth FROM PUBLIC;
CREATE TABLE IF NOT EXISTS mecha_auth.studio_jti (
  jti text primary key,
  exp timestamptz not null
);
CREATE INDEX IF NOT EXISTS studio_jti_exp ON mecha_auth.studio_jti (exp);
INSERT INTO mecha.rls_exempt VALUES ('mecha_auth.studio_jti', 'the auth service''s own table, in a schema no app role may use')
  ON CONFLICT DO NOTHING;
`;

export type StudioConfig = { jwks: string; iss: string; origin: string };

/** The deployment's Studio settings, or null while any of the three is unset: the route is then off. */
export function studioFrom(env: (name: string) => string | undefined): StudioConfig | null {
  const jwks = env("STUDIO_JWKS_URL") ?? "";
  const iss = env("STUDIO_ISS") ?? "";
  const origin = env("PUBLIC_ORIGIN") ?? "";
  if (jwks === "" || iss === "" || origin === "") return null;
  const url = new URL(jwks);
  if (url.protocol !== "https:" && url.hostname !== "localhost") throw new Error(`STUDIO_JWKS_URL ${jwks} is not https`);
  return { jwks, iss, origin };
}

export const KEYS_FRESH_MS = 10 * 60_000;
export const KEYS_STALE_MS = 60 * 60_000;
export const REFETCH_MS = 60_000;
export const JWKS_MAX_BYTES = 64 * 1024;
export const JWKS_TIMEOUT_MS = 3000;

/** The keys at `url`: ES256 keys only (EC, P-256, for signing), at most JWKS_MAX_BYTES of them, from a
 * server that does not redirect, in JWKS_TIMEOUT_MS. Throws for anything else. */
async function fetchKeys(url: string, fetcher: typeof fetch): Promise<JsonWebKey[]> {
  const res = await fetcher(url, { redirect: "manual", signal: AbortSignal.timeout(JWKS_TIMEOUT_MS), headers: { accept: "application/json" } });
  try {
    if (res.type === "opaqueredirect" || res.status < 200 || res.status > 299) throw new Error(`${url}: ${res.status}`);
    const reader = res.body?.getReader();
    if (!reader) throw new Error(`${url}: no body`);
    const chunks: Uint8Array[] = [];
    let size = 0;
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      size += value.length;
      if (size > JWKS_MAX_BYTES) {
        await reader.cancel();
        throw new Error(`${url}: more than ${JWKS_MAX_BYTES} bytes`);
      }
      chunks.push(value);
    }
    const body = new Uint8Array(size);
    let at = 0;
    for (const c of chunks) {
      body.set(c, at);
      at += c.length;
    }
    const keys: unknown = JSON.parse(new TextDecoder().decode(body)).keys;
    if (!Array.isArray(keys)) throw new Error(`${url}: no keys`);
    const usable = keys.filter((k) =>
      typeof k === "object" && k !== null && k.kty === "EC" && k.crv === "P-256" && k.use === "sig" &&
      typeof k.kid === "string" && typeof k.x === "string" && typeof k.y === "string"
    ).map((k) => ({ kty: "EC", crv: "P-256", use: "sig", kid: k.kid, x: k.x, y: k.y }));
    if (usable.length === 0) throw new Error(`${url}: no usable key`);
    return usable;
  } finally {
    await res.body?.cancel().catch(() => {});
  }
}

/** Studio's keys, held: fresh for KEYS_FRESH_MS, fetched again for a key id not held (at most once a
 * REFETCH_MS) and once they are old, and kept up to KEYS_STALE_MS when that fails. Held nothing and
 * unable to fetch, it throws, so a token is refused. */
export function studioKeys(
  url: string,
  fetcher: () => typeof fetch = () => fetch,
  now: () => number = Date.now,
): (kid: string) => Promise<JsonWebKey | undefined> {
  let held: JsonWebKey[] = [];
  let fetchedAt = -Infinity;
  let triedAt = -Infinity;
  const find = (kid: string) => held.find((k) => (k as { kid?: string }).kid === kid);
  async function refresh(): Promise<boolean> {
    triedAt = now();
    try {
      held = await fetchKeys(url, fetcher());
      fetchedAt = now();
      return true;
    } catch (e) {
      console.error(`studio keys: ${(e as Error).message}`);
      return false;
    }
  }
  return async (kid) => {
    const age = now() - fetchedAt;
    if (age < KEYS_FRESH_MS) {
      const k = find(kid);
      if (k !== undefined || now() - triedAt < REFETCH_MS) return k;
      await refresh();
      return find(kid);
    }
    if (held.length === 0 || now() - triedAt >= REFETCH_MS) await refresh();
    if (now() - fetchedAt >= KEYS_STALE_MS || held.length === 0) throw new Error("no Studio keys");
    return find(kid);
  };
}

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
export const MAX_TOKEN_CHARS = 2048;
export const MAX_FUTURE_IAT_S = 30;
export const MAX_LIFETIME_S = 120;
const MAX_HANDLE_CHARS = 120;

export type Play = { jti: string; exp: number; sub: string; handle: string };
export type Refused = "malformed" | "alg" | "kid" | "signature" | "jwks" | "iss" | "aud" | "expired" | "iat" | "claims" | "lifetime" | "sub" | "handle" | "jti";

/** A play token's player, or the reason it is refused: signed ES256 under one of Studio's keys, issued by
 * `cfg.iss` for this game (`cfg.origin`), live (no leeway on `exp`), made no more than MAX_LIFETIME_S before it
 * ends and not from the future, for a uuid. The token is never echoed. */
export async function verifyPlayToken(
  token: string,
  key: (kid: string) => Promise<JsonWebKey | undefined>,
  cfg: StudioConfig,
  nowS: number = Math.floor(Date.now() / 1000),
): Promise<{ play: Play } | { refused: Refused }> {
  if (token.length > MAX_TOKEN_CHARS) return { refused: "malformed" };
  let jws;
  try {
    jws = await verifyJws(token, key, ["ES256"]);
  } catch {
    return { refused: "jwks" };
  }
  if ("refused" in jws) return jws;
  const c = jws.claims;
  if (c.iss !== cfg.iss) return { refused: "iss" };
  if (c.aud !== cfg.origin) return { refused: "aud" };
  if (typeof c.exp !== "number" || typeof c.iat !== "number" || !Number.isFinite(c.exp) || !Number.isFinite(c.iat)) return { refused: "claims" };
  if (c.exp <= nowS) return { refused: "expired" };
  if (c.iat > nowS + MAX_FUTURE_IAT_S) return { refused: "iat" };
  if (c.exp - c.iat > MAX_LIFETIME_S) return { refused: "lifetime" };
  if (typeof c.sub !== "string" || !UUID.test(c.sub)) return { refused: "sub" };
  if (typeof c.handle !== "string" || c.handle.trim() === "" || c.handle.length > MAX_HANDLE_CHARS) return { refused: "handle" };
  if (typeof c.jti !== "string" || c.jti === "" || c.jti.length > 128) return { refused: "jti" };
  return { play: { jti: c.jti, exp: c.exp, sub: c.sub, handle: c.handle } };
}

/** At most `max` calls per key in `windowMs`, the window opening at a key's first call. */
export function rateLimit(max: number, windowMs: number, now: () => number = Date.now): (key: string) => boolean {
  const seen = new Map<string, { since: number; calls: number }>();
  return (key) => {
    const t = now();
    if (seen.size > 10_000) for (const [k, v] of seen) if (t - v.since >= windowMs) seen.delete(k);
    const w = seen.get(key);
    if (w === undefined || t - w.since >= windowMs) {
      seen.set(key, { since: t, calls: 1 });
      return true;
    }
    return ++w.calls <= max;
  };
}
