// Requires DATABASE_URL pointing at a throwaway postgres, and the rest of the
// environment main.ts reads as the dev cluster sets it (cluster.cue). app_user is owned elsewhere (see main.ts); tests
// create a minimal stand-in before running the service's own migration
// against it.
import { ANDROID_FINGERPRINT } from "./main_test_env.ts";
import { fileURLToPath } from "node:url";
import {
  assert,
  assertEquals,
  assertRejects,
  assertStringIncludes,
  assertThrows,
} from "jsr:@std/assert@1.0.13";
import { isoBase64URL, isoCBOR, isoUint8Array, toHash } from "@simplewebauthn/server/helpers";
import { androidOrigin } from "./origins.ts";
import { admittedOrigin, apiKeysGate, ceremonyOrigin, handler, handoffSpender, issueUserToken, KEY_TOKEN_TTL_S, keyExchangedHook, links, MAX_LIVE_KEYS, migrate, signJwt, sql, upgradeTtlOf, verifyJwt } from "./main.ts";
import { handoffSpentSql } from "./schema.ts";
import postgres from "postgres";
import { PUBLIC_WHERE, signJwt as signWith } from "./jwt.ts";
import { PUBLIC_WHERE as CLIENT_PUBLIC_WHERE } from "../../packages/client/src/public-where.ts";

await sql`CREATE TABLE IF NOT EXISTS app_user (
  id uuid primary key,
  handle text not null unique,
  created_at timestamptz not null default now()
)`;
// The gatekeeper asks whether a table is floored, so the table it is asked
// about has to exist and carry the column that answers.
await sql`CREATE TABLE IF NOT EXISTS article (
  id uuid primary key default gen_random_uuid(),
  scope_id text generated always as ('public:') stored not null
)`;
await sql`CREATE TABLE IF NOT EXISTS scoped_article (
  id uuid primary key default gen_random_uuid(),
  scope_id text not null default 'public:'
)`;
await sql`CREATE TABLE IF NOT EXISTS mutable_article (
  id uuid primary key default gen_random_uuid(),
  scope_id text not null
)`;
await sql`CREATE TABLE IF NOT EXISTS owned_article (
  id uuid primary key default gen_random_uuid(),
  owner_id uuid not null,
  scope_id text generated always as ('user:' || owner_id) stored not null
)`;
await sql`CREATE TABLE IF NOT EXISTS private_article (
  id uuid primary key default gen_random_uuid(),
  scope_id text generated always as ('user:private') stored not null
)`;
await sql`CREATE TABLE IF NOT EXISTS virtual_article (
  id uuid primary key default gen_random_uuid(),
  scope_id text generated always as ('public:') virtual not null
)`;
await sql`CREATE TABLE IF NOT EXISTS nullable_article (
  id uuid primary key default gen_random_uuid(),
  scope_id text generated always as ('public:') stored
)`;
await sql`CREATE TABLE IF NOT EXISTS partitioned_article (
  id int,
  owner_id uuid not null,
  scope_id text generated always as ('public:') stored not null
) PARTITION BY RANGE (id)`;
await sql`CREATE TABLE IF NOT EXISTS partitioned_article_child (
  id int,
  owner_id uuid not null,
  scope_id text generated always as ('user:' || owner_id) stored not null
)`;
await sql`DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_inherits
    WHERE inhparent = 'partitioned_article'::regclass AND inhrelid = 'partitioned_article_child'::regclass) THEN
    ALTER TABLE partitioned_article ATTACH PARTITION partitioned_article_child FOR VALUES FROM (0) TO (10);
  END IF;
END $$`;
await sql`CREATE TABLE IF NOT EXISTS inherited_article (
  id int,
  owner_id uuid not null,
  scope_id text generated always as ('public:') stored not null
)`;
await sql`CREATE TABLE IF NOT EXISTS inherited_article_child (
  scope_id text generated always as ('user:' || owner_id) stored not null
) INHERITS (inherited_article)`;
// A per-row shape is answered as the subject, so the role the gate switches
// to has to exist, and the fixture needs a policy for it to read through:
// gk_doc is readable by its owner, gk_line is content of a doc.
await sql`DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'app_user') THEN CREATE ROLE app_user NOLOGIN; END IF;
END $$`;
await sql`GRANT USAGE ON SCHEMA public, mecha TO app_user`;
await sql`CREATE TABLE IF NOT EXISTS gk_doc (
  id uuid primary key default gen_random_uuid(),
  owner_id uuid not null
)`;
await sql`CREATE TABLE IF NOT EXISTS gk_line (
  id uuid primary key default gen_random_uuid(),
  doc_id uuid not null references gk_doc(id),
  scope_id text generated always as ('public:') stored not null
)`;
await sql`ALTER TABLE gk_doc ENABLE ROW LEVEL SECURITY`;
await sql`DROP POLICY IF EXISTS gk_doc_own ON gk_doc`;
await sql`CREATE POLICY gk_doc_own ON gk_doc FOR SELECT TO app_user USING (owner_id = auth_uid())`;
await sql`GRANT SELECT ON gk_doc, gk_line TO app_user`;
await sql`INSERT INTO mecha.shape_key VALUES
  ('public.gk_doc', 'id', 'public.gk_doc', 'id'),
  ('public.gk_line', 'doc_id', 'public.gk_doc', 'id')
  ON CONFLICT DO NOTHING`;
// The key table is made only where keys are on (AUTH_API_KEYS); the cases below turn them on and off.
await withKeys(true, migrate);
await sql`delete from mecha_auth.webauthn_credential`;
await sql`delete from mecha_auth.identity_link`;
await sql`delete from mecha_auth.api_key`;
await sql`delete from app_user`;

function post(path: string, body: unknown, token?: string): Request {
  return new Request(`http://auth:9999${path}`, {
    method: "POST",
    headers: { "content-type": "application/json", ...(token ? { authorization: `Bearer ${token}` } : {}) },
    body: JSON.stringify(body),
  });
}

const opts = { sanitizeResources: false, sanitizeOps: false };

Deno.test({
  name: "register/start is usernameless: generated identity, resident key",
  ...opts,
  fn: async () => {
    const res = await handler(post("/auth/register/start", {}));
    assertEquals(res.status, 200);
    const body = await res.json();
    assertEquals(typeof body.challenge, "string");
    assertEquals(body.rp.id, "localhost");
    assert(/^[a-z]+-[a-z]+-\d\d$/.test(body.user.name), `generated handle, got ${body.user.name}`);
    assertEquals(body.authenticatorSelection.residentKey, "required");
    assert(Array.isArray(body.pubKeyCredParams) && body.pubKeyCredParams.length > 0);
    const st = await verifyJwt(body.state);
    assert(st !== null);
    assertEquals(st.purpose, "register");
    assertEquals(st.handle, body.user.name);
    assertEquals(st.challenge, body.challenge);
    assertEquals(typeof st.userId, "string");
  },
});

Deno.test({
  name: "login/start is discoverable: no identifier, empty allowCredentials",
  ...opts,
  fn: async () => {
    const res = await handler(post("/auth/login/start", {}));
    assertEquals(res.status, 200);
    const body = await res.json();
    assertEquals(typeof body.challenge, "string");
    assertEquals(body.rpId, "localhost");
    assertEquals(body.allowCredentials.length, 0);
    const st = await verifyJwt(body.state);
    assert(st !== null);
    assertEquals(st.purpose, "login");
    assertEquals(st.challenge, body.challenge);
  },
});

Deno.test({
  name: "register/start from a guest's session keeps the guest's identity",
  ...opts,
  async fn() {
    const guest = await (await handler(post("/auth/guest", {}))).json();
    const res = await handler(post("/auth/register/start", {}, guest.token));
    assertEquals(res.status, 200);
    const st = await verifyJwt((await res.json()).state);
    assertEquals([st?.userId, st?.handle, st?.promote], [guest.user.id, guest.user.handle, true]);
  },
});

Deno.test({
  name: "a guest's token says it is a guest, and an account's does not",
  ...opts,
  async fn() {
    const guest = await (await handler(post("/auth/guest", {}))).json();
    assertEquals([(await verifyJwt(guest.token))?.guest, guest.user.guest], [true, true]);
    // Stated either way: a policy that admits only `guest = false` refuses a
    // token minted before the claim existed rather than taking it for an account.
    assertEquals((await verifyJwt(await issueUserToken(guest.user.id, guest.user.handle)))?.guest, false);
  },
});

Deno.test({
  name: "register/start refuses to add a passkey to an account's session",
  ...opts,
  async fn() {
    const guest = await (await handler(post("/auth/guest", {}))).json();
    const account = await issueUserToken(guest.user.id, guest.user.handle);
    const res = await handler(post("/auth/register/start", {}, account));
    assertEquals(res.status, 409);
    await res.body?.cancel();
  },
});

Deno.test({
  name: "register/start refuses a token that is not a session",
  ...opts,
  async fn() {
    const res = await handler(post("/auth/register/start", {}, "garbage"));
    assertEquals(res.status, 401);
    await res.body?.cancel();
  },
});

Deno.test({
  name: "register/verify rejects garbage state and garbage response",
  ...opts,
  fn: async () => {
    let res = await handler(
      post("/auth/register/verify", { state: "garbage", response: {} }),
    );
    assertEquals(res.status, 401);
    assertEquals((await res.json()).error, "invalid state");

    const start = await handler(post("/auth/register/start", {}));
    const { state } = await start.json();
    res = await handler(
      post("/auth/register/verify", { state, response: { junk: true } }),
    );
    assertEquals(res.status, 401);
    assertEquals((await res.json()).error, "registration verification failed");
  },
});

Deno.test({
  name: "login/verify rejects garbage cleanly",
  ...opts,
  fn: async () => {
    const start = await handler(post("/auth/login/start", { handle: "bob" }));
    const { state } = await start.json();
    const res = await handler(
      post("/auth/login/verify", { state, response: { id: "dGVzdC1jcmVk" } }),
    );
    assertEquals(res.status, 401);
    assertEquals((await res.json()).error, "authentication verification failed");
  },
});

Deno.test({
  name: "whoami 401s without a token",
  ...opts,
  fn: async () => {
    const res = await handler(new Request("http://auth:9999/auth/whoami"));
    assertEquals(res.status, 401);
    assertEquals((await res.json()).error, "invalid token");
  },
});

Deno.test({
  name: "issued user JWT carries the frozen claims and satisfies whoami",
  ...opts,
  fn: async () => {
    const id = crypto.randomUUID();
    const token = await issueUserToken(id, "alice");
    const claims = await verifyJwt(token);
    assert(claims !== null);
    assertEquals(claims.role, "app_user");
    assertEquals(claims.sub, id);
    assertEquals(claims.handle, "alice");
    // USER_TOKEN_TTL_S from the environment (a day, main_test_env.ts) sets the mint's exp.
    const exp = claims.exp as number;
    const oneDay = Math.floor(Date.now() / 1000) + 24 * 3600;
    assert(Math.abs(exp - oneDay) < 60, `exp ${exp} not ~1d out`);
    const res = await handler(
      new Request("http://auth:9999/auth/whoami", {
        headers: { authorization: `Bearer ${token}` },
      }),
    );
    assertEquals(res.status, 200);
    assertEquals(await res.json(), { id, handle: "alice" });
  },
});

// --- A guest's refresh (POST /auth/guest/refresh): a kept guest lives on past its token ---

const nowS = () => Math.floor(Date.now() / 1000);
async function refresh(token?: string): Promise<{ status: number; body: Record<string, unknown> }> {
  const res = await handler(post("/auth/guest/refresh", {}, token));
  return { status: res.status, body: await res.json() };
}
// A guest's token as the service would have minted it `ago` seconds past its expiry.
const expiredGuest = (id: string, handle: string, ago: number) =>
  signJwt({ role: "app_user", sub: id, handle, guest: true, exp: nowS() - ago });

Deno.test({
  name: "a live guest is refreshed: same id and handle, a new exp",
  ...opts,
  fn: async () => {
    const guest = await (await handler(post("/auth/guest", {}))).json();
    const old = await verifyJwt(guest.token);
    await new Promise((r) => setTimeout(r, 1100));
    const { status, body } = await refresh(guest.token);
    assertEquals(status, 200);
    assertEquals(body.user, { id: guest.user.id, handle: guest.user.handle, guest: true });
    const claims = await verifyJwt(body.token as string);
    assertEquals([claims?.sub, claims?.handle, claims?.guest, claims?.role], [guest.user.id, guest.user.handle, true, "app_user"]);
    assert((claims?.exp as number) > (old?.exp as number), "the refreshed token lives longer");
  },
});

Deno.test({
  name: "a guest whose token expired within the grace is refreshed; past it, it is refused",
  ...opts,
  fn: async () => {
    const guest = (await (await handler(post("/auth/guest", {}))).json()).user;
    // A week and a day after it expired: the grace (90 days by default) still admits it.
    const late = await expiredGuest(guest.id, guest.handle, 8 * 24 * 3600);
    assertEquals(await verifyJwt(late), null, "an expired token is no session");
    const ok = await refresh(late);
    assertEquals([ok.status, (ok.body.user as { id: string }).id], [200, guest.id]);
    assert(await verifyJwt(ok.body.token as string) !== null, "the new token is a session");
    const gone = await refresh(await expiredGuest(guest.id, guest.handle, 91 * 24 * 3600));
    assertEquals(gone.status, 401);
  },
});

Deno.test({
  name: "refresh refuses a forged token, an account's, no token, and a promoted guest; an unknown user is 404",
  ...opts,
  fn: async () => {
    const guest = (await (await handler(post("/auth/guest", {}))).json()).user;
    const real = await issueUserToken(guest.id, guest.handle, true);
    const [h, p] = real.split(".");
    const forged = `${h}.${p}.${"A".repeat(43)}`;
    assertEquals((await refresh(forged)).status, 401);
    assertEquals((await refresh("garbage")).status, 401);
    assertEquals((await refresh()).status, 401);
    // An account's token (guest: false) is no guest's: its way back is its own sign-in.
    assertEquals((await refresh(await issueUserToken(guest.id, guest.handle))).status, 401);
    // A shape token or any other role is refused.
    assertEquals((await refresh(await signJwt({ role: "service", sub: guest.id, handle: guest.handle, guest: true, exp: nowS() + 60 }))).status, 401);
    // A guest that became an account (a passkey, or a provider's link) is refused, even with its old guest token.
    const promoted = (await (await handler(post("/auth/guest", {}))).json());
    await sql`insert into mecha_auth.webauthn_credential (id, user_id, public_key, counter) values (${"cred-r-" + promoted.user.id}, ${promoted.user.id}, ${new Uint8Array([1])}, 0)`;
    assertEquals((await refresh(promoted.token)).status, 409);
    const linked = (await (await handler(post("/auth/guest", {}))).json());
    await links.userFor({ provider: "google", issuer: "https://accounts.google.com", sub: "g-refresh-linked", name: null, picture: null, email: null }, linked.user.id);
    assertEquals((await refresh(linked.token)).status, 409);
    // A guest token for no such user.
    assertEquals((await refresh(await issueUserToken(crypto.randomUUID(), "nobody-here-00", true))).status, 404);
  },
});

Deno.test({
  name: "door always answers 2xx, naming the account only for a verified session",
  ...opts,
  fn: async () => {
    const door = async (headers: Record<string, string> = {}) => {
      const res = await handler(new Request("http://auth:9999/auth/door", { headers }));
      assertEquals(res.status, 204);
      await res.body?.cancel();
      return res.headers.get("x-pronto-account");
    };
    const id = crypto.randomUUID();
    assertEquals(await door({ authorization: `Bearer ${await issueUserToken(id, "alice")}` }), id);
    assertEquals(await door(), null, "no session");
    assertEquals(await door({ authorization: "Bearer not-a-token" }), null, "an invalid token");
    const shape = await signJwt({ typ: "shape", table: "article", where: "true", sub: id, exp: Math.floor(Date.now() / 1000) + 60 });
    assertEquals(await door({ authorization: `Bearer ${shape}` }), null, "a shape token is no session");
    assertEquals(await door({ "x-pronto-account": id }), null, "a header the page sent names no one");
  },
});

Deno.test({
  name: "guest mints a fresh app_user per call with a valid token",
  ...opts,
  fn: async () => {
    const res = await handler(post("/auth/guest", {}));
    assertEquals(res.status, 200);
    const body = await res.json();
    assert(/^[a-z]+-[a-z]+-\d\d$/.test(body.user.handle), `generated handle, got ${body.user.handle}`);
    const claims = await verifyJwt(body.token);
    assert(claims !== null);
    assertEquals(claims.role, "app_user");
    assertEquals(claims.sub, body.user.id);
    assertEquals(claims.handle, body.user.handle);
    const rows = await sql`select handle from app_user where id = ${body.user.id}`;
    assertEquals(rows.length, 1);
    assertEquals(rows[0].handle, body.user.handle);
    // Each call is a fresh guest — the endpoint never reuses an identity.
    const again = await (await handler(post("/auth/guest", {}))).json();
    assert(again.user.id !== body.user.id, "second guest call reused the identity");
  },
});

// --- upgrade ---
//
// A service asks for a session's token again, scoped to one operation. The
// refusals are the substance: who may ask, which token it hands over, which
// claims it adds, and for how long.

const serviceToken = () => signJwt({ role: "service", sub: "00000000-0000-0000-0000-000000000000", exp: nowS() + 3600 });
const operation = { operation_kind: "ORDER", operation_id: "op-1", amr: ["otp"], idp: "issuer-a" };
const upgradeOf = (token: unknown, over: Record<string, unknown> = {}) => ({
  token,
  claims: operation,
  exp: nowS() + 600,
  cap: nowS() + 3600,
  ...over,
});
async function upgraded(body: unknown, caller?: string) {
  const res = await handler(post("/auth/upgrade", body, caller ?? await serviceToken()));
  return { status: res.status, body: await res.json() };
}

Deno.test({
  name: "upgrade is the service's alone",
  ...opts,
  async fn() {
    const guest = await (await handler(post("/auth/guest", {}))).json();
    const body = upgradeOf(guest.token);
    const res = await handler(post("/auth/upgrade", body));
    assertEquals([res.status, (await res.json()).error], [401, "invalid token"]);
    assertEquals((await upgraded(body, "garbage")).status, 401);
    // A service's token of another key, or one expired, is no service's.
    const foreign = await signWith("another-secret-entirely-0000000000", { role: "service", exp: nowS() + 3600 });
    assertEquals((await upgraded(body, foreign)).status, 401);
    assertEquals((await upgraded(body, await signJwt({ role: "service", exp: nowS() - 1 }))).status, 401);
    // A person's session cannot upgrade itself, nor another's.
    assertEquals(await upgraded(body, guest.token), { status: 403, body: { error: "service only" } });
  },
});

Deno.test({
  name: "upgrade takes only a live session of a person, never one already upgraded",
  ...opts,
  async fn() {
    const guest = await (await handler(post("/auth/guest", {}))).json();
    const sub = guest.user.id;
    const refused = async (token: unknown) => (await upgraded(upgradeOf(token))).status;
    assertEquals(await refused(undefined), 400);
    assertEquals(await refused("garbage"), 401);
    assertEquals(await refused(await signJwt({ role: "app_user", sub, handle: "x", guest: true, exp: nowS() - 1 })), 401);
    assertEquals(await refused(await signWith("another-secret-entirely-0000000000", { role: "app_user", sub, exp: nowS() + 600 })), 401);
    // A service's token, a shape's and a ceremony's state are no person's session.
    assertEquals(await refused(await serviceToken()), 403);
    assertEquals(await refused(await signJwt({ typ: "shape", table: "article", where: "false", sub, exp: nowS() + 600 })), 403);
    assertEquals(await refused(await signJwt({ purpose: "login", challenge: "c", exp: nowS() + 600 })), 403);
    // A key's token is scoped to its key, which an upgrade would drop.
    const keyToken = await signJwt({ role: "app_user", sub, handle: "x", guest: false, kid: crypto.randomUUID(), scp: ["read"], exp: nowS() + 600 });
    assertEquals(await upgraded(upgradeOf(keyToken)), { status: 403, body: { error: "key token" } });
    // A session already scoped to an operation, or carrying any claim an
    // upgrade adds, is not scoped again.
    const once = await upgraded(upgradeOf(guest.token));
    assertEquals(once.status, 200);
    assertEquals(await upgraded(upgradeOf(once.body.token)), { status: 409, body: { error: "already upgraded" } });
    for (const k of Object.keys(operation)) {
      const marked = await signJwt({ role: "app_user", sub, guest: true, [k]: (operation as Record<string, unknown>)[k], exp: nowS() + 600 });
      assertEquals(await refused(marked), 409, k);
    }
  },
});

Deno.test({
  name: "upgrade refuses a session's own claim, and any claim off its list",
  ...opts,
  async fn() {
    const guest = await (await handler(post("/auth/guest", {}))).json();
    for (const k of ["role", "sub", "handle", "guest"]) {
      const res = await upgraded(upgradeOf(guest.token, { claims: { ...operation, [k]: "x" } }));
      assertEquals(res.status, 400, k);
      assertStringIncludes(res.body.error, `${k} is the session's own`);
    }
    // A computed key is an own property, `__proto__` included, as JSON makes it.
    for (const k of ["scope_id", "exp", "aud", "iss", "typ", "__proto__"]) {
      const res = await upgraded(upgradeOf(guest.token, { claims: { ...operation, [k]: "x" } }));
      assertEquals(res.status, 400, k);
      assertStringIncludes(res.body.error, `${k} is not a claim an upgrade adds`);
    }
    // Every claim on the list, each of its shape.
    const { operation_id: _, ...partial } = operation;
    for (
      const claims of [
        partial,
        { ...operation, operation_id: "" },
        { ...operation, operation_kind: 7 },
        { ...operation, idp: "x".repeat(201) },
        { ...operation, amr: [] },
        { ...operation, amr: "otp" },
        { ...operation, amr: [""] },
        null,
        ["operation_id"],
      ]
    ) {
      assertEquals((await upgraded(upgradeOf(guest.token, { claims }))).status, 400, JSON.stringify(claims));
    }
  },
});

Deno.test({
  name: "an upgraded session keeps its person and adds the operation, under the auth key",
  ...opts,
  async fn() {
    const guest = await (await handler(post("/auth/guest", {}))).json();
    const res = await upgraded(upgradeOf(guest.token));
    assertEquals(res.status, 200);
    const claims = await verifyJwt(res.body.token);
    assert(claims !== null, "signed with the key every reader verifies");
    const { exp: _, ...rest } = claims;
    assertEquals(rest, { role: "app_user", sub: guest.user.id, handle: guest.user.handle, guest: true, ...operation });
    // whoami reads it as the same person.
    const who = await handler(new Request("http://auth:9999/auth/whoami", { headers: { authorization: `Bearer ${res.body.token}` } }));
    assertEquals(await who.json(), { id: guest.user.id, handle: guest.user.handle });
    // An account's session stays an account's.
    const account = await upgraded(upgradeOf(await issueUserToken(guest.user.id, guest.user.handle)));
    assertEquals((await verifyJwt(account.body.token))?.guest, false);
  },
});

Deno.test({
  name: "upgrade cuts exp at the deployment's ceiling and at the family's cap",
  ...opts,
  async fn() {
    const guest = await (await handler(post("/auth/guest", {}))).json();
    const expOf = async (over: Record<string, unknown>) => {
      const res = await upgraded(upgradeOf(guest.token, over));
      assertEquals(res.status, 200, JSON.stringify(over));
      return (await verifyJwt(res.body.token))!.exp as number;
    };
    const t = nowS();
    // A week asked for is the ceiling, an hour by default.
    assert(Math.abs(await expOf({ exp: t + 7 * 24 * 3600, cap: t + 8 * 24 * 3600 }) - (t + 3600)) < 5);
    assertEquals(await expOf({ exp: t + 1800, cap: t + 900 }), t + 900);
    assertEquals(await expOf({ exp: t + 900, cap: t + 1800 }), t + 900);
    // Nor past the token it came from.
    const brief = await signJwt({ role: "app_user", sub: guest.user.id, handle: guest.user.handle, guest: true, exp: t + 120 });
    const res = await upgraded(upgradeOf(brief, { exp: t + 1800, cap: t + 3600 }));
    assertEquals(res.status, 200);
    assertEquals((await verifyJwt(res.body.token))!.exp, t + 120);
    // A token that would end within seconds is refused, whichever bound ends it.
    const dying = await signJwt({ role: "app_user", sub: guest.user.id, handle: guest.user.handle, guest: true, exp: t + 3 });
    for (const [token, over] of [[guest.token, { exp: t + 3 }], [guest.token, { cap: t + 3 }], [dying, {}]] as const) {
      const refused = await upgraded(upgradeOf(token, over));
      assertEquals([refused.status, refused.body.error], [400, "the upgraded token would end within 5s"], JSON.stringify(over));
    }
    assertEquals(await expOf({ exp: t + 30, cap: t + 60 }), t + 30);
    // The same session can be upgraded again: once per proof is the caller's to keep.
    assertEquals((await upgraded(upgradeOf(guest.token))).status, 200);
    assertEquals((await upgraded(upgradeOf(guest.token))).status, 200);
    for (const over of [{ exp: t - 1 }, { cap: t - 1 }, { exp: t + 0.5 }, { exp: String(t + 600) }, { cap: undefined }, { exp: undefined }]) {
      assertEquals((await upgraded(upgradeOf(guest.token, over))).status, 400, JSON.stringify(over));
    }
  },
});

Deno.test({
  name: "an upgraded guest token is not refreshed, before its end or after it",
  ...opts,
  async fn() {
    const guest = await (await handler(post("/auth/guest", {}))).json();
    const t = nowS();
    const live = await upgraded(upgradeOf(guest.token));
    assertEquals(live.status, 200);
    assertEquals(await refresh(live.body.token), { status: 403, body: { error: "upgraded token" } });
    // Expired within the refresh's grace, as a guest's own token would still be refreshed.
    const ended = await signJwt({ role: "app_user", sub: guest.user.id, handle: guest.user.handle, guest: true, ...operation, exp: t - 60 });
    assertEquals(await refresh(ended), { status: 403, body: { error: "upgraded token" } });
    // The session it was upgraded from is still refreshed.
    assertEquals((await refresh(guest.token)).status, 200);
  },
});

Deno.test("the upgrade ceiling is an hour unless the deployment names one, and refuses to start on another value", async () => {
  assertEquals([upgradeTtlOf(undefined), upgradeTtlOf(""), upgradeTtlOf("600"), upgradeTtlOf("5")], [3600, 3600, 600, 5]);
  for (const v of ["0", "-1", "1.5", "1h", "NaN"]) assertThrows(() => upgradeTtlOf(v), Error, "UPGRADE_TOKEN_TTL_S", v);
  // A ceiling under the least an upgraded token lives would refuse every upgrade.
  for (const v of ["1", "4"]) assertThrows(() => upgradeTtlOf(v), Error, "under the 5s an upgraded token must live", v);
  const { success, stderr } = await new Deno.Command(Deno.execPath(), {
    args: ["run", "-A", "--frozen", fileURLToPath(new URL("./main.ts", import.meta.url))],
    env: { UPGRADE_TOKEN_TTL_S: "1h" },
    stdout: "null",
    stderr: "piped",
  }).output();
  assert(!success);
  assertStringIncludes(new TextDecoder().decode(stderr), "UPGRADE_TOKEN_TTL_S is 1h");
});

// --- the sync path's gatekeeper ---
//
// The refusals are the substance. A mint that works proves the happy path; what
// makes this a boundary is that every parameter deciding reach is compared, and
// that a token for one shape cannot be spent on another.

function shapeReq(token: string, uri: string, method = "GET"): Request {
  return new Request("http://auth:9999/auth/shape/verify", {
    headers: {
      authorization: `Bearer ${token}`,
      "x-forwarded-uri": uri,
      "x-forwarded-method": method,
    },
  });
}

async function mint(table: string) {
  const user = await sql`INSERT INTO app_user (id, handle)
    VALUES (gen_random_uuid(), ${"gk-" + crypto.randomUUID().slice(0, 8)}) RETURNING id, handle`;
  const userToken = await issueUserToken(user[0].id, user[0].handle);
  const res = await handler(
    new Request("http://auth:9999/auth/shape", {
      method: "POST",
      headers: { "content-type": "application/json", authorization: `Bearer ${userToken}` },
      body: JSON.stringify({ table }),
    }),
  );
  return { res, userToken, uid: user[0].id as string };
}

Deno.test({
  name: "the shape token carries the subject's scopes, not the client's request",
  ...opts,
  async fn() {
    const { res, uid } = await mint("scoped_article");
    assertEquals(res.status, 200);
    const body = await res.json();
    // The same derivation the CRUD path reads, so the two cannot disagree.
    assertEquals(body.where, `scope_id IN ('public:','user:${uid}')`);
    const claims = await verifyJwt(body.token);
    assertEquals(claims!.table, "scoped_article");
    assertEquals(claims!.where, body.where);
  },
});

Deno.test({
  name: "public stored-generated leaf scopes share one predicate while keeping distinct subjects",
  ...opts,
  async fn() {
    const first = await mint("article");
    const second = await mint("article");
    assert(first.uid !== second.uid);
    for (const minted of [first, second]) {
      assertEquals(minted.res.status, 200);
      const body = await minted.res.json();
      assertEquals(body.where, "scope_id IN ('public:')");
      const claims = await verifyJwt(body.token);
      assertEquals(claims!.sub, minted.uid);
      assertEquals(claims!.table, "article");
      assertEquals(claims!.where, body.where);
      const uri = `/v1/shape?table=article&where=${encodeURIComponent(body.where)}`;
      assertEquals((await handler(shapeReq(body.token, uri))).status, 200);
      const wider = `scope_id IN ('public:','user:${minted.uid}')`;
      assertEquals((await handler(shapeReq(body.token, `/v1/shape?table=article&where=${encodeURIComponent(wider)}`))).status, 403);
    }
  },
});

Deno.test({
  name: "defaults, mutable scopes, private generated scopes and virtual scopes retain full subject reach",
  ...opts,
  async fn() {
    for (const table of ["scoped_article", "mutable_article", "owned_article", "private_article", "virtual_article"]) {
      const minted = await mint(table);
      assertEquals(minted.res.status, 200, table);
      const body = await minted.res.json();
      assertEquals(body.where, `scope_id IN ('public:','user:${minted.uid}')`, table);
      assertEquals((await verifyJwt(body.token))!.where, body.where);
    }
    assertEquals((await mint("nullable_article")).res.status, 409);
  },
});

Deno.test({
  name: "public parent expressions cannot remove reachable private scopes stored by descendants",
  ...opts,
  async fn() {
    for (const [table, insertInto] of [
      ["partitioned_article", "partitioned_article"],
      ["inherited_article", "inherited_article_child"],
    ]) {
      const { res, uid } = await mint(table);
      assertEquals(res.status, 200);
      await sql`INSERT INTO ${sql(insertInto)} (id, owner_id) VALUES (1, ${uid}::uuid)`;
      const rows = await sql`SELECT scope_id FROM ${sql(table)} WHERE owner_id = ${uid}::uuid`;
      assertEquals(rows.map((row) => row.scope_id), [`user:${uid}`]);
      assertEquals((await res.json()).where, `scope_id IN ('public:','user:${uid}')`, table);
    }
  },
});

Deno.test({
  name: "a shape request matching its token is allowed",
  ...opts,
  async fn() {
    const { res } = await mint("article");
    const { token, where } = await res.json();
    const uri = `/v1/shape?table=article&where=${encodeURIComponent(where)}`;
    assertEquals((await handler(shapeReq(token, uri))).status, 200);
  },
});

Deno.test({
  name: "a token for one table cannot be spent on another",
  ...opts,
  async fn() {
    const { res } = await mint("article");
    const { token, where } = await res.json();
    const uri = `/v1/shape?table=app_user&where=${encodeURIComponent(where)}`;
    assertEquals((await handler(shapeReq(token, uri))).status, 403);
  },
});

Deno.test({
  name: "a widened predicate is refused, and so is a dropped one",
  ...opts,
  async fn() {
    const { res } = await mint("article");
    const { token } = await res.json();
    const wide = encodeURIComponent("scope_id IS NOT NULL");
    assertEquals((await handler(shapeReq(token, `/v1/shape?table=article&where=${wide}`))).status, 403);
    // Absent is not equal. A `??` in the comparison would read this as allowed.
    assertEquals((await handler(shapeReq(token, `/v1/shape?table=article`))).status, 403);
  },
});

Deno.test({
  name: "columns, params and the secret stay server-owned",
  ...opts,
  async fn() {
    const { res } = await mint("article");
    const { token, where } = await res.json();
    const w = encodeURIComponent(where);
    for (const extra of ["columns=id,body", "params[1]=x", "secret=guessed"]) {
      const uri = `/v1/shape?table=article&where=${w}&${extra}`;
      assertEquals((await handler(shapeReq(token, uri))).status, 403);
    }
  },
});

Deno.test({
  name: "a repeated parameter is refused, whichever copy matches",
  ...opts,
  async fn() {
    const { res } = await mint("article");
    const { token, where } = await res.json();
    const w = encodeURIComponent(where);
    // Electric keeps the last copy of a repeated parameter; a gate that read
    // the first would pass `table=article&table=app_user` and hand Electric
    // the second. Neither order may pass, and nor may a benign duplicate.
    for (
      const uri of [
        `/v1/shape?table=article&table=app_user&where=${w}&where=true`,
        `/v1/shape?table=app_user&table=article&where=true&where=${w}`,
        `/v1/shape?table=article&where=${w}&where=${w}`,
        `/v1/shape?table=article&table=article&where=${w}`,
      ]
    ) {
      assertEquals((await handler(shapeReq(token, uri))).status, 403, uri);
    }
  },
});

Deno.test({
  name: "a fragment does not hide a parameter",
  ...opts,
  async fn() {
    const { res } = await mint("article");
    const { token, where } = await res.json();
    const w = encodeURIComponent(where);
    // A request line has no fragment: the proxy and Electric read `#` as query
    // text, and a WHATWG parse would stop there and pass a request that
    // carries a second table behind it.
    for (const uri of [
      `/v1/shape?table=article&where=${w}#&table=app_user&where=true`,
      `/v1/shape?table=article&where=${w}%23&table=app_user&where=true`,
      `/v1/shape?table=article&where=${w}#`,
    ]) {
      assertEquals((await handler(shapeReq(token, uri))).status, 403, uri);
    }
  },
});

Deno.test({
  name: "a parameter the gate does not know is refused",
  ...opts,
  async fn() {
    const { res } = await mint("article");
    const { token, where } = await res.json();
    const w = encodeURIComponent(where);
    // Electric's paging and streaming parameters pass; anything else is a
    // parameter added after this gate was written, and its reach is unknown.
    const paging = `/v1/shape?table=article&where=${w}&offset=-1&live=true&handle=abc&cursor=1&experimental_live_sse=true`;
    assertEquals((await handler(shapeReq(token, paging))).status, 200);
    for (const extra of ["table[]=app_user", "schema=other", "columns=secret", "params=x"]) {
      const uri = `/v1/shape?table=article&where=${w}&${extra}`;
      assertEquals((await handler(shapeReq(token, uri))).status, 403, extra);
    }
  },
});

// An on-demand collection asks for its rows as subset snapshots of the one
// shape its token names, from `offset=now` with only changes logged, and
// replica=full so an update of a row it never loaded is a whole row. The
// premises that make a subset only narrow the token are tests/entrypoint.sh's,
// against Electric itself; this holds the vocabulary and the grammar.
Deno.test({
  name: "a subset snapshot passes, and only in the form the client sends it",
  ...opts,
  async fn() {
    const { res } = await mint("article");
    const { token, where } = await res.json();
    const w = encodeURIComponent(where);
    const subset = `/v1/shape?table=article&where=${w}&offset=now&log=changes_only&replica=full` +
      `&subset__where=${encodeURIComponent('"x" = $1')}&subset__params=${encodeURIComponent('{"1":"a"}')}` +
      `&subset__limit=1&subset__order_by=${encodeURIComponent('"x" DESC')}`;
    assertEquals((await handler(shapeReq(token, subset))).status, 200);
    for (const extra of ["replica=default", "replica=", "replica=full&replica=default"]) {
      const uri = `/v1/shape?table=article&where=${w}&${extra}`;
      assertEquals((await handler(shapeReq(token, uri))).status, 403, extra);
    }
    // A subset outside the grammar is refused as Electric refuses one, which
    // the store reads as the program's error and asks no further.
    for (const [extra, param] of [
      ["subset__offset=1", "offset"],
      // Regression: a repeated subset parameter was a 403, which the store
      // takes for a token to re-mint and asks again seven times.
      ["subset__where=true&subset__where=false", "where"],
      [`subset__params=${encodeURIComponent("{}")}&subset__params=${encodeURIComponent("{}")}`, "params"],
      ["subset__offset=1&subset__offset=2", "offset"],
      [`subset__where_expr=${encodeURIComponent("{}")}`, "where_expr"],
      [`subset__order_by_expr=${encodeURIComponent("[]")}`, "order_by_expr"],
      // Regression: the gate admitted any subset__where Electric parses, and
      // Electric parses a cast. Postgres ran it on rows outside the token's
      // where and answered `invalid input syntax for type integer:
      // "secret_1"`, a value of a row the token does not reach.
      [`subset__where=${encodeURIComponent('"x"::int4 > 0')}`, "where"],
      [`subset__where=${encodeURIComponent('"x" + 1 > 0')}`, "where"],
      [`subset__where=${encodeURIComponent('"pg_sleep"(1) IS NULL')}`, "where"],
      [`subset__where=${encodeURIComponent('true) OR (true')}`, "where"],
      [`subset__order_by=${encodeURIComponent('"x"::int4')}`, "order_by"],
      ["subset__limit=1e3", "limit"],
    ]) {
      const res = await handler(shapeReq(token, `/v1/shape?table=article&where=${w}&${extra}`));
      assertEquals(res.status, 400, extra);
      assertEquals(Object.keys((await res.json()).errors.subset), [param], extra);
    }
    assertEquals((await handler(shapeReq(token, subset, "POST"))).status, 403);
  },
});

// Regression: the grammar admitted `"handle" LIKE $1` whatever $1 held, and
// Postgres raises "LIKE pattern must not end with escape character" only once
// a row's value has matched the pattern up to that escape. Against Electric,
// `{"1":"Fla\\"}` on the team table answered 500 and `{"1":"Zzz\\"}` 200: a
// bit per request about rows the token does not reach. No view the store
// maintains filters by a pattern, so a pattern is refused whatever it binds.
Deno.test({
  name: "a subset states no pattern, and binds its params by position",
  ...opts,
  async fn() {
    const { res } = await mint("article");
    const { token, where } = await res.json();
    const uri = (subsetWhere: string, params?: string) =>
      `/v1/shape?table=article&where=${encodeURIComponent(where)}&offset=now&log=changes_only&replica=full` +
      `&subset__where=${encodeURIComponent(subsetWhere)}` +
      (params === undefined ? "" : `&subset__params=${encodeURIComponent(params)}`);
    const status = async (subsetWhere: string, params?: string) => (await handler(shapeReq(token, uri(subsetWhere, params)))).status;
    for (const [w, p] of [
      ['"x" = $1', '{"1":"a"}'],
      ['"x" = ANY($1)', '{"1":"{a,b}"}'],
      // A null the client compiled is left out of the params, so $2 is unbound.
      ['"x" = $1 OR "x" = $2 OR "y" = $3', '{"1":"a","3":"b"}'],
    ]) assertEquals(await status(w, p), 200, `${w} ${p}`);
    for (const [w, p] of [
      ['"x" LIKE $1', '{"1":"adm%"}'],
      ['"x" ILIKE $1', '{"1":"adm%"}'],
      ['"x" LIKE $1', String.raw`{"1":"adm\\"}`],
      [String.raw`"x" LIKE 'adm\'`, undefined],
      ['LOWER("x") = $1', '{"1":"a"}'],
      ['"x" = $1', '{"1":1}'],
      ['"x" = $1', '["a"]'],
      ['"x" = $1', '{"01":"a"}'],
      ['"x" = $1', "not json"],
    ] as const) assertEquals(await status(w, p), 400, `${w} ${p}`);
  },
});

// Regression: the grammar admitted a column compared with a column, and
// Postgres casts one of two numeric types to the other on every row:
// `"amount" = "ratio"` (numeric, float8) raised `value out of range` on a row
// holding 1e400, a bit per request about rows the token does not reach. A
// typed literal picks the column's cast the same way, as two adjacent
// operands: `"amount" = "float8" '1'` raises on that row where
// `"amount" = 1.5` reads none. A comparison is a column against a $n or a
// literal, whose type Postgres infers from the column.
Deno.test({
  name: "a subset compares a column with a value only",
  ...opts,
  async fn() {
    const { res } = await mint("article");
    const { token, where } = await res.json();
    const answer = async (subsetWhere: string) => {
      const res = await handler(shapeReq(token,
        `/v1/shape?table=article&where=${encodeURIComponent(where)}&offset=now&log=changes_only&replica=full` +
          `&subset__where=${encodeURIComponent(subsetWhere)}&subset__params=${encodeURIComponent('{"1":"a","2":"b","3":"c"}')}`));
      return res.status === 400 ? Object.keys((await res.json()).errors.subset) : res.status;
    };
    // What electric-db-collection 0.4.0's compiler emits.
    for (const w of [
      "true = true", "true", "false", '"x" = $1', '$1 = "x"', '"x" >= $1', '"x" <> $1', '"x" = ANY($1)',
      '"x" IS NULL', '"x" IS NOT NULL', 'NOT ("x" = $1)', '("x" = $1) AND ("y" > $2) AND ("z" < $3)',
      '"x" > $1 OR ("x" = $1 AND "id" > $2)', `"x" = 8 AND "y" = 'f' AND "z" = 1.5`,
    ]) assertEquals(await answer(w), 200, w);
    for (const w of [
      '"amount" = "ratio"', `"amount" = "float8" '1'`, '"x" < "y"', '"x" = ANY("y")', '$1 = ANY("x")', `"x" = "int4" '1'`, `"x" = "numeric" $1`,
      '"x" = $1 $2', '"x" = NULL', '$1 IS NULL', '"x"', 'NOT "x"', '"x" = $1 AND', '("x" = $1', '"x" = ($1)', '"x" = $1 "y" = $2',
    ]) assertEquals(await answer(w), ["where"], w);
  },
});

// Regression: URLSearchParams read `where=title%20%3D%20'a;b'` as the
// token's predicate and passed it, and Caddy's re-encoding through Go's
// ParseQuery dropped the pair, so Electric served the whole table.
Deno.test({
  name: "a query Caddy would read differently from the gate is refused",
  ...opts,
  async fn() {
    const where = `"title" = 'a;b%'`;
    const token = await signJwt({ typ: "shape", table: "article", where, exp: Math.floor(Date.now() / 1000) + 60 });
    const encoded = encodeURIComponent(where);
    assertEquals((await handler(shapeReq(token, `/v1/shape?table=article&where=${encoded}`))).status, 200);
    for (const raw of [encoded.replace("%3B", ";"), encoded.replace("%25", "%"), `${encoded}&offset=-1%zz`, `${encoded}&offset=%FF`]) {
      assertEquals((await handler(shapeReq(token, `/v1/shape?table=article&where=${raw}`))).status, 403, raw);
    }
  },
});

Deno.test({
  name: "only GET reaches a shape",
  ...opts,
  async fn() {
    const { res } = await mint("article");
    const { token, where } = await res.json();
    const uri = `/v1/shape?table=article&where=${encodeURIComponent(where)}`;
    for (const method of ["POST", "DELETE", "PUT"]) {
      assertEquals((await handler(shapeReq(token, uri, method))).status, 403, method);
    }
    // Absent is not GET: a proxy that forwards no method has not said.
    const unsaid = new Request("http://auth:9999/auth/shape/verify", {
      headers: { authorization: `Bearer ${token}`, "x-forwarded-uri": uri },
    });
    assertEquals((await handler(unsaid)).status, 403);
  },
});

Deno.test({
  name: "only the shape route passes, whatever the token says",
  ...opts,
  async fn() {
    const { res } = await mint("article");
    const { token, where } = await res.json();
    const w = encodeURIComponent(where);
    assertEquals((await handler(shapeReq(token, `/v1/shape?table=article&where=${w}`))).status, 200);
    for (const uri of [`/v1/health?table=article&where=${w}`, `/v1/shapes?table=article&where=${w}`, `/v1/shape/x?table=article&where=${w}`]) {
      assertEquals((await handler(shapeReq(token, uri))).status, 403, uri);
    }
  },
});

Deno.test({
  name: "a shape needs a session: the floor is all a shape carries",
  ...opts,
  async fn() {
    // The CRUD path keeps anon out of a table by its permissive policies, which
    // sit above the floor; a shape carries the floor alone, so a subject
    // holding only public: would read on the sync path what CRUD refuses.
    const post = (headers: Record<string, string>) =>
      handler(new Request("http://auth:9999/auth/shape", {
        method: "POST",
        headers: { "content-type": "application/json", ...headers },
        body: JSON.stringify({ table: "article" }),
      }));
    assertEquals((await post({})).status, 401);
    assertEquals((await post({ authorization: "Bearer nope" })).status, 401);
  },
});

Deno.test({
  name: "a session opens a table's public rows and nothing wider; a shape token is no session",
  ...opts,
  async fn() {
    const { res, userToken, uid } = await mint("article");
    const { token } = await res.json();
    const shape = (table: string, where: string) =>
      handler(shapeReq(userToken, `/v1/shape?table=${table}&where=${encodeURIComponent(where)}`));
    // Every subject's scopes open with public:, so the session reaches no row
    // a minted token would not, and a screen mounts without a mint per table.
    assertEquals(PUBLIC_WHERE, CLIENT_PUBLIC_WHERE);
    assertEquals((await shape("article", PUBLIC_WHERE)).status, 200);
    assertEquals((await shape("scoped_article", PUBLIC_WHERE)).status, 200);
    // Its own rows still need the mint, which reads the subject's scopes.
    assertEquals((await shape("scoped_article", `scope_id IN ('public:','user:${uid}')`)).status, 403);
    assertEquals((await shape("article", "true")).status, 403);
    assertEquals((await shape("article; drop table article", PUBLIC_WHERE)).status, 403);
    // And the shape token cannot stand in for a session.
    const mintWithShape = await handler(
      new Request("http://auth:9999/auth/shape", {
        method: "POST",
        headers: { "content-type": "application/json", authorization: `Bearer ${token}` },
        body: JSON.stringify({ table: "article" }),
      }),
    );
    assertEquals(mintWithShape.status, 401);
  },
});

Deno.test({
  name: "a table name that could carry a predicate is refused",
  ...opts,
  async fn() {
    for (const t of ["article; drop table article", "article WHERE 1=1", "Article", ""]) {
      const { res } = await mint(t);
      assertEquals(res.status, 400, `accepted ${JSON.stringify(t)}`);
    }
  },
});

// --- per-row shapes ---
//
// A row the floor does not deliver is reached one shape at a time, keyed on a
// column the app declared (mecha.shape_key), and the gate answers as the
// subject: the app's own policies decide whether the parent row is readable.

async function mintRow(userToken: string, table: string, column: string, value: string) {
  return await handler(
    new Request("http://auth:9999/auth/shape", {
      method: "POST",
      headers: { "content-type": "application/json", authorization: `Bearer ${userToken}` },
      body: JSON.stringify({ table, key: { column, value } }),
    }),
  );
}

Deno.test({
  name: "a per-row shape is minted for a row the subject reads, keyed by itself or by its parent",
  ...opts,
  async fn() {
    const { userToken, uid } = await mint("article");
    const [doc] = await sql`INSERT INTO gk_doc (owner_id) VALUES (${uid}::uuid) RETURNING id`;
    const own = await mintRow(userToken, "gk_doc", "id", doc.id);
    assertEquals(own.status, 200);
    const body = await own.json();
    assertEquals(body.where, `id = '${doc.id}'`);
    const claims = await verifyJwt(body.token);
    assertEquals(claims!.table, "gk_doc");
    assertEquals(claims!.where, body.where);
    const uri = `/v1/shape?table=gk_doc&where=${encodeURIComponent(body.where)}`;
    assertEquals((await handler(shapeReq(body.token, uri))).status, 200);

    const lines = await mintRow(userToken, "gk_line", "doc_id", doc.id);
    assertEquals(lines.status, 200);
    assertEquals((await lines.json()).where, `doc_id = '${doc.id}'`);
  },
});

Deno.test({
  name: "a per-row shape over another subject's row is refused, and so is one over no row",
  ...opts,
  async fn() {
    const { userToken } = await mint("article");
    const other = await mint("article");
    const [doc] = await sql`INSERT INTO gk_doc (owner_id) VALUES (${other.uid}::uuid) RETURNING id`;
    // The policy is the judge: the row exists, and this subject is not its owner.
    assertEquals((await mintRow(userToken, "gk_doc", "id", doc.id)).status, 403);
    assertEquals((await mintRow(userToken, "gk_line", "doc_id", doc.id)).status, 403);
    assertEquals((await mintRow(userToken, "gk_doc", "id", crypto.randomUUID())).status, 403);
  },
});

Deno.test({
  name: "a per-row shape keyed on an undeclared column is refused, whatever the row",
  ...opts,
  async fn() {
    const { userToken, uid } = await mint("article");
    const [doc] = await sql`INSERT INTO gk_doc (owner_id) VALUES (${uid}::uuid) RETURNING id`;
    // owner_id names a row the subject reads (their own app_user), but no edge
    // says gk_doc rows keyed by owner are that row's content.
    assertEquals((await mintRow(userToken, "gk_doc", "owner_id", uid)).status, 403);
    assertEquals((await mintRow(userToken, "article", "id", doc.id)).status, 403);
  },
});

Deno.test({
  name: "a per-row key that could carry a predicate is refused",
  ...opts,
  async fn() {
    const { userToken, uid } = await mint("article");
    const [doc] = await sql`INSERT INTO gk_doc (owner_id) VALUES (${uid}::uuid) RETURNING id`;
    for (const column of ["id = 'x' OR 1=1 --", "Id", ""]) {
      assertEquals((await mintRow(userToken, "gk_doc", column, doc.id)).status, 400, column);
    }
    // A key that is not an object is a bad request, not an outage.
    for (const key of [null, 5, "id"]) {
      const res = await handler(
        new Request("http://auth:9999/auth/shape", {
          method: "POST",
          headers: { "content-type": "application/json", authorization: `Bearer ${userToken}` },
          body: JSON.stringify({ table: "gk_doc", key }),
        }),
      );
      assertEquals(res.status, 400, JSON.stringify(key));
    }
    // A value is a literal whatever it holds: quoted on the way out, and never
    // reaching a row it does not name.
    const res = await mintRow(userToken, "gk_doc", "id", `${doc.id}' OR '1'='1`);
    assertEquals(res.status, 403);
  },
});

Deno.test({
  name: "a table the floor does not reach cannot be shaped",
  ...opts,
  async fn() {
    // No scope_id: a predicate naming one would be answered 400 by Electric and
    // read as a sync fault, so the gate refuses where the reason is known.
    await sql`CREATE TABLE IF NOT EXISTS gk_unfloored (id int primary key)`;
    const { res } = await mint("gk_unfloored");
    assertEquals(res.status, 409);
    assert((await res.text()).includes("scope_id"));
    await sql`DROP TABLE gk_unfloored`;
    // A table that does not exist is not floored either; a regclass cast would
    // throw and turn the answer into a 500.
    assertEquals((await mint("gk_absent")).res.status, 409);
  },
});

// A passkey as a browser makes one: an EC2 P-256 key under a "none"
// attestation, and client data naming the page's origin.
type Cbor = Parameters<typeof isoCBOR.encode>[0];
async function passkey() {
  const pair = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
  const raw = new Uint8Array(await crypto.subtle.exportKey("raw", pair.publicKey));
  const id = crypto.getRandomValues(new Uint8Array(16));
  const rpIdHash = await toHash(isoUint8Array.fromUTF8String("localhost"));
  const b64 = (bytes: Uint8Array) => isoBase64URL.fromBuffer(bytes);
  const clientData = (type: string, challenge: string, origin: string) =>
    isoUint8Array.fromUTF8String(JSON.stringify({ type, challenge, origin, crossOrigin: false }));
  // WebCrypto signs r||s; WebAuthn carries ECDSA signatures as DER.
  const der = (sig: Uint8Array) => {
    const int = (n: Uint8Array) => {
      let i = 0;
      while (i < n.length - 1 && n[i] === 0) i++;
      const v = n[i] & 0x80 ? [0, ...n.slice(i)] : [...n.slice(i)];
      return [0x02, v.length, ...v];
    };
    const body = [...int(sig.slice(0, 32)), ...int(sig.slice(32))];
    return new Uint8Array([0x30, body.length, ...body]);
  };
  return {
    register(challenge: string, origin: string) {
      const key = isoCBOR.encode(
        new Map<number, Cbor>([[1, 2], [3, -7], [-1, 1], [-2, raw.slice(1, 33)], [-3, raw.slice(33)]]),
      );
      const authData = isoUint8Array.concat([
        rpIdHash,
        new Uint8Array([0x41, 0, 0, 0, 0]),
        new Uint8Array(16),
        new Uint8Array([0, id.length]),
        id,
        key,
      ]);
      const attestation = isoCBOR.encode(
        new Map<string, Cbor>([["fmt", "none"], ["attStmt", new Map()], ["authData", authData]]),
      );
      return {
        id: b64(id),
        rawId: b64(id),
        type: "public-key",
        response: { clientDataJSON: b64(clientData("webauthn.create", challenge, origin)), attestationObject: b64(attestation) },
        clientExtensionResults: {},
      };
    },
    async login(challenge: string, origin: string) {
      const authData = isoUint8Array.concat([rpIdHash, new Uint8Array([0x01, 0, 0, 0, 1])]);
      const data = clientData("webauthn.get", challenge, origin);
      const signed = isoUint8Array.concat([authData, await toHash(data)]);
      const sig = new Uint8Array(await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, pair.privateKey, new Uint8Array(signed)));
      return {
        id: b64(id),
        rawId: b64(id),
        type: "public-key",
        response: { clientDataJSON: b64(data), authenticatorData: b64(authData), signature: b64(der(sig)) },
        clientExtensionResults: {},
      };
    },
  };
}

function atDoor(path: string, body: unknown, host: string): Request {
  return new Request(`http://auth:9999${path}`, {
    method: "POST",
    headers: { "content-type": "application/json", host },
    body: JSON.stringify(body),
  });
}

Deno.test({
  name: "a passkey made at the dev door registers and signs in, whatever port the host gave the door",
  ...opts,
  async fn() {
    // The door publishes on an ephemeral port while the expected origin named
    // 8443, so every ceremony on a cluster launched without the port pinned
    // failed its origin check.
    const door = "localhost:54321";
    const key = await passkey();
    const reg = await (await handler(atDoor("/auth/register/start", {}, door))).json();
    const made = await handler(
      atDoor("/auth/register/verify", { state: reg.state, response: key.register(reg.challenge, `https://${door}`) }, door),
    );
    assertEquals(made.status, 200, await made.clone().text());
    const user = (await made.json()).user;
    const login = await (await handler(atDoor("/auth/login/start", {}, door))).json();
    const signed = await handler(
      atDoor("/auth/login/verify", { state: login.state, response: await key.login(login.challenge, `https://${door}`) }, door),
    );
    assertEquals(signed.status, 200, await signed.clone().text());
    assertEquals((await signed.json()).user, user);
  },
});

Deno.test({
  name: "a ceremony made anywhere but the door it reached is refused",
  ...opts,
  async fn() {
    const key = await passkey();
    for (const [origin, door] of [["https://evil.example", "localhost:54321"], ["https://localhost:54321", "localhost:1"]]) {
      const reg = await (await handler(atDoor("/auth/register/start", {}, door))).json();
      const res = await handler(
        atDoor("/auth/register/verify", { state: reg.state, response: key.register(reg.challenge, origin) }, door),
      );
      assertEquals(res.status, 401, `${origin} at ${door}`);
    }
  },
});

Deno.test({
  name: "a passkey made by the app's Android build registers and signs in; another app's is refused",
  ...opts,
  async fn() {
    // Credential Manager names no page: the client data carries the app's signing certificate.
    const door = "localhost:54321";
    const app = androidOrigin(ANDROID_FINGERPRINT);
    const key = await passkey();
    const reg = await (await handler(atDoor("/auth/register/start", {}, door))).json();
    const made = await handler(atDoor("/auth/register/verify", { state: reg.state, response: key.register(reg.challenge, app) }, door));
    assertEquals(made.status, 200, await made.clone().text());
    const user = (await made.json()).user;
    const login = await (await handler(atDoor("/auth/login/start", {}, door))).json();
    const signed = await handler(
      atDoor("/auth/login/verify", { state: login.state, response: await key.login(login.challenge, app) }, door),
    );
    assertEquals(signed.status, 200, await signed.clone().text());
    assertEquals((await signed.json()).user, user);

    const other = androidOrigin("00".repeat(32));
    const again = await (await handler(atDoor("/auth/register/start", {}, door))).json();
    const refused = await handler(
      atDoor("/auth/register/verify", { state: again.state, response: (await passkey()).register(again.challenge, other) }, door),
    );
    assertEquals(refused.status, 401);
  },
});

Deno.test("a malformed Android fingerprint is refused at startup", async () => {
  const { success, stderr } = await new Deno.Command(Deno.execPath(), {
    args: ["run", "-A", "--frozen", fileURLToPath(new URL("./main.ts", import.meta.url))],
    env: { WEBAUTHN_RP_ID: "localhost", WEBAUTHN_ORIGIN: "https://localhost:*", WEBAUTHN_ANDROID_ORIGINS: "AB:CD" },
    stdout: "null",
    stderr: "piped",
  }).output();
  assert(!success);
  assertStringIncludes(new TextDecoder().decode(stderr), "is not a SHA-256 certificate fingerprint");
});

Deno.test("the dev door admits only the localhost relying party, at startup", async () => {
  // The compose default fills a forgotten WEBAUTHN_ORIGIN with the dev door;
  // a deployment naming its own relying party then booted and refused every
  // ceremony with a bare 401.
  assertEquals(admittedOrigin("localhost", "https://localhost:*"), "https://localhost:*");
  assertEquals(admittedOrigin("app.example", "https://app.example"), "https://app.example");
  assertThrows(() => admittedOrigin("app.example", "https://localhost:*"), Error, "WEBAUTHN_ORIGIN");
  const { success, stderr } = await new Deno.Command(Deno.execPath(), {
    args: ["run", "-A", "--frozen", fileURLToPath(new URL("./main.ts", import.meta.url))],
    env: { WEBAUTHN_RP_ID: "app.example", WEBAUTHN_ORIGIN: "https://localhost:*" },
    stdout: "null",
    stderr: "piped",
  }).output();
  assert(!success);
  assertStringIncludes(new TextDecoder().decode(stderr), "serves only WEBAUTHN_RP_ID=localhost");
});

Deno.test("an origin off the relying party's domain is refused at startup", async () => {
  // Checked only from the dev door's side, an origin the compose default RP id
  // (localhost) cannot cover booted and refused every ceremony with a 401.
  assertEquals(admittedOrigin("example.com", "https://app.example.com"), "https://app.example.com");
  assertEquals(admittedOrigin("localhost", "https://localhost:8443"), "https://localhost:8443");
  assertThrows(() => admittedOrigin("localhost", "https://app.example"), Error, "is not on WEBAUTHN_RP_ID");
  assertThrows(() => admittedOrigin("example.com", "https://badexample.com"), Error, "is not on WEBAUTHN_RP_ID");
  const { success, stderr } = await new Deno.Command(Deno.execPath(), {
    args: ["run", "-A", "--frozen", fileURLToPath(new URL("./main.ts", import.meta.url))],
    env: { WEBAUTHN_RP_ID: "localhost", WEBAUTHN_ORIGIN: "https://app.example" },
    stdout: "null",
    stderr: "piped",
  }).output();
  assert(!success);
  assertStringIncludes(new TextDecoder().decode(stderr), "is not on WEBAUTHN_RP_ID");
});

Deno.test("an origin no ceremony can have is refused at startup", async () => {
  // Compared exactly with the ceremony's bare https origin, an origin with a
  // trailing slash or a path, or http on a real host, booted and refused
  // every ceremony with a 401.
  assertEquals(admittedOrigin("localhost", "http://localhost:8080"), "http://localhost:8080");
  for (const origin of ["https://app.example/", "https://app.example/auth", "https://APP.example"]) {
    assertThrows(() => admittedOrigin("app.example", origin), Error, "is not an origin", origin);
  }
  assertThrows(() => admittedOrigin("app.example", "http://app.example"), Error, "is not https");
  const { success, stderr } = await new Deno.Command(Deno.execPath(), {
    args: ["run", "-A", "--frozen", fileURLToPath(new URL("./main.ts", import.meta.url))],
    env: { WEBAUTHN_RP_ID: "app.example", WEBAUTHN_ORIGIN: "https://app.example/" },
    stdout: "null",
    stderr: "piped",
  }).output();
  assert(!success);
  assertStringIncludes(new TextDecoder().decode(stderr), "set it to https://app.example");
});

Deno.test("a configured origin is exact, and only localhost stands for the dev door", () => {
  assertEquals(ceremonyOrigin("https://app.example", "localhost:54321"), "https://app.example");
  assertEquals(ceremonyOrigin("https://localhost:*", "localhost:54321"), "https://localhost:54321");
  assert(ceremonyOrigin("https://localhost:*", "evil.example:54321") !== "https://evil.example:54321");
  assert(ceremonyOrigin("https://localhost:*", null).endsWith("*"));
});

const alice = { provider: "google", issuer: "https://accounts.google.com", sub: "g-alice", name: "Alice", picture: null, email: "alice@mail.test" };

Deno.test({
  name: "a provider's subject is one person, however many sign-ins race to make it",
  ...opts,
  fn: async () => {
    // Connections opened first: a sign-in on the one already open commits
    // before the others have connected, and nothing races.
    await Promise.all(Array.from({ length: 8 }, () => sql`select pg_sleep(0.05)`));
    for (const sub of ["g-race-1", "g-race-2", "g-race-3"]) {
      const racers = await Promise.all(Array.from({ length: 8 }, () => links.userFor({ ...alice, sub })));
      assertEquals(new Set(racers.map((u) => u.id)).size, 1, sub);
    }
    const users = [await links.userFor(alice)];
    const [link] = await sql`select user_id from mecha_auth.identity_link where provider = 'google' and sub = 'g-alice'`;
    assertEquals(link.user_id, users[0].id);
    await links.userFor({ ...alice, name: "Alice B." });
    assertEquals((await sql`select name from mecha_auth.identity_link where sub = 'g-alice'`)[0].name, "Alice B.");
    assertEquals((await sql`select email from mecha_auth.identity_link where sub = 'g-alice'`)[0].email, "alice@mail.test");
    await links.userFor({ ...alice, email: null });
    assertEquals((await sql`select email from mecha_auth.identity_link where sub = 'g-alice'`)[0].email, null, "the provider no longer vouches for one");
    assertEquals(await links.handleOf("google", alice.issuer, users[0].id), users[0].handle);
  },
});

Deno.test({
  name: "a new subject from a guest's browser takes the guest in once, keeping its id and handle; no one else's guest is taken",
  ...opts,
  fn: async () => {
    const guest = (await (await handler(post("/auth/guest", {}))).json()).user;
    const taken = await links.userFor({ ...alice, sub: "g-adopts" }, guest.id);
    assertEquals(taken, { id: guest.id, handle: guest.handle });
    assertEquals((await sql`select user_id from mecha_auth.identity_link where sub = 'g-adopts'`)[0].user_id, guest.id);
    // Signing in again is the same person, the guest named or not.
    assertEquals((await links.userFor({ ...alice, sub: "g-adopts" })).id, guest.id);
    assertEquals((await links.userFor({ ...alice, sub: "g-adopts" }, crypto.randomUUID())).id, guest.id);
    // A guest already someone's is not taken by a second subject: that subject is a new user.
    const second = await links.userFor({ ...alice, sub: "g-adopts-2" }, guest.id);
    assert(second.id !== guest.id);
    // A guest with a passkey is an account, not a guest.
    const promoted = (await (await handler(post("/auth/guest", {}))).json()).user;
    await sql`insert into mecha_auth.webauthn_credential (id, user_id, public_key, counter) values (${"cred-" + promoted.id}, ${promoted.id}, ${new Uint8Array([1])}, 0)`;
    assert((await links.userFor({ ...alice, sub: "g-adopts-3" }, promoted.id)).id !== promoted.id);
    // An id that is no guest at all (unknown, or not an id) is ignored.
    assert((await links.userFor({ ...alice, sub: "g-adopts-4" }, crypto.randomUUID())).id.length > 0);
    assert((await links.userFor({ ...alice, sub: "g-adopts-5" }, "not-a-uuid")).id.length > 0);
  },
});

Deno.test({
  name: "two subjects racing for one guest end with one winner",
  ...opts,
  fn: async () => {
    await Promise.all(Array.from({ length: 6 }, () => sql`select pg_sleep(0.05)`));
    const guest = (await (await handler(post("/auth/guest", {}))).json()).user;
    const racers = await Promise.all(["g-race-a", "g-race-b", "g-race-c"].map((sub) => links.userFor({ ...alice, sub }, guest.id)));
    assertEquals(racers.filter((u) => u.id === guest.id).length, 1);
    assertEquals(new Set(racers.map((u) => u.id)).size, 3);
  },
});

Deno.test({
  name: "a session is only a provider's while its link is there",
  ...opts,
  fn: async () => {
    const guest = (await (await handler(post("/auth/guest", {}))).json()).user;
    assertEquals(await links.handleOf("google", alice.issuer, guest.id), null);
    const u = await links.userFor({ ...alice, sub: "g-revoked" });
    await sql`delete from mecha_auth.identity_link where sub = 'g-revoked'`;
    assertEquals(await links.handleOf("google", alice.issuer, u.id), null);
  },
});

Deno.test({
  name: "legacy links require their original issuer before migration can admit sign-in",
  ...opts,
  fn: async () => {
    // The shape its auth service made, in public, with a row signed in through the broker.
    await sql`drop view public.identity_link`;
    await sql`drop table mecha_auth.identity_link`;
    await sql`create table identity_link (
      provider text not null, sub text not null,
      user_id uuid not null unique references app_user(id) on delete cascade,
      created_at timestamptz not null default now(), primary key (provider, sub))`;
    const guest = (await (await handler(post("/auth/guest", {}))).json()).user;
    await sql`insert into identity_link (provider, sub, user_id) values ('google', 'pairwise-1', ${guest.id})`;
    await assertRejects(() => migrate(), Error, "identity_link has unassigned issuers");
    await sql`alter table identity_link add column issuer text`;
    await sql`update identity_link set issuer = ${alice.issuer}`;
    await migrate();
    assertEquals((await links.userFor({ ...alice, sub: "pairwise-1", name: null, picture: null, email: null })).id, guest.id);
    const replacement = await links.userFor({ ...alice, issuer: "https://broker.test", sub: "pairwise-1" });
    assert(replacement.id !== guest.id);
    assertEquals(await links.handleOf("google", "https://broker.test", guest.id), null);
    assertEquals(await links.handleOf("google", alice.issuer, guest.id), guest.handle);
  },
});

// An app grants every table in public, BYPASSRLS roles included, and the CRUD
// API serves public: the links and passkeys decide who signs in as whom, so
// no app grant reaches them.
Deno.test({
  name: "no app grant reaches the links or the passkeys",
  ...opts,
  fn: async () => {
    const owner = await links.userFor({ ...alice, sub: "g-closed" });
    const rollback = new Error("rolled back");
    const tried = await sql.begin(async (tx) => {
      await tx`DO $$ BEGIN
        IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'service_probe') THEN CREATE ROLE service_probe NOLOGIN BYPASSRLS; END IF;
      END $$`;
      await tx`GRANT USAGE ON SCHEMA public TO app_user, service_probe`;
      await tx`GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO app_user, service_probe`;
      await tx`ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO app_user, service_probe`;
      const seen: Record<string, string> = {};
      for (const role of ["app_user", "service_probe"]) {
        for (const query of ["select * from mecha_auth.identity_link", "select * from mecha_auth.webauthn_credential",
          `insert into mecha_auth.webauthn_credential (id, user_id, public_key) values ('stolen', '${owner.id}', '\\x00')`,
          "select * from identity_link", "select * from webauthn_credential"]) {
          await tx`SAVEPOINT probe`;
          await tx.unsafe(`SET LOCAL ROLE ${role}`);
          seen[`${role}: ${query}`] = await tx.unsafe(query).then(() => "answered", (e: Error) => e.message);
          await tx`ROLLBACK TO SAVEPOINT probe`;
        }
      }
      throw Object.assign(rollback, { seen });
    }).catch((e) => e === rollback ? (e as Error & { seen: Record<string, string> }).seen : Promise.reject(e));
    for (const [probe, outcome] of Object.entries(tried)) {
      if (probe.includes("mecha_auth.")) assertEquals(outcome, "permission denied for schema mecha_auth", probe);
      else assert(outcome.startsWith("permission denied for "), `${probe}: ${outcome}`);
    }
    const left = await sql`select c.relname, c.relkind, c.reloptions from pg_class c join pg_namespace n on n.oid = c.relnamespace
      where n.nspname = 'public' and c.relname in ('identity_link', 'webauthn_credential') order by 1`;
    assertEquals(left.map((r) => [r.relname, r.relkind, r.reloptions]), [
      ["identity_link", "v", ["security_invoker=true"]],
      ["webauthn_credential", "v", ["security_invoker=true"]],
    ]);
    assertEquals((await links.userFor({ ...alice, sub: "g-closed", name: "Still Alice" })).id, owner.id);
  },
});

// A release before mecha_auth made both tables in public, where an app's
// grants reached them; they move with their rows and without those grants,
// and an earlier release still running reads and writes through the views
// left behind, while one starting again fails rather than making empty tables.
Deno.test({
  name: "tables an earlier release made in public move with their rows and none of public's grants",
  ...opts,
  fn: async () => {
    const owner = await links.userFor({ ...alice, sub: "g-moved" });
    await sql`insert into mecha_auth.webauthn_credential (id, user_id, public_key) values ('moved', ${owner.id}, '\\x01')`;
    for (const table of ["webauthn_credential", "identity_link"]) {
      await sql.unsafe(`drop view public.${table}`);
      await sql.unsafe(`alter table mecha_auth.${table} set schema public`);
      await sql.unsafe(`grant select, insert, update, delete on public.${table} to app_user`);
    }
    await sql`DO $$ BEGIN
      IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'column_probe') THEN CREATE ROLE column_probe NOLOGIN; END IF;
    END $$`;
    await sql`grant select (user_id) on public.webauthn_credential to column_probe`;
    await sql`grant usage on schema mecha_auth to app_user`;
    await migrate();
    const [schema] = await sql`select has_schema_privilege('app_user', 'mecha_auth', 'USAGE') as usable`;
    assertEquals(schema.usable, false);
    const [column] = await sql`select has_column_privilege('column_probe', 'mecha_auth.webauthn_credential', 'user_id', 'select') as granted`;
    assertEquals(column.granted, false);
    for (const table of ["webauthn_credential", "identity_link"]) {
      const [acl] = await sql`select has_table_privilege('app_user', ${"mecha_auth." + table}, 'select, insert, update, delete') as granted`;
      assertEquals(acl.granted, false, table);

    }
    assertEquals((await sql`select user_id from mecha_auth.webauthn_credential where id = 'moved'`)[0].user_id, owner.id);
    assertEquals((await links.userFor({ ...alice, sub: "g-moved" })).id, owner.id);
    await sql`insert into webauthn_credential (id, user_id, public_key) values ('through-view', ${owner.id}, '\\x02')`;
    assertEquals((await sql`select count(*)::int as n from mecha_auth.webauthn_credential where id = 'through-view'`)[0].n, 1);
    await assertRejects(() => sql`ALTER TABLE identity_link ADD COLUMN IF NOT EXISTS issuer text`, Error, "cannot be performed on relation");
  },
});

Deno.test("a provider named without its client is refused at startup", async () => {
  const { success, stderr } = await new Deno.Command(Deno.execPath(), {
    args: ["run", "-A", "--frozen", fileURLToPath(new URL("./main.ts", import.meta.url))],
    env: { OIDC_PROVIDERS: "google" },
    stdout: "null",
    stderr: "piped",
  }).output();
  assert(!success);
  assertStringIncludes(new TextDecoder().decode(stderr), "OIDC_GOOGLE_CLIENT_ID is required");
});

// --- Handoff codes spent in the database (PRONTO-368) ---

Deno.test({
  name: "a handoff code is spent once across auth instances on one database, and expired rows are pruned",
  sanitizeResources: false,
  sanitizeOps: false,
  async fn() {
    // Made by migrate where provider sign-in is on; this file's environment names no provider.
    await sql.unsafe(handoffSpentSql());
    // Two instances: each its own connection pool, as two pods would hold.
    const other = postgres(Deno.env.get("DATABASE_URL")!);
    try {
      const a = handoffSpender(sql), b = handoffSpender(other);
      const exp = Math.floor(Date.now() / 1000) + 60;
      const jti = crypto.randomUUID();
      assertEquals(await a(jti, exp), true, "honoured once");
      assertEquals(await a(jti, exp), false, "not twice on the same instance");
      assertEquals(await b(jti, exp), false, "nor on another instance on the same database");
      // Two instances racing for one code: exactly one honours it.
      const raced = crypto.randomUUID();
      assertEquals((await Promise.all([a(raced, exp), b(raced, exp)])).filter(Boolean).length, 1);
      // A row past its code's lifetime and the grace is pruned as the next code is spent; one within it stays.
      const old = crypto.randomUUID(), recent = crypto.randomUUID();
      await sql`insert into mecha_auth.handoff_spent (jti, expires_at) values (${old}, now() - interval '1 hour'), (${recent}, now() - interval '1 minute')`;
      assertEquals(await b(crypto.randomUUID(), exp), true);
      const left = await sql`select jti from mecha_auth.handoff_spent where jti in (${old}, ${recent})`;
      assertEquals(left.map((r) => r.jti), [recent]);
      // No app role reaches it.
      const [acl] = await sql`select relacl from pg_class where oid = 'mecha_auth.handoff_spent'::regclass`;
      assertEquals(acl.relacl, null);
    } finally {
      await other.end();
    }
  },
});

// --- API keys (PRONTO-312): POST/GET /auth/keys, DELETE /auth/keys/{id}, POST /auth/key ---

// Each case runs with the app's auth config's api_keys on (AUTH_API_KEYS) unless it says otherwise.
async function withKeys<T>(on: boolean, fn: () => Promise<T>): Promise<T> {
  const was = Deno.env.get("AUTH_API_KEYS");
  Deno.env.set("AUTH_API_KEYS", on ? "true" : "false");
  try {
    return await fn();
  } finally {
    if (was === undefined) Deno.env.delete("AUTH_API_KEYS");
    else Deno.env.set("AUTH_API_KEYS", was);
  }
}
// A signed-in account (not a guest) and its session token.
async function account(): Promise<{ id: string; handle: string; token: string }> {
  const id = crypto.randomUUID();
  const handle = `key-holder-${id.slice(0, 8)}`;
  await sql`insert into app_user (id, handle) values (${id}, ${handle})`;
  return { id, handle, token: await issueUserToken(id, handle) };
}
function call(method: string, path: string, token?: string, body?: unknown): Request {
  return new Request(`http://auth:9999${path}`, {
    method,
    headers: { "content-type": "application/json", ...(token ? { authorization: `Bearer ${token}` } : {}) },
    ...(body === undefined ? {} : { body: JSON.stringify(body) }),
  });
}
async function created(token: string, label = "bot", scopes = ["read", "write"]) {
  const res = await handler(call("POST", "/auth/keys", token, { label, scopes }));
  return { status: res.status, body: await res.json() };
}
const exchange = async (key: string) => {
  const res = await handler(call("POST", "/auth/key", undefined, { key }));
  return { status: res.status, body: await res.json() };
};

Deno.test({
  name: "a key is answered once, when it is made, and only its SHA-256 is kept",
  ...opts,
  fn: () => withKeys(true, async () => {
    const a = await account();
    const { status, body } = await created(a.token, "my bot", ["read", "machines:match"]);
    assertEquals(status, 201);
    assert(/^pk_live_[A-Za-z0-9_-]{43}$/.test(body.key), `a pk_live_ key, got ${body.key}`);
    assertEquals([body.label, body.scopes], ["my bot", ["read", "machines:match"]]);
    const [row] = await sql`select owner, sha256, label from mecha_auth.api_key where id = ${body.id}`;
    assertEquals(row.owner, a.id);
    const hash = new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(body.key)));
    assertEquals(new Uint8Array(row.sha256), hash);
    const [whole] = await sql`select count(*)::int as n from mecha_auth.api_key k
      where position(convert_to(${body.key}, 'UTF8') in k.sha256) > 0 or k.label = ${body.key}`;
    assertEquals(whole.n, 0, "the key itself is stored nowhere");
  }),
});

Deno.test({
  name: "a list names the caller's live keys and never a key or its hash",
  ...opts,
  fn: () => withKeys(true, async () => {
    const a = await account();
    const b = await account();
    const one = (await created(a.token, "one")).body;
    const two = (await created(a.token, "two", ["read"])).body;
    await created(b.token, "not a's");
    const res = await handler(call("GET", "/auth/keys", a.token));
    assertEquals(res.status, 200);
    const text = await res.text();
    const { keys } = JSON.parse(text);
    assertEquals(keys.map((k: Record<string, unknown>) => [k.id, k.label, k.scopes]), [[one.id, "one", ["read", "write"]], [two.id, "two", ["read"]]]);
    for (const k of keys) assertEquals(Object.keys(k).sort(), ["created_at", "id", "label", "last_used", "scopes"]);
    assert(!text.includes(one.key) && !text.includes(two.key) && !text.includes("pk_live_"), "no key in the list");
  }),
});

Deno.test({
  name: "an account holds at most MAX_LIVE_KEYS live keys: one more is refused, and a revoke frees a place",
  ...opts,
  fn: () => withKeys(true, async () => {
    const a = await account();
    const ids = [];
    for (let i = 0; i < MAX_LIVE_KEYS; i++) {
      const { status, body } = await created(a.token, `k${i}`);
      assertEquals(status, 201);
      ids.push(body.id);
    }
    const sixth = await created(a.token, "sixth");
    assertEquals(sixth.status, 409);
    const [n] = await sql`select count(*)::int as n from mecha_auth.api_key where owner = ${a.id}`;
    assertEquals(n.n, MAX_LIVE_KEYS);
    assertEquals((await handler(call("DELETE", `/auth/keys/${ids[0]}`, a.token))).status, 204);
    assertEquals((await created(a.token, "after a revoke")).status, 201);
  }),
});

Deno.test({
  name: "an exchange gives a token of the key's owner that expires at KEY_TOKEN_TTL_S and carries kid and scp; last_used moves",
  ...opts,
  fn: () => withKeys(true, async () => {
    const a = await account();
    const k = (await created(a.token, "bot", ["read", "machines:match"])).body;
    const [before] = await sql`select last_used from mecha_auth.api_key where id = ${k.id}`;
    assertEquals(before.last_used, null);
    const at = Math.floor(Date.now() / 1000);
    const { status, body } = await exchange(k.key);
    assertEquals(status, 200);
    assertEquals(body.expires_in, KEY_TOKEN_TTL_S);
    assertEquals(KEY_TOKEN_TTL_S, 15 * 60);
    const claims = await verifyJwt(body.token);
    assertEquals([claims?.role, claims?.sub, claims?.handle, claims?.guest, claims?.kid, claims?.scp], ["app_user", a.id, a.handle, false, k.id, ["read", "machines:match"]]);
    const exp = claims?.exp as number;
    assert(exp >= at + KEY_TOKEN_TTL_S && exp <= at + KEY_TOKEN_TTL_S + 2, `exp ${exp - at}s from now`);
    const [after] = await sql`select last_used from mecha_auth.api_key where id = ${k.id}`;
    assert(after.last_used instanceof Date, "last_used is set by the exchange");
    const expired = await signJwt({ ...claims, exp: at - 1 });
    assertEquals(await verifyJwt(expired), null, "past its exp the token is no session");
  }),
});

Deno.test({
  name: "a revoked key's next exchange is 401, as is a key nobody made; another's key cannot be revoked",
  ...opts,
  fn: () => withKeys(true, async () => {
    const a = await account();
    const b = await account();
    const k = (await created(a.token)).body;
    assertEquals((await exchange(k.key)).status, 200);
    assertEquals((await handler(call("DELETE", `/auth/keys/${k.id}`, b.token))).status, 404, "b cannot revoke a's key");
    assertEquals((await exchange(k.key)).status, 200);
    assertEquals((await handler(call("DELETE", `/auth/keys/${k.id}`, a.token))).status, 204);
    assertEquals((await handler(call("DELETE", `/auth/keys/${k.id}`, a.token))).status, 404, "already revoked");
    assertEquals((await exchange(k.key)).status, 401);
    assertEquals((await exchange("pk_live_" + "x".repeat(43))).status, 401);
    assertEquals((await exchange("not a key")).status, 401);
    const listed = await (await handler(call("GET", "/auth/keys", a.token))).json();
    assertEquals(listed.keys, [], "a revoked key is not listed");
  }),
});

Deno.test({
  name: "a guest's create is 403 guest; no token, another role, a key's own token or a bad body are refused",
  ...opts,
  fn: () => withKeys(true, async () => {
    const guest = await (await handler(post("/auth/guest", {}))).json();
    const g = await created(guest.token);
    assertEquals([g.status, g.body.error], [403, "guest"]);
    assertEquals((await handler(call("GET", "/auth/keys", guest.token))).status, 403);
    assertEquals((await handler(call("POST", "/auth/keys", undefined, { label: "x", scopes: ["read"] }))).status, 401);
    const service = await signJwt({ role: "service", sub: crypto.randomUUID(), exp: Math.floor(Date.now() / 1000) + 60 });
    assertEquals((await created(service)).status, 401);
    const a = await account();
    const k = (await created(a.token)).body;
    const keyToken = (await exchange(k.key)).body.token;
    const byKey = await created(keyToken);
    assertEquals([byKey.status, byKey.body.error], [403, "key token"]);
    assertEquals((await handler(call("DELETE", `/auth/keys/${k.id}`, keyToken))).status, 403);
    assertEquals((await created(a.token, "")).status, 400);
    assertEquals((await created(a.token, "x".repeat(65))).status, 400);
    assertEquals((await created(a.token, "x", [])).status, 400);
    assertEquals((await created(a.token, "x", ["admin"])).status, 400);
    assertEquals((await created(a.token, "x", ["machines:"])).status, 400);
    const [n] = await sql`select count(*)::int as n from mecha_auth.api_key where owner = ${a.id}`;
    assertEquals(n.n, 1, "no refused create made a key");
  }),
});

Deno.test({
  name: "with api_keys off every key route is 404, and a key made while on no longer exchanges",
  ...opts,
  fn: async () => {
    const a = await account();
    const k = await withKeys(true, async () => (await created(a.token)).body);
    await withKeys(false, async () => {
      for (const req of [
        call("POST", "/auth/keys", a.token, { label: "x", scopes: ["read"] }),
        call("GET", "/auth/keys", a.token),
        call("DELETE", `/auth/keys/${k.id}`, a.token),
        call("POST", "/auth/key", undefined, { key: k.key }),
      ]) {
        const res = await handler(req);
        assertEquals([req.method, new URL(req.url).pathname, res.status], [req.method, new URL(req.url).pathname, 404]);
      }
    });
    const unset = Deno.env.get("AUTH_API_KEYS");
    Deno.env.delete("AUTH_API_KEYS");
    try {
      assertEquals((await handler(call("GET", "/auth/keys", a.token))).status, 404, "unset is off");
    } finally {
      if (unset !== undefined) Deno.env.set("AUTH_API_KEYS", unset);
    }
  },
});

// The app's gate (AUTH_API_KEYS_GATE, PRONTO-323): a function of the owner, asked per request.
async function withGate<T>(gate: string | null, fn: () => Promise<T>): Promise<T> {
  const was = Deno.env.get("AUTH_API_KEYS_GATE");
  if (gate === null) Deno.env.delete("AUTH_API_KEYS_GATE");
  else Deno.env.set("AUTH_API_KEYS_GATE", gate);
  try {
    return await fn();
  } finally {
    if (was === undefined) Deno.env.delete("AUTH_API_KEYS_GATE");
    else Deno.env.set("AUTH_API_KEYS_GATE", was);
  }
}

Deno.test({
  name: "the app's gate answers per request: closed, keys are off for that owner and a revoke still cuts one",
  ...opts,
  fn: () => withKeys(true, async () => {
    await sql`create table if not exists public.key_gate_open (owner uuid primary key)`;
    await sql`create or replace function public.key_gate_test(o uuid) returns boolean language sql stable as
      $$ select exists (select 1 from public.key_gate_open where owner = o) $$`;
    const a = await account();
    await withGate("public.key_gate_test", async () => {
      assertEquals((await created(a.token)).status, 404, "closed: no key is made");
      assertEquals((await handler(call("GET", "/auth/keys", a.token))).status, 404, "closed: no list");
      await sql`insert into public.key_gate_open (owner) values (${a.id})`;
      const k = (await created(a.token)).body;
      assertEquals((await exchange(k.key)).status, 200, "open: the key is exchanged");
      await sql`delete from public.key_gate_open where owner = ${a.id}`;
      assertEquals((await exchange(k.key)).status, 404, "closed again, with no deploy: no token");
      const res = await handler(call("DELETE", `/auth/keys/${k.id}`, a.token));
      assertEquals(res.status, 204, "a revoke is never refused");
    });
    assertEquals((await created(a.token)).status, 201, "no gate: keys answer to AUTH_API_KEYS alone");
    await withGate("nope; drop table x", async () => {
      assertThrows(() => apiKeysGate(), Error, "schema.name");
      assertEquals((await handler(call("GET", "/auth/keys", a.token))).status, 500, "never run as SQL");
    });
  }),
});

// The app's hook on an exchange (AUTH_KEY_EXCHANGED_HOOK, PRONTO-316): called with the owner, and a failure issues no token.
async function withHook<T>(hook: string | null, fn: () => Promise<T>): Promise<T> {
  const was = Deno.env.get("AUTH_KEY_EXCHANGED_HOOK");
  if (hook === null) Deno.env.delete("AUTH_KEY_EXCHANGED_HOOK");
  else Deno.env.set("AUTH_KEY_EXCHANGED_HOOK", hook);
  try {
    return await fn();
  } finally {
    if (was === undefined) Deno.env.delete("AUTH_KEY_EXCHANGED_HOOK");
    else Deno.env.set("AUTH_KEY_EXCHANGED_HOOK", was);
  }
}

Deno.test({
  name: "the app's keyExchanged hook is called with the owner on an exchange, not on make or list, and a failure issues no token",
  ...opts,
  fn: () => withKeys(true, async () => {
    await sql`create table if not exists public.key_hook_log (owner uuid)`;
    await sql`create table if not exists public.key_hook_fail (owner uuid primary key)`;
    await sql`create or replace function public.key_hook_test(o uuid) returns void language plpgsql as
      $$ begin
        if exists (select 1 from public.key_hook_fail where owner = o) then raise exception 'hook refused'; end if;
        insert into public.key_hook_log (owner) values (o);
      end $$`;
    const a = await account();
    const calls = async () => (await sql`select count(*)::int as n from public.key_hook_log where owner = ${a.id}`)[0].n;
    await withHook("public.key_hook_test", async () => {
      const k = (await created(a.token)).body;
      assertEquals((await handler(call("GET", "/auth/keys", a.token))).status, 200);
      assertEquals(await calls(), 0, "not called on make or list");
      assertEquals((await exchange(k.key)).status, 200);
      assertEquals(await calls(), 1, "called once with the owner on exchange");
      await sql`insert into public.key_hook_fail (owner) values (${a.id})`;
      const res = await exchange(k.key);
      assertEquals(res.status, 500, "a failing hook answers 500");
      assertEquals(res.body.token, undefined, "and no token is issued");
      assertEquals(await calls(), 1);
      assertEquals((await handler(call("DELETE", `/auth/keys/${k.id}`, a.token))).status, 204, "a revoke never calls it");
      await sql`delete from public.key_hook_fail where owner = ${a.id}`;
    });
    const k2 = (await created(a.token)).body;
    assertEquals((await exchange(k2.key)).status, 200, "no hook: nothing is called");
    assertEquals(await calls(), 1);
    await withHook("nope; drop table x", async () => {
      assertThrows(() => keyExchangedHook(), Error, "schema.name");
      assertEquals((await exchange(k2.key)).status, 500, "never run as SQL");
    });
  }),
});

Deno.test({
  name: "with keys off a migration makes no key table",
  ...opts,
  fn: async () => {
    await sql`drop function if exists mecha_auth.api_key_owner(bytea)`;
    await sql`drop table if exists mecha_auth.api_key`;
    await withKeys(false, migrate);
    assertEquals((await sql`select to_regclass('mecha_auth.api_key') as t`)[0].t, null);
    await withKeys(true, migrate);
    assertEquals((await sql`select to_regclass('mecha_auth.api_key') as t`)[0].t, "mecha_auth.api_key");
  },
});

Deno.test({
  name: "the key table is the auth service's: no app role reaches it, and only api_key_owner reads it by hash",
  ...opts,
  fn: async () => {
    const [grants] = await sql`select count(*)::int as n from information_schema.role_table_grants
      where table_schema = 'mecha_auth' and table_name = 'api_key' and grantee <> current_user`;
    assertEquals(grants.n, 0);
    const [fn] = await sql`select p.prosecdef, p.proacl from pg_proc p where p.oid = 'mecha_auth.api_key_owner(bytea)'::regprocedure`;
    assertEquals(fn.prosecdef, true);
    assert(fn.proacl !== null && !/(^|[{,])=X\//.test(String(fn.proacl)), `PUBLIC's execute revoked, got ${fn.proacl}`);
    assertEquals((await sql`select to_regclass('public.api_key') as v`)[0].v, null, "no view in public for a table no release had there");
    const [exempt] = await sql`select count(*)::int as n from mecha.rls_exempt where table_name = 'mecha_auth.api_key'`;
    assertEquals(exempt.n, 1);
  },
});

// Last, and it has to be: Deno runs tests in source order, and this closes the
// pool every test above it queries through.
Deno.test({
  name: "teardown",
  ...opts,
  fn: async () => {
    await sql.end();
  },
});
