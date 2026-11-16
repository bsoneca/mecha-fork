// POST /auth/studio against a Studio of the test's own: a key pair generated here, its JWKS served by a
// Deno.serve of the test's, and Postgres as main_test.ts needs it (DATABASE_URL and the rest of the
// environment main.ts reads). Each case is a way a play token could be forged, replayed, misdirected or
// carried by a JWKS that is not to be trusted; AUTH_GUESTS=off is held to the routes it closes.
import { assert, assertEquals, assertRejects, assertThrows } from "jsr:@std/assert@1.0.13";
import "./main_test_env.ts";
import { cleanStudioJti, clientIp, handler, migrate, sql, verifyJwt } from "./main.ts";
import { encodeBase64Url } from "./jwt.ts";
import { KEYS_FRESH_MS, KEYS_STALE_MS, REFETCH_MS, rateLimit, studioFrom, studioKeys } from "./studio.ts";

const ISS = "https://studio.test";
const ORIGIN = "https://game-a.test";
const SUB = "3f0c1c2e-8d7a-4a55-9a53-0d2f6d0b7e11";
const opts = { sanitizeResources: false, sanitizeOps: false };
const enc = new TextEncoder();
const b64 = (s: string) => encodeBase64Url(enc.encode(s));
const now = () => Math.floor(Date.now() / 1000);

await sql`CREATE TABLE IF NOT EXISTS app_user (
  id uuid primary key,
  handle text not null unique,
  created_at timestamptz not null default now()
)`;

type Env = Record<string, string | undefined>;
async function withEnv<T>(env: Env, fn: () => Promise<T>): Promise<T> {
  const was = Object.fromEntries(Object.keys(env).map((k) => [k, Deno.env.get(k)]));
  for (const [k, v] of Object.entries(env)) v === undefined ? Deno.env.delete(k) : Deno.env.set(k, v);
  try {
    return await fn();
  } finally {
    for (const [k, v] of Object.entries(was)) v === undefined ? Deno.env.delete(k) : Deno.env.set(k, v);
  }
}

// The table is made where Studio is configured.
await withEnv({ STUDIO_JWKS_URL: "http://localhost:1/jwks", STUDIO_ISS: ISS, PUBLIC_ORIGIN: ORIGIN }, migrate);

const generate = (curve = "P-256") => crypto.subtle.generateKey({ name: "ECDSA", namedCurve: curve }, true, ["sign", "verify"]) as Promise<CryptoKeyPair>;
const keys = await generate();
const publicJwk = { ...(await crypto.subtle.exportKey("jwk", keys.publicKey)), kid: "k1", use: "sig", alg: "ES256" };

/** A JWS over `claims`, signed by `key` (the test key unless said) as the header says. */
async function jws(claims: Record<string, unknown>, head: Record<string, unknown> = {}, key: CryptoKey = keys.privateKey): Promise<string> {
  const h = { alg: "ES256", kid: "k1", typ: "JWT", ...head };
  const input = `${b64(JSON.stringify(h))}.${b64(JSON.stringify(claims))}`;
  const sig = await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, key, enc.encode(input));
  return `${input}.${encodeBase64Url(new Uint8Array(sig))}`;
}
let jtis = 0;
const claims = (over: Record<string, unknown> = {}) => ({
  iss: ISS,
  aud: ORIGIN,
  sub: SUB,
  handle: "lia",
  iat: now(),
  exp: now() + 60,
  jti: `jti-${Date.now()}-${++jtis}`,
  ...over,
});

type Jwks = { hits: number; respond: () => Response };
/** A JWKS server on a port of its own; `url` is what STUDIO_JWKS_URL names, so each case has keys of its own. */
function serveJwks(respond: (jwks: Jwks) => Response = () => Response.json({ keys: [publicJwk] })) {
  const jwks: Jwks = { hits: 0, respond: () => new Response(null, { status: 500 }) };
  const server = Deno.serve({ port: 0, onListen() {} }, () => {
    jwks.hits++;
    return jwks.respond();
  });
  jwks.respond = () => respond(jwks);
  return { jwks, url: `http://localhost:${server.addr.port}/jwks`, [Symbol.asyncDispose]: () => server.shutdown() };
}

let ips = 0;
const ip = () => `10.0.${Math.floor(++ips / 250)}.${ips % 250}`;
const call = (path: string, body: unknown, headers: Record<string, string> = {}) =>
  new Request(`http://auth:9999${path}`, { method: "POST", headers: { "content-type": "application/json", "x-forwarded-for": ip(), ...headers }, body: JSON.stringify(body) });
const studio = (token: unknown, headers: Record<string, string> = {}) => call("/auth/studio", { token }, headers);

async function inStudio<T>(url: string, fn: () => Promise<T>): Promise<T> {
  return await withEnv({ STUDIO_JWKS_URL: url, STUDIO_ISS: ISS, PUBLIC_ORIGIN: ORIGIN }, fn);
}
async function refused(url: string, token: string, status: number, reason: string) {
  const res = await inStudio(url, () => handler(studio(token)));
  const text = await res.text();
  assertEquals(res.status, status, text);
  assertEquals(JSON.parse(text).reason, reason);
  assert(!text.includes(token.slice(0, 40)), "the token is never echoed");
}
const userRow = async (id: string) => (await sql`select handle from app_user where id = ${id}`)[0];
const jtiRow = async (jti: string) => (await sql`select jti from mecha_auth.studio_jti where jti = ${jti}`)[0];

Deno.test({
  name: "a valid play token is a signed-in session for its player, made once",
  ...opts,
  fn: async () => {
    await sql`delete from app_user where id = ${SUB}`;
    await using s = serveJwks();
    const c = claims();
    const token = await jws(c);
    const res = await inStudio(s.url, () => handler(studio(token)));
    assertEquals(res.status, 200);
    const body = await res.json();
    const session = await verifyJwt(body.token);
    assertEquals(session?.sub, SUB);
    assertEquals(session?.guest, false);
    assertEquals(session?.role, "app_user");
    assertEquals(session?.handle, "lia");
    // Half a day, not the week's.
    const life = (session!.exp as number) - now();
    assert(life > 12 * 3600 - 10 && life <= 12 * 3600, `${life}`);
    assertEquals(body.user, { id: SUB, handle: "lia", guest: false });
    assertEquals((await userRow(SUB)).handle, "lia");
    // The same token again is a replay, and so is its twin.
    await refused(s.url, token, 409, "replay");
  },
});

Deno.test({
  name: "a returning player keeps their row, and takes the handle Studio now names",
  ...opts,
  fn: async () => {
    await sql`delete from app_user where id = ${SUB}`;
    await using s = serveJwks();
    for (const handle of ["lia", "lia-2"]) {
      const res = await inStudio(s.url, async () => await handler(studio(await jws(claims({ handle })))));
      assertEquals(res.status, 200);
    }
    assertEquals((await sql`select handle from app_user where id = ${SUB}`).map((r) => r.handle), ["lia-2"]);
  },
});

Deno.test({
  name: "a token is refused, with its reason, unless every claim holds",
  ...opts,
  fn: async () => {
    await using s = serveJwks();
    const bad: [string, Record<string, unknown>][] = [
      ["aud", { aud: "https://game-b.test" }],
      ["iss", { iss: "https://elsewhere.test" }],
      ["expired", { iat: now() - 120, exp: now() - 60 }],
      ["iat", { iat: now() + 300, exp: now() + 360 }],
      ["lifetime", { exp: now() + 3600 }],
      ["sub", { sub: "not-a-uuid" }],
      ["handle", { handle: 7 }],
      ["jti", { jti: undefined }],
      ["claims", { exp: "soon" }],
    ];
    for (const [reason, over] of bad) await refused(s.url, await jws(claims(over)), 401, reason);
    // exp has no leeway: a token that ends this second is over.
    await refused(s.url, await jws(claims({ exp: now() })), 401, "expired");
  },
});

Deno.test({
  name: "only ES256 under a kid Studio publishes: HS256 with the public key, none, an unknown kid and a P-384 key are refused",
  ...opts,
  fn: async () => {
    const p384 = await generate("P-384");
    const p384Jwk = { ...(await crypto.subtle.exportKey("jwk", p384.publicKey)), kid: "k384", use: "sig" };
    await using s = serveJwks(() => Response.json({ keys: [publicJwk, p384Jwk] }));
    // HS256, its MAC made with the JWKS's own public key bytes.
    const hmacKey = await crypto.subtle.importKey("raw", enc.encode(JSON.stringify(publicJwk)), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
    const input = `${b64(JSON.stringify({ alg: "HS256", kid: "k1" }))}.${b64(JSON.stringify(claims()))}`;
    const mac = encodeBase64Url(new Uint8Array(await crypto.subtle.sign("HMAC", hmacKey, enc.encode(input))));
    await refused(s.url, `${input}.${mac}`, 401, "alg");
    const none = `${b64(JSON.stringify({ alg: "none", kid: "k1" }))}.${b64(JSON.stringify(claims()))}.`;
    await refused(s.url, none, 401, "alg");
    await refused(s.url, await jws(claims(), { kid: "other" }), 401, "kid");
    await refused(s.url, await jws(claims(), { kid: undefined }), 401, "kid");
    await refused(s.url, await jws(claims(), { kid: "k384" }, p384.privateKey), 401, "kid");
    // A good key's kid with another key's signature.
    await refused(s.url, await jws(claims(), {}, (await generate()).privateKey), 401, "signature");
    // A body that is no token at all.
    await refused(s.url, "a.b", 401, "malformed");
    const res = await inStudio(s.url, () => handler(call("/auth/studio", { token: 5 })));
    assertEquals(res.status, 401);
  },
});

Deno.test({
  name: "a key that is not EC, P-256 and for signing is not a key",
  ...opts,
  fn: async () => {
    await using s = serveJwks(() => Response.json({ keys: [{ ...publicJwk, use: "enc" }] }));
    await refused(s.url, await jws(claims()), 401, "jwks");
    await using t = serveJwks(() => Response.json({ keys: [{ ...publicJwk, kty: "RSA" }] }));
    await refused(t.url, await jws(claims()), 401, "jwks");
  },
});

Deno.test({
  name: "the JWKS fetch refuses a redirect, a body over 64 KB, and fails closed with nothing cached",
  ...opts,
  fn: async () => {
    // A redirect to a perfectly good JWKS is still a refusal, and the target is never asked.
    await using target = serveJwks();
    await using redirecting = serveJwks(() => new Response(null, { status: 302, headers: { location: target.url } }));
    await refused(redirecting.url, await jws(claims()), 401, "jwks");
    assertEquals(target.jwks.hits, 0);
    // 100 KB of an otherwise valid document.
    await using big = serveJwks(() => Response.json({ keys: [publicJwk], pad: "x".repeat(100 * 1024) }));
    await refused(big.url, await jws(claims()), 401, "jwks");
    // The cap is on what is read, not what is promised: a body that says nothing of its length.
    await using stream = serveJwks(() =>
      new Response(new ReadableStream({ start(c) { c.enqueue(enc.encode(`{"keys":[${JSON.stringify(publicJwk)}],"pad":"`)); c.enqueue(enc.encode("x".repeat(100 * 1024))); c.enqueue(enc.encode(`"}`)); c.close(); } }))
    );
    await refused(stream.url, await jws(claims()), 401, "jwks");
    // A server that fails, and one that is not there.
    await using down = serveJwks(() => new Response("no", { status: 503 }));
    await refused(down.url, await jws(claims()), 401, "jwks");
    await refused("http://localhost:1/jwks", await jws(claims()), 401, "jwks");
  },
});

Deno.test({
  name: "a JWKS that does not answer in 3 s is a failure",
  ...opts,
  fn: async () => {
    await using slow = serveJwks(() => new Response(new ReadableStream({ start() {} })));
    const t0 = Date.now();
    await refused(slow.url, await jws(claims()), 401, "jwks");
    const took = Date.now() - t0;
    assert(took >= 2900 && took < 6000, `${took} ms`);
  },
});

Deno.test({
  name: "no fetch goes anywhere but STUDIO_JWKS_URL, whatever iss says",
  ...opts,
  fn: async () => {
    await using canary = serveJwks();
    await using s = serveJwks();
    const asked: string[] = [];
    const real = globalThis.fetch;
    globalThis.fetch = ((input: Request | URL | string, init?: RequestInit) => {
      asked.push(String(input instanceof Request ? input.url : input));
      return real(input, init);
    }) as typeof fetch;
    try {
      // iss (and a jku and x5u for good measure) name the canary; it is refused for its iss, and never asked.
      const token = await jws(claims({ iss: canary.url, jku: canary.url }), { jku: canary.url, x5u: canary.url });
      await refused(s.url, token, 401, "iss");
      // A token this deployment accepts is checked against its own URL alone.
      await inStudio(s.url, async () => assertEquals((await handler(studio(await jws(claims(), { jku: canary.url })))).status, 200));
    } finally {
      globalThis.fetch = real;
    }
    assertEquals(canary.jwks.hits, 0);
    assertEquals([...new Set(asked)], [s.url]);
  },
});

Deno.test({
  name: "keys are held 10 minutes, fetched again for an unknown kid once a minute, and kept an hour when that fails",
  ...opts,
  fn: async () => {
    await using s = serveJwks();
    let t = 1_000_000;
    const key = studioKeys(s.url, () => fetch, () => t);
    assertEquals((await key("k1"))?.kty, "EC");
    assertEquals(s.jwks.hits, 1);
    // Held: no fetch for a key it has.
    t += KEYS_FRESH_MS - 1;
    await key("k1");
    assertEquals(s.jwks.hits, 1);
    // An unknown kid asks again, but not twice in a minute.
    t = 2_000_000;
    s.jwks.respond = () => Response.json({ keys: [publicJwk] });
    const key2 = studioKeys(s.url, () => fetch, () => t);
    await key2("k1");
    const base = s.jwks.hits;
    // The fetch just made counts: a minute has to pass before an unknown kid asks again.
    t += 1000;
    assertEquals(await key2("nope"), undefined);
    assertEquals(s.jwks.hits, base);
    t += REFETCH_MS;
    assertEquals(await key2("nope"), undefined);
    assertEquals(s.jwks.hits, base + 1);
    const fetchedAt = t;
    t += 1000;
    assertEquals(await key2("nope"), undefined);
    assertEquals(await key2("nope"), undefined);
    assertEquals(s.jwks.hits, base + 1);
    // Old, and the refetch fails: the keys held are used until an hour has passed.
    s.jwks.respond = () => new Response(null, { status: 500 });
    t = fetchedAt + KEYS_FRESH_MS;
    assertEquals((await key2("k1"))?.kty, "EC");
    t = fetchedAt + KEYS_STALE_MS - 1;
    assertEquals((await key2("k1"))?.kty, "EC");
    t = fetchedAt + KEYS_STALE_MS + 1;
    await assertRejects(() => key2("k1"), Error, "no Studio keys");
    // And a service that never had keys fails closed.
    const none = studioKeys(s.url, () => fetch, () => t);
    await assertRejects(() => none("k1"), Error, "no Studio keys");
  },
});

Deno.test({
  name: "a service that has Studio's keys still verifies while a refetch fails",
  ...opts,
  fn: async () => {
    await using s = serveJwks();
    assertEquals((await inStudio(s.url, async () => await handler(studio(await jws(claims()))))).status, 200);
    s.jwks.respond = () => new Response(null, { status: 500 });
    // An unknown kid refetches, fails, and is refused as unknown; the key held still verifies.
    await refused(s.url, await jws(claims(), { kid: "rotated" }), 401, "kid");
    assertEquals((await inStudio(s.url, async () => await handler(studio(await jws(claims()))))).status, 200);
  },
});

Deno.test({
  name: "an upsert that fails leaves the token unspent, and it passes once the fault is gone",
  ...opts,
  fn: async () => {
    await sql`delete from app_user where id = ${SUB}`;
    await sql`CREATE OR REPLACE FUNCTION studio_test_fault() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN
      IF NEW.handle = 'boom' THEN RAISE EXCEPTION 'injected'; END IF; RETURN NEW; END $$`;
    await sql`DROP TRIGGER IF EXISTS studio_test_fault ON app_user`;
    await sql`CREATE TRIGGER studio_test_fault BEFORE INSERT ON app_user FOR EACH ROW EXECUTE FUNCTION studio_test_fault()`;
    try {
      await using s = serveJwks();
      const c = claims({ handle: "boom" });
      const token = await jws(c);
      const res = await inStudio(s.url, () => handler(studio(token)));
      assertEquals(res.status, 500);
      assertEquals(await jtiRow(c.jti), undefined);
      assertEquals(await userRow(SUB), undefined);
      await sql`DROP TRIGGER studio_test_fault ON app_user`;
      const again = await inStudio(s.url, () => handler(studio(token)));
      assertEquals(again.status, 200);
      assert(await jtiRow(c.jti));
      assertEquals((await userRow(SUB)).handle, "boom");
    } finally {
      await sql`DROP TRIGGER IF EXISTS studio_test_fault ON app_user`;
    }
  },
});

Deno.test({
  name: "a handle another account holds is taken with the player's id after it, and only if that is free too",
  ...opts,
  fn: async () => {
    await sql`delete from app_user where id = ${SUB}`;
    await sql`delete from app_user where handle in ('taken', ${"taken-" + SUB.slice(0, 8)})`;
    await sql`insert into app_user (id, handle) values (gen_random_uuid(), 'taken')`;
    await using s = serveJwks();
    const c = claims({ handle: "taken" });
    const res = await inStudio(s.url, async () => await handler(studio(await jws(c))));
    assertEquals(res.status, 200);
    const derived = `taken-${SUB.slice(0, 8)}`;
    const body = await res.json();
    assertEquals(body.user.handle, derived);
    assertEquals((await verifyJwt(body.token))?.handle, derived);
    assertEquals((await userRow(SUB)).handle, derived);
    assert(await jtiRow(c.jti));
    // Both held by others: nothing is made and the token is not spent.
    await sql`delete from app_user where id = ${SUB}`;
    await sql`insert into app_user (id, handle) values (gen_random_uuid(), ${derived})`;
    const c2 = claims({ handle: "taken" });
    const res2 = await inStudio(s.url, async () => await handler(studio(await jws(c2))));
    assertEquals(res2.status, 409);
    assertEquals((await res2.json()).reason, "handle_taken");
    assertEquals(await jtiRow(c2.jti), undefined);
    assertEquals(await userRow(SUB), undefined);
    await sql`delete from app_user where handle in ('taken', ${derived})`;
  },
});

Deno.test({
  name: "a spent token's row is deleted once past exp, and refused until then",
  ...opts,
  fn: async () => {
    await using s = serveJwks();
    await sql`insert into mecha_auth.studio_jti (jti, exp) values ('old-one', now() - interval '10 minutes'), ('recent-one', now() - interval '1 minute'), ('live-one', now() + interval '1 minute')
      on conflict (jti) do update set exp = excluded.exp`;
    await cleanStudioJti();
    assertEquals(await jtiRow("old-one"), undefined);
    // Past exp by less than the 5 minutes of grace a database clock may differ by: kept.
    assert(await jtiRow("recent-one"));
    assert(await jtiRow("live-one"));
    // Another call cleans too, and the live one is still a replay.
    await sql`insert into mecha_auth.studio_jti (jti, exp) values ('old-two', now() - interval '6 minutes')`;
    const fresh = await inStudio(s.url, async () => await handler(studio(await jws(claims()))));
    assertEquals(fresh.status, 200);
    assertEquals(await jtiRow("old-two"), undefined);
    await refused(s.url, await jws(claims({ jti: "live-one" })), 409, "replay");
    // A token past exp is refused for that; its jti is no longer asked.
    await refused(s.url, await jws(claims({ jti: "old-one", iat: now() - 100, exp: now() - 40 })), 401, "expired");
  },
});

Deno.test({
  name: "the 61st call a minute from one address is 429, and another address is not held to it",
  ...opts,
  fn: async () => {
    await using s = serveJwks();
    const from = "203.0.113.9";
    await inStudio(s.url, async () => {
      for (let i = 1; i <= 60; i++) assertEquals((await handler(studio("junk", { "x-forwarded-for": from }))).status, 401, `call ${i}`);
      const res = await handler(studio("junk", { "x-forwarded-for": from }));
      assertEquals(res.status, 429);
      assertEquals(res.headers.get("retry-after"), "60");
      // A client's own entry comes first; the proxy's is the address that counts.
      assertEquals((await handler(studio("junk", { "x-forwarded-for": `${from}, 198.51.100.2` }))).status, 401);
      assertEquals((await handler(studio("junk", { "x-forwarded-for": "203.0.113.10" }))).status, 401);
    });
    const limit = rateLimit(2, 1000, (() => { let t = 0; return () => (t += 400); })());
    assertEquals([limit("a"), limit("a"), limit("a"), limit("a")], [true, true, false, true]);
  },
});

Deno.test({
  name: "the route is a 404 with no Studio setting, and a partial or malformed one is refused at startup",
  ...opts,
  fn: async () => {
    await using s = serveJwks();
    const token = await jws(claims());
    const none = { STUDIO_JWKS_URL: undefined, STUDIO_ISS: undefined, PUBLIC_ORIGIN: undefined };
    assertEquals((await withEnv(none, () => handler(studio(token)))).status, 404);
    assertEquals((await withEnv({ ...none, STUDIO_ISS: "" }, () => handler(studio(token)))).status, 404);
    assertEquals(s.jwks.hits, 0);
    assertEquals(studioFrom(() => undefined), null);
    const all: Env = { STUDIO_JWKS_URL: "https://s.test/k", STUDIO_ISS: ISS, PUBLIC_ORIGIN: ORIGIN };
    assertEquals(studioFrom((n) => all[n])?.jwks, "https://s.test/k");
    assertEquals(studioFrom((n) => ({ ...all, STUDIO_JWKS_URL: "http://localhost:8/k" })[n])?.origin, ORIGIN);
    const refuses = (over: Env, text: string) => assertThrows(() => studioFrom((n) => ({ ...all, ...over })[n]), Error, text);
    for (const name of Object.keys(all)) refuses({ [name]: undefined }, `${name} must be set`);
    refuses({ STUDIO_JWKS_URL: "http://s.test/k" }, "is not https");
    refuses({ PUBLIC_ORIGIN: `${ORIGIN}/` }, "PUBLIC_ORIGIN");
    refuses({ STUDIO_ISS: `${ISS}/path` }, "STUDIO_ISS");
    refuses({ STUDIO_ISS: "studio.test" }, "STUDIO_ISS");
  },
});

const own = [
  ["/auth/guest", {}],
  ["/auth/guest/refresh", {}],
  ["/auth/register/start", {}],
  ["/auth/register/verify", {}],
  ["/auth/login/start", {}],
  ["/auth/login/verify", {}],
] as const;

Deno.test({
  name: "AUTH_GUESTS=off closes the game's own sign-ins, the provider's among them",
  ...opts,
  fn: async () => {
    await withEnv({ AUTH_GUESTS: "off", OIDC_PROVIDERS: undefined }, async () => {
      for (const [path, body] of own) assertEquals((await handler(call(path, body))).status, 403, path);
      for (const path of ["/auth/oidc/google/start", "/auth/oidc/google/callback", "/auth/oidc/session", "/auth/oidc/adopt", "/auth/oidc/signout"]) {
        const method = path.endsWith("start") || path.endsWith("callback") ? "GET" : "POST";
        assertEquals((await handler(new Request(`http://auth:9999${path}`, { method }))).status, 403, path);
      }
      // The rest of the surface is as it was.
      assertEquals((await handler(new Request("http://auth:9999/auth/whoami"))).status, 401);
      assertEquals((await handler(new Request("http://auth:9999/auth/nowhere"))).status, 404);
    });
    // Studio's route stays open with guests off.
    await using s = serveJwks();
    await withEnv({ AUTH_GUESTS: "off" }, async () => {
      assertEquals((await inStudio(s.url, async () => await handler(studio(await jws(claims()))))).status, 200);
    });
  },
});

Deno.test({
  name: "AUTH_GUESTS=off makes no guest row",
  ...opts,
  fn: async () => {
    const before = (await sql`select count(*)::int as n from app_user`)[0].n;
    await withEnv({ AUTH_GUESTS: "off" }, async () => assertEquals((await handler(call("/auth/guest", {}))).status, 403));
    assertEquals((await sql`select count(*)::int as n from app_user`)[0].n, before);
  },
});

Deno.test({
  name: "with AUTH_GUESTS unset or on, the sign-ins answer as they did",
  ...opts,
  fn: async () => {
    for (const value of [undefined, "", "on"]) {
      await withEnv({ AUTH_GUESTS: value }, async () => {
        const res = await handler(call("/auth/guest", {}));
        assertEquals(res.status, 200, String(value));
        assertEquals((await res.json()).user.guest, true);
        assertEquals((await handler(call("/auth/register/start", {}))).status, 200);
        assertEquals((await handler(call("/auth/login/start", {}))).status, 200);
      });
    }
  },
});

/** The service started with `env` on top of what it needs, and what it said when it stopped. */
const startup = async (env: Record<string, string>) => {
  const out = await new Deno.Command(Deno.execPath(), {
    args: ["eval", "--frozen", `import("./main.ts")`],
    env: { DATABASE_URL: Deno.env.get("DATABASE_URL")!, AUTH_STATEMENT_TIMEOUT_MS: "5000", PGRST_JWT_SECRET: "x", WEBAUTHN_RP_ID: "localhost", WEBAUTHN_ORIGIN: "https://localhost:*", ...env },
    cwd: new URL(".", import.meta.url).pathname,
    stdout: "null",
    stderr: "piped",
  }).output();
  return { ok: out.success, stderr: new TextDecoder().decode(out.stderr) };
};

Deno.test({
  name: "AUTH_GUESTS, AUTH_TRUSTED_HOPS and a partial Studio setting are refused at startup",
  ...opts,
  fn: async () => {
    const guests = await startup({ AUTH_GUESTS: "maybe" });
    assert(!guests.ok);
    assert(guests.stderr.includes("AUTH_GUESTS must be on or off, not maybe"));
    for (const hops of ["0", "-1", "1.5", "two"]) {
      const r = await startup({ AUTH_TRUSTED_HOPS: hops });
      assert(!r.ok, hops);
      assert(r.stderr.includes("AUTH_TRUSTED_HOPS must be a whole number from 1"), r.stderr);
    }
    const partial = await startup({ STUDIO_ISS: ISS });
    assert(!partial.ok);
    assert(partial.stderr.includes("STUDIO_JWKS_URL and PUBLIC_ORIGIN must be set"), partial.stderr);
  },
});

Deno.test({
  name: "the client is the entry AUTH_TRUSTED_HOPS from the end of X-Forwarded-For, else the socket's",
  ...opts,
  fn: async () => {
    const req = (xff?: string) => new Request("http://auth:9999/", { headers: xff === undefined ? {} : { "x-forwarded-for": xff } });
    const sock = { remoteAddr: { hostname: "192.0.2.1" } };
    await withEnv({ AUTH_TRUSTED_HOPS: undefined }, async () => {
      assertEquals(clientIp(req("1.1.1.1, 2.2.2.2"), sock), "2.2.2.2");
      assertEquals(clientIp(req("2.2.2.2"), sock), "2.2.2.2");
      assertEquals(clientIp(req(), sock), "192.0.2.1");
    });
    await withEnv({ AUTH_TRUSTED_HOPS: "2" }, async () => {
      // Spoofed first entry, a CDN's address, the proxy's: the client is the second from the end.
      assertEquals(clientIp(req("9.9.9.9, 1.1.1.1, 2.2.2.2"), sock), "1.1.1.1");
      assertEquals(clientIp(req("2.2.2.2"), sock), "192.0.2.1");
      assertEquals(clientIp(req(), sock), "192.0.2.1");
    });
    // The limit follows it: with 2 hops two proxies' addresses are one client.
    await using s = serveJwks();
    await withEnv({ AUTH_TRUSTED_HOPS: "2", STUDIO_JWKS_URL: s.url, STUDIO_ISS: ISS, PUBLIC_ORIGIN: ORIGIN }, async () => {
      const as = (first: string) => studio("junk", { "x-forwarded-for": `${first}, 198.51.100.77, 10.1.1.1` });
      for (let i = 0; i < 60; i++) assertEquals((await handler(as(`7.7.${i}.1`))).status, 401);
      assertEquals((await handler(as("7.7.99.1"))).status, 429);
    });
  },
});

Deno.test({
  name: "a handle or jti Postgres cannot store is refused as a claim, not a fault",
  ...opts,
  fn: async () => {
    await using s = serveJwks();
    await refused(s.url, await jws(claims({ handle: "li\u0000a" })), 401, "claims");
    await refused(s.url, await jws(claims({ jti: "j\u0000ti" })), 401, "claims");
  },
});

Deno.test({
  name: "one fetch serves every caller that waits on it, and with no keys a failed fetch is not retried within a minute",
  ...opts,
  fn: async () => {
    let release: () => void = () => {};
    const gate = new Promise<void>((r) => release = r);
    await using s = serveJwks(() => new Response(new ReadableStream({ async start(c) { await gate; c.enqueue(enc.encode(JSON.stringify({ keys: [publicJwk] }))); c.close(); } })));
    const key = studioKeys(s.url);
    const three = Promise.all([key("k1"), key("k1"), key("k1")]);
    await new Promise((r) => setTimeout(r, 50));
    release();
    assertEquals((await three).map((k) => k?.kty), ["EC", "EC", "EC"]);
    assertEquals(s.jwks.hits, 1);
    // A kid new at the keys' rotation, asked during a refresh, waits for it and is served.
    let t = 5_000_000;
    let rotated = false;
    await using r = serveJwks(() => Response.json({ keys: rotated ? [{ ...publicJwk, kid: "k2" }, publicJwk] : [publicJwk] }));
    const rot = studioKeys(r.url, () => fetch, () => t);
    await rot("k1");
    rotated = true;
    t += REFETCH_MS;
    const [a, b] = await Promise.all([rot("k2"), rot("k2")]);
    assertEquals([a?.kty, b?.kty], ["EC", "EC"]);
    assertEquals(r.jwks.hits, 2);
    // Nothing held and the fetch failing: asked once, then refused without asking until a minute has passed.
    await using down = serveJwks(() => new Response(null, { status: 500 }));
    const none = studioKeys(down.url, () => fetch, () => t);
    for (let i = 0; i < 3; i++) await assertRejects(() => none("k1"), Error, "no Studio keys");
    assertEquals(down.jwks.hits, 1);
    t += REFETCH_MS;
    await assertRejects(() => none("k1"), Error, "no Studio keys");
    assertEquals(down.jwks.hits, 2);
  },
});

Deno.test({
  name: "the limiter holds at most maxKeys addresses, the oldest going first",
  ...opts,
  fn: () => {
    let t = 0;
    const limit = rateLimit(1, 60_000, () => ++t, 3);
    for (const k of ["a", "b", "c"]) assertEquals(limit(k), true);
    assertEquals(limit("a"), false);
    // "d" evicts "a", the oldest; "a" starts a new window.
    assertEquals(limit("d"), true);
    assertEquals(limit("a"), true);
    // That evicted "b": it has a fresh window too, while "d" is still held to its one call.
    assertEquals(limit("d"), false);
  },
});
