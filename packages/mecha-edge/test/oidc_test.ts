// Provider sign-in in the edge cluster: the auth service's oidc.ts answered by
// createEdgeCluster over PGlite, against an OpenID provider of the test's own
// on a local port, as a browser walks it — start, the provider's
// authorization, the callback, the session the terminal adopts — and the
// person it makes, whose rows are theirs. oidc.ts's own tests cover the ways a
// sign-in could be forged; these cover what the edge adds: the links on
// PGlite, the door's origin, and a directory an earlier edge left. The same
// walk through the Worker under wrangler dev is oidc-worker_test.ts.
import assert from 'node:assert/strict'
import { PGlite } from '@electric-sql/pglite'
import { providersFrom } from '../../../services/auth/oidc.ts'
import { createEdgeCluster } from '../src/cluster.ts'
import { CLIENT, CLIENT_SECRET, cookiesOf, provider } from './oidc-provider.ts'

const door = 'https://edge.test'
const secret = 'edge-oidc-secret'

async function cluster(db: PGlite, issuer: string) {
  return await createEdgeCluster({
    db,
    tables: ['note', 'board'],
    secret,
    providers: providersFrom((name) => ({
      OIDC_PROVIDERS: 'test',
      OIDC_TEST_ISSUER: issuer,
      OIDC_TEST_CLIENT_ID: CLIENT,
      OIDC_TEST_CLIENT_SECRET: CLIENT_SECRET,
    } as Record<string, string>)[name]),
    log: (line) => console.error('CLUSTER LOG:', line),
    fail: (e) => { throw e },
  })
}

async function fixture() {
  const db = await PGlite.create()
  await db.exec(await Deno.readTextFile(new URL('../../../services/database/rls/rls.sql', import.meta.url)))
  await db.exec(await Deno.readTextFile(new URL('fixture.sql', import.meta.url)))
  return db
}

Deno.test({ name: 'a person signs in at the edge through a provider', sanitizeResources: false, sanitizeOps: false }, async (t) => {
  const idp = await provider()
  const db = await fixture()
  try {
    const edge = await cluster(db, idp.issuer)
    const at = (path: string) => `${door}${path}`
    const call = (path: string, init: RequestInit = {}) => edge.handle(new Request(at(path), init))
    /** A browser's walk from start to the session it adopts. */
    const signIn = async (ret = '/notes') => {
      const start = await call(`/auth/oidc/test/start?return=${encodeURIComponent(ret)}`)
      assert.equal(start.status, 303, await start.clone().text())
      const authorize = new URL(start.headers.get('location')!)
      assert.equal(authorize.origin, idp.issuer)
      assert.equal(authorize.searchParams.get('redirect_uri'), at('/auth/oidc/test/callback'))
      const back = await fetch(authorize, { redirect: 'manual' })
      assert.equal(back.status, 302)
      const callback = new URL(back.headers.get('location')!)
      assert.equal(callback.origin, door)
      const answered = await call(`${callback.pathname}${callback.search}`, { headers: { cookie: cookiesOf(start).join('; ') } })
      assert.equal(answered.status, 303, await answered.clone().text())
      assert.equal(answered.headers.get('location'), ret)
      const cookie = cookiesOf(answered).join('; ')
      const session = await call('/auth/oidc/session', { method: 'POST', headers: { cookie, origin: door } })
      assert.equal(session.status, 200, await session.clone().text())
      return { cookie, ...(await session.json()) as { token: string; user: { id: string; handle: string } } }
    }
    const crud = async (token: string, path: string, init: RequestInit = {}) => {
      const res = await call(`/crud/${path}`, { ...init, headers: { authorization: `Bearer ${token}`, 'content-type': 'application/json', prefer: 'return=representation' } })
      const text = await res.text()
      assert.ok(res.ok, `${path}: ${res.status} ${text}`)
      return JSON.parse(text)
    }

    let alice: Awaited<ReturnType<typeof signIn>>
    await t.step('the provider signs a person in, with a handle as the auth service makes one', async () => {
      alice = await signIn()
      assert.match(alice.user.handle, /^[a-z]+-[a-z]+-\d\d$/)
      const who = await call('/auth/whoami', { headers: { authorization: `Bearer ${alice.token}` } })
      assert.deepEqual(await who.json(), { id: alice.user.id, handle: alice.user.handle })
    })
    await t.step('the link names the provider, its issuer and the subject', async () => {
      const { rows } = await db.query<{ provider: string; issuer: string; sub: string; user_id: string; name: string }>('SELECT provider, issuer, sub, user_id, name FROM identity_link')
      assert.deepEqual(rows, [{ provider: 'test', issuer: idp.issuer, sub: 'alice-sub', user_id: alice.user.id, name: 'Alice' }])
    })
    await t.step("the session is no guest's, and its rows are its own", async () => {
      const [, payload] = alice.token.split('.')
      assert.equal(JSON.parse(atob(payload.replaceAll('-', '+').replaceAll('_', '/'))).guest, false)
      const [note] = await crud(alice.token, 'note', { method: 'POST', body: JSON.stringify({ body: 'da Alice, pelo provedor' }) })
      assert.equal(note.owner, alice.user.id)
    })
    await t.step('signing in again is the same person, and a tab opened later adopts the cookie', async () => {
      const again = await signIn()
      assert.deepEqual(again.user, alice.user)
      assert.equal((await crud(again.token, 'note')).length, 1)
      const later = await call('/auth/oidc/session', { method: 'POST', headers: { cookie: alice.cookie } })
      assert.equal(later.status, 200)
    })
    await t.step("another subject is another person, who reads none of Alice's rows", async () => {
      idp.as('bob-sub')
      const bob = await signIn()
      assert.notEqual(bob.user.id, alice.user.id)
      assert.equal((await crud(bob.token, 'note')).length, 0)
    })
    await t.step("a callback without the browser's verifier is refused", async () => {
      const start = await call('/auth/oidc/test/start')
      await start.body?.cancel()
      const back = await fetch(start.headers.get('location')!, { redirect: 'manual' })
      const callback = new URL(back.headers.get('location')!)
      const answered = await call(`${callback.pathname}${callback.search}`)
      assert.equal(answered.status, 400)
      assert.deepEqual(await answered.json(), { error: "state is another browser's" })
    })
    await t.step("no table of the auth service's is the app's to read", async () => {
      for (const table of ['identity_link', 'webauthn_credential']) {
        const res = await call(`/crud/${table}`, { headers: { authorization: `Bearer ${alice.token}` } })
        await res.body?.cancel()
        assert.ok(!res.ok, `${table} answered ${res.status}`)
      }
    })
    await t.step('another origin cannot adopt the session, and sign-out clears it', async () => {
      const elsewhere = await call('/auth/oidc/session', { method: 'POST', headers: { cookie: alice.cookie, origin: 'https://evil.test' } })
      await elsewhere.body?.cancel()
      assert.equal(elsewhere.status, 403)
      const out = await call('/auth/oidc/signout', { method: 'POST', headers: { origin: door } })
      await out.body?.cancel()
      assert.equal(out.status, 204)
      assert.ok(out.headers.getSetCookie().every((c) => c.includes('Max-Age=0')))
    })
    await t.step('a provider no setting names is no route', async () => {
      const res = await call('/auth/oidc/google/start')
      await res.body?.cancel()
      assert.equal(res.status, 404)
    })
  } finally {
    await db.close()
    await idp.stop()
  }
})

Deno.test({ name: "links an earlier edge made without their issuer refuse provider sign-in until it is named", sanitizeResources: false, sanitizeOps: false }, async () => {
  const idp = await provider()
  const db = await fixture()
  try {
    // mecha 0.12's edge: a link keyed by the provider and the subject alone.
    const id = crypto.randomUUID()
    await db.exec(`CREATE TABLE identity_link (
      provider text not null, sub text not null,
      user_id uuid not null unique references app_user(id) on delete cascade,
      created_at timestamptz not null default now(), name text, picture text,
      primary key (provider, sub))`)
    await db.query("INSERT INTO app_user (id, handle) VALUES ($1, 'amber-fox-11')", [id])
    await db.query("INSERT INTO identity_link (provider, sub, user_id) VALUES ('test', 'alice-sub', $1)", [id])
    const edge = await cluster(db, idp.issuer)
    const call = (path: string, init: RequestInit = {}) => edge.handle(new Request(`${door}${path}`, init))
    const walk = async () => {
      const start = await call('/auth/oidc/test/start')
      const back = await fetch(start.headers.get('location')!, { redirect: 'manual' })
      const callback = new URL(back.headers.get('location')!)
      return await call(`${callback.pathname}${callback.search}`, { headers: { cookie: cookiesOf(start).join('; ') } })
    }
    const refused = await walk()
    assert.equal(refused.status, 500)
    assert.match((await refused.json() as { error: string }).error, /unassigned issuers/)
    // Passkeys and guests go on meanwhile.
    assert.equal((await call('/auth/guest', { method: 'POST' })).status, 200)
    assert.equal((await call('/auth/login/start', { method: 'POST' })).status, 200)
    // Its owner names the issuer: the person signs in as who they were.
    await db.exec('ALTER TABLE identity_link ADD COLUMN issuer text')
    await db.query('UPDATE identity_link SET issuer = $1', [idp.issuer])
    const signedIn = await walk()
    assert.equal(signedIn.status, 303, await signedIn.clone().text())
    const session = await call('/auth/oidc/session', { method: 'POST', headers: { cookie: cookiesOf(signedIn).join('; '), origin: door } })
    assert.deepEqual((await session.json() as { user: unknown }).user, { id, handle: 'amber-fox-11' })
    const { rows } = await db.query<{ k: string[] }>(`SELECT array_agg(a.attname ORDER BY a.attname) AS k FROM pg_constraint c
      JOIN pg_attribute a ON a.attrelid = c.conrelid AND a.attnum = ANY(c.conkey)
      WHERE c.conrelid = 'identity_link'::regclass AND c.contype = 'p'`)
    assert.deepEqual(rows[0].k, ['issuer', 'provider', 'sub'])
  } finally {
    await db.close()
    await idp.stop()
  }
})
