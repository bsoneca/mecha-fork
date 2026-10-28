// Provider sign-in through the Worker: the auth service's oidc.ts answered by
// the cluster's object under wrangler dev, its providers read from the
// Worker's vars (OIDC_*) as a release sets them, against an OpenID provider of
// the test's own on a local port, as a browser walks it. oidc_test.ts covers
// the links on PGlite; these cover the vars, the door's origin and the
// cookies through the Worker. Needs ../pglite-workerd/dist.
import assert from 'node:assert/strict'
import { startWorker } from '../../pglite-workerd/wrangler-dev.ts'
import { load } from '../../pglite-workerd/load.ts'
import { CLIENT, CLIENT_SECRET, cookiesOf, provider } from './oidc-provider.ts'
import { seed } from './seed.ts'

Deno.test({ name: 'a person signs in through a provider the Worker names', sanitizeResources: false, sanitizeOps: false }, async (t) => {
  Deno.statSync(new URL('../../pglite-workerd/dist/pglite.wasm', import.meta.url))
  const tmp = await Deno.makeTempDir({ prefix: 'mecha-edge-oidc-' })
  await seed(`${tmp}/pgdata`)
  const idp = await provider()
  const worker = await startWorker(new URL('wrangler.jsonc', import.meta.url), `${tmp}/state`, {
    OIDC_PROVIDERS: 'test',
    OIDC_TEST_ISSUER: idp.issuer,
    OIDC_TEST_CLIENT_ID: CLIENT,
    OIDC_TEST_CLIENT_SECRET: CLIENT_SECRET,
  })
  const at = (path: string) => `${worker.origin}${path}`
  /** A browser's walk from start to the session it adopts. */
  const signIn = async (ret = '/notes') => {
    const start = await fetch(at(`/auth/oidc/test/start?return=${encodeURIComponent(ret)}`), { redirect: 'manual' })
    assert.equal(start.status, 303, await start.clone().text())
    const authorize = new URL(start.headers.get('location')!)
    assert.equal(authorize.searchParams.get('redirect_uri'), at('/auth/oidc/test/callback'))
    const back = await fetch(authorize, { redirect: 'manual' })
    assert.equal(back.status, 302)
    const callback = await fetch(back.headers.get('location')!, { redirect: 'manual', headers: { cookie: cookiesOf(start).join('; ') } })
    assert.equal(callback.status, 303, await callback.clone().text())
    assert.equal(callback.headers.get('location'), ret)
    const cookie = cookiesOf(callback).join('; ')
    const session = await fetch(at('/auth/oidc/session'), { method: 'POST', headers: { cookie, origin: worker.origin } })
    assert.equal(session.status, 200, await session.clone().text())
    return { cookie, ...(await session.json()) as { token: string; user: { id: string; handle: string } } }
  }
  const crud = async (token: string, path: string, init: RequestInit = {}) => {
    const res = await fetch(at(`/crud/${path}`), { ...init, headers: { authorization: `Bearer ${token}`, 'content-type': 'application/json', prefer: 'return=representation' } })
    const text = await res.text()
    assert.ok(res.ok, `${path}: ${res.status} ${text}`)
    return JSON.parse(text)
  }
  try {
    await load(`${tmp}/pgdata`, (route, init) => fetch(at(`/import/${route}`), { ...init, headers: { authorization: 'Bearer test-import' } }), { log: () => {} })

    let alice: Awaited<ReturnType<typeof signIn>>
    await t.step('the provider signs a person in, with a handle as the auth service makes one', async () => {
      alice = await signIn()
      assert.match(alice.user.handle, /^[a-z]+-[a-z]+-\d\d$/)
      const who = await fetch(at('/auth/whoami'), { headers: { authorization: `Bearer ${alice.token}` } })
      assert.deepEqual(await who.json(), { id: alice.user.id, handle: alice.user.handle })
    })
    await t.step("the session is no guest's, and its rows are its own", async () => {
      const [, payload] = alice.token.split('.')
      assert.equal(JSON.parse(atob(payload.replaceAll('-', '+').replaceAll('_', '/'))).guest, false)
      const [note] = await crud(alice.token, 'note', { method: 'POST', body: JSON.stringify({ body: 'da Alice, pelo provedor' }) })
      assert.equal(note.owner, alice.user.id)
    })
    await t.step('signing in again, after an eviction, is the same person', async () => {
      await worker.restart()
      const again = await signIn()
      assert.deepEqual(again.user, alice.user)
      assert.equal((await crud(again.token, 'note')).length, 1)
      const later = await fetch(at('/auth/oidc/session'), { method: 'POST', headers: { cookie: alice.cookie } })
      assert.equal(later.status, 200)
    })
    await t.step("another subject is another person, who reads none of Alice's rows", async () => {
      idp.as('bob-sub')
      const bob = await signIn()
      assert.notEqual(bob.user.id, alice.user.id)
      assert.equal((await crud(bob.token, 'note')).length, 0)
    })
    await t.step("no table of the auth service's is the app's to read", async () => {
      const res = await fetch(at('/crud/identity_link'), { headers: { authorization: `Bearer ${alice.token}` } })
      await res.body?.cancel()
      assert.ok(!res.ok, `identity_link answered ${res.status}`)
    })
    await t.step('another origin cannot adopt the session, and sign-out clears it', async () => {
      const elsewhere = await fetch(at('/auth/oidc/session'), { method: 'POST', headers: { cookie: alice.cookie, origin: 'https://evil.test' } })
      await elsewhere.body?.cancel()
      assert.equal(elsewhere.status, 403)
      const out = await fetch(at('/auth/oidc/signout'), { method: 'POST', headers: { origin: worker.origin } })
      await out.body?.cancel()
      assert.equal(out.status, 204)
      assert.ok(out.headers.getSetCookie().every((c) => c.includes('Max-Age=0')))
    })
    await t.step('a provider no var names is no route', async () => {
      const res = await fetch(at('/auth/oidc/google/start'), { redirect: 'manual' })
      await res.body?.cancel()
      assert.equal(res.status, 404)
    })
  } finally {
    await worker.stop()
    await idp.stop()
  }
})
