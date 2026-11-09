import assert from 'node:assert/strict'
import { PGlite } from '@electric-sql/pglite'
import { createEdgeCluster } from '../src/cluster.ts'

Deno.test('the door route always answers 204, naming the account only for a verified session', async () => {
  const db = await PGlite.create()
  try {
    await db.exec(await Deno.readTextFile(new URL('../../../services/database/rls/rls.sql', import.meta.url)))
    await db.exec(await Deno.readTextFile(new URL('fixture.sql', import.meta.url)))
    const cluster = await createEdgeCluster({ db, tables: ['note', 'board'], secret: 'test', log: line => { throw new Error(line) }, fail: error => { throw error } })
    const guest = await (await cluster.handle(new Request('https://test/auth/guest', { method: 'POST' }))).json() as { token: string; user: { id: string } }
    const door = async (headers: Record<string, string> = {}) => {
      const res = await cluster.handle(new Request('https://test/auth/door', { headers }))
      assert.equal(res.status, 204)
      return res.headers.get('x-pronto-account')
    }
    assert.equal(await door({ authorization: `Bearer ${guest.token}` }), guest.user.id)
    assert.equal(await door(), null, 'no session')
    assert.equal(await door({ authorization: 'Bearer not-a-token' }), null, 'an invalid token')
    assert.equal(await door({ 'x-pronto-account': guest.user.id }), null, 'a header the page sent names no one')
  } finally { await db.close() }
})
