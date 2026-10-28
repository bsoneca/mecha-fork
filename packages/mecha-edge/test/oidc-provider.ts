// An OpenID provider over HTTP on a local port, for the edge's sign-in tests:
// it authorizes whoever the test says, at once — the authorization endpoint
// redirects back with a code — and redeems a code only for its client, with
// the client's secret, the redirect it was issued for and the PKCE verifier.
import { encodeBase64Url } from '../../../services/auth/jwt.ts'
import { sha256url } from '../../../services/auth/oidc.ts'

export const CLIENT = 'edge-client'
export const CLIENT_SECRET = 'edge-client-secret'
const b64 = (s: string) => encodeBase64Url(new TextEncoder().encode(s))

export async function provider() {
  const keys = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']) as CryptoKeyPair
  const jwk = { ...(await crypto.subtle.exportKey('jwk', keys.publicKey)), kid: 'k1' }
  const codes = new Map<string, { redirect: string; challenge: string; nonce: string; sub: string }>()
  let sub = 'alice-sub'
  let issuer = ''
  const server = Deno.serve({ hostname: '127.0.0.1', port: 0, onListen: () => {} }, async (req): Promise<Response> => {
    const url = new URL(req.url)
    if (url.pathname === '/.well-known/openid-configuration') {
      return Response.json({ issuer, authorization_endpoint: `${issuer}/authorize`, token_endpoint: `${issuer}/token`, jwks_uri: `${issuer}/jwks` })
    }
    if (url.pathname === '/jwks') return Response.json({ keys: [jwk] })
    if (url.pathname === '/authorize') {
      const q = url.searchParams
      if (q.get('client_id') !== CLIENT) return new Response('unknown client', { status: 400 })
      const code = crypto.randomUUID()
      codes.set(code, { redirect: q.get('redirect_uri')!, challenge: q.get('code_challenge')!, nonce: q.get('nonce')!, sub })
      const back = new URL(q.get('redirect_uri')!)
      back.search = new URLSearchParams({ code, state: q.get('state')! }).toString()
      return new Response(null, { status: 302, headers: { location: back.toString() } })
    }
    if (url.pathname === '/token' && req.method === 'POST') {
      const form = new URLSearchParams(await req.text())
      const grant = codes.get(form.get('code') ?? '')
      codes.delete(form.get('code') ?? '')
      if (
        !grant || form.get('client_id') !== CLIENT || form.get('client_secret') !== CLIENT_SECRET ||
        form.get('redirect_uri') !== grant.redirect || (await sha256url(form.get('code_verifier') ?? '')) !== grant.challenge
      ) return Response.json({ error: 'invalid_grant' }, { status: 400 })
      const head = b64(JSON.stringify({ alg: 'ES256', kid: 'k1', typ: 'JWT' }))
      const body = b64(JSON.stringify({ iss: issuer, aud: CLIENT, sub: grant.sub, name: 'Alice', nonce: grant.nonce, exp: Math.floor(Date.now() / 1000) + 300 }))
      const sig = new Uint8Array(await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, keys.privateKey, new TextEncoder().encode(`${head}.${body}`)))
      return Response.json({ id_token: `${head}.${body}.${encodeBase64Url(sig)}` })
    }
    return new Response('not found', { status: 404 })
  })
  issuer = `http://localhost:${server.addr.port}`
  return {
    issuer,
    as(next: string) { sub = next },
    stop: () => server.shutdown(),
  }
}

/** The cookies a response sets, as a browser would send them back. */
export const cookiesOf = (res: Response) => res.headers.getSetCookie().map((c) => c.split(';')[0]).filter((c) => !c.endsWith('='))
