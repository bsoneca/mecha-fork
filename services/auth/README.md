# The auth service's token contract

Three components read these tokens and only one mints them, so the shape is
stated here rather than in each: this service issues, PostgREST verifies, and
the emitter writes the policies that call `auth_uid()`.

- **HS256**, claims `{role, sub, handle, exp}`, secret from `PGRST_JWT_SECRET`.
  A dev default ships so a fresh cluster boots; production overrides it.
- **A user token** carries role `app_user` and `sub` = the `app_user` row id.
- **A guest's refresh**: `POST /auth/guest/refresh` with a guest's bearer, live or
  expired up to `GUEST_REFRESH_GRACE_S` ago (90 days by default), answers a new
  token of the same id and handle (`{token, user}`, as `/auth/guest`) while the
  account is still a guest: 401 for anything else, 409 once it has a passkey or
  a provider's link (its way back is its own sign-in), 404 for no such user.
  `USER_TOKEN_TTL_S` (a week by default) is a token's life.
- **A Studio play token's session** (`POST /auth/studio`, below) is a user token
  with `guest: false` that lives 12 hours, whatever `USER_TOKEN_TTL_S` is.
- **A service token** carries role `service` and the nil uuid, pre-signed
  against the dev secret and delivered as a compose env default. It exists so a
  transform can write without a reader, which is the only caller that has no
  session to borrow.
- **`auth_uid()`** reads `sub` out of `request.jwt.claims`. It is a replaceable
  object, restated by the database image with the tenancy floor and never
  migrated with the tables, so a correction reaches every database without a
  migration.

- **A shape token** carries `typ: "shape"`, the `table` and the `where` its
  scopes reach. `/auth/shape/verify` answers Caddy for every shape request:
  `table` and `where` must equal the token's, and a subset snapshot narrows it
  with the `subset__*` parameters the gate names ([proxy](../../docs/proxy.md)).

When the catalogs prove a leaf table's `scope_id` is a stored generated
NOT NULL constant `'public:'`, its shape predicate retains only the subject's
public scope. Readers share one Electric log while their tokens keep distinct
subjects. Defaults, mutable or private scopes, virtual generated columns and
tables with descendants retain the full subject scope set. Keyed shapes keep
their row authorization; every request must still match its token's table and
exact predicate.

The alternative was server-side sessions. It was refused because the WebAuthn
challenge is the only state a ceremony needs, and a short-lived `state` JWT
carries it without giving the service anything to lose on restart.

## Provider sign-in

A provider `signIn` names (`oidc.ts`) signs a person in by OpenID Connect's
authorization code flow with PKCE, by redirect, so no provider script runs in
a page the door serves:

- `GET /auth/oidc/<provider>/start?return=<path>` sends the browser to the
  provider's authorization endpoint with a signed `state`, a nonce and the
  PKCE challenge; the verifier stays in an HttpOnly cookie scoped to the
  callback, and the state carries only its hash.
- `GET /auth/oidc/<provider>/callback` redeems the code at the provider's token
  endpoint with that verifier, verifies the ID token (RS256 or ES256) against
  the provider's published keys, issuer, client and nonce, and links the
  subject to an `app_user` in `identity_link`, making both the first time. It
  leaves an HttpOnly `mecha_oidc` cookie on `/auth/oidc` and a readable
  `mecha_oidc_hint` naming the provider, and returns to `return`, a
  same-origin path.
- `POST /auth/oidc/session` exchanges the cookie for a **user token**, guest
  false, while the link still stands: the terminal keeps a tab's session in
  sessionStorage, which a redirect cannot write, and a tab opened later adopts
  the same sign-in this way. `POST /auth/oidc/signout` clears both cookies.

A provider is found by its discovery document. Each setting is `signIn`'s
default for the provider (`issuer`, `internal`, `client`, `scope`, `params`),
which the deployment's variable overrides; a secret is the deployment's alone,
and a provider whose client neither gives refuses to start:

| Variable | |
|---|---|
| `OIDC_<NAME>_CLIENT_ID` | required; `origin` makes the client the door's own origin, a public client as an issuer that registers none takes it |
| `OIDC_<NAME>_ISSUER` | the issuer, required unless the name is a preset (`google`); setting it puts another issuer in the preset's place |
| `OIDC_<NAME>_INTERNAL` | where this service reaches the issuer when the cluster's way differs from the reader's |
| `OIDC_<NAME>_CLIENT_SECRET` | where the provider wants one; Google's code flow does |
| `OIDC_<NAME>_SCOPE` | `openid`, or the preset's |
| `OIDC_<NAME>_AUTHORIZE_PARAMS` | further authorization parameters, URL-encoded; never one the flow sets |

The service holds no account policy: a subject signs into its own account,
made the first time, and a guest who signs in through a provider leaves the
guest behind. A person signed in through a provider and one holding a passkey
are two `app_user`s.

`identity_link` is `(provider, issuer, sub, user_id unique, created_at)`, with the
provider's `name` and `picture` where it gives them, refreshed on every
sign-in. An app that keeps its people elsewhere copies them with a trigger on
it, as a reader is made on `webauthn_credential`; the service creates the table
when it starts, so an app's migration that declares such a trigger declares the
table as the service does.

The issuer is the configured issuer URL, with the preset's accepted ID-token
aliases treated as that same issuer. Replacing an issuer never transfers its
subjects or browser sessions. Removing a provider also ends cookie adoption.
For an existing link table without issuers, add an `issuer text` column and
populate it with each row's original issuer before starting auth; startup
refuses unassigned rows because the provider label cannot identify their issuer.

## API keys

An account's durable credential for a client with no browser (a bot), behind
the program's `apiKeys` capability (cluster.cue, `AUTH_API_KEYS=true`): off,
every route below answers 404, so no app gets them by a pin bump alone.

- `POST /auth/keys {label, scopes}` with a signed-in account's session makes a
  key and answers it once, `pk_live_…`; `mecha_auth.api_key` keeps only its
  SHA-256, with its owner, label, scopes, `created_at`, `last_used` and
  `revoked_at`. Scopes are `read`, `write` and `machines:<name>`. At most five
  live keys an account (409 past them; a revoke frees a place). A guest is 403
  `guest`; a token a key minted is 403 `key token`, so a key never makes or
  revokes another.
- `GET /auth/keys` lists the caller's live keys, never a key or its hash.
- `DELETE /auth/keys/<id>` revokes the caller's own live key (204); another's,
  or one already revoked, is 404.
- `POST /auth/key {key}` exchanges a live key for a **user token** of its owner
  that lives 15 minutes and carries `kid` (the key's id) and `scp` (its
  scopes) beside the usual claims, so `/crud` takes it as the owner and RLS
  applies unchanged. An unknown or revoked key is 401. The key's `last_used`
  moves.

The table is in `mecha_auth` (api_keys.ts), a schema no app role may use, unlike
the passkeys and links this line keeps in public: no app role reaches it, and the one reader by hash is `mecha_auth.api_key_owner`,
`SECURITY DEFINER`, whose execute no one but its owner holds. The signing
secret stays in this service: no other process mints a key's token.

## Studio play tokens

A game played only inside Studio takes no sign-in of its own: Studio signs the
player in, and hands the game a one-minute token for that game alone
(`studio.ts`). `POST /auth/studio {token}` trades it for the game's session,
`{token, user: {id, handle, guest: false}}`, as `/auth/guest` answers one.
Off (404) unless `STUDIO_JWKS_URL`, `STUDIO_ISS` and `PUBLIC_ORIGIN` are all
set.

- **The token** is a JWS with `alg` ES256 and nothing else, and a `kid`.
  Its claims are checked in this order, each with its error code: `iss` equals
  `STUDIO_ISS` (`iss`); `aud` equals `PUBLIC_ORIGIN` (`aud`); `exp` is in the
  future, with no leeway (`expired`); `iat` is at most 30 s ahead (`iat`);
  `exp - iat` is at most 120 s (`lifetime`); `sub` is a uuid (`sub`); `handle`
  is a string (`handle`); `jti` is a string (`jti`). A claim of the wrong type
  is `claims`.
- **The keys** come from `STUDIO_JWKS_URL` alone, never from the token's `iss`
  or a header. A key must be `kty` EC, `crv` P-256 and `use` sig; any other is
  not a key. The fetch takes no redirect (a 3xx fails), at most 64 KB and 3 s.
  Keys are held 10 minutes; a `kid` not held fetches again, at most once a
  minute; when a fetch fails the keys held serve for up to 1 hour, and with none
  held every token is refused.
- **Spent once**: in one transaction the `jti` is inserted into
  `mecha_auth.studio_jti (jti, exp)` and `app_user (id = sub, handle)` is
  upserted. A `jti` already there is 409 `replay`; a handle another account
  holds is 409 `handle_taken`; a failed upsert rolls the `jti` back, so the
  token is not spent. Rows past `exp` are deleted at each call, which is safe
  because `exp` has no leeway.
- **Errors** are 401 `{reason}`: `malformed`, `alg` (any alg but ES256,
  `none` included), `kid` (none, unknown, or not a usable key), `signature`,
  `jwks` (the keys could not be had), and the claims' above. The token is never
  echoed. 60 calls a minute from one address, then 429; the address is the last
  entry of `X-Forwarded-For` (the nearest proxy's), else the socket's.

`AUTH_GUESTS=off` closes the game's own ways in: `POST /auth/guest`,
`/auth/guest/refresh`, `/auth/register/{start,verify}`,
`/auth/login/{start,verify}` and everything under `/auth/oidc/` answer 403.
Unset (or `on`), the service behaves as it always has, so no app changes by a
pin bump alone; any other value is refused at startup.
