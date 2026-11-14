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

## Passkeys from an Android app

A passkey an Android app makes through Credential Manager carries no page origin:
its client data names the app's signing certificate,
`android:apk-key-hash:<SHA-256, base64url, unpadded>`. Android admits the app to
the web's relying party only where the door's Digital Asset Links name it.
`WEBAUTHN_ANDROID_ORIGINS` lists the app's release certificates' SHA-256
fingerprints, as `keytool -list` prints them, comma-separated (`origins.ts`).
Both ceremonies admit each one beside `WEBAUTHN_ORIGIN`. A fingerprint that is
not 32 bytes stops the service at startup. Unset, the door admits no app. A
program declares them as `capabilities.android`, the variable's default.

## Upgrade

`POST /auth/upgrade` issues a **user token** again, scoped to one operation, for
a service that has proven something about the session's person on its own (a
token of another issuer, say). The service holds no key and adds no claim of
its own choosing:

- Only a **service token** calls it (`Authorization`), else 401 or 403.
- `token` is the session to upgrade: a live `app_user` token of this secret
  that carries none of the claims below, else 401, 403 or 409. Its `role`,
  `sub`, `handle` and `guest` are kept, so whatever it reads by its subject it
  reads still, and nothing else of it is carried. A key's token (`kid`, `scp`)
  is a 403: its scopes would not survive the upgrade. An upgraded token is never
  upgraded again; the session it came from can be, so a caller that wants one
  upgrade per proof keeps that itself.
- `claims` is the closed list, all four: `operation_kind`, `operation_id` and
  `idp` as text, `amr` as a list of methods. Any other name, the four a session
  keeps among them, is a 400.
- `exp` is the time the caller asks for and `cap` the end of the session's
  family (a refresh's absolute ceiling), both in seconds; the token's `exp` is
  the earliest of the two, of now plus `UPGRADE_TOKEN_TTL_S` (an hour unless
  the deployment names one, of at least 5; another value refuses to start) and of the session
  token's own `exp`, so an upgraded token never outlives the one it came from.
  One that would end within 5 seconds is a 400.

The answer is `{token}`, signed as every user token is. Nothing of either
token is logged.

An upgraded token is a full `app_user` session of the same person, narrowed only
by the policies and functions that read its claims: a consumer that grants
something for the operation reads `operation_kind` and `operation_id`, and one
that serves only accounts checks `guest`, since a guest's session upgrades too.
`POST /auth/guest/refresh` refuses an upgraded token (403), so it never outlives
its cap as a plain session; its holder refreshes the session it came from.

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
  leaves an HttpOnly `__Host-mecha_oidc` cookie (host-only, `Path=/`; a bare `mecha_oidc` on
  `/auth/oidc` over plain http, and read from before the prefix unless `OIDC_LEGACY_COOKIE=off`) and a readable
  `mecha_oidc_hint` naming the provider, and returns to `return`, a
  same-origin path.
- `POST /auth/oidc/session` exchanges the cookie for a **user token**, guest
  false, while the link still stands: the terminal keeps a tab's session in
  sessionStorage, which a redirect cannot write, and a tab opened later adopts
  the same sign-in this way. `POST /auth/oidc/signout` clears both cookies.
- An app on a device signs in in the system browser, whose cookie it never
  reads. It keeps a random secret and starts with
  `start?return=<path>&native=<S256(secret)>`; the callback then leaves no
  session cookie and returns to `<path>#handoff=<code>` (the app's link back;
  a fragment, which no browser sends on), and `POST /auth/oidc/session` with
  the JSON body `{handoff, secret}` answers the user token within a minute of
  the callback, once per instance. Whoever catches the link has the code and
  not the secret: PKCE again, between door and app.

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

Both tables live in the schema `mecha_auth`, which no app role may use: an
app's grants on every table in `public` and the CRUD API serving `public` reach
neither. The service moves them there, rows and all, from `public`, where
earlier releases made them, and refuses to start where both copies exist. A
trigger or reader an app declares names them `mecha_auth.identity_link` and
`mecha_auth.webauthn_credential`.

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

An app that wants a feature flag, not a deploy, to turn keys on names a gate
(`apiKeysGate`, as `AUTH_API_KEYS_GATE=schema.name`): a function
`schema.name(owner uuid) returns boolean` in its database, asked for the caller
on every make and list and for the key's owner on every exchange. False
answers 404, as keys off; a revoke is never refused, so a credential can
always be cut. A token already minted lives out its 15 minutes.

An app that must act when a key is used names a hook (`keyExchanged`, as
`AUTH_KEY_EXCHANGED_HOOK=schema.name`): a function `schema.name(owner uuid)
returns void` in its database, called with the key's owner on every exchange,
after the gate (if any) passed and before the token is signed. If it throws,
the exchange answers 500 and no token is issued, so what it does, such as
marking the owner a bot, cannot be skipped. It is not called on make, list or
revoke, and naming one does not turn keys on.

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

The table is in `mecha_auth` with the passkeys and links (schema.ts): no app
role reaches it, and the one reader by hash is `mecha_auth.api_key_owner`,
`SECURITY DEFINER`, whose execute no one but its owner holds. The signing
secret stays in this service: no other process mints a key's token.
