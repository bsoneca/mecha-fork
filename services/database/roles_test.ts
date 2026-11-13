// What the roles migration changes, and what it leaves alone where the roles
// are managed outside; and that both password steps set nothing then. The
// Postgres cases run where initdb is on PATH.
//
//   deno test --no-config --no-lock --allow-read --allow-write --allow-env --allow-net --allow-run roles_test.ts

import assert from "node:assert/strict";
import { fileURLToPath } from "node:url";
import { pgTest, postgres } from "../compute/pg-test.ts";

const HERE = fileURLToPath(new URL(".", import.meta.url));
const ROLES = `${HERE}migrations/001_roles.sql`;
const PASSWORDS = `${HERE}role_passwords.sh`;

async function psql(url: string, args: string[]) {
  const out = await new Deno.Command("psql", {
    args: [url, "-X", "-q", "-v", "ON_ERROR_STOP=1", "-tA", ...args],
    stdout: "piped",
    stderr: "piped",
  }).output();
  const text = (b: Uint8Array) => new TextDecoder().decode(b).trim();
  return { ok: out.success, out: text(out.stdout), err: text(out.stderr) };
}

const as = (url: string, user: string) => url.replace("postgres@", `${user}@`);

// What the file sets: attributes, authenticator's memberships with their
// options, and the role timeouts.
const STATE = `SELECT string_agg(x, ' ' ORDER BY x) FROM (
  SELECT rolname || ':' || rolinherit || rolcanlogin || rolbypassrls || rolreplication AS x
    FROM pg_roles WHERE rolname IN ('anon','authenticator','app_user','service','electric')
  UNION ALL SELECT 'm:' || roleid::regrole || ':' || inherit_option || set_option
    FROM pg_auth_members WHERE member = 'authenticator'::regrole
  UNION ALL SELECT 's:' || setrole::regrole || ':' || array_to_string(setconfig, ',')
    FROM pg_db_role_setting WHERE setdatabase = 0
      AND setrole IN (SELECT oid FROM pg_roles WHERE rolname IN ('anon','authenticator','app_user','service'))) t`;

pgTest("the roles migration sets the roles once and changes nothing the second time", async () => {
  await using pg = await postgres();
  assert.equal((await psql(pg.url, ["-f", ROLES])).ok, true);
  const first = (await psql(pg.url, ["-c", STATE])).out;
  assert.match(first, /authenticator:falsetruefalsefalse/);
  assert.match(first, /service:truefalsetruefalse/);
  assert.match(first, /electric:truetruetruetrue/);
  for (const r of ["anon", "app_user", "service"]) assert.match(first, new RegExp(`m:${r}:falsetrue`));
  const again = await psql(pg.url, ["-f", ROLES]);
  assert.equal(again.ok, true, again.err);
  assert.equal((await psql(pg.url, ["-c", STATE])).out, first);
});

// Roles a DBA made as the file makes them, and a login with no role
// privileges: the file runs and changes nothing.
pgTest("a login without role privileges migrates roles made as the file makes them", async () => {
  await using pg = await postgres();
  assert.equal((await psql(pg.url, ["-f", ROLES])).ok, true);
  const made = (await psql(pg.url, ["-c", STATE])).out;
  const setup = await psql(pg.url, ["-c", `CREATE ROLE migrator LOGIN;
    GRANT CREATE ON DATABASE postgres TO migrator; GRANT CREATE ON SCHEMA public TO migrator;`]);
  assert.equal(setup.ok, true, setup.err);
  const run = await psql(as(pg.url, "migrator"), ["-f", ROLES]);
  assert.equal(run.ok, true, run.err);
  assert.equal((await psql(pg.url, ["-c", STATE])).out, made);
  // A role made short of something is still set, and the login's missing
  // privilege is the error.
  await psql(pg.url, ["-c", "ALTER ROLE service NOBYPASSRLS"]);
  const short = await psql(as(pg.url, "migrator"), ["-f", ROLES]);
  assert.equal(short.ok, false);
  assert.match(short.err, /permission denied/);
});

pgTest("a membership made with other options is set again to SET and no INHERIT", async () => {
  await using pg = await postgres();
  assert.equal((await psql(pg.url, ["-f", ROLES])).ok, true);
  await psql(pg.url, ["-c", "REVOKE anon FROM authenticator; GRANT anon TO authenticator WITH INHERIT TRUE, SET FALSE"]);
  assert.equal((await psql(pg.url, ["-f", ROLES])).ok, true);
  assert.match((await psql(pg.url, ["-c", STATE])).out, /m:anon:falsetrue/);
});

// role_passwords.sh is sourced by the image's docker-entrypoint.sh, which
// defines docker_process_sql; here a stand-in records whether it ran.
async function passwords(env: Record<string, string>) {
  const out = await new Deno.Command("bash", {
    args: ["-c", `docker_process_sql() { cat >/dev/null; echo ran; }; . "${PASSWORDS}"`],
    env: { PATH: Deno.env.get("PATH") ?? "", ...env },
    clearEnv: true,
    stdout: "piped",
    stderr: "piped",
  }).output();
  return { ok: out.success, out: new TextDecoder().decode(out.stdout) };
}

Deno.test("the password step sets nothing where the roles are managed outside", async () => {
  const outside = await passwords({ ROLES_MANAGED_OUTSIDE: "true" });
  assert.equal(outside.ok, true);
  assert.doesNotMatch(outside.out, /ran/);
  const unset = await passwords({});
  assert.equal(unset.ok, false);
  const set = await passwords({ ELECTRIC_PASSWORD: "e", AUTHENTICATOR_PASSWORD: "a" });
  assert.equal(set.ok, true);
  assert.match(set.out, /ran/);
});

// The process runtime does not source the step: its entrypoint runs its own
// password SQL for that file, and must honour the same opt-out.
Deno.test("the process runtime's entrypoint honours the opt-out too", async () => {
  const text = await Deno.readTextFile(`${HERE}entrypoint.nu`);
  const branch = text.slice(text.indexOf('str ends-with "role_passwords.sh"'));
  const optOut = branch.indexOf("ROLES_MANAGED_OUTSIDE");
  assert.ok(optOut > 0 && optOut < branch.indexOf("ALTER ROLE electric PASSWORD"));
});
