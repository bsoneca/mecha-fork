import { assert, assertEquals, assertStringIncludes } from "jsr:@std/assert@1.0.13";
import postgresJs from "postgres";
import { pgTest, postgres } from "../compute/pg-test.ts";
import { signJwt } from "../auth/jwt.ts";

const start = (env: Record<string, string>, output: "null" | "piped" = "piped") =>
  new Deno.Command(Deno.execPath(), {
    args: ["run", "-A", "--config", new URL("../auth/deno.json", import.meta.url).pathname, new URL("./main.ts", import.meta.url).pathname],
    env: { DATABASE_URL: "postgres://nobody@127.0.0.1:1/none", ELECTRIC_SECRET: "s", PGRST_JWT_SECRET: "j", PORT: "0", ...env },
    stdout: "null",
    stderr: output,
  });

// A schema's name is spliced into statements, so the stand-in refuses one that is not a plain name,
// before it reads anything.
Deno.test("the host's Electric refuses an app or floor schema that is not a schema name", async () => {
  for (const [name, value] of [["MECHA_DB_SCHEMA", "app; drop"], ["MECHA_FLOOR_SCHEMA", "Floor"]]) {
    const out = await start({ [name]: value }).output();
    assert(!out.success, name);
    assertStringIncludes(new TextDecoder().decode(out.stderr), `${name} is ${value}, not a schema name`);
  }
});

const free = () => {
  const l = Deno.listen({ hostname: "127.0.0.1", port: 0 });
  const port = (l.addr as Deno.NetAddr).port;
  l.close();
  return port;
};

// The stand-in over a real Postgres, its tables, publication and floor in the schemas the cluster
// names (meta.schema): a request names the table as the door sends it (`<schema>.<table>` for an
// app's own schema, bare for public's), and the subject reaches the scopes the floor's
// subject_scopes gives it.
for (const [app, floor] of [["public", "public"], ["app", "floor"]]) {
  pgTest(`the host's Electric serves the ${app} schema's tables through the ${floor} floor`, async () => {
    await using pg = await postgres();
    const sql = postgresJs(pg.url, { onnotice: () => {} });
    try {
      await sql.unsafe(`CREATE SCHEMA IF NOT EXISTS ${app}; CREATE SCHEMA IF NOT EXISTS ${floor};
        CREATE FUNCTION ${floor}.subject_scopes(uid text) RETURNS text[] LANGUAGE sql STABLE AS $$
          SELECT ARRAY['public:', 'user:' || uid] $$;
        CREATE TABLE ${app}.article(id integer PRIMARY KEY, title text NOT NULL, scope_id text NOT NULL);
        INSERT INTO ${app}.article VALUES (1, 'open', 'public:'), (2, 'mine', 'user:u1'), (3, 'theirs', 'user:u2');
        CREATE PUBLICATION electric_publication_default FOR TABLE ${app}.article;`);
    } finally {
      await sql.end();
    }
    const port = free();
    const env = {
      DATABASE_URL: pg.url,
      PORT: String(port),
      ...(app === "public" ? {} : { MECHA_DB_SCHEMA: app }),
      ...(floor === "public" ? {} : { MECHA_FLOOR_SCHEMA: floor }),
    };
    const child = start(env, "null").spawn();
    try {
      let up = false;
      for (let i = 0; i < 60 && !up; i++) {
        up = await fetch(`http://127.0.0.1:${port}/v1/health`).then(async (r) => (await r.body?.cancel(), r.ok)).catch(() => false);
        if (!up) await new Promise((r) => setTimeout(r, 250));
      }
      assert(up, "the stand-in never answered");
      const token = await signJwt("j", { sub: "u1", exp: Math.floor(Date.now() / 1000) + 300 });
      const shape = async (table: string) => {
        const r = await fetch(`http://127.0.0.1:${port}/v1/shape?table=${table}&offset=-1&secret=s`, { headers: { authorization: `Bearer ${token}` } });
        return { status: r.status, body: await r.json() };
      };
      const named = app === "public" ? "article" : `${app}.article`;
      const got = await shape(named);
      assertEquals(got.status, 200);
      const rows = (got.body as { key?: string; value?: { id: string }; headers: { relation?: string[] } }[]).filter((x) => x.value);
      assertEquals(rows.map((x) => ({ key: x.key, relation: x.headers.relation, id: x.value!.id })), [
        { key: `"${app}"."article"/"1"`, relation: [app, "article"], id: "1" },
        { key: `"${app}"."article"/"2"`, relation: [app, "article"], id: "2" },
      ]);
      // A bare name is public's, which an app of its own schema has no shape table in.
      if (app !== "public") assertEquals((await shape("article")).status, 400);
    } finally {
      child.kill("SIGTERM");
      await child.status;
    }
  });
}
