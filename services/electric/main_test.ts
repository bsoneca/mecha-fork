import { assert, assertStringIncludes } from "jsr:@std/assert@1.0.13";

// The host's Electric stand-in serves public's tables and floor alone: a cluster naming its own
// schemas has it refuse to start, before it reads anything, rather than sync the wrong relations.
const start = (env: Record<string, string>) =>
  new Deno.Command(Deno.execPath(), {
    args: ["run", "-A", "--config", new URL("../auth/deno.json", import.meta.url).pathname, new URL("./main.ts", import.meta.url).pathname],
    env: { DATABASE_URL: "postgres://nobody@127.0.0.1:1/none", ELECTRIC_SECRET: "s", PGRST_JWT_SECRET: "j", PORT: "0", ...env },
    stdout: "null",
    stderr: "piped",
  }).output();

Deno.test("the host's Electric refuses an app or floor schema other than public", async () => {
  for (const [name, value] of [["MECHA_DB_SCHEMA", "shop"], ["MECHA_FLOOR_SCHEMA", "mecha"]]) {
    const out = await start({ [name]: value });
    assert(!out.success, name);
    assertStringIncludes(new TextDecoder().decode(out.stderr), `${name} is ${value}: the host's Electric serves only public's tables and floor`);
  }
});
