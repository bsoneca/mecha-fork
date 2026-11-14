import { assertEquals } from "jsr:@std/assert@1.0.13";

// The door's /electric route against stand-ins: a gate that admits every request and an Electric that
// answers with the `table` it was sent. The gate compares the bare table; Electric reads a bare name
// as public's, so under an app schema of its own the door names it (ELECTRIC_TABLE_PREFIX).
// Runs the caddy on PATH (toolchain/tools.cue pins it).
const free = () => {
  const l = Deno.listen({ hostname: "127.0.0.1", port: 0 });
  const port = (l.addr as Deno.NetAddr).port;
  l.close();
  return port;
};

async function withDoor(prefix: string | undefined, use: (port: number) => Promise<void>) {
  const scratch = await Deno.makeTempDir({ prefix: "mecha-proxy-" });
  const [door, auth, electric] = [free(), free(), free()];
  const stand = (port: number, body: string) => `{\n  admin off\n  storage file_system ${scratch}/data-${port}\n}\n:${port} {\n  ${body}\n}\n`;
  await Deno.writeTextFile(`${scratch}/auth`, stand(auth, `respond "" 200`));
  await Deno.writeTextFile(`${scratch}/electric`, stand(electric, `respond "{query.table}|{query.secret}" 200`));
  const env: Record<string, string> = {
    HOME: scratch,
    PATH: Deno.env.get("PATH") ?? "",
    PORT: String(door),
    ELECTRIC_SECRET: "s3",
    PRONTO_UPSTREAM_AUTH: `127.0.0.1:${auth}`,
    PRONTO_UPSTREAM_ELECTRIC: `127.0.0.1:${electric}`,
    ...(prefix === undefined ? {} : { ELECTRIC_TABLE_PREFIX: prefix }),
  };
  const configs = [[`${scratch}/auth`, {}], [`${scratch}/electric`, {}], [new URL("./Caddyfile", import.meta.url).pathname, env]] as const;
  const started = configs.map(([config, extra]) =>
    new Deno.Command("caddy", {
      args: ["run", "--config", config, "--adapter", "caddyfile"],
      env: { HOME: scratch, XDG_DATA_HOME: scratch, XDG_CONFIG_HOME: scratch, PATH: Deno.env.get("PATH") ?? "", ...extra },
      clearEnv: true,
      stdout: "null",
      stderr: "null",
    }).spawn()
  );
  try {
    let up = false;
    for (let i = 0; i < 40 && !up; i++) {
      up = (await fetch(`http://127.0.0.1:${door}/electric/v1/shape?table=article`).then(async (r) => (await r.body?.cancel(), r.ok)).catch(() => false));
      if (!up) await new Promise((r) => setTimeout(r, 250));
    }
    if (!up) throw new Error("the door never answered");
    await use(door);
  } finally {
    for (const p of started) {
      try {
        p.kill("SIGTERM");
      } catch (e) {
        if (!(e instanceof TypeError)) throw e;
      }
      await p.status;
    }
    await Deno.remove(scratch, { recursive: true });
  }
}

const sent = async (port: number) => await (await fetch(`http://127.0.0.1:${port}/electric/v1/shape?table=article&offset=-1`)).text();

Deno.test({ name: "Electric is sent the app schema's table, and public's as asked", sanitizeOps: false, sanitizeResources: false, fn: async () => {
  await withDoor("shop.", async (port) => assertEquals(await sent(port), "shop.article|s3"));
  await withDoor(undefined, async (port) => assertEquals(await sent(port), "article|s3"));
} });
