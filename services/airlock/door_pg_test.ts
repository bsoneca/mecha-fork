// The door's ledger in Postgres: airlock.sql applied to a throwaway cluster on
// this host's own binaries (PG_BIN, the directory holding initdb and pg_ctl),
// and a call claimed, entered, settled and replayed through it. Skipped where
// PG_BIN is not set.

import { assertEquals, assertRejects } from "@std/assert";
import pg from "pg";
import { pass, pgLedger, Refused, request } from "./door.ts";
import type { Transport } from "./handler.ts";

const bin = Deno.env.get("PG_BIN");

async function run(cmd: string, args: string[]): Promise<void> {
  const out = await new Deno.Command(`${bin}/${cmd}`, { args, stdout: "piped", stderr: "piped" }).output();
  if (!out.success) throw new Error(`${cmd}: ${new TextDecoder().decode(out.stderr)}`);
}

Deno.test({ name: "the door's ledger in Postgres claims, enters, settles and replays", ignore: bin === undefined }, async () => {
  // Under /tmp: a socket path is at most 103 bytes.
  const dir = await Deno.makeTempDir({ dir: "/tmp", prefix: "door" });
  const port = 20000 + Math.floor(Math.random() * 20000);
  await run("initdb", ["-D", dir, "-U", "airlock", "--auth=trust", "-E", "UTF8"]);
  // A log file, or the server would hold this process's pipe open and the start would never end.
  await run("pg_ctl", ["-D", dir, "-l", `${dir}/log`, "-o", `-p ${port} -k ${dir} -c listen_addresses=''`, "-w", "start"]);
  const db = new pg.Pool({ host: dir, port, user: "airlock", database: "postgres" });
  try {
    // The ticker's schedule table, which the database image puts before this step.
    await db.query("CREATE TABLE schedule (name TEXT PRIMARY KEY, due_at TIMESTAMPTZ, last_tick_at TIMESTAMPTZ, emits_entity TEXT)");
    await db.query(await Deno.readTextFile(new URL("./airlock.sql", import.meta.url)));
    const door = { idempotent: true as const, headers: ["Stripe-Version"], callers: ["broker"] };
    const r = request(door, {
      key: "checkout-42",
      method: "POST",
      path: "/v1/checkout/sessions",
      body: "mode=subscription",
      contentType: "application/x-www-form-urlencoded",
      headers: { "Stripe-Version": "2024-06-20" },
    });
    let calls = 0;
    const transport: Transport = () => Promise.resolve({ status: 200, body: { id: `cs_${++calls}`, nested: { b: 1, a: 2 } } });
    const ledger = pgLedger(db);
    assertEquals(await pass("stripe", r, ledger, transport, {}), { status: 200, body: { id: "cs_1", nested: { b: 1, a: 2 } }, replayed: false });
    // jsonb hands the frozen input back in its own key order: still the same request.
    assertEquals(await pass("stripe", r, ledger, transport, {}), { status: 200, body: { id: "cs_1", nested: { a: 2, b: 1 } }, replayed: true });
    assertEquals(calls, 1);
    await assertRejects(() => pass("stripe", { ...r, body: "mode=payment" }, ledger, transport, {}), Refused);
    const { rows: [l] } = await db.query("SELECT effect, row, entered, outcome->>'kind' AS kind FROM airlock.external_effect_ledger WHERE key = 'stripe:checkout-42'");
    assertEquals(l, { effect: "stripe", row: {}, entered: 1, kind: "done" });
  } finally {
    await db.end();
    await run("pg_ctl", ["-D", dir, "-m", "immediate", "stop"]);
    await Deno.remove(dir, { recursive: true });
  }
});
