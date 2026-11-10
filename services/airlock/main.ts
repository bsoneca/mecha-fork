// Airlock: loads effects.json and admits every handler, dying on one it
// refuses, holds this process's liveness, and runs every external effect a
// guard enqueues to an outcome (airlock.ts). Port 9997 opens once all of that
// is up: the cluster's healthcheck, and the ticker's wake, which GETs /healthz
// so that a cluster scaled to zero brings this process up for what a guard
// enqueued meanwhile. Port 9998 is the doors', where a program declares one
// (door.ts).

import pg from "pg";
import { hold, start } from "./airlock.ts";
import { admitAll, bindingsTransport } from "./handler.ts";
import { parseDoors, pgLedger, serveDoors } from "./door.ts";

function required(name: string): string {
  const value = Deno.env.get(name);
  if (value === undefined || value === "") throw new Error(`${name} is required`);
  return value;
}

if (import.meta.main) {
  const connectionString = required("DATABASE_URL");
  const mesh = required("MESH_URL");
  const dir = required("AIRLOCK_DIR");
  const { effects, handlers } = await admitAll(`${dir}/effects.json`, dir);
  const doors = parseDoors(await Deno.readTextFile(`${dir}/effects.json`), effects);
  // Read once here and handed to the handler at each call; written nowhere, not
  // the manifest and not the ledger.
  const secrets = Object.fromEntries(
    Object.entries(effects).map(([name, e]) => [name, Object.fromEntries((e.secrets ?? []).map((s) => [s, required(s)]))]),
  );
  // The credential a sink reads from a header: read here, added by the host
  // to each call, and handed to no handler.
  const headerValue = (name: string) => {
    const value = required(name);
    if (!/^[\x21-\x7e]+$/.test(value)) throw new Error(`${name}: a header value is visible ASCII with no space; a mounted file's trailing newline is the usual cause`);
    return value;
  };
  const credential = (c: { header: string; scheme?: string; secret: string } | undefined) =>
    c === undefined ? {} : { [c.header]: `${c.scheme === undefined ? "" : c.scheme + " "}${headerValue(c.secret)}` };
  const headers = Object.fromEntries(Object.entries(effects).map(([name, e]) => [name, credential(e.credential)]));
  const doorHeaders = Object.fromEntries(Object.entries(doors).map(([name, d]) => [name, credential(d.credential)]));
  const db = new pg.Pool({ connectionString });
  const { key } = await hold(connectionString);
  const runner = await start({ connectionString, db, effects, handlers, transport: bindingsTransport(mesh), secrets, headers }, key);
  Deno.serve({ port: 9997, onListen() {} }, (req) => new Response(null, { status: new URL(req.url).pathname === "/healthz" ? 204 : 404 }));
  // The doors' port, on a network only their declared callers join (door.ts).
  if (Object.keys(doors).length > 0) Deno.serve({ port: 9998, onListen() {} }, serveDoors(doors, pgLedger(db), bindingsTransport(mesh), doorHeaders));
  await runner.promise;
  // On a signal Graphile returns its jobs and ends the process itself; a
  // worker that stops otherwise has nothing left to run.
  throw new Error("the airlock's worker stopped");
}
