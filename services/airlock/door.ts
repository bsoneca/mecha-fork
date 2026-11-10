// The airlock's door: the one way out for a call that needs its answer now.
//
// An effect starts from a machine's transition and answers later (airlock.ts).
// A door answers the call that asks: a declared caller POSTs the request, and
// the airlock performs it against the door's sink in the effect's own order,
// each step committed before the next:
//
//   claim    the ledger row `<door>:<key>`, its input frozen; a key that already
//            holds an outcome is answered from it, and one that names another
//            input is refused
//   enter    `entered + 1`, before the call: past one, a call may have reached
//            the sink
//   call     through the door's binding, the credential added by the host from
//            what it read at startup, the ledger key as the Idempotency-Key, or
//            the caller's own `sinkKey` where it names one (the key it sends the
//            sink by another way too, so a call retried that other way is the
//            same call at the sink)
//   outcome  a sink answer below 500, committed, then answered
//
// A 5xx or no answer is not an outcome: the caller is answered 502 and calls
// again with the same key, which the sink's idempotency makes safe. So a door
// is declared idempotent only. The caller never holds the credential: it names
// a path, a body and the headers its door declares, and nothing else.

import type pg from "pg";
import { sinkPath, type Transport } from "./handler.ts";
import { ENDPOINT, HEADER, RESERVED_HEADERS, SECRET, TOKEN } from "./reentry.ts";

/** What the program declared for a door, as pronto emits it into effects.json's
 * `doors`. */
export type Door = {
  idempotent: true;
  /** A header the airlock adds to every call, its value the named variable's. */
  credential?: { header: string; scheme?: string; secret: string };
  /** The request headers a caller may set (Stripe-Version). */
  headers?: string[];
  /** The services that may reach the door; the cluster's wall, not this file's. */
  callers: string[];
};

/** One call through a door, as its caller sends it. */
export type DoorRequest = {
  key: string;
  method: string;
  path: string;
  /** JSON, or a string sent as it is when `contentType` names another type. */
  body?: unknown;
  contentType?: string;
  headers?: Record<string, string>;
  /** The sink's Idempotency-Key, where the caller keeps one of its own (1 to 255
   * visible characters, Stripe's limit); frozen with the request. */
  sinkKey?: string;
};

/** The ledger as a door uses it: three commits. */
export type DoorLedger = {
  /** Inserts the row, or answers the one there: its input and its outcome. */
  claim(key: string, door: string, input: unknown): Promise<{ input: unknown; outcome: unknown }>;
  /** `entered + 1`, committed. */
  enter(key: string): Promise<number>;
  /** The outcome, committed once. */
  settle(key: string, outcome: unknown): Promise<void>;
};

export type DoorAnswer = { status: number; body: unknown };

const METHODS = new Set(["GET", "POST", "PUT", "PATCH", "DELETE"]);
/** A caller's key: what Stripe takes as an Idempotency-Key, once prefixed. */
const KEY = /^[A-Za-z0-9._:-]{1,200}$/;
const SINK_KEY = /^[\x20-\x7e]{1,255}$/;
const CONTENT_TYPE = /^[a-z]+\/[a-z0-9.+-]+$/;

/** effects.json's `doors`, checked; an absent map is no door. */
export function parseDoors(text: string, effects: Record<string, unknown> = {}): Record<string, Door> {
  const doors = JSON.parse(text)?.doors ?? {};
  if (typeof doors !== "object" || doors === null || Array.isArray(doors)) throw new Error("effects.json: `doors` is not a map");
  for (const [name, d] of Object.entries(doors as Record<string, Door>)) {
    const bad = (why: string): never => {
      throw new Error(`effects.json: door ${name}: ${why}`);
    };
    if (!ENDPOINT.test(name)) bad("the name is not a DNS label");
    if (name in effects) bad("an effect has the same name, and the name is the binding's");
    if (d.idempotent !== true) bad("a door is idempotent: a call with no answer is called again with the same key");
    if (!Array.isArray(d.callers) || d.callers.length === 0 || !d.callers.every((c) => typeof c === "string" && ENDPOINT.test(c))) {
      bad("callers is not a list of services");
    }
    const c = d.credential;
    if (c !== undefined) {
      const header = typeof c?.header === "string" && HEADER.test(c.header) && !RESERVED_HEADERS.has(c.header.toLowerCase());
      if (!header || typeof c.secret !== "string" || !SECRET.test(c.secret) || (c.scheme !== undefined && !(typeof c.scheme === "string" && TOKEN.test(c.scheme)))) {
        bad("credential is not {header, scheme?, secret}");
      }
    }
    if (d.headers !== undefined) {
      if (!Array.isArray(d.headers) || !d.headers.every((h) => typeof h === "string" && HEADER.test(h) && !RESERVED_HEADERS.has(h.toLowerCase()))) {
        bad("headers is not a list of header names daprd forwards (uppercase first), none the host's or HTTP's own");
      }
      if (c !== undefined && d.headers.some((h) => h.toLowerCase() === c.header.toLowerCase())) bad("a caller may not set the credential's header");
    }
  }
  return doors as Record<string, Door>;
}

/** A refusal of the request itself, answered 400 and never claimed. */
export class Refused extends Error {}

/** The request checked against its door: what may be claimed and called. */
export function request(door: Door, r: unknown): DoorRequest {
  const q = r as DoorRequest;
  if (typeof q !== "object" || q === null) throw new Refused("the request is not an object");
  if (typeof q.key !== "string" || !KEY.test(q.key)) throw new Refused("key is 1 to 200 of A-Z a-z 0-9 . _ : -");
  if (typeof q.method !== "string" || !METHODS.has(q.method)) throw new Refused(`method ${JSON.stringify(q.method)}`);
  try {
    sinkPath(q.path);
  } catch (e) {
    throw new Refused((e as Error).message);
  }
  if (q.contentType !== undefined && (typeof q.contentType !== "string" || !CONTENT_TYPE.test(q.contentType))) throw new Refused("contentType is not a media type");
  if (q.contentType !== undefined && q.contentType !== "application/json" && typeof q.body !== "string") throw new Refused("a body that is not JSON is a string");
  const allowed = new Set((door.headers ?? []).map((h) => h.toLowerCase()));
  const headers: Record<string, string> = {};
  for (const [h, v] of Object.entries(q.headers ?? {})) {
    const declared = door.headers?.find((d) => d.toLowerCase() === h.toLowerCase());
    if (!allowed.has(h.toLowerCase()) || declared === undefined) throw new Refused(`header ${h} is not one the door declares`);
    if (typeof v !== "string" || !/^[\x20-\x7e]{1,200}$/.test(v)) throw new Refused(`header ${h}: a short visible value`);
    headers[declared] = v;
  }
  if (q.sinkKey !== undefined && (typeof q.sinkKey !== "string" || !SINK_KEY.test(q.sinkKey))) throw new Refused("sinkKey is 1 to 255 visible characters");
  return { key: q.key, method: q.method, path: q.path, body: q.body, contentType: q.contentType, headers, ...(q.sinkKey === undefined ? {} : { sinkKey: q.sinkKey }) };
}

/** What the ledger freezes: the request a key names. */
const input = (r: DoorRequest) => ({
  method: r.method, path: r.path, body: r.body ?? null, contentType: r.contentType ?? null, headers: r.headers ?? {},
  ...(r.sinkKey === undefined ? {} : { sinkKey: r.sinkKey }),
});

/** JSON with every object's keys sorted: Postgres's jsonb hands keys back in
 * its own order. */
const canonical = (v: unknown): string =>
  JSON.stringify(v, (_, x) => x !== null && typeof x === "object" && !Array.isArray(x) ? Object.fromEntries(Object.entries(x).sort(([a], [b]) => a < b ? -1 : 1)) : x);

/** One call through `name`, in the door's order. `credential` is the header the
 * host read at startup; the caller's request never carries it. */
export async function pass(
  name: string,
  r: DoorRequest,
  ledger: DoorLedger,
  transport: Transport,
  credential: Record<string, string>,
): Promise<DoorAnswer & { replayed: boolean } | { unanswered: string }> {
  const key = `${name}:${r.key}`;
  const frozen = input(r);
  const held = await ledger.claim(key, name, frozen);
  if (canonical(held.input) !== canonical(frozen)) throw new Refused(`key ${r.key} already names another request`);
  if (held.outcome !== null && held.outcome !== undefined) return { ...(held.outcome as DoorAnswer), replayed: true };
  await ledger.enter(key);
  let answer: DoorAnswer;
  try {
    answer = await transport(name, r.path, { method: r.method, body: r.body, contentType: r.contentType, headers: r.headers }, r.sinkKey ?? key, credential);
  } catch (e) {
    return { unanswered: e instanceof Error ? e.message : String(e) };
  }
  if (answer.status >= 500) return { unanswered: `the sink answered ${answer.status}` };
  await ledger.settle(key, { status: answer.status, body: answer.body });
  return { ...answer, replayed: false };
}

/** The ledger in Postgres: the effects' table, a door's row holding no
 * instance. */
export function pgLedger(db: pg.Pool): DoorLedger {
  return {
    async claim(key, door, frozen) {
      await db.query(
        "INSERT INTO airlock.external_effect_ledger (key, effect, row, input) VALUES ($1, $2, '{}', $3) ON CONFLICT (key) DO NOTHING",
        [key, door, frozen],
      );
      const { rows: [l] } = await db.query("SELECT input, outcome FROM airlock.external_effect_ledger WHERE key = $1", [key]);
      return { input: l.input, outcome: l.outcome === null ? null : l.outcome.data };
    },
    async enter(key) {
      const { rows: [c] } = await db.query("UPDATE airlock.external_effect_ledger SET entered = entered + 1 WHERE key = $1 RETURNING entered", [key]);
      return c.entered;
    },
    async settle(key, answer) {
      await db.query(
        "UPDATE airlock.external_effect_ledger SET outcome = $2, settled_at = clock_timestamp() WHERE key = $1 AND outcome IS NULL",
        [key, { target: "door", kind: "done", data: answer, reconciled: false }],
      );
    },
  };
}

/** The door's HTTP: `POST /door/<name>` with a DoorRequest, answered 200 with
 * the sink's {status, body} and whether it was replayed, 400 for a request the
 * door refuses, 404 for no such door, and 502 when the sink gave no answer. */
export function serveDoors(
  doors: Record<string, Door>,
  ledger: DoorLedger,
  transport: Transport,
  credentials: Record<string, Record<string, string>>,
): (req: Request) => Promise<Response> {
  const json = (status: number, body: unknown) => Response.json(body, { status });
  return async (req) => {
    const m = /^\/door\/([a-z][a-z0-9-]*)$/.exec(new URL(req.url).pathname);
    const door = m ? doors[m[1]] : undefined;
    if (m === null || door === undefined) return json(404, { error: "no such door" });
    if (req.method !== "POST") return json(405, { error: "POST a request" });
    try {
      const r = request(door, await req.json().catch(() => null));
      const answer = await pass(m[1], r, ledger, transport, credentials[m[1]] ?? {});
      return "unanswered" in answer ? json(502, { error: answer.unanswered }) : json(200, answer);
    } catch (e) {
      if (e instanceof Refused) return json(400, { error: e.message });
      console.error(`door ${m[1]}:`, e);
      return json(500, { error: "the airlock could not record the call" });
    }
  };
}
