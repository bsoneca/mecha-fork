// The door's contract, with the ledger and the transport faked: the order of a
// call (claim, enter, call with the credential, outcome), a replay, a refused
// key, the credential kept from the caller, and what is never an outcome.

import { assert, assertEquals, assertRejects, assertThrows } from "@std/assert";
import { type Door, type DoorLedger, parseDoors, pass, Refused, request, serveDoors } from "./door.ts";
import { meshTransport, type Transport } from "./handler.ts";

const stripe: Door = {
  idempotent: true,
  credential: { header: "Authorization", scheme: "Bearer", secret: "STRIPE_SECRET_KEY" },
  headers: ["Stripe-Version"],
  callers: ["broker"],
};
const KEY = { Authorization: "Bearer sk_test_secret" };

/** A ledger in memory that writes each step into `log`. */
function memory(log: string[]): DoorLedger & { rows: Map<string, { input: unknown; outcome: unknown; entered: number }> } {
  const rows = new Map<string, { input: unknown; outcome: unknown; entered: number }>();
  return {
    rows,
    claim(key, _door, input) {
      log.push(`claim ${key}`);
      if (!rows.has(key)) rows.set(key, { input: structuredClone(input), outcome: null, entered: 0 });
      const r = rows.get(key)!;
      return Promise.resolve({ input: r.input, outcome: r.outcome });
    },
    enter(key) {
      const r = rows.get(key)!;
      log.push(`enter ${key} ${++r.entered}`);
      return Promise.resolve(r.entered);
    },
    settle(key, outcome) {
      log.push(`settle ${key}`);
      const r = rows.get(key)!;
      r.outcome ??= outcome;
      return Promise.resolve();
    },
  };
}

type Sent = { endpoint: string; path: string; init: Parameters<Transport>[2]; key: string; headers: Record<string, string> };
function sink(log: string[], answer: () => { status: number; body: unknown } | Error): { sent: Sent[]; transport: Transport } {
  const sent: Sent[] = [];
  return {
    sent,
    transport: (endpoint, path, init, key, headers) => {
      log.push(`call ${endpoint}${path}`);
      sent.push({ endpoint, path, init, key, headers });
      const a = answer();
      return a instanceof Error ? Promise.reject(a) : Promise.resolve(a);
    },
  };
}

const checkout = {
  key: "checkout-42",
  method: "POST",
  path: "/v1/checkout/sessions",
  body: "mode=subscription&line_items[0][price]=price_1",
  contentType: "application/x-www-form-urlencoded",
  headers: { "Stripe-Version": "2024-06-20" },
};

Deno.test("a call claims, enters, calls with the credential, then records the outcome", async () => {
  const log: string[] = [];
  const ledger = memory(log);
  const { sent, transport } = sink(log, () => ({ status: 200, body: { id: "cs_1", url: "https://checkout.stripe.com/c/1" } }));
  const answer = await pass("stripe", request(stripe, checkout), ledger, transport, KEY);
  assertEquals(log, ["claim stripe:checkout-42", "enter stripe:checkout-42 1", "call stripe/v1/checkout/sessions", "settle stripe:checkout-42"]);
  assertEquals(answer, { status: 200, body: { id: "cs_1", url: "https://checkout.stripe.com/c/1" }, replayed: false });
  // The ledger key is the sink's idempotency key; the credential is the host's.
  assertEquals(sent[0].key, "stripe:checkout-42");
  assertEquals(sent[0].headers, KEY);
  assertEquals(sent[0].init, { method: "POST", body: checkout.body, contentType: checkout.contentType, headers: { "Stripe-Version": "2024-06-20" } });
});

Deno.test("a caller's own sinkKey is the sink's Idempotency-Key, frozen with the request", async () => {
  const log: string[] = [];
  const ledger = memory(log);
  const { sent, transport } = sink(log, () => ({ status: 200, body: { id: "cus_1" } }));
  const own = { ...checkout, sinkKey: "customer https://a.example ana" };
  await pass("stripe", request(stripe, own), ledger, transport, KEY);
  assertEquals(sent[0].key, "customer https://a.example ana", "the caller's key, not the ledger's");
  assertEquals(log[0], "claim stripe:checkout-42", "the ledger keeps its own");
  await assertRejects(() => pass("stripe", request(stripe, { ...own, sinkKey: "another" }), ledger, transport, KEY), Refused, "another request");
  for (const bad of ["", "x".repeat(256), "tab\there", 7]) assertThrows(() => request(stripe, { ...checkout, sinkKey: bad }), Refused, "sinkKey");
});

Deno.test("the credential never reaches the caller, and a caller cannot set it", async () => {
  const log: string[] = [];
  const { transport } = sink(log, () => ({ status: 200, body: { ok: true } }));
  const answer = await pass("stripe", request(stripe, checkout), memory(log), transport, KEY);
  assert(!JSON.stringify(answer).includes("sk_test_secret"));
  assertThrows(() => request(stripe, { ...checkout, headers: { Authorization: "Bearer sk_mine" } }), Refused, "not one the door declares");
  assertThrows(() => parseDoors(JSON.stringify({ doors: { stripe: { ...stripe, headers: ["Authorization"] } } })), Error, "may not set the credential's header");
});

Deno.test("a key that already holds an outcome is answered from the ledger, with no call", async () => {
  const log: string[] = [];
  const ledger = memory(log);
  let n = 0;
  const { sent, transport } = sink(log, () => ({ status: 200, body: { id: `cs_${++n}` } }));
  await pass("stripe", request(stripe, checkout), ledger, transport, KEY);
  const again = await pass("stripe", request(stripe, checkout), ledger, transport, KEY);
  assertEquals(again, { status: 200, body: { id: "cs_1" }, replayed: true });
  assertEquals(sent.length, 1);
});

Deno.test("a key that names another request is refused before any call", async () => {
  const log: string[] = [];
  const ledger = memory(log);
  const { sent, transport } = sink(log, () => ({ status: 200, body: {} }));
  await pass("stripe", request(stripe, checkout), ledger, transport, KEY);
  await assertRejects(() => pass("stripe", request(stripe, { ...checkout, body: "mode=payment" }), ledger, transport, KEY), Refused, "another request");
  assertEquals(sent.length, 1);
});

Deno.test("a 5xx or no answer is not an outcome: the same key calls again", async () => {
  const log: string[] = [];
  const ledger = memory(log);
  const answers: ({ status: number; body: unknown } | Error)[] = [new Error("timeout"), { status: 503, body: "busy" }, { status: 200, body: { id: "cs_1" } }];
  const { sent, transport } = sink(log, () => answers.shift()!);
  assertEquals(await pass("stripe", request(stripe, checkout), ledger, transport, KEY), { unanswered: "timeout" });
  assertEquals(await pass("stripe", request(stripe, checkout), ledger, transport, KEY), { unanswered: "the sink answered 503" });
  assertEquals(await pass("stripe", request(stripe, checkout), ledger, transport, KEY), { status: 200, body: { id: "cs_1" }, replayed: false });
  assertEquals(ledger.rows.get("stripe:checkout-42")!.entered, 3);
  assertEquals(new Set(sent.map((s) => s.key)), new Set(["stripe:checkout-42"]));
});

Deno.test("a sink's refusal below 500 is an outcome, replayed as it is", async () => {
  const log: string[] = [];
  const ledger = memory(log);
  const { sent, transport } = sink(log, () => ({ status: 402, body: { error: { code: "card_declined" } } }));
  await pass("stripe", request(stripe, checkout), ledger, transport, KEY);
  assertEquals(await pass("stripe", request(stripe, checkout), ledger, transport, KEY), { status: 402, body: { error: { code: "card_declined" } }, replayed: true });
  assertEquals(sent.length, 1);
});

Deno.test("a request the door refuses is never claimed", () => {
  for (
    const bad of [
      { ...checkout, key: "" },
      { ...checkout, key: "has space" },
      { ...checkout, method: "TRACE" },
      { ...checkout, path: "https://evil.example/x" },
      { ...checkout, path: "/v1/../admin" },
      { ...checkout, contentType: "text/plain", body: { not: "a string" } },
      { ...checkout, headers: { "Stripe-Version": "x\ny" } },
    ]
  ) assertThrows(() => request(stripe, bad), Refused);
});

Deno.test("the manifest's doors are checked", () => {
  const doors = (d: unknown, effects = {}) => () => parseDoors(JSON.stringify({ effects: {}, doors: d }), effects);
  assertEquals(Object.keys(doors({ stripe })()), ["stripe"]);
  assertEquals(parseDoors(JSON.stringify({ effects: {} })), {});
  assertThrows(doors({ Stripe: stripe }), Error, "DNS label");
  assertThrows(doors({ stripe: { ...stripe, idempotent: false } }), Error, "idempotent");
  assertThrows(doors({ stripe: { ...stripe, callers: [] } }), Error, "callers");
  assertThrows(doors({ stripe: { ...stripe, credential: { header: "Content-Type", secret: "K" } } }), Error, "credential");
  assertThrows(doors({ stripe }, { stripe: {} }), Error, "same name");
});

Deno.test("the door's HTTP answers 200, 400, 404 and 502", async () => {
  const log: string[] = [];
  const answers: ({ status: number; body: unknown } | Error)[] = [{ status: 200, body: { id: "cs_1" } }, new Error("timeout")];
  const { transport } = sink(log, () => answers.shift()!);
  const serve = serveDoors({ stripe }, memory(log), transport, { stripe: KEY });
  const post = (path: string, body: unknown) => serve(new Request(`http://airlock:9998${path}`, { method: "POST", body: JSON.stringify(body) }));
  const ok = await post("/door/stripe", checkout);
  assertEquals([ok.status, await ok.json()], [200, { status: 200, body: { id: "cs_1" }, replayed: false }]);
  assertEquals((await post("/door/stripe", { ...checkout, key: "" })).status, 400);
  assertEquals((await post("/door/paypal", checkout)).status, 404);
  assertEquals((await post("/door/stripe", { ...checkout, key: "other" })).status, 502);
  assertEquals((await serve(new Request("http://airlock:9998/door/stripe"))).status, 405);
});

Deno.test("the mesh sends a door's form body as it is, its headers below the host's", async () => {
  let sent: { url: string; init: RequestInit } | undefined;
  const real = globalThis.fetch;
  globalThis.fetch = (url, init) => {
    sent = { url: String(url), init: init! };
    return Promise.resolve(new Response("{}", { status: 200, headers: { "content-type": "application/json" } }));
  };
  try {
    await meshTransport("http://mesh")("stripe", "/v1/checkout/sessions", {
      method: "POST",
      body: checkout.body,
      contentType: checkout.contentType,
      headers: { "Stripe-Version": "2024-06-20", "Idempotency-Key": "forged" },
    }, "stripe:checkout-42", KEY);
  } finally {
    globalThis.fetch = real;
  }
  assertEquals(sent!.url, "http://mesh/v1.0/invoke/stripe/method/v1/checkout/sessions");
  assertEquals(String(sent!.init.body), checkout.body);
  assertEquals(sent!.init.headers, {
    Accept: "application/json",
    "Stripe-Version": "2024-06-20",
    Authorization: "Bearer sk_test_secret",
    "Idempotency-Key": "stripe:checkout-42",
    "Content-Type": "application/x-www-form-urlencoded",
  });
});
