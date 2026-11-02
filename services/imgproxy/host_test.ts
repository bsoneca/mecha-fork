// The imgproxy stand-in answers what the cluster asks of imgproxy and nothing else:
// a preset's size in WebP over the store's object, and a refusal of anything the
// cluster's settings do not allow.
//
//   deno test --allow-all services/imgproxy/host_test.ts
import assert from "node:assert/strict";
import sharp from "npm:sharp@0.34.5";

const png = await sharp({ create: { width: 600, height: 300, channels: 3, background: "#369" } }).png().toBuffer();
const store = Deno.serve({ hostname: "127.0.0.1", port: 0, onListen() {} }, (req) =>
  new URL(req.url).pathname === "/mecha-objects/a/b.png" ? new Response(new Uint8Array(png)) : new Response("none", { status: 404 }));
const free = Deno.listen({ hostname: "127.0.0.1", port: 0 });
const port = (free.addr as Deno.NetAddr).port;
free.close();
const server = new Deno.Command(Deno.execPath(), {
  args: ["run", "--allow-all", new URL("host.ts", import.meta.url).pathname],
  env: {
    IMGPROXY_PRESETS: "thumb=rs:fill:128:128/f:webp,picture=rs:fit:1024:1024/f:webp",
    IMGPROXY_ALLOWED_SOURCES: "s3://mecha-objects/,https://lh3.googleusercontent.com/",
    IMGPROXY_S3_ENDPOINT: `http://127.0.0.1:${store.addr.port}`,
    IMGPROXY_MAX_SRC_RESOLUTION: "50",
    IMGPROXY_MAX_RESULT_DIMENSION: "1024",
    IMGPROXY_PORT: String(port),
  },
  stdout: "null", stderr: "null",
}).spawn();
for (let i = 0; i < 120; i++) {
  if ((await fetch(`http://127.0.0.1:${port}/health`).catch(() => null))?.ok) break;
  await new Promise((r) => setTimeout(r, 500));
}
const get = (path: string) => fetch(`http://127.0.0.1:${port}${path}`);
const size = async (r: Response) => {
  const m = await sharp(new Uint8Array(await r.arrayBuffer())).metadata();
  return [m.format, m.width, m.height];
};

Deno.test("a preset is the size it names, in WebP", async () => {
  assert.deepEqual(await size(await get("/insecure/thumb/plain/s3://mecha-objects/a/b.png")), ["webp", 128, 128]);
  assert.deepEqual(await size(await get("/insecure/picture/plain/s3://mecha-objects/a/b.png")), ["webp", 600, 300]);
  assert.deepEqual(await size(await get("/insecure/thumb/plain/s3:/mecha-objects/a/b.png")), ["webp", 128, 128], "slashes merged by a proxy");
});

Deno.test("a source outside the allowed, a preset of its own choosing and a missing object are refused", async () => {
  for (const path of [
    "/insecure/thumb/plain/https://example.com/x.png",
    "/insecure/rs:fill:9999:9999/plain/s3://mecha-objects/a/b.png",
    "/insecure/thumb/plain/s3://mecha-objects/none.png",
  ]) {
    const r = await get(path);
    await r.body?.cancel();
    assert.equal(r.status, 404, path);
  }
});

Deno.test("teardown", async () => {
  server.kill();
  await server.status;
  await store.shutdown();
});
