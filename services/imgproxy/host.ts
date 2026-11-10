// imgproxy's stand-in on a host, under process-compose. imgproxy publishes an
// image and, for macOS, no binary (it links libvips), so the host runs this
// instead of it: the one request the cluster makes of it,
//
//   GET /insecure/<preset>/plain/<source>      (the door strips /img)
//
// answered as the image's imgproxy answers it with the cluster's settings
// (cluster.cue, the imgproxy service): only the presets, each a resize to a
// size in WebP, and only the sources allowed. It is not imgproxy, so anything
// else imgproxy does (signed URLs, other options, other formats, other
// sources) is refused, never approximated.
//
//   deno run --allow-all host.ts
//
// Reads what the image reads: IMGPROXY_PRESETS (`name=rs:fill|fit:W:H/f:webp,...`),
// IMGPROXY_ALLOWED_SOURCES (prefixes, comma separated), IMGPROXY_MAX_SRC_RESOLUTION
// (megapixels), IMGPROXY_MAX_RESULT_DIMENSION, IMGPROXY_S3_ENDPOINT (rclone's, as the
// image reaches it) and IMGPROXY_PORT, which the host moves.
import sharp from "npm:sharp@0.34.5";

const env = (k: string) => Deno.env.get(k) ?? (console.error(`${k} is not set`), Deno.exit(1));

type Preset = { mode: "fill" | "fit"; width: number; height: number };
const presets = new Map<string, Preset>();
for (const p of env("IMGPROXY_PRESETS").split(",")) {
  const m = p.match(/^([a-z0-9_]+)=rs:(fill|fit):(\d+):(\d+)\/f:webp$/);
  if (!m) { console.error(`preset '${p}' is none this stand-in knows`); Deno.exit(1); }
  presets.set(m[1], { mode: m[2] as Preset["mode"], width: Number(m[3]), height: Number(m[4]) });
}
const allowed = env("IMGPROXY_ALLOWED_SOURCES").split(",");
const endpoint = env("IMGPROXY_S3_ENDPOINT").replace(/\/$/, "");
const maxPixels = Number(env("IMGPROXY_MAX_SRC_RESOLUTION")) * 1e6;
const maxSide = Number(env("IMGPROXY_MAX_RESULT_DIMENSION"));
const port = Number(env("IMGPROXY_PORT"));

const reply = (status: number, body: BodyInit | null = null, type?: string) => {
  if (status >= 400 && typeof body === "string") console.error(`imgproxy: ${status} ${body}`);
  return new Response(body, { status, headers: type ? { "content-type": type } : {} });
};

Deno.serve({ hostname: "127.0.0.1", port }, async (req) => {
  const url = new URL(req.url);
  if (url.pathname === "/health") return reply(200, "imgproxy is running");
  if (req.method !== "GET") return reply(405);
  const m = req.url.slice(url.origin.length).match(/^\/insecure\/([a-z0-9_]+)\/plain\/(.+?)(?:@webp)?$/);
  const preset = m && presets.get(m[1]);
  if (!m || !preset) return reply(404, `no such preset: ${req.url.slice(url.origin.length)}`);
  // A proxy in between may merge the slashes after the scheme, as imgproxy takes either.
  const source = decodeURIComponent(m[2]).replace(/^([a-z0-9]+):\/+/, "$1://");
  if (!allowed.some((a) => source.startsWith(a))) return reply(404, `source is not allowed: ${source}`);
  const s3 = source.match(/^s3:\/\/([^/]+)\/(.+)$/);
  const from = s3 ? `${endpoint}/${s3[1]}/${s3[2]}` : source;
  const res = await fetch(from).catch(() => null);
  if (!res?.ok) return reply(404, `source is not there: ${from}`);
  try {
    const out = await sharp(new Uint8Array(await res.arrayBuffer()), { limitInputPixels: maxPixels })
      .rotate()
      .resize({
        width: Math.min(preset.width, maxSide), height: Math.min(preset.height, maxSide),
        fit: preset.mode === "fill" ? "cover" : "inside", withoutEnlargement: true,
      })
      .webp()
      .toBuffer();
    return reply(200, new Uint8Array(out), "image/webp");
  } catch {
    return reply(422, "source is no image");
  }
});
