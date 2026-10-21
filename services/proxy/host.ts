// The door on a host, under process-compose, as the caddy image serves it in a
// container (cluster.cue): the statics the image bakes in are copied under a
// directory of their own, each with its `.etag` beside it, and the Caddyfile is
// read with that directory where it names an absolute root, the host's ports
// where its site addresses name the container's, and loopback where it names a
// peer the host runs.
//
//   deno run -A host.ts <caddyfile> --door <port> --health <port>
//     --peers <name>=<port>,... [<target> <file> ...]
//
// A file is a path from the working directory, the app's, or from a mise
// tool's install directory when it opens with `{<tool>}/`. The environment
// holds the origin as DOOR_ORIGIN, which the door is given as ORIGIN, the
// host's door and health ports as DOOR_PORT and HEALTH_PORT, and DOOR_PEERS,
// each peer of --peers at its host address, in order.

const args: Record<string, string> = {};
const rest: string[] = [];
for (let i = 0; i < Deno.args.length; i++) {
  const a = Deno.args[i];
  if (a.startsWith("--")) args[a.slice(2)] = Deno.args[++i] ?? "";
  else rest.push(a);
}
const [caddyfile, ...pairs] = rest;
const fail = (msg: string): never => {
  console.error(`door: ${msg}`);
  Deno.exit(1);
};
if (!caddyfile || !args.door || !args.health || pairs.length % 2) {
  fail("usage: host.ts <caddyfile> --door <port> --health <port> --peers <name>=<port>,... [<target> <file> ...]");
}
const env = (k: string) => Deno.env.get(k) ?? fail(`${k} is unset`);

// An ORIGIN that is no origin stops the door as it starts, as it does in the
// container: a template writes it into markup as it stands.
const origin = env("DOOR_ORIGIN");
const host = origin.replace(/^https?:\/\//, "");
if (host === origin || host === "" || /[^A-Za-z0-9.:-]/.test(host)) {
  fail(`ORIGIN '${origin}' is no origin: set it to the scheme and host readers reach the door at, as https://app.example`);
}

const peers = (args.peers ?? "").split(",").filter((p) => p !== "");
const addresses = (Deno.env.get("DOOR_PEERS") ?? "").split(" ").filter((a) => a !== "");
if (peers.length !== addresses.length) fail(`--peers names ${peers.length} peers and DOOR_PEERS ${addresses.length}`);

const tools = new Map<string, string>();
const where = async (tool: string) => {
  if (!tools.has(tool)) {
    const out = await new Deno.Command("mise", { args: ["where", tool], stderr: "inherit" }).output();
    if (!out.success) fail(`mise has no install of ${tool}`);
    tools.set(tool, new TextDecoder().decode(out.stdout).trim());
  }
  return tools.get(tool)!;
};
const resolve = async (file: string) => {
  const m = file.match(/^\{([^}]+)\}\/(.*)$/);
  return m ? `${await where(m[1])}/${m[2]}` : file;
};

const root = await Deno.makeTempDir({ prefix: "mecha-door." });
const cleanup = () => Deno.removeSync(root, { recursive: true });

// Copied, not linked, so what the door serves matches the validator written
// beside it until the door restarts, as an image's files do.
for (let i = 0; i < pairs.length; i += 2) {
  const [target, file] = [pairs[i], await resolve(pairs[i + 1])];
  const dst = `${root}${target}`;
  await Deno.mkdir(dst.slice(0, dst.lastIndexOf("/")), { recursive: true });
  await Deno.copyFile(file, dst);
  const hash = new Uint8Array(await crypto.subtle.digest("SHA-256", await Deno.readFile(dst)));
  await Deno.writeTextFile(`${dst}.etag`, `"${Array.from(hash, (b) => b.toString(16).padStart(2, "0")).join("")}"`);
}

const portEnd = "(?![0-9])";
const unquote = (s: string) => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
let text = await Deno.readTextFile(caddyfile);
text = text.replace(/^(\s*root\s+(?:\*\s+)?)\//gm, `$1${root}/`);
// Only a site address, a top-level line opening a block, names a listener.
text = text.replace(/^[^\s#({].*\{\s*$/gm, (line) =>
  line
    .replace(new RegExp(`:${args.door}${portEnd}`, "g"), `:${env("DOOR_PORT")}`)
    .replace(new RegExp(`:${args.health}${portEnd}`, "g"), `:${env("HEALTH_PORT")}`));
peers.forEach((p, i) => {
  const [name, port] = p.split("=");
  text = text.replace(new RegExp(`(?<![A-Za-z0-9_.-])${unquote(name)}:${port}${portEnd}`, "g"), addresses[i]);
});
// No admin endpoint, which every door on the host would claim at :2019, and
// no root certificate put into the host's trust store, which asks for a
// password: the image's caddy needs neither.
const global = "admin off\n\tskip_install_trust";
const first = text.split("\n").find((l) => l.trim() !== "" && !l.trim().startsWith("#"));
text = first?.trim() === "{"
  ? text.replace(/^\{\s*$/m, `{\n\t${global}`)
  : `{\n\t${global}\n}\n\n${text}`;
await Deno.writeTextFile(`${root}/Caddyfile`, text);

// mkcert's pair, where `sayt setup` issued one; Caddy's own CA otherwise.
const cert = `${Deno.cwd()}/.certs/localhost.pem`;
const tls = await Deno.stat(cert).then(() => `${cert} ${Deno.cwd()}/.certs/localhost-key.pem`, () => undefined);

const caddy = new Deno.Command("caddy", {
  args: ["run", "--config", `${root}/Caddyfile`, "--adapter", "caddyfile"],
  env: { ORIGIN: origin, ...(tls ? { CADDY_TLS: tls } : {}) },
}).spawn();
for (const signal of ["SIGTERM", "SIGINT"] as const) {
  Deno.addSignalListener(signal, () => caddy.kill(signal));
}
const { code } = await caddy.status;
cleanup();
Deno.exit(code);
