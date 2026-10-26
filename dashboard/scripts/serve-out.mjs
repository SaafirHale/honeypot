// Serve the static export in out/ for previewing the built dashboard.
// Usage: node scripts/serve-out.mjs [port]   (default 3101)
import { createReadStream, existsSync, statSync } from "node:fs";
import { createServer } from "node:http";
import { extname, join, normalize, resolve } from "node:path";

const root = resolve(import.meta.dirname, "..", "out");
const port = Number(process.argv[2] || process.env.PORT || 3101);
const basePath = process.env.NEXT_PUBLIC_BASE_PATH || "";
const types = {
  ".html": "text/html; charset=utf-8", ".js": "text/javascript", ".css": "text/css",
  ".json": "application/json", ".woff2": "font/woff2", ".svg": "image/svg+xml",
  ".ico": "image/x-icon", ".txt": "text/plain",
};

createServer((req, res) => {
  let path = decodeURIComponent(new URL(req.url, "http://x").pathname);
  if (basePath && path.startsWith(basePath)) path = path.slice(basePath.length) || "/";
  let file = normalize(join(root, path));
  if (!file.startsWith(root)) return res.writeHead(403).end();
  if (existsSync(file) && statSync(file).isDirectory()) file = join(file, "index.html");
  if (!existsSync(file) && existsSync(file + ".html")) file += ".html";
  if (!existsSync(file)) return res.writeHead(404).end("not found");
  res.writeHead(200, { "content-type": types[extname(file)] || "application/octet-stream" });
  createReadStream(file).pipe(res);
}).listen(port, () => console.log(`serving ${root} at http://localhost:${port}${basePath}/`));
