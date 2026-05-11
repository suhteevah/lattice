// Post-build: compute SRI hashes for every emitted asset and rewrite the
// dist/index.html so all <script src=...> and <link rel="stylesheet"...>
// tags carry an `integrity` attribute.
//
// Verbose logging on by default — set LATTICE_QUIET=1 to mute.

import { createHash } from "node:crypto";
import { readFile, writeFile, readdir, stat } from "node:fs/promises";
import { join, relative, resolve } from "node:path";

const DIST = resolve(process.cwd(), "dist");
const QUIET = process.env.LATTICE_QUIET === "1";

function log(...args) {
  if (!QUIET) console.log("[sri-pin]", ...args);
}

async function walk(dir, out = []) {
  for (const name of await readdir(dir)) {
    const full = join(dir, name);
    const st = await stat(full);
    if (st.isDirectory()) {
      await walk(full, out);
    } else {
      out.push(full);
    }
  }
  return out;
}

async function sha384(path) {
  const buf = await readFile(path);
  const digest = createHash("sha384").update(buf).digest("base64");
  return `sha384-${digest}`;
}

async function main() {
  log("scanning", DIST);
  const files = await walk(DIST);
  const hashes = new Map();

  for (const f of files) {
    if (/\.(js|mjs|css|wasm)$/.test(f)) {
      const rel = "/" + relative(DIST, f).replaceAll("\\", "/");
      const integrity = await sha384(f);
      hashes.set(rel, integrity);
      log("hashed", rel, integrity.slice(0, 24) + "…");
    }
  }

  const indexPath = join(DIST, "index.html");
  let html = await readFile(indexPath, "utf8");

  html = html.replace(
    /<script\s+([^>]*?)src="([^"]+)"([^>]*?)>/g,
    (match, before, src, after) => {
      const integrity = hashes.get(src);
      if (!integrity) {
        log("WARN no hash for script", src);
        return match;
      }
      return `<script ${before}src="${src}" integrity="${integrity}" crossorigin="anonymous"${after}>`;
    },
  );

  html = html.replace(
    /<link\s+([^>]*?)href="([^"]+\.css)"([^>]*?)>/g,
    (match, before, href, after) => {
      const integrity = hashes.get(href);
      if (!integrity) {
        log("WARN no hash for stylesheet", href);
        return match;
      }
      return `<link ${before}href="${href}" integrity="${integrity}" crossorigin="anonymous"${after}>`;
    },
  );

  await writeFile(indexPath, html);
  log("rewrote", indexPath, "with", hashes.size, "integrity attributes");
}

main().catch((err) => {
  console.error("[sri-pin] FAILED:", err);
  process.exit(1);
});
