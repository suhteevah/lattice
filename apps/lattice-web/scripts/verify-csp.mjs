// CI gate: verify the dev-server CSP (vite.config.ts), the production CSP
// (csp.json), and the meta-tag CSP (index.html) are consistent and do not
// contain disallowed directives.
//
// Disallowed: 'unsafe-eval', any '*' value, http: connect targets.

import { readFile } from "node:fs/promises";

const DISALLOWED = ["'unsafe-eval'", "*", "http:"];

function findViolations(name, policyText) {
  const violations = [];
  for (const token of DISALLOWED) {
    if (policyText.includes(token)) {
      violations.push(`${name}: disallowed token ${token}`);
    }
  }
  return violations;
}

async function main() {
  let allViolations = [];

  const csp = JSON.parse(await readFile("csp.json", "utf8"));
  const flat = JSON.stringify(csp.directives);
  allViolations.push(...findViolations("csp.json", flat));

  const vite = await readFile("vite.config.ts", "utf8");
  allViolations.push(...findViolations("vite.config.ts", vite));

  const html = await readFile("index.html", "utf8");
  const meta = html.match(/Content-Security-Policy"\s+content="([^"]+)"/);
  if (meta) {
    allViolations.push(...findViolations("index.html (meta)", meta[1]));
  } else {
    allViolations.push("index.html: missing CSP meta tag");
  }

  if (allViolations.length > 0) {
    console.error("[verify-csp] FAIL");
    for (const v of allViolations) console.error("  -", v);
    process.exit(1);
  }

  console.log("[verify-csp] OK — no disallowed CSP tokens");
}

main().catch((err) => {
  console.error("[verify-csp] error:", err);
  process.exit(1);
});
