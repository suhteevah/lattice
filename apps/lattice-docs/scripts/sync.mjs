#!/usr/bin/env node
// Cross-platform mirror of repo-root `docs/` content into the Astro /
// Starlight content collection. Pure Node so it runs inside the Vercel
// build container (no PowerShell on Linux) and on the dev host alike.
//
// Two source trees fold into `src/content/docs/`:
//
//   1. `docs/usage/*.{md,mdx}`            -> `src/content/docs/docs/usage/`
//      (user-facing manual; what visitors land on)
//   2. `docs/{HANDOFF,DECISIONS,ARCHITECTURE,THREAT_MODEL,ROADMAP}.md`
//                                         -> `src/content/docs/wiki/`
//      (project wiki — design choices + threat model + architecture)
//
// Idempotent. Destination is git-ignored. Invoked by npm prebuild /
// predev hooks and by `npm run sync` directly.

import fs from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const here = path.dirname(fileURLToPath(import.meta.url));
const appRoot = path.dirname(here);
const repoRoot = path.resolve(appRoot, '..', '..');

const USAGE_SRC = path.join(repoRoot, 'docs', 'usage');
const USAGE_DEST = path.join(appRoot, 'src', 'content', 'docs', 'docs', 'usage');

const WIKI_DEST = path.join(appRoot, 'src', 'content', 'docs', 'wiki');
// **Public wiki only.** HANDOFF / ROADMAP / DECISIONS / README are
// internal — they leak machine names, future plans, session logs,
// and tentative product decisions. Do not add them here without an
// explicit scrub-and-review pass.
const WIKI_FILES = [
  { name: 'ARCHITECTURE', src: 'docs/ARCHITECTURE.md', sort: 10, label: 'Architecture' },
  { name: 'THREAT_MODEL', src: 'docs/THREAT_MODEL.md', sort: 20, label: 'Threat model' },
];

function log(...args) {
  console.log('[sync]', ...args);
}

async function exists(p) {
  try { await fs.access(p); return true; } catch { return false; }
}

async function rmrf(dir) {
  await fs.rm(dir, { recursive: true, force: true });
}

function toTitle(slug) {
  if (!slug) return 'Untitled';
  const words = slug.split(/[-_]/);
  const first = words[0];
  const cap = first.length > 1
    ? first[0].toUpperCase() + first.slice(1).toLowerCase()
    : first.toUpperCase();
  return [cap, ...words.slice(1).map((w) => w.toLowerCase())].join(' ');
}

function normalizeMarkdown(raw, { fallbackSlug, extra = '' }) {
  raw = raw ?? '';

  const fmMatch = /^\s*---\s*\r?\n([\s\S]*?)\r?\n---\s*\r?\n/.exec(raw);
  const hasFrontmatter = !!fmMatch;
  const hasTitle = hasFrontmatter && /^\s*title\s*:/m.test(fmMatch[1]);

  if (hasTitle && !extra) {
    return raw;
  }

  let title = null;
  const h1 = /^\s*#\s+(.+?)\s*$/m.exec(raw);
  if (h1) {
    title = h1[1].trim();
  }
  if (!title) {
    title = toTitle(fallbackSlug || 'untitled');
  }
  const safeTitle = title.replace(/"/g, '\\"');

  const injectLines = [];
  if (!hasTitle) injectLines.push(`title: "${safeTitle}"`);
  if (extra) injectLines.push(extra.trim());

  if (hasFrontmatter) {
    return raw.replace(
      /^\s*---\s*\r?\n/,
      `---\n${injectLines.join('\n')}\n`,
    );
  }
  return `---\n${injectLines.join('\n')}\n---\n\n${raw}`;
}

async function copyMarkdown(srcFile, destFile, options) {
  let raw;
  try {
    raw = await fs.readFile(srcFile, 'utf8');
  } catch (e) {
    log(`skipping ${srcFile} — ${e.message}`);
    return false;
  }
  const out = normalizeMarkdown(raw, options);
  await fs.mkdir(path.dirname(destFile), { recursive: true });
  await fs.writeFile(destFile, out, 'utf8');
  return true;
}

async function syncUsage() {
  log(`source: ${USAGE_SRC}`);
  log(`dest:   ${USAGE_DEST}`);

  if (!(await exists(USAGE_SRC))) {
    log('usage source directory missing — writing placeholder');
    await fs.mkdir(USAGE_DEST, { recursive: true });
    const placeholder = [
      '---',
      'title: Documentation pending',
      'description: The Lattice usage docs are still being written.',
      '---',
      '',
      'The usage documentation is being authored at `docs/usage/` in the repo',
      'root and will appear here on the next site build.',
      '',
    ].join('\n');
    await fs.writeFile(path.join(USAGE_DEST, 'index.md'), placeholder, 'utf8');
    return;
  }

  await rmrf(USAGE_DEST);
  await fs.mkdir(USAGE_DEST, { recursive: true });

  const entries = await fs.readdir(USAGE_SRC, { recursive: true, withFileTypes: true });
  let copied = 0;
  for (const ent of entries) {
    if (!ent.isFile()) continue;
    if (!/\.(md|mdx)$/.test(ent.name)) continue;
    const full = path.join(ent.parentPath ?? ent.path ?? USAGE_SRC, ent.name);
    const rel = path.relative(USAGE_SRC, full);
    const dest = path.join(USAGE_DEST, rel);
    const slug = path.basename(ent.name, path.extname(ent.name));
    const ok = await copyMarkdown(full, dest, { fallbackSlug: slug });
    if (ok) copied++;
  }
  log(`mirrored ${copied} usage file(s)`);
}

async function syncWiki() {
  log(`wiki dest: ${WIKI_DEST}`);
  await rmrf(WIKI_DEST);
  await fs.mkdir(WIKI_DEST, { recursive: true });

  let copied = 0;
  for (const w of WIKI_FILES) {
    const src = path.join(repoRoot, w.src);
    if (!(await exists(src))) {
      log(`wiki: ${w.src} missing — skipping`);
      continue;
    }
    const extra = [
      `sidebar:`,
      `  order: ${w.sort}`,
      `  label: ${JSON.stringify(w.label)}`,
    ].join('\n');
    const dest = path.join(WIKI_DEST, `${w.name}.md`);
    const ok = await copyMarkdown(src, dest, {
      fallbackSlug: w.name.toLowerCase(),
      extra,
    });
    if (ok) copied++;
  }

  const indexBody = [
    '---',
    'title: "Wiki"',
    'description: "Lattice architecture + threat model reference."',
    'sidebar:',
    '  order: -10',
    '  label: "Wiki overview"',
    '---',
    '',
    '# Lattice wiki',
    '',
    'Reference pages for the design surface — published verbatim from the',
    'repository so readers can audit the construction without cloning the',
    'source tree.',
    '',
    '- [Architecture](architecture/) — workspace layout, crate responsibilities, the layered view, federation topology, and the hybrid PQXDH handshake.',
    '- [Threat model](threat_model/) — adversary classes considered, mitigations in place, and the residual exposure we explicitly do not defend against.',
    '',
    'For installation, day-to-day usage, the HTTP API surface, and the',
    "operator-side self-hosting runbook, head to the [Documentation](/docs/usage/) section.",
    '',
  ].join('\n');
  await fs.writeFile(path.join(WIKI_DEST, 'index.md'), indexBody, 'utf8');
  copied++;

  log(`mirrored ${copied} wiki file(s)`);
}

async function main() {
  await syncUsage();
  await syncWiki();
  log('done');
}

main().catch((e) => {
  console.error('[sync] failed:', e);
  process.exit(1);
});
