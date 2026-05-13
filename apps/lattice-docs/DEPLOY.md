# Deploying lattice-docs to Vercel

This is a fully static [Astro Starlight](https://starlight.astro.build) site.
It deploys to Vercel via the `@astrojs/vercel` adapter in **static** mode —
no serverless functions, no Edge Functions, no runtime cost. The Vercel
output lives at `.vercel/output/`, which is what `vercel deploy` ships.

Per the project policy (`CLAUDE.md` in the repo root), there is **no
GitHub Actions / CI integration** for deploys. The flow is manual from
the workstation that owns the Vercel account.

---

## One-time setup

### 1. Install the Vercel CLI

```powershell
npm install -g vercel
vercel --version          # 39.x or newer
```

### 2. Authenticate

```powershell
vercel login
```

Pick `Continue with Email` and use the account you want this project to
live under. The Vercel team scope can be picked at link time.

### 3. Install project dependencies

```powershell
cd J:\lattice\apps\lattice-docs
npm install
```

Tested with Node 20.10+ (Astro 5 minimum). Kokonoe ships Node 24.13.1
which is fine. Bun also works (`bun install` + `bun run dev`) but the
npm scripts are the documented path because the Vercel build container
uses npm/pnpm/yarn — not Bun by default.

### 4. Run the site once locally to verify

```powershell
npm run dev              # http://localhost:4321
```

The `predev` hook runs `scripts/sync-usage.ps1` which mirrors
`../../docs/usage/*.md` into `src/content/docs/docs/usage/`. If
`docs/usage/` is empty (the docs author hasn't written it yet) the
script writes a placeholder index so the build still succeeds. Real
content appears the moment the upstream files land.

Build verification:

```powershell
npm run build
npm run preview          # serves ./dist on http://localhost:4321
```

The Vercel manifest will be in `.vercel/output/` after `npm run build`.

### 5. Link this directory to a Vercel project

From `J:\lattice\apps\lattice-docs\`:

```powershell
vercel link
```

Answer the prompts:

| Prompt | Answer |
|---|---|
| Set up "lattice-docs"? | **Yes** |
| Which scope? | Pick your personal scope or `ridge-cell-repair` team |
| Link to existing project? | **No** (first time) |
| What's your project's name? | `lattice-docs` |
| In which directory is your code? | `./` (you're already in it) |
| Want to override the settings? | **No** — `vercel.json` covers it |

The settings come from `vercel.json`:

- **Framework preset:** `astro`
- **Build command:** `npm run build`
- **Output directory:** `.vercel/output`
- **Install command:** `npm install`

If for some reason you have to set these manually in the Vercel
dashboard, the equivalents under **Project Settings → Build & Development
Settings** are:

| Field | Value |
|---|---|
| Framework preset | Astro |
| Build command | `npm run build` |
| Output directory | (leave default — the adapter writes `.vercel/output`) |
| Install command | `npm install` |
| Root directory | `apps/lattice-docs` |
| Node.js version | 20.x or 22.x (Astro 5 supports both) |

**Root directory matters.** Lattice is a monorepo. In the Vercel
dashboard under **Project Settings → General → Root Directory**, set
`apps/lattice-docs` so Vercel builds only this app and not the whole
Rust workspace.

---

## Day-to-day

### Preview deploy

```powershell
cd J:\lattice\apps\lattice-docs
vercel
```

Gives you a `lattice-docs-<hash>-<scope>.vercel.app` URL. Use this to
share work-in-progress without touching prod.

### Production deploy

```powershell
vercel --prod
```

Promotes a build to the production alias. There is no auto-deploy from
git — you control every push to prod.

### Environment variables

The site is fully static and does not read any env vars at build or
runtime. The only env var that matters is the local one:

```powershell
$env:ASTRO_TELEMETRY_DISABLED = '1'
```

Set this in your shell profile if you don't want Astro to phone home.
(The repo doesn't ship a `.env` because there's nothing in it.)

If you ever add a build-time secret (e.g. an analytics key), put it in
**Project Settings → Environment Variables** under the **Production**
and **Preview** scopes separately. Don't bake secrets into git.

---

## Domain setup

### Until a domain is bought

Vercel assigns `lattice-docs-<scope>.vercel.app`. Use that. It has a
valid TLS cert on day one. No DNS work required.

### Once a domain is owned

Per [`docs/DECISIONS.md` §D-22](../../docs/DECISIONS.md), the tentative
choice is **`lattice.chat`**, with `getlattice.app` as a secondary /
redirect target. The decision is still flagged "Open — needs Matt"
until the domain is actually purchased.

When ready:

1. Buy `lattice.chat` from a registrar that supports modern DNS
   (Cloudflare, Porkbun, Namecheap).
2. In the Vercel dashboard → **Project → Settings → Domains**, click
   **Add Domain** and enter `lattice.chat` and `www.lattice.chat`.
3. Vercel will show you exactly what DNS records to set. Two paths:
   - **Apex on Vercel DNS.** Easiest. Point the nameservers to Vercel,
     they handle the A record + auto-renewing Let's Encrypt cert.
   - **Apex on external DNS (Cloudflare).** Add an A record
     `76.76.21.21` for the apex and a CNAME `cname.vercel-dns.com`
     for `www`. Cloudflare also supports CNAME flattening on the apex.
4. Pick one of (`lattice.chat`, `www.lattice.chat`) as canonical and
   set the other to redirect.
5. Update `site:` in `astro.config.mjs` if the canonical domain
   changes from `https://lattice.chat`.

For `getlattice.app` as a redirect target:

1. Add it under **Project → Settings → Domains**.
2. Mark it **Redirect to** `lattice.chat`.
3. DNS is the same as above.

### TLS

Vercel auto-provisions Let's Encrypt certs for every linked domain.
If you're using external DNS, ensure your DNS provider allows the
ACME challenge — most do, but if you're behind Cloudflare make sure
the `_acme-challenge` records aren't proxied (DNS-only / grey cloud).

---

## Rollback

Vercel keeps every deploy as a permanent immutable URL. Rollback is
instant:

```powershell
# List recent deployments
vercel ls

# Roll back to a specific deployment (instant — no rebuild)
vercel rollback <deployment-url>

# Or promote a known-good preview to prod
vercel promote <deployment-url>
```

Because there's no auto-deploy from git, the typical rollback story is
"deploy the previous commit explicitly":

```powershell
git checkout <good-sha>
cd apps\lattice-docs
vercel --prod
git checkout main
```

---

## CI banned — no GitHub Actions

The repo has a top-level `.github/workflows/ci.yml` for contributors,
but Matt's account has GitHub Actions disabled by policy. Do **not** add
a deploy workflow there. Manual `vercel --prod` from this directory is
the only sanctioned path.

If you want a one-keypress shortcut, add it to your PowerShell profile:

```powershell
function Deploy-LatticeDocs {
    Push-Location J:\lattice\apps\lattice-docs
    try { vercel --prod } finally { Pop-Location }
}
```

---

## Known gotchas

- **Windows / MinGW symlinks.** We do **not** use symlinks to pull in
  `docs/usage/`. The `sync-usage.ps1` script copies instead, because
  symlinks created on MinGW-flavored Git Bash do not always survive
  the round trip through the Vercel build container.
- **Vercel build container is Linux + case-sensitive.** All filenames
  under `src/content/docs/` and `docs/usage/` must match their
  internal references exactly. Astro will fail loudly in `npm run
  build` long before you ship a broken case.
- **Pagefind needs the built `dist/` to index.** Don't try to preview
  search in `npm run dev` — it only works after `npm run build` /
  `npm run preview`.
- **`@astrojs/vercel/static` not `/serverless`.** This site is fully
  static. If you ever flip to dynamic routes, swap to
  `@astrojs/vercel/serverless` and set `output: 'server'` (or
  `'hybrid'`) in `astro.config.mjs`. Don't mix the modes.
- **First build downloads sharp.** The first `npm install` pulls a
  ~30 MB platform-native `sharp` binary. Subsequent installs are
  cached.

---

## Verification checklist before promoting to prod

- [ ] `npm run build` finishes with zero warnings about missing pages
- [ ] `npm run preview` renders the homepage at `/`
- [ ] Search box at the top right finds known docs strings
- [ ] Dark mode is the default (no flash of light mode on load)
- [ ] The sidebar shows the curated order, not alphabetical
- [ ] Every page in `docs/usage/` has a working "Edit this page" link
- [ ] `vercel ls --prod` shows the new build at the top of the list
