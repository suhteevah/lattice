# lattice-docs

Public documentation site for [Lattice](https://github.com/suhteevah/lattice)
— post-quantum encrypted, federated messaging.

This is the source for what (eventually) ships at `lattice.chat`.

## Stack

- [Astro](https://astro.build) 5 + [Starlight](https://starlight.astro.build) 0.30
- Output: fully static (`output: 'static'`).
- Adapter: `@astrojs/vercel` (static output mode, no serverless functions).
- Search: built-in [Pagefind](https://pagefind.app/) (offline, client-side).
- Theme: lilac-anchored, dark-mode-first. Tokens sourced from
  `../../design/tokens/colors.json`.

## Content layout

The substantive documentation is **not** authored under this app. It lives at
the repo root in `docs/usage/*.md` so it sits beside `docs/HANDOFF.md`,
`docs/ARCHITECTURE.md`, etc. and can be read as plain markdown without a
build step.

At dev/build time, `scripts/sync-usage.ps1` mirrors `../../docs/usage/`
into `src/content/docs/docs/usage/`. The mirrored tree is git-ignored;
edits made there will be wiped on the next sync. Edit the originals.

- `src/content/docs/index.mdx` — homepage landing
- `src/content/docs/changelog.mdx` — derived from `../../docs/ROADMAP.md`
- `src/content/docs/docs/usage/**` — synced from `../../docs/usage/`

## Local development

```powershell
cd apps\lattice-docs
npm install                  # first-time, pulls Astro + Starlight + Vercel adapter
npm run dev                  # http://localhost:4321 — runs sync-usage.ps1 first
npm run build                # static build to ./dist + Vercel manifest in .vercel/output
npm run preview              # serve the built site
npm run sync-usage           # re-run the docs mirror manually
```

Node 20.10+ required (Astro 5 minimum). Tested on Node 24.13.1.

## Deploy

See [`DEPLOY.md`](./DEPLOY.md). Short version:

```powershell
vercel link              # one-time, attach to a Vercel project
vercel                   # preview deploy
vercel --prod            # production deploy
```

Matt's account has GitHub Actions banned by policy, so there's no CI workflow
that auto-deploys. Run `vercel --prod` manually from this directory when ready.

## License

AGPL-3.0-or-later, same as the parent workspace.
