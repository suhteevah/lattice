# lattice-web

The Lattice browser client.

- **Framework:** Solid 1.9 + Vite 5
- **Styling:** Tailwind, themed from `../../design/tokens/`
- **Core logic:** `lattice-core` compiled to `wasm32-unknown-unknown`,
  loaded on app boot
- **Security posture:** strict CSP, SRI on every asset, no `unsafe-eval`

## Commands

```
npm install
npm run dev          # vite dev server at localhost:5173
npm run build        # production bundle into dist/, with SRI pinning
npm run preview      # serve the production bundle
npm run typecheck    # tsc --noEmit
npm run verify-csp   # CI gate on CSP / SRI consistency
```

## Security knobs

- **CSP:** dev-server policy is in `vite.config.ts`. Production policy is
  in `csp.json` — served as a header by the host server. Both are
  mirror-checked by `scripts/verify-csp.mjs`. Add a domain in **all three
  places** or CI fails.
- **SRI:** `scripts/sri-pin.mjs` runs after `vite build` and rewrites
  `dist/index.html` so every script and stylesheet carries a
  `sha384-…` integrity attribute. The build fails loudly if a hash
  can't be computed.
- **No `unsafe-eval`:** verified by `verify-csp.mjs`. WASM is loaded via
  `'wasm-unsafe-eval'` which is narrower and intentional.
