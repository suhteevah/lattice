# lattice-web

The Lattice browser client.

- **Framework:** [Leptos](https://leptos.dev) 0.8 (CSR), compiled to
  `wasm32-unknown-unknown` via [Trunk](https://trunkrs.dev/) 0.21.
- **Toolchain:** pure Rust — no `npm`, no `node`, no TypeScript build.
- **Styling:** hand-written CSS in `styles.css`, hooked to the lilac /
  ink / sage design tokens at `../../design/tokens/`.
- **Crypto:** the same `lattice-core` / `lattice-crypto` /
  `lattice-protocol` crates the server uses are imported directly and
  compiled to WASM alongside the UI.
- **Security posture:** strict CSP (header-based in prod via
  `csp.json`), SRI on every asset via Trunk's hashed-filename output,
  no `unsafe-eval`.

## Commands

```powershell
# One-shot helpers from this directory
.\scripts\serve.ps1                # trunk serve at http://127.0.0.1:5173
.\scripts\serve.ps1 -NoAutoReload  # disable file watching

# Or invoke trunk directly (requires VC++ env loaded yourself)
trunk serve
trunk build --release
```

`scripts/serve.ps1` loads `vcvars64.bat` from the Visual Studio 2022
Build Tools so MSVC `link.exe` is on PATH for cargo's build scripts.
Without it cargo can't compile host-target proc-macros under WSL-free
Windows. See `..\..\.cargo\config.toml` for the linker override.

## Security knobs

- **CSP:** dev-server policy is intentionally NOT set (Trunk injects an
  inline bootstrap module with a per-request nonce that any static CSP
  would block). Production CSP lives in `csp.json` and is served as a
  `Content-Security-Policy` HTTP header by the home server in front of
  `dist/`. The header is verified by `..\..\scripts\verify-csp.ps1`.
- **SRI:** Trunk emits hashed asset filenames and `sha384-…`
  `integrity=` attributes on every `<script>` / `<link>` it generates.
  The production server checks them via `verify-csp.ps1`.
- **No `unsafe-eval`:** WASM is loaded via `'wasm-unsafe-eval'` which
  is narrower and intentional.

## Migration note (2026-05)

Earlier scaffolding used Solid + Vite + Tailwind + TypeScript. Per the
"Rust everywhere" project directive, the client was rebuilt in Leptos
during M4 Phase α. The previous JS/TS toolchain (package.json,
vite.config.ts, tsconfig.json, tailwind.config.ts, src/App.tsx,
src/main.tsx, src/styles.css, scripts/sri-pin.mjs,
scripts/verify-csp.mjs, scripts/build-wasm.ps1) is gone.
