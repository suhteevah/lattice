import { defineConfig } from "vite";
import solid from "vite-plugin-solid";

// Vite config for lattice-web.
//
// Notes:
// - `assetsInlineLimit: 0` forces all assets to ship as separate files so
//   SRI hashes can be pinned individually.
// - `build.rollupOptions.output.entryFileNames` keeps hashes deterministic
//   for SRI generation.
// - Source maps are enabled in dev only; production builds strip them to
//   minimize attack surface.
export default defineConfig(({ mode }) => ({
  plugins: [solid()],
  server: {
    port: 5173,
    strictPort: true,
    headers: {
      // Dev-server CSP. Production CSP lives in apps/lattice-web/csp.json
      // and is emitted by the host server. Keep these in sync.
      "Content-Security-Policy": [
        "default-src 'self'",
        "script-src 'self' 'wasm-unsafe-eval'",
        "style-src 'self' 'unsafe-inline'",
        "img-src 'self' data: blob:",
        "connect-src 'self' ws: wss:",
        "font-src 'self'",
        "object-src 'none'",
        "base-uri 'self'",
        "frame-ancestors 'none'",
        "form-action 'self'",
      ].join("; "),
      "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
      "X-Content-Type-Options": "nosniff",
      "Referrer-Policy": "no-referrer",
      "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
    },
  },
  build: {
    target: "es2022",
    sourcemap: mode === "development",
    assetsInlineLimit: 0,
    rollupOptions: {
      output: {
        entryFileNames: "assets/[name]-[hash].js",
        chunkFileNames: "assets/[name]-[hash].js",
        assetFileNames: "assets/[name]-[hash][extname]",
      },
    },
  },
}));
