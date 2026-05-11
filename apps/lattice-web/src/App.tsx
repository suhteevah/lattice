import { createSignal, onMount, type Component } from "solid-js";

// Auto-imported from the wasm-bindgen output. Until `wasm-pack build`
// produces it, the typed shim in `./lattice.d.ts` keeps the editor +
// build happy. The dynamic import below resolves at runtime.
type LatticeWasm = typeof import("./wasm/lattice_core");

const App: Component = () => {
  const [status, setStatus] = createSignal<string>("loading wasm…");
  const [wasm, setWasm] = createSignal<LatticeWasm | null>(null);
  const [demoLines, setDemoLines] = createSignal<string[]>([]);

  const log = (line: string) =>
    setDemoLines((lines) => [...lines, line]);

  onMount(async () => {
    try {
      const m = (await import("./wasm/lattice_core")) as unknown as LatticeWasm;
      await (m as unknown as { default: (input?: unknown) => Promise<unknown> }).default();
      m.init();
      setWasm(m);
      setStatus(`lattice-core v${m.version()} ready`);
    } catch (e) {
      setStatus(`wasm load failed: ${String(e)}`);
    }
  });

  const runDemo = () => {
    const m = wasm();
    if (!m) return;
    setDemoLines([]);
    try {
      log("== hybrid signature ==");
      const kp = m.generateSigningKeypair();
      log(`user_id: ${kp.user_id_b64.slice(0, 20)}…`);
      log(`sig pk: ${kp.sig_pk_b64.length} chars b64`);
      const msg = btoa("hello, lattice browser");
      const sig = m.sign(kp.sig_sk_b64, msg);
      log(`sig: ${sig.length} chars b64`);
      const ok = m.verify(kp.sig_pk_b64, sig, msg);
      log(`verify: ${ok}`);

      log("== hybrid kem (X25519 + ML-KEM-768) ==");
      const kem = m.generateKemKeypair();
      log(`pk: ${kem.pk_b64.length} chars b64`);
      const info = btoa("lattice/browser-demo/v1");
      const encap = m.hybridKemEncap(kem.pk_b64, info);
      log(`ct: ${encap.ciphertext_b64.length} chars b64`);
      log(`session: ${encap.session_key_b64.slice(0, 12)}…`);
      const decap = m.hybridKemDecap(kem.sk_b64, encap.ciphertext_b64, info);
      const agree = decap.session_key_b64 === encap.session_key_b64;
      log(`secrets agree: ${agree}`);
    } catch (e) {
      log(`error: ${String(e)}`);
    }
  };

  return (
    <div class="min-h-screen flex items-center justify-center bg-ink-950">
      <div class="max-w-xl w-full p-8 rounded-xl bg-ink-900 border border-ink-700 shadow-lg">
        <h1 class="text-3xl font-medium text-lilac-400 mb-2">Lattice</h1>
        <p class="text-ink-300 text-sm leading-relaxed mb-4">
          Post-quantum encrypted messaging. M4 in-browser preview.
        </p>
        <div class="text-xs text-ink-500 mb-4">{status()}</div>
        <button
          type="button"
          class="px-4 py-2 rounded-md bg-lilac-400/20 hover:bg-lilac-400/30 text-lilac-400 text-sm font-medium disabled:opacity-50"
          disabled={!wasm()}
          onClick={runDemo}
        >
          Run crypto demo
        </button>
        {demoLines().length > 0 && (
          <pre class="mt-4 p-3 text-xs bg-ink-800 border border-ink-700 rounded text-ink-300 font-mono overflow-x-auto">
            {demoLines().join("\n")}
          </pre>
        )}
        <div class="mt-6 flex items-center gap-2 text-xs">
          <span class="inline-block w-2 h-2 rounded-full bg-sage-500" />
          <span class="text-ink-500">End-to-end encrypted • PQ-hybrid</span>
        </div>
      </div>
    </div>
  );
};

export default App;
