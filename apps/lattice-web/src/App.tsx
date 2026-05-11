import { createSignal, type Component } from "solid-js";

// Placeholder UI. Real chat surface lands once lattice-core (WASM) is wired
// up — see docs/HANDOFF.md §4.
const App: Component = () => {
  const [name] = createSignal("Lattice");

  return (
    <div class="min-h-screen flex items-center justify-center bg-ink-950">
      <div class="max-w-md w-full p-8 rounded-xl bg-ink-900 border border-ink-700 shadow-lg">
        <h1 class="text-3xl font-medium text-lilac-400 mb-2">{name()}</h1>
        <p class="text-ink-300 text-sm leading-relaxed">
          Post-quantum encrypted messaging. The browser client lives here.
          See <code class="text-slate-300 font-mono">docs/HANDOFF.md</code>{" "}
          to pick up the build.
        </p>
        <div class="mt-6 flex items-center gap-2 text-xs">
          <span class="inline-block w-2 h-2 rounded-full bg-sage-500" />
          <span class="text-ink-500">End-to-end encrypted • PQ-hybrid</span>
        </div>
      </div>
    </div>
  );
};

export default App;
