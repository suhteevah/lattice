import type { Config } from "tailwindcss";
import colors from "../../design/tokens/colors.json" with { type: "json" };

// Tailwind theme is derived from design/tokens/colors.json so the design
// system is single-sourced. When adding palette steps, edit the JSON, not
// this file.
const tokenColors = colors as Record<string, Record<string, { $value: string }>>;

function ramp(name: keyof typeof tokenColors) {
  const out: Record<string, string> = {};
  for (const [step, def] of Object.entries(tokenColors[name] ?? {})) {
    if (typeof def === "object" && def !== null && "$value" in def) {
      out[step] = (def as { $value: string }).$value;
    }
  }
  return out;
}

export default {
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  darkMode: "class",
  theme: {
    extend: {
      colors: {
        lilac: ramp("lilac"),
        sage: ramp("sage"),
        amber: ramp("amber"),
        rose: ramp("rose"),
        slate: ramp("slate"),
        ink: ramp("ink"),
      },
      fontFamily: {
        sans: [
          "Inter",
          "ui-sans-serif",
          "system-ui",
          "-apple-system",
          "Segoe UI",
          "Roboto",
          "Helvetica",
          "Arial",
          "sans-serif",
        ],
        mono: [
          "JetBrains Mono",
          "ui-monospace",
          "SFMono-Regular",
          "Menlo",
          "Consolas",
          "monospace",
        ],
      },
    },
  },
  plugins: [],
} satisfies Config;
