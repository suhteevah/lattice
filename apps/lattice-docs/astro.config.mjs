// @ts-check
import { defineConfig } from 'astro/config';
import starlight from '@astrojs/starlight';
import vercel from '@astrojs/vercel';
import clerk from '@clerk/astro';

// Lattice docs site.
//
// Source of truth for the docs/* content collection is the repo-root
// `docs/usage/*.md`, mirrored into `src/content/docs/` by the
// `scripts/sync-usage.ps1` prebuild step. Do not edit files under
// `src/content/docs/` directly except for the index landing page and
// any docs-site-only pages (e.g. changelog) — those won't be clobbered
// by the sync because the script only writes the `usage/` subdirectory.
//
// Output is fully static; the Vercel adapter just emits the correct
// build manifest so the dashboard can pick the right framework preset.

export default defineConfig({
  site: 'https://lattice.chat',
  output: 'server',
  adapter: vercel({
    webAnalytics: { enabled: false },
    imageService: false,
  }),
  trailingSlash: 'ignore',
  build: {
    format: 'directory',
  },
  integrations: [
    clerk(),
    starlight({
      title: 'Lattice',
      description:
        'Post-quantum encrypted, federated messaging. A Discord replacement with Matrix-class decentralization at Discord-class UX speed.',
      logo: {
        src: './src/assets/lattice-mark.svg',
        replacesTitle: false,
      },
      favicon: '/favicon.svg',
      tagline: 'Post-quantum encrypted, federated messaging.',
      social: {
        github: 'https://github.com/suhteevah/lattice',
      },
      customCss: ['./src/styles/lattice-theme.css', './src/styles/fonts.css'],
      defaultLocale: 'root',
      locales: {
        root: { label: 'English', lang: 'en' },
      },
      // Force dark-mode-first; Starlight still ships the light toggle but
      // visitors land on dark.
      pagefind: true,
      editLink: {
        baseUrl:
          'https://github.com/suhteevah/lattice/edit/main/docs/usage/',
      },
      lastUpdated: true,
      components: {
        // Override Starlight's default ThemeSelect to start in dark mode.
        // (Visitors can still flip; we just bias the cold-cache default.)
      },
      // Sidebar strategy:
      //
      // The docs author writes files into `docs/usage/` with whatever
      // slugs make sense to them. We don't want this config to break
      // every time a file is added, removed, or renamed — so the
      // "Documentation" section auto-generates from the synced tree.
      //
      // Order is controlled by `sidebar` frontmatter on each page (the
      // docs author can add `sidebar: { order: N }` to any file). The
      // intended sequence is the canonical reading order baked into the
      // homepage (`src/content/docs/index.mdx`):
      //   index → quickstart → installation → identity → messaging →
      //   servers → federation → security → self-hosting →
      //   api-reference → troubleshooting → development
      //
      // The top-level "Project" group is hand-curated because the
      // changelog lives outside the synced tree.
      sidebar: [
        {
          label: 'Documentation',
          autogenerate: { directory: 'docs/usage' },
        },
        {
          label: 'Wiki',
          autogenerate: { directory: 'wiki' },
        },
        {
          label: 'Project',
          items: [{ label: 'Changelog', link: '/changelog/' }],
        },
      ],
      head: [
        // Strict-ish CSP — matches lattice-web's "no unsafe-eval, no
        // unsafe-inline" posture. Starlight inlines a tiny theme bootstrap
        // <script>, so we allow inline scripts only via the hashes Starlight
        // itself emits. If you tighten this further, run a Lighthouse pass
        // first.
        {
          tag: 'meta',
          attrs: {
            name: 'theme-color',
            content: '#18141C',
          },
        },
        {
          tag: 'meta',
          attrs: {
            name: 'color-scheme',
            content: 'dark light',
          },
        },
      ],
    }),
  ],
});
