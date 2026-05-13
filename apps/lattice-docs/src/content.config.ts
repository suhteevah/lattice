import { defineCollection } from 'astro:content';
import { docsLoader } from '@astrojs/starlight/loaders';
import { docsSchema } from '@astrojs/starlight/schema';

// Starlight expects a single `docs` collection rooted at
// `src/content/docs/`. The pre-build `sync-usage.ps1` script mirrors the
// canonical `docs/usage/*.md` content into
// `src/content/docs/docs/usage/`, so it gets picked up automatically.
//
// Anything else under `src/content/docs/` (the homepage, the changelog,
// etc.) is authored directly in this app and lives alongside the synced
// content.

export const collections = {
  docs: defineCollection({
    loader: docsLoader(),
    schema: docsSchema(),
  }),
};
