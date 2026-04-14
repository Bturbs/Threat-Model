import { defineConfig } from 'astro/config';

// SITE and BASE are injected by CI when deploying to GitHub Pages.
// For local dev, defaults to localhost root.
export default defineConfig({
  output: 'static',
  site: process.env.SITE || 'https://bturbs.github.io',
  base: process.env.BASE || '/Threat-Model',
});
