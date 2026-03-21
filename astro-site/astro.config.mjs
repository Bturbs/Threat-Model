import { defineConfig } from 'astro/config';

// SITE and BASE are injected by CI when deploying to GitHub Pages.
// For local dev, defaults to localhost root.
export default defineConfig({
  output: 'static',
  site: process.env.SITE || 'http://localhost:4321',
  base: process.env.BASE || '/',
});
