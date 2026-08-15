import { defineConfig } from '@playwright/test';

/**
 * Accessibility gate. Tests run against the production build served by
 * `vite preview`, so what passes here is what actually ships to Pages.
 * The build runs as part of the webServer command rather than being left to
 * the caller: `preview` only serves whatever is already in dist/, so without
 * it the suite scores an arbitrarily old bundle, and a build that FAILS
 * leaves the last good bundle on disk and passes green against source that no
 * longer compiles — which silently invalidates every mutation check here.
 */
const BASE = '/crypto-lab-kyber-vault/';
const PORT = 4715;
const ORIGIN = `http://localhost:${PORT}`;

export default defineConfig({
  testDir: './e2e',
  fullyParallel: true,
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 1 : 0,
  reporter: process.env.CI ? 'list' : [['list'], ['html', { open: 'never' }]],
  webServer: {
    command: `npm run build && npm run preview -- --port ${PORT} --strictPort`,
    url: `${ORIGIN}${BASE}`,
    reuseExistingServer: !process.env.CI,
  },
  use: {
    baseURL: `${ORIGIN}${BASE}`,
    colorScheme: 'dark',
  },
  projects: [
    {
      name: 'chromium',
      use: { browserName: 'chromium' },
    },
  ],
});
