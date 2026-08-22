import { defineConfig, devices } from '@playwright/test';

/**
 * E2E runs against the PRODUCTION build served by `vite preview`, so what
 * passes here is what ships. Two suites:
 *   - a11y.spec.ts   — the axe WCAG A/AA gate, Chromium only.
 *   - claims.spec.ts — the page tells the truth: every number on screen is
 *     cross-checked or independently re-derived.
 *
 * Port 4689 is unique to this lab across the fleet (never the Vite default
 * 4173 — with 170+ labs side by side a shared port means `reuseExistingServer`
 * silently scans a different lab's preview).
 */
export default defineConfig({
  testDir: './e2e',
  fullyParallel: false,
  timeout: 180_000, // the axe driver walks every panel and disclosure before scanning
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 1 : 0,
  reporter: process.env.CI ? 'list' : [['list'], ['html', { open: 'never' }]],
  use: {
    baseURL: 'http://localhost:4689/crypto-lab-dnssec-chain/',
    colorScheme: 'dark', // dark is the only theme
  },
  projects: [
    { name: 'a11y', testMatch: /a11y\.spec\.ts/, use: { ...devices['Desktop Chrome'] } },
    { name: 'claims', testMatch: /claims\.spec\.ts/, use: { ...devices['Desktop Chrome'] } },
  ],
  webServer: {
    // Build before serving: `vite preview` only serves whatever is already in
    // dist/, so without this a failing build leaves the previous good bundle in
    // place and the suite passes green against code that no longer compiles.
    command: 'npm run build && npm run preview -- --port 4689 --strictPort',
    url: 'http://localhost:4689/crypto-lab-dnssec-chain/',
    reuseExistingServer: !process.env.CI,
    timeout: 180_000,
  },
});
