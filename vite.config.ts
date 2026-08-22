import { defineConfig, configDefaults } from 'vitest/config';

// base must match the GitHub Pages project subpath:
// https://systemslibrarian.github.io/crypto-lab-dnssec-chain/
export default defineConfig({
  base: '/crypto-lab-dnssec-chain/',
  test: {
    // Colocated unit tests only; keep the Playwright specs in e2e/ out of the
    // Vitest run so they are never collected as unit tests.
    include: ['src/**/*.test.ts'],
    exclude: [...configDefaults.exclude, 'e2e/**'],
  },
});
