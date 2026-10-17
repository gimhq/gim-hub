import process from 'node:process'
import { defineConfig } from '@playwright/test'

// Browser E2E against a running hub, driven by scripts/admin-e2e.sh in the
// pinned mcr.microsoft.com/playwright image (same version as @playwright/test).
export default defineConfig({
  testDir: '.',
  testMatch: '*.e2e.ts',
  outputDir: process.env.E2E_OUTPUT_DIR ?? 'test-results',
  timeout: 120_000,
  expect: { timeout: 15_000 },
  retries: 0,
  workers: 1,
  reporter: [['list', { printSteps: true }]],
  use: {
    baseURL: process.env.E2E_ADMIN_URL,
    locale: 'en-US',
    trace: 'retain-on-failure',
    screenshot: 'only-on-failure',
  },
})
