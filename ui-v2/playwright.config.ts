import { defineConfig, devices } from '@playwright/test';

/**
 * The viewports the console is checked at.
 *
 * The console's layout is a fixed shell with a responsive content area, and
 * the audit found the mobile and tablet widths untested: a page could
 * overflow sideways at 390px and nothing would notice, because every spec
 * ran at the desktop width.
 *
 * The three widths are the ones the shell is designed around: the phone
 * (the mobile navigation drawer), the tablet (the two-column grids), and
 * the desktop.
 */
export const VIEWPORTS = {
  mobile: { width: 390, height: 844 },
  tablet: { width: 820, height: 1180 },
  desktop: { width: 1440, height: 900 },
} as const;

export default defineConfig({
  testDir: './e2e',
  fullyParallel: false,
  workers: process.env.CI ? 1 : undefined,
  retries: process.env.CI ? 1 : 0,
  timeout: 30_000,
  expect: { timeout: 10_000 },
  reporter: process.env.CI ? [['list'], ['github']] : [['list']],
  use: {
    baseURL: 'http://127.0.0.1:4173',
    trace: 'retain-on-failure',
    screenshot: 'only-on-failure',
  },
  projects: [
    {
      name: 'mobile',
      use: { ...devices['Desktop Chrome'], viewport: VIEWPORTS.mobile },
    },
    {
      name: 'tablet',
      use: { ...devices['Desktop Chrome'], viewport: VIEWPORTS.tablet },
    },
    {
      name: 'desktop',
      use: { ...devices['Desktop Chrome'], viewport: VIEWPORTS.desktop },
    },
  ],
  webServer: {
    command: 'node e2e/serve.mjs',
    url: 'http://127.0.0.1:4173/admin/v2',
    reuseExistingServer: !process.env.CI,
    timeout: 60_000,
  },
});
