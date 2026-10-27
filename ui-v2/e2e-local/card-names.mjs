/**
 * What are the mobile card's actions actually called?
 *
 * The accessible name of a card that opens a row has to SAY what it opens.
 * "Open row 3" does not, and the card's own text used to be the name
 * before the action became a real button.
 */
import { chromium, devices } from '@playwright/test';
import { localBase, localPassword, login } from './guard.mjs';

const BASE = localBase();
const PASSWORD = localPassword();

const PAGES = [
  ['/admin/v2/devices', 'Devices'],
  ['/admin/v2/events', 'Events'],
  ['/admin/v2/traps', 'Traps'],
  ['/admin/v2/flows', 'Flows'],
  ['/admin/v2/syslog', 'Syslog'],
  ['/admin/v2/alerts', 'Alerts'],
  ['/admin/v2/collectors', 'Collectors'],
];

const browser = await chromium.launch();
const context = await browser.newContext({
  ...devices['Desktop Chrome'],
  viewport: { width: 390, height: 844 },
});
const page = await context.newPage();
await login(page, BASE, PASSWORD);

for (const [path, label] of PAGES) {
  await page.goto(`${BASE}${path}`, { waitUntil: 'domcontentloaded' });
  // Wait for the data, not for a fixed time: the page's first query can
  // take a while on a big table.
  await page
    .waitForFunction(() => document.querySelectorAll('table tbody tr').length > 0, { timeout: 15000 })
    .catch(() => {});
  await page.waitForTimeout(1200);
  const names = await page.evaluate(() =>
    [...document.querySelectorAll('button[aria-label]')]
      .map((b) => b.getAttribute('aria-label'))
      .filter((n) => n && n.startsWith('Open ') && n !== 'Open navigation menu')
      .slice(0, 4),
  );
  const rows = await page.evaluate(() => document.querySelectorAll('table tbody tr').length);
  console.log(
    `${label.padEnd(12)} rows=${String(rows).padStart(3)} ${names.length ? names.join(' | ') : '(no row action)'}`,
  );
}

await browser.close();
