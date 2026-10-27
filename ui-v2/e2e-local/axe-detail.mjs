/**
 * The axe details for one page: which element, which colour, which ratio.
 *
 * The summary says "color-contrast: 1 node(s)" — that is not enough to fix
 * anything. This prints the selector, the text, the foreground and the
 * background, and the required ratio.
 *
 * Usage:
 *   FWMON_LOCAL_PASSWORD=... node axe-detail.mjs --page /admin/v2/devices --theme light
 */
import { chromium, devices } from '@playwright/test';
import AxeBuilder from '@axe-core/playwright';
import { localBase, localPassword, login } from './guard.mjs';

const args = process.argv.slice(2);
const argOf = (n, d) => {
  const i = args.indexOf(`--${n}`);
  return i >= 0 && args[i + 1] ? args[i + 1] : d;
};
const BASE = localBase();
const PASSWORD = localPassword();
const PAGE = argOf('page', '/admin/v2/devices');
const VP = argOf('viewport', 'mobile');
const THEME = argOf('theme', 'dark');
const VIEWPORTS = {
  mobile: { width: 390, height: 844 },
  tablet: { width: 820, height: 1180 },
  desktop: { width: 1440, height: 900 },
};

const browser = await chromium.launch();
const context = await browser.newContext({
  ...devices['Desktop Chrome'],
  viewport: VIEWPORTS[VP],
});
await context.addInitScript((t) => {
  try {
    localStorage.setItem('fwmon-theme', t);
  } catch (e) {
    /* ignore */
  }
}, THEME);
const page = await context.newPage();

await login(page, BASE, PASSWORD);
await page.goto(`${BASE}${PAGE}`, { waitUntil: 'domcontentloaded' });
await page.waitForTimeout(2500);

const report = await new AxeBuilder({ page })
  .withTags(['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa'])
  .analyze();

for (const v of report.violations) {
  console.log(`\n### ${v.id} [${v.impact}] — ${v.help}`);
  console.log(`    ${v.helpUrl}`);
  for (const n of v.nodes.slice(0, 6)) {
    console.log(`  - target: ${JSON.stringify(n.target)}`);
    const text = (n.html || '').replace(/\s+/g, ' ').slice(0, 160);
    console.log(`    html: ${text}`);
    for (const c of n.any.concat(n.all, n.none)) {
      if (c.message) console.log(`    ${c.id}: ${c.message.slice(0, 200)}`);
      if (c.data && Object.keys(c.data).length) {
        const d = c.data;
        console.log(
          `    data: fg=${d.fgColor} bg=${d.bgColor} ratio=${d.contrastRatio} expected=${d.expectedContrastRatio}`,
        );
      }
    }
    if (n.failureSummary) console.log(`    why: ${n.failureSummary.replace(/\n/g, ' | ').slice(0, 300)}`);
  }
  if (v.nodes.length > 6) console.log(`  ... and ${v.nodes.length - 6} more`);
}

await browser.close();
