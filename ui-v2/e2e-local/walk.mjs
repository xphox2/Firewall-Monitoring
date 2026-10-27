/**
 * The real console, against the real API, with the real data.
 *
 * The mocked suite (ui-v2/e2e) drives a MOCK shell: the API calls are
 * intercepted by page.route() and answered from fixtures, so it never
 * exercises the Go server, the SQL, the migrations or the real data. That
 * is the right shape for a fast gate, and the wrong shape for finding out
 * whether the console actually works.
 *
 * This script points the browser at a LOCAL instance — the real binary
 * against a copy of the production database — and walks it:
 *
 *   1. log in through the real login form;
 *   2. visit every page, at three viewports, in BOTH themes;
 *   3. count what the page actually rendered;
 *   4. run axe on each page;
 *   5. collect the console errors and the failed network requests;
 *   6. screenshot every page.
 *
 * This is what found the two defects the mocked suite could not see: the
 * mobile card was a control that contained controls, and the tinted chips
 * were below the contrast bar.
 *
 * Usage:
 *   FWMON_LOCAL_PASSWORD=... node walk.mjs --base http://127.0.0.1:8099
 */
import { chromium, devices } from '@playwright/test';
import AxeBuilder from '@axe-core/playwright';
import { mkdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { localBase, localPassword, login } from './guard.mjs';

const BASE = localBase();
const PASSWORD = localPassword();
const OUT = process.argv.includes('--out')
  ? process.argv[process.argv.indexOf('--out') + 1]
  : '../tasks/localprod/walk';

const VIEWPORTS = {
  mobile: { width: 390, height: 844 },
  tablet: { width: 820, height: 1180 },
  desktop: { width: 1440, height: 900 },
};

/** Both themes: the shell reads the theme from localStorage on boot. */
const THEMES = ['dark', 'light'];

/** Every page the console has, with the path and a human name. */
const PAGES = [
  ['/admin/v2/overview', 'Overview'],
  ['/admin/v2/topology', 'Topology'],
  ['/admin/v2/events', 'Events'],
  ['/admin/v2/flows', 'Flows'],
  ['/admin/v2/syslog', 'Syslog'],
  ['/admin/v2/traps', 'Traps'],
  ['/admin/v2/alerts', 'Alerts'],
  ['/admin/v2/threat-intel', 'Threat intel'],
  ['/admin/v2/devices', 'Devices'],
  ['/admin/v2/collectors', 'Collectors'],
  ['/admin/v2/configuration/storage', 'Configuration / storage'],
  ['/admin/v2/configuration/alerting', 'Configuration / alerting'],
  ['/admin/v2/configuration/integrations', 'Configuration / integrations'],
  ['/admin/v2/configuration/system', 'Configuration / system'],
];

mkdirSync(OUT, { recursive: true });

const results = [];
const axeFindings = [];

/** What the page actually rendered. */
async function rendered(page) {
  return page.evaluate(() => {
    const rows = document.querySelectorAll('table tbody tr').length;
    const cards = document.querySelectorAll('[data-testid="row-card"], article').length;
    const text = (document.body.innerText || '').trim();
    const headings = [...document.querySelectorAll('h1, h2')].map((h) => h.innerText.trim());
    return {
      theme: document.documentElement.getAttribute('data-theme'),
      bodyBg: getComputedStyle(document.body).backgroundColor,
      rows,
      cards,
      buttons: document.querySelectorAll('button').length,
      inputs: document.querySelectorAll('input, select, textarea').length,
      headings: headings.slice(0, 3),
      textLength: text.length,
      firstText: text.slice(0, 160).replace(/\s+/g, ' '),
    };
  });
}

const browser = await chromium.launch();

for (const [name, viewport] of Object.entries(VIEWPORTS)) {
  for (const theme of THEMES) {
    const context = await browser.newContext({
      ...devices['Desktop Chrome'],
      viewport,
      ignoreHTTPSErrors: true,
    });
    // The theme is a localStorage flag the shell reads on boot.
    await context.addInitScript((t) => {
      try {
        localStorage.setItem('fwmon-theme', t);
      } catch (e) {
        /* ignore */
      }
    }, theme);
    const page = await context.newPage();

    const consoleErrors = [];
    const netErrors = [];
    page.on('console', (m) => {
      if (m.type() === 'error') consoleErrors.push(m.text().slice(0, 240));
    });
    page.on('response', (r) => {
      if (r.status() >= 400) netErrors.push(`${r.status()} ${r.url().replace(BASE, '')}`);
    });

    console.log(`\n=== ${name} (${viewport.width}x${viewport.height}) ${theme} ===`);
    try {
      await login(page, BASE, PASSWORD);
    } catch (e) {
      console.log(`  LOGIN FAILED: ${e.message}`);
      await page.screenshot({ path: join(OUT, `${name}-${theme}-login-failed.png`) });
      await context.close();
      continue;
    }

    for (const [path, label] of PAGES) {
      const before = consoleErrors.length;
      const beforeNet = netErrors.length;
      await page.goto(`${BASE}${path}`, { waitUntil: 'domcontentloaded' });
      await page.waitForTimeout(2200);

      const info = await rendered(page);
      const overflow = await page.evaluate(
        () => document.documentElement.scrollWidth - document.documentElement.clientWidth,
      );

      const newErrors = consoleErrors.slice(before);
      const newNet = netErrors.slice(beforeNet);

      // axe, on the real rendered page.
      let axe = [];
      try {
        const report = await new AxeBuilder({ page })
          .withTags(['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa'])
          .analyze();
        axe = report.violations
          .filter((v) => v.impact === 'serious' || v.impact === 'critical')
          .map((v) => `${v.id}: ${v.nodes.length} node(s) — ${v.help}`);
        for (const v of report.violations) {
          axeFindings.push({
            page: label,
            viewport: name,
            theme,
            id: v.id,
            impact: v.impact,
            nodes: v.nodes.length,
            help: v.help,
          });
        }
      } catch (e) {
        axeFindings.push({
          page: label,
          viewport: name,
          theme,
          id: 'axe-failed',
          impact: 'error',
          help: String(e).slice(0, 200),
        });
      }

      results.push({
        viewport: name,
        theme,
        appliedTheme: info.theme,
        bodyBg: info.bodyBg,
        path,
        label,
        headings: info.headings,
        tableRows: info.rows,
        cards: info.cards,
        buttons: info.buttons,
        inputs: info.inputs,
        textLength: info.textLength,
        overflowPx: overflow,
        consoleErrors: newErrors,
        networkErrors: newNet,
        axeViolations: axe,
        firstText: info.firstText,
      });

      await page.screenshot({
        path: join(OUT, `${name}-${theme}-${label.replace(/\W+/g, '-')}.png`),
        fullPage: false,
      });

      console.log(
        `  ${label.padEnd(30)} rows=${String(info.rows).padStart(3)} cards=${String(info.cards).padStart(3)} ` +
          `btn=${String(info.buttons).padStart(3)} text=${String(info.textLength).padStart(5)} ` +
          `ovf=${overflow}px err=${newErrors.length}/${newNet.length} axe=${axe.length}`,
      );
      for (const e of newErrors) console.log(`      console: ${e}`);
      for (const e of newNet) console.log(`      network: ${e}`);
      for (const e of axe) console.log(`      axe: ${e}`);
    }

    await context.close();
  }
}

await browser.close();

writeFileSync(join(OUT, 'results.json'), JSON.stringify({ base: BASE, results, axeFindings }, null, 2));

console.log('\n=== the summary ===');
const bad = results.filter(
  (r) => r.consoleErrors.length || r.networkErrors.length || r.overflowPx > 2 || r.axeViolations.length,
);
const empty = results.filter((r) => r.textLength < 200);
console.log(`pages visited: ${results.length}`);
console.log(`with an error, an overflow or an axe violation: ${bad.length}`);
for (const b of bad) {
  console.log(
    `  ${b.viewport}/${b.theme} ${b.label}: console=${b.consoleErrors.length} net=${b.networkErrors.length} overflow=${b.overflowPx}px axe=${b.axeViolations.length}`,
  );
  for (const e of b.consoleErrors) console.log(`      console: ${e}`);
  for (const e of b.networkErrors) console.log(`      network: ${e}`);
  for (const e of b.axeViolations) console.log(`      axe: ${e}`);
}
console.log(`pages that rendered almost nothing: ${empty.length}`);
for (const e of empty) console.log(`  ${e.viewport}/${e.theme} ${e.label} (${e.textLength} chars)`);
process.exit(bad.length ? 1 : 0);
