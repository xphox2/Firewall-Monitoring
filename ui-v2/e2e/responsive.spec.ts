import { expect, test } from '@playwright/test';
import { installApiMocks } from './mocks';

/**
 * The pages every viewport is checked on.
 *
 * These are the routes with the densest layouts: the tables, the filter
 * bars and the charts. A sideways scroll on a phone is the failure this
 * catches.
 */
const ROUTES = [
  'overview',
  'topology',
  'events',
  'flows',
  'syslog',
  'traps',
  'alerts',
  'threat-intel',
  'devices',
  'collectors',
  'maintenance',
  'configuration/storage',
  'configuration/alerting',
  'configuration/integrations',
  'configuration/system',
];

/**
 * The widest element that is NOT inside an intentionally scrollable strip.
 *
 * The shell sets `overflow-x: hidden` on `html, body`, so the DOCUMENT
 * never scrolls sideways — the content is CLIPPED instead. That is why
 * `documentElement.scrollWidth` is useless here: it always equals
 * `clientWidth`, and an assertion on it passes on every page, whatever is
 * hanging off the edge.
 *
 * So the check is on the GEOMETRY: an element that reaches past the
 * viewport is either cut off (a bug) or inside a strip the operator can
 * scroll (fine). The strips are `overflow-x: auto|scroll`, so those are
 * skipped.
 */
async function horizontalOverflow(page: import('@playwright/test').Page) {
  return page.evaluate(() => {
    const limit = document.documentElement.clientWidth;
    let worst = { selector: '', right: 0 };
    for (const el of Array.from(document.body.querySelectorAll('*'))) {
      // Inside a strip the operator can scroll to? Fine.
      let scrollable = false;
      for (let p = el.parentElement; p; p = p.parentElement) {
        const ox = getComputedStyle(p).overflowX;
        if (ox === 'auto' || ox === 'scroll') {
          scrollable = true;
          break;
        }
      }
      if (scrollable) continue;
      const rect = el.getBoundingClientRect();
      // A hidden or zero-sized element cannot be cut off.
      if (rect.width === 0 || rect.height === 0) continue;
      if (getComputedStyle(el).display === 'none') continue;
      if (rect.right > worst.right) {
        const cls =
          typeof el.className === 'string' && el.className.trim()
            ? '.' + el.className.trim().split(/\s+/).slice(0, 3).join('.')
            : '';
        worst = {
          selector: el.tagName.toLowerCase() + cls,
          right: Math.round(rect.right),
        };
      }
    }
    return { limit, worst };
  });
}

test.describe('the console never overflows sideways', () => {
  test.beforeEach(async ({ page }) => {
    await installApiMocks(page);
  });

  for (const route of ROUTES) {
    test(`${route} fits the viewport`, async ({ page }) => {
      await page.goto(`/admin/v2/${route}`);
      // The shell's main region, not the brand in the sidebar: the sidebar
      // is hidden at the mobile width, so the brand is not visible there.
      await expect(page.locator('#main-content')).toBeVisible();
      // The charts and the tables settle after the mocked API answers.
      await page.waitForTimeout(400);

      const { limit, worst } = await horizontalOverflow(page);
      expect(
        worst.right,
        `an element reaches ${worst.right}px past a ${limit}px viewport (${worst.selector}); the shell clips it, so the operator loses it`,
      ).toBeLessThanOrEqual(limit + 1);
    });
  }

  test('the check would catch an element that overflows', async ({ page }) => {
    // The check has to be able to fail, or it is decoration. A deliberately
    // over-wide element is injected, and the check has to see it.
    await page.goto('/admin/v2/overview');
    await expect(page.locator('#main-content')).toBeVisible();
    await page.evaluate(() => {
      const el = document.createElement('div');
      el.style.width = '3000px';
      el.style.height = '10px';
      el.id = 'fwmon-overflow-probe';
      document.body.appendChild(el);
    });
    const { limit, worst } = await horizontalOverflow(page);
    expect(worst.right, 'the overflow check did not see the injected element').toBeGreaterThan(
      limit + 1,
    );
  });
});
