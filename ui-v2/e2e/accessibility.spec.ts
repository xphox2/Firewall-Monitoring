import AxeBuilder from '@axe-core/playwright';
import { expect, test } from '@playwright/test';
import { installApiMocks } from './mocks';

/**
 * The automated accessibility check.
 *
 * The console was written without an accessibility pass, and the audit
 * found the debt by hand: orphaned labels, unannounced errors, mouse-only
 * sorting, a drawer with no focus trap. A hand audit catches those once;
 * an automated check catches the NEXT one, on every PR.
 *
 * axe is not a substitute for a manual review — it cannot tell that a
 * button's name is the wrong name, or that a tab order is confusing. It
 * catches the mechanical half: a control with no name, a contrast failure,
 * a landmark that is missing.
 *
 * The bar is SERIOUS and CRITICAL. A "moderate" finding is often a
 * deliberate choice (a `role="status"` region that is also a live region),
 * and failing the build on those would make the gate something people
 * route around.
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

test.describe('the console has no serious accessibility violations', () => {
  test.beforeEach(async ({ page }) => {
    await installApiMocks(page);
  });

  for (const route of ROUTES) {
    test(`${route} passes axe`, async ({ page }) => {
      await page.goto(`/admin/v2/${route}`);
      await expect(page.locator('#main-content')).toBeVisible();
      // The charts and the tables settle after the mocked API answers.
      await page.waitForTimeout(400);

      const results = await new AxeBuilder({ page })
        // WCAG 2.2 is INCLUDED on purpose: this PR is about the keyboard
        // and the focus, and 2.2's `target-size` and `focus-not-obscured`
        // are the rules that catch a control an operator cannot hit.
        .withTags(['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa', 'wcag22aa'])
        .analyze();

      const serious = results.violations.filter(
        (v) => v.impact === 'serious' || v.impact === 'critical',
      );

      expect(
        serious.map((v) => ({
          id: v.id,
          impact: v.impact,
          help: v.help,
          nodes: v.nodes.slice(0, 3).map((n) => n.target.join(' ')),
        })),
        'serious or critical axe violations',
      ).toEqual([]);
    });
  }
});
