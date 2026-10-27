import { expect, test } from '@playwright/test';
import { installApiMocks } from './mocks';

// Every top-level workspace loads inside the shell without tripping the
// render boundary. This catches build/runtime regressions that typechecking
// cannot: missing exports, stale lazy chunks, a component throwing on an
// empty API response.
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

test.describe('V2 shell smoke', () => {
  test.beforeEach(async ({ page }) => {
    await installApiMocks(page);
  });

  for (const route of ROUTES) {
    test(`${route} renders`, async ({ page }) => {
      const pageErrors: string[] = [];
      page.on('pageerror', (error) => pageErrors.push(error.message));

      await page.goto(`/admin/v2/${route}`);
      // The shell's main region, not the brand in the sidebar: the sidebar
      // is hidden below the large breakpoint, so the brand is not visible
      // there and the check would SKIP rather than test anything.
      await expect(page.locator('#main-content')).toBeVisible();
      await expect(page.getByText('This workspace failed to render')).toHaveCount(0);

      expect(
        pageErrors.filter((message) =>
          /does not provide an export|dynamically imported module|Importing a module script failed/i.test(
            message,
          ),
        ),
      ).toEqual([]);
    });
  }
});
