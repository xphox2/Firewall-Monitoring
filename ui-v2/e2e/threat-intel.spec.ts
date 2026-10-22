import { expect, test } from '@playwright/test';
import { installApiMocks } from './mocks';

test('adds a custom threat indicator', async ({ page }) => {
  const created: unknown[] = [];

  await installApiMocks(page, [
    {
      match: (url) => url.pathname === '/admin/api/threat-intel/feeds',
      body: { feeds_enabled: true, status: [] },
    },
    {
      match: (url) => url.pathname === '/admin/api/threat-intel/search',
      body: { entries: [], total: 0 },
    },
    {
      match: (url) => url.pathname === '/admin/api/flows/threat-intel',
      method: 'POST',
      onRequest: (request) => {
        created.push(request.postDataJSON());
        return { id: 11 };
      },
    },
  ]);

  await page.goto('/admin/v2/threat-intel?tab=feeds');
  await expect(page.getByText('Add custom operator indicator')).toBeVisible();

  await page.getByPlaceholder('IP or CIDR').fill('203.0.113.0/24');
  await page.getByPlaceholder('Category / ticket').fill('CHG-1234');
  await page.getByRole('button', { name: 'Add indicator' }).click();

  await expect(page.getByText('Custom indicator added')).toBeVisible();
  expect(created).toEqual([
    {
      cidr: '203.0.113.0/24',
      category: 'CHG-1234',
      source: 'manual',
      severity: 'warning',
      expires_at: null,
    },
  ]);
});
