import { expect, test } from '@playwright/test';
import { installApiMocks } from './mocks';

test('schedules a weekly recurring maintenance window', async ({ page }) => {
  const posted: Array<Record<string, unknown>> = [];
  await installApiMocks(page, [
    {
      match: (url) => url.pathname === '/admin/api/maintenance-windows',
      method: 'GET',
      body: [],
    },
    {
      match: (url) => url.pathname === '/admin/api/maintenance-windows/active',
      body: [],
    },
    {
      match: (url) => url.pathname === '/admin/api/maintenance-windows',
      method: 'POST',
      onRequest: (request) => {
        posted.push(request.postDataJSON() as Record<string, unknown>);
        return { id: 42 };
      },
    },
    {
      match: (url) => url.pathname === '/admin/api/devices',
      body: [{ id: 1, name: 'FW-1' }],
    },
    { match: (url) => url.pathname === '/admin/api/sites', body: [] },
    { match: (url) => url.pathname === '/admin/api/alert-types', body: [] },
  ]);

  await page.goto('/admin/v2/maintenance');
  await expect(page.getByRole('heading', { name: /Scheduled Maintenance/ })).toBeVisible();

  await page.getByRole('button', { name: 'Schedule Window' }).click();
  await expect(page.getByRole('heading', { name: 'Schedule Maintenance Window' })).toBeVisible();

  await page.getByPlaceholder('FortiOS 7.4 Patch Window').fill('Weekly patching');
  await page.getByLabel('Repeat this window').check();
  await page.getByLabel('Repeat frequency').selectOption('weekly');
  await page.getByText('Mon', { exact: true }).click();
  await page.getByText('Wed', { exact: true }).click();

  await page.getByRole('button', { name: 'Save Window' }).click();
  await expect(page.getByText('Maintenance window scheduled')).toBeVisible();

  expect(posted).toHaveLength(1);
  expect(posted[0]).toMatchObject({
    name: 'Weekly patching',
    recurring: true,
    recur_rule: 'weekly',
    recur_days: 'mon,wed',
  });
  expect(String(posted[0].start_time)).toMatch(/Z$/);
  expect(String(posted[0].end_time)).toMatch(/Z$/);
});
