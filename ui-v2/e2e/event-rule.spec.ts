import { expect, test } from '@playwright/test';
import { installApiMocks } from './mocks';

test('creates an event rule from the drawer', async ({ page }) => {
  const created: unknown[] = [];

  await installApiMocks(page, [
    {
      match: (url) => url.pathname === '/admin/api/alert-config/overview',
      body: { global: {}, overrides: [] },
    },
    { match: (url) => url.pathname === '/admin/api/settings', body: [] },
    { match: (url) => url.pathname === '/admin/api/alert-policies', body: [] },
    { match: (url) => url.pathname === '/admin/api/event-rule-profiles', body: [] },
    { match: (url) => url.pathname === '/admin/api/alert-types', body: [] },
    {
      match: (url) => url.pathname === '/admin/api/event-rules',
      method: 'GET',
      body: [],
    },
    {
      match: (url) => url.pathname === '/admin/api/event-rules',
      method: 'POST',
      onRequest: (request) => {
        created.push(request.postDataJSON());
        return { id: 9 };
      },
    },
    { match: (url) => url.pathname === '/admin/api/devices', body: [] },
    { match: (url) => url.pathname === '/admin/api/sites', body: [] },
  ]);

  await page.goto('/admin/v2/configuration/alerting?tab=event-rules');
  await page.getByRole('button', { name: 'New Rule' }).click();
  await expect(page.getByRole('heading', { name: 'Create Event Rule' })).toBeVisible();

  await page
    .getByPlaceholder('Suppress FortiGate admin login failures')
    .fill('E2E suppress rule');
  await page.getByRole('button', { name: 'Create rule' }).click();

  await expect.poll(() => created.length).toBe(1);
  expect(created[0]).toMatchObject({
    name: 'E2E suppress rule',
    source: 'syslog',
    action: 'alert',
    enabled: true,
  });
});
