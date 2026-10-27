import { expect, test } from '@playwright/test';
import { installApiMocks } from './mocks';
import { dataRow, dataView } from './helpers';

test('approves and rejects a pending collector with a reason', async ({ page }) => {
  const calls: Array<{ path: string; body: unknown }> = [];

  await installApiMocks(page, [
    {
      match: (url) => url.pathname === '/admin/api/probes',
      body: [
        {
          id: 5,
          name: 'edge-probe',
          description: 'Branch edge',
          status: 'offline',
          approval_status: 'pending',
          last_seen: null,
        },
      ],
    },
    {
      match: (url) => url.pathname === '/admin/api/probes/5/approve',
      method: 'POST',
      onRequest: () => {
        calls.push({ path: 'approve', body: null });
        return { ok: true };
      },
    },
    {
      match: (url) => url.pathname === '/admin/api/probes/5/reject',
      method: 'POST',
      onRequest: (request) => {
        calls.push({ path: 'reject', body: request.postDataJSON() });
        return { ok: true };
      },
    },
  ]);

  await page.goto('/admin/v2/collectors');
  const table = dataView(page);
  const row = dataRow(page, 'edge-probe');
  await expect(row).toBeVisible();

  await row.getByRole('button', { name: 'Approve' }).click();
  await expect(page.getByText('Collector approve succeeded')).toBeVisible();
  expect(calls).toEqual([{ path: 'approve', body: null }]);

  await row.getByRole('button', { name: 'Reject' }).click();
  await expect(page.getByRole('heading', { name: 'Reject collector: edge-probe' })).toBeVisible();
  await page
    .getByPlaceholder('Unknown host / failed change ticket CHG-1234')
    .fill('duplicate probe');
  await page.getByRole('button', { name: 'Reject Collector' }).click();

  await expect(page.getByText('Collector rejected')).toBeVisible();
  expect(calls.at(-1)).toEqual({ path: 'reject', body: { reason: 'duplicate probe' } });
});
