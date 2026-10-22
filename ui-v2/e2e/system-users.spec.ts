import { expect, test } from '@playwright/test';
import { installApiMocks } from './mocks';

test('disables another user but blocks disabling yourself', async ({ page }) => {
  const putBodies: unknown[] = [];

  await installApiMocks(page, [
    {
      match: (url) => url.pathname === '/admin/api/users',
      body: [
        {
          id: 1,
          username: 'e2e-admin',
          role: 'admin',
          totp_enabled: false,
          disabled: false,
          created_at: '2026-01-01T00:00:00Z',
        },
        {
          id: 2,
          username: 'operator',
          role: 'operator',
          totp_enabled: false,
          disabled: false,
          created_at: '2026-02-01T00:00:00Z',
        },
      ],
    },
    {
      match: (url) => url.pathname === '/admin/api/users/2',
      method: 'PUT',
      onRequest: (request) => {
        putBodies.push(request.postDataJSON());
        return { ok: true };
      },
    },
  ]);

  await page.goto('/admin/v2/configuration/system');
  const table = page.getByTestId('responsive-desktop-table');
  await expect(table.getByText('operator', { exact: true })).toBeVisible();

  const selfRow = table.getByRole('row').filter({ hasText: 'e2e-admin' });
  await expect(selfRow.getByRole('button', { name: 'Disable' })).toBeDisabled();

  const operatorRow = table
    .getByRole('row')
    .filter({ has: page.getByText('operator', { exact: true }) });
  await operatorRow.getByRole('button', { name: 'Disable' }).click();

  await expect(page.getByText('User disabled')).toBeVisible();
  expect(putBodies).toEqual([{ disabled: true }]);
});
