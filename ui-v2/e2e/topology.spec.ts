import { expect, test } from '@playwright/test';
import { installApiMocks } from './mocks';

test('loads the lazy topology map and exposes save/reset layout', async ({ page }) => {
  const pageErrors: string[] = [];
  page.on('pageerror', (error) => pageErrors.push(error.message));

  await installApiMocks(page, [
    {
      match: (url) => url.pathname === '/admin/api/connections/vpn-map',
      body: {},
    },
    {
      match: (url) => url.pathname === '/admin/api/devices',
      body: [
        { id: 1, name: 'FW-1', site_id: 1, status: 'up', ip_address: '10.0.0.1' },
        { id: 2, name: 'FW-2', site_id: 1, status: 'up', ip_address: '10.0.0.2' },
      ],
    },
    {
      match: (url) => url.pathname === '/admin/api/sites',
      body: [{ id: 1, name: 'HQ' }],
    },
    {
      match: (url) => url.pathname === '/admin/api/connections',
      body: [
        {
          id: 1,
          name: 'FW-1 to FW-2',
          source_device_id: 1,
          dest_device_id: 2,
          connection_type: 'ethernet',
          status: 'up',
          source_if_name: 'port1',
          dest_if_name: 'port1',
        },
      ],
    },
    {
      match: (url) => url.pathname === '/admin/api/connections/status-summary',
      body: { connections: [], devices: [] },
    },
  ]);

  await page.goto('/admin/v2/topology');
  await expect(page.getByRole('heading', { name: /Topology Map/ })).toBeVisible();
  await expect(page.getByRole('button', { name: 'Save layout' })).toBeDisabled();
  await expect(page.getByRole('button', { name: 'Reset layout' })).toBeVisible();

  // The map chunk is lazy: a canvas means the hashed chunk loaded and Cytoscape
  // mounted (the version-skew failure mode this suite exists to catch).
  await expect(page.locator('canvas').first()).toBeVisible();

  await page.getByRole('button', { name: 'Reset layout' }).click();
  await expect(page.getByText('Reset the map layout?')).toBeVisible();
  await page.getByRole('button', { name: 'Cancel' }).click();
  await expect(page.getByText('Reset the map layout?')).toHaveCount(0);

  expect(pageErrors.filter((message) => /export named|dynamically imported module/i.test(message))).toEqual([]);
});
