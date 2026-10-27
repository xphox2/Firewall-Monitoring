import { expect, test } from '@playwright/test';
import { installApiMocks } from './mocks';
import { dataRows, dataView } from './helpers';

const ALERTS = [
  {
    id: 1,
    device_id: 1,
    device_name: 'FW-1',
    alert_type: 'CPU_HIGH',
    severity: 'critical',
    message: 'CPU is above threshold',
    metric_name: 'cpu_usage',
    threshold: 80,
    current_value: 93,
    acknowledged: false,
    resolved_at: null,
    timestamp: '2026-10-22T12:00:00Z',
  },
  {
    id: 2,
    device_id: 1,
    device_name: 'FW-1',
    alert_type: 'MEMORY_HIGH',
    severity: 'warning',
    message: 'Memory is high',
    metric_name: 'memory_usage',
    threshold: 85,
    current_value: 88,
    acknowledged: false,
    resolved_at: null,
    timestamp: '2026-10-22T12:01:00Z',
  },
];

test('filters alerts and bulk-acknowledges a selection', async ({ page }) => {
  const listUrls: string[] = [];
  const ackBodies: unknown[] = [];

  await installApiMocks(page, [
    {
      match: (url) => url.pathname === '/admin/api/alerts',
      onRequest: (request) => {
        const url = new URL(request.url());
        listUrls.push(url.search);
        return { alerts: ALERTS, total: ALERTS.length };
      },
    },
    {
      match: (url) => url.pathname === '/admin/api/alerts/stats',
      body: {
        total: 2,
        by_severity: [
          { key: 'critical', count: 1 },
          { key: 'warning', count: 1 },
        ],
        by_type: [{ key: 'CPU_HIGH', count: 1 }],
        over_time: [],
      },
    },
    {
      match: (url) => url.pathname === '/admin/api/alerts/bulk-acknowledge',
      method: 'POST',
      onRequest: (request) => {
        ackBodies.push(request.postDataJSON());
        return { acknowledged: 1 };
      },
    },
    { match: (url) => url.pathname === '/admin/api/devices', body: [{ id: 1, name: 'FW-1' }] },
    { match: (url) => url.pathname === '/admin/api/sites', body: [] },
  ]);

  await page.goto('/admin/v2/alerts');
  await expect(dataRows(page, 'CPU is above threshold')).toBeVisible();

  // A filter change must reach the list endpoint, not just the local state.
  await page.getByLabel('Filter by severity').selectOption('critical');
  await expect.poll(() => listUrls.at(-1) ?? '').toContain('severity=critical');

  // The view for the CURRENT viewport: both views are in the DOM and one
  // of them is hidden, so a bare label locator matches two.
  await dataView(page).getByLabel('Select alert 1').check();
  await expect(page.getByText('1 selected')).toBeVisible();
  await page.getByRole('button', { name: 'Acknowledge' }).click();

  await expect(page.getByText('Acknowledged 1 alert(s)')).toBeVisible();
  expect(ackBodies).toEqual([{ ids: [1] }]);
});
