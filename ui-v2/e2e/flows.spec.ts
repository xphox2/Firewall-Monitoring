import { expect, test } from '@playwright/test';
import { installApiMocks } from './mocks';

const SAMPLES = [
  {
    timestamp: '2026-10-22T12:00:00Z',
    device_id: 1,
    src_addr: '10.0.0.5',
    src_port: 51000,
    dst_addr: '192.0.2.10',
    dst_port: 443,
    protocol: 6,
    bytes: 4096,
    packets: 12,
    flow_source: 'sflow',
    firewall_event: 'allow',
  },
  {
    timestamp: '2026-10-22T12:00:05Z',
    device_id: 1,
    src_addr: '10.0.0.5',
    src_port: 51001,
    dst_addr: '192.0.2.11',
    dst_port: 53,
    protocol: 17,
    bytes: 512,
    packets: 2,
    flow_source: 'sflow',
  },
];

test('filters flow samples and exports the filtered CSV', async ({ page }) => {
  const sampleUrls: string[] = [];
  await installApiMocks(page, [
    {
      match: (url) => url.pathname === '/admin/api/flows',
      onRequest: (request) => {
        sampleUrls.push(new URL(request.url()).search);
        return SAMPLES;
      },
    },
    {
      match: (url) => url.pathname === '/admin/api/flows/stats',
      body: { total_bytes: 0, top_talkers: [], conversations: [], protocols: [] },
    },
    { match: (url) => url.pathname === '/admin/api/flows/detections', body: { detections: [] } },
    { match: (url) => url.pathname === '/admin/api/devices', body: [{ id: 1, name: 'FW-1' }] },
  ]);

  await page.goto('/admin/v2/flows?tab=samples');
  await expect(page.getByText('Newest 2 samples')).toBeVisible();

  // Filters are debounced (350 ms) before the samples endpoint sees them.
  await page.getByLabel('Filter by source address').fill('10.0.0.5');
  await expect.poll(() => sampleUrls.at(-1) ?? '').toContain('src_addr=10.0.0.5');

  const downloadPromise = page.waitForEvent('download');
  await page.getByRole('button', { name: /Export CSV/ }).click();
  await expect.poll(() => sampleUrls.at(-1) ?? '').toContain('limit=5000');
  await expect.poll(() => sampleUrls.at(-1) ?? '').toContain('src_addr=10.0.0.5');
  await expect(page.getByText('2 flow samples exported')).toBeVisible();

  const download = await downloadPromise;
  expect(download.suggestedFilename()).toMatch(/^flows-1h-\d{4}-\d{2}-\d{2}\.csv$/);
});
