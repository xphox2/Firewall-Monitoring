import { expect, test, type Page } from '@playwright/test';
import { installApiMocks } from './mocks';
import { dataRow } from './helpers';

const MASK = '********';

function devices() {
  return [
    { id: 1, name: 'fw-a', ip_address: '192.0.2.1', vendor: 'fortigate', snmp_version: '2c', snmp_community: MASK, api_token: MASK, enabled: true },
    { id: 2, name: 'fw-b', ip_address: '192.0.2.2', vendor: 'fortigate', snmp_version: '2c', snmp_community: MASK, api_token: MASK, enabled: true },
  ];
}

async function openEditor(page: Page, name: string) {
  await dataRow(page, name).getByRole('button', { name: 'Edit device' }).first().click();
  await expect(page.getByRole('dialog')).toBeVisible();
}

async function clearApiToken(page: Page) {
  await page.getByRole('tab', { name: 'SSH & API Keys' }).click();
  // The API token's own Clear control (the field's label names it).
  const field = page.locator('div', { has: page.getByText('API Token', { exact: true }) }).last();
  await field.getByRole('button', { name: 'Clear' }).click();
  await page.getByRole('button', { name: 'Remove it' }).click();
}

// A pending credential Clear belongs to ONE device.
//
// It was once kept across the editor's sessions, so a Clear asked for on
// device A - even one followed by Cancel - was sent with the next save of
// device B, and the server (admin, allow-listed) wiped B's credential.
test('a Clear confirmed on one device and cancelled never reaches the next device saved', async ({ page }) => {
  const puts: Array<{ id: string; body: Record<string, unknown> }> = [];
  await installApiMocks(page, [
    { match: (url) => url.pathname === '/admin/api/devices', method: 'GET', body: devices() },
    {
      match: (url) => /^\/admin\/api\/devices\/\d+$/.test(url.pathname),
      method: 'PUT',
      onRequest: (request) => {
        const body = request.postDataJSON();
        puts.push({ id: new URL(request.url()).pathname.split('/').pop() ?? '', body });
        return body;
      },
    },
  ]);

  await page.goto('/admin/v2/devices');

  // Device A: Clear the API token, then Cancel the editor.
  await openEditor(page, 'fw-a');
  await clearApiToken(page);
  await expect.soft(page.getByText('The stored credential will be removed when you save.')).toBeVisible();
  await page.getByRole('button', { name: 'Cancel' }).click();
  await expect(page.getByRole('dialog')).toBeHidden();

  // Device B: an unrelated edit, saved.
  await openEditor(page, 'fw-b');
  await page.getByRole('button', { name: 'Save Device' }).click();

  await expect.poll(() => puts.length).toBe(1);
  expect(puts[0].id).toBe('2');
  expect('clear_secrets' in puts[0].body).toBe(false);
});

test('typing a new value withdraws a pending Clear, and the new value is sent', async ({ page }) => {
  const puts: Array<Record<string, unknown>> = [];
  await installApiMocks(page, [
    { match: (url) => url.pathname === '/admin/api/devices', method: 'GET', body: devices() },
    {
      match: (url) => url.pathname === '/admin/api/devices/1',
      method: 'PUT',
      onRequest: (request) => {
        const body = request.postDataJSON();
        puts.push(body);
        return body;
      },
    },
  ]);

  await page.goto('/admin/v2/devices');
  await openEditor(page, 'fw-a');
  await clearApiToken(page);
  await page.getByLabel('API Token').fill('a-new-token');
  await page.getByRole('button', { name: 'Save Device' }).click();

  await expect.poll(() => puts.length).toBe(1);
  expect(puts[0].api_token).toBe('a-new-token');
  expect('clear_secrets' in puts[0]).toBe(false);
});
