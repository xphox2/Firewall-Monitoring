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

// Clear, then Reveal, then Clear again.
//
// A Reveal withdraws a pending Clear (the field shows the credential, so the
// save keeps it). The Clear control then has to come back: it read only the
// form's value, which the first Clear had emptied, so it stayed hidden until
// the editor was reopened.
test('after Clear then Reveal, the credential is kept and can be cleared again', async ({ page }) => {
  const puts: Array<Record<string, unknown>> = [];
  await installApiMocks(page, [
    { match: (url) => url.pathname === '/admin/api/devices', method: 'GET', body: devices() },
    {
      match: (url) => url.pathname === '/admin/api/devices/1/reveal-secret',
      method: 'POST',
      body: { secret: 'the-stored-token' },
    },
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

  // Reveal: the stored credential is shown and the pending Clear is withdrawn.
  const field = page.locator('div', { has: page.getByText('API Token', { exact: true }) }).last();
  await field.getByRole('button', { name: 'Reveal' }).click();
  await page.getByPlaceholder('Enter your password').fill('admin-password');
  await page.getByRole('button', { name: 'Decrypt & Reveal' }).click();
  await expect(page.getByLabel('API Token')).toHaveValue('the-stored-token');
  await expect(page.getByText('The stored credential will be removed when you save.')).toHaveCount(0);

  // The Clear control is offered again, and a second Clear really clears.
  await expect(field.getByRole('button', { name: 'Clear' })).toBeVisible();
  await clearApiToken(page);
  await page.getByRole('button', { name: 'Save Device' }).click();

  await expect.poll(() => puts.length).toBe(1);
  expect(puts[0].clear_secrets).toEqual(['api_token']);
  expect('api_token' in puts[0]).toBe(false);
});

// A revealed credential that the operator empties is still a revealed field.
//
// It flipped back to a password box with no placeholder (the input tested the
// revealed value for truthiness). An empty field leaves the stored credential
// as it is, so it reads "Unchanged" - and the save sends no clear.
test('emptying a revealed credential keeps the field visible and says Unchanged', async ({ page }) => {
  const puts: Array<Record<string, unknown>> = [];
  await installApiMocks(page, [
    { match: (url) => url.pathname === '/admin/api/devices', method: 'GET', body: devices() },
    {
      match: (url) => url.pathname === '/admin/api/devices/1/reveal-secret',
      method: 'POST',
      body: { secret: 'the-stored-token' },
    },
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
  await page.getByRole('tab', { name: 'SSH & API Keys' }).click();
  const field = page.locator('div', { has: page.getByText('API Token', { exact: true }) }).last();
  await field.getByRole('button', { name: 'Reveal' }).click();
  await page.getByPlaceholder('Enter your password').fill('admin-password');
  await page.getByRole('button', { name: 'Decrypt & Reveal' }).click();

  const input = page.getByLabel('API Token');
  await expect(input).toHaveValue('the-stored-token');
  await input.fill('');
  await expect(input).toHaveAttribute('type', 'text');
  await expect(input).toHaveAttribute('placeholder', 'Unchanged');

  await page.getByRole('button', { name: 'Save Device' }).click();
  await expect.poll(() => puts.length).toBe(1);
  expect('clear_secrets' in puts[0]).toBe(false);
});

// The phone-width card carries the row's actions column (Inspect, Edit
// device). It also rendered its own Edit button: two controls for one action.
test('a device card offers one Edit control', async ({ page }) => {
  test.skip((page.viewportSize()?.width ?? 0) >= 768, 'the card is the phone-width view');
  await installApiMocks(page, [
    { match: (url) => url.pathname === '/admin/api/devices', method: 'GET', body: devices() },
  ]);
  await page.goto('/admin/v2/devices');
  await expect(dataRow(page, 'fw-a').getByRole('button', { name: /^Edit/ })).toHaveCount(1);
});
