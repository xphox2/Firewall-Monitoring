import { expect, test } from '@playwright/test';
import { installApiMocks } from './mocks';
import { dataRow } from './helpers';

// The alert-override drawer, driven through the UI the operator uses.
//
// It once requested `/admin/api/admin/api/.../alert-config`: every load, save
// and reset 404ed in production while this suite stayed green, because the
// mock's catch-all answered the doubled path. These handlers match the EXACT
// pathname, and the test fails unless both the GET and the PUT reach them.
test('the site override drawer loads, saves the whole override, and hands a blanked field back', async ({ page }) => {
  const seen: string[] = [];
  let saved: Record<string, unknown> | null = null;

  await installApiMocks(page, [
    {
      match: (url) => url.pathname === '/admin/api/sites',
      method: 'GET',
      body: [{ id: 3, name: 'HQ', address: '', description: '' }],
    },
    {
      match: (url) => url.pathname === '/admin/api/sites/3/alert-config',
      method: 'GET',
      onRequest: () => {
        seen.push('GET');
        return {
          site_id: 3,
          policy_id: null,
          cpu_threshold: 0,
          memory_threshold: 75,
          disk_threshold: 0,
          session_threshold: 0,
          cooldown_minutes: 10,
          storm_sources: 4,
        };
      },
    },
    {
      match: (url) => url.pathname === '/admin/api/sites/3/alert-config',
      method: 'PUT',
      onRequest: (request) => {
        seen.push('PUT');
        saved = request.postDataJSON();
        return saved;
      },
    },
  ]);

  await page.goto('/admin/v2/collectors?tab=sites');
  await dataRow(page, 'HQ')
    .getByRole('button', { name: 'Alert thresholds & routing for this site' })
    .click();

  // A stored 0 is "inherit", so it is shown blank; a set value is shown.
  const memory = page.getByLabel('Memory threshold (%)');
  await expect(memory).toHaveValue('75');
  await expect(page.getByLabel('CPU threshold (%)')).toHaveValue('');

  // Blank the memory threshold and the storm threshold: both go back to
  // inheriting, which the server only sees if the body says so.
  await memory.fill('');
  await page.getByLabel(/Storm digest threshold/).fill('');
  await page.getByRole('button', { name: 'Save override' }).click();

  // The load reached the real route, then the save did (a refetch may follow).
  await expect.poll(() => seen.includes('PUT')).toBe(true);
  expect(seen.slice(0, 2)).toEqual(['GET', 'PUT']);
  expect(saved).toMatchObject({
    cpu_threshold: 0,
    memory_threshold: 0,
    cooldown_minutes: 10,
    storm_sources: null,
    policy_id: null,
  });
  // An unchanged profile is left OUT: assigning one is admin-only.
  expect(saved && 'event_profile_id' in saved).toBe(false);
});
