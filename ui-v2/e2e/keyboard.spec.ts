import { expect, test } from '@playwright/test';
import { installApiMocks } from './mocks';

/**
 * The keyboard specs.
 *
 * The console is a NOC surface: an operator drives it from a keyboard, with
 * the console next to the screen and no mouse in reach. The audit found the
 * drawer had no focus trap, the sort was mouse-only and the tab strips
 * could not be reached with the arrow keys — none of which a typecheck or
 * a unit test can see.
 *
 * These are the behaviours that have to hold.
 */

/**
 * Whether the focused element shows a focus indicator.
 *
 * A focus indicator is an outline or a box-shadow. The check reads the
 * COMPUTED style, so a `focus-visible` outline that is only applied on
 * keyboard focus counts, and an element that removes its outline without
 * replacing it does not.
 */
async function focusIndicator(page: import('@playwright/test').Page) {
  return page.evaluate(() => {
    const el = document.activeElement as HTMLElement | null;
    if (!el || el === document.body) return { tag: 'none', indicator: false };
    const style = getComputedStyle(el);
    const hasOutline =
      style.outlineStyle !== 'none' &&
      parseFloat(style.outlineWidth || '0') > 0;
    const hasShadow = style.boxShadow && style.boxShadow !== 'none';
    return {
      tag: el.tagName.toLowerCase(),
      label: el.getAttribute('aria-label') ?? el.textContent?.trim().slice(0, 40) ?? '',
      indicator: hasOutline || hasShadow,
    };
  });
}

test.describe('the console works from the keyboard', () => {
  test.beforeEach(async ({ page }) => {
    await installApiMocks(page);
  });

  test('every focused control shows a focus indicator', async ({ page }) => {
    await page.goto('/admin/v2/overview');
    await expect(page.locator('#main-content')).toBeVisible();

    // Tab through the first few controls and check each one as the focus
    // lands on it.
    const withoutIndicator: string[] = [];
    for (let i = 0; i < 12; i += 1) {
      await page.keyboard.press('Tab');
      const { tag, label, indicator } = await focusIndicator(page);
      if (tag === 'none') break;
      if (!indicator) {
        withoutIndicator.push(`${tag} "${label}"`);
      }
    }
    expect(withoutIndicator, 'focused controls with no visible focus indicator').toEqual([]);
  });

  test('the mobile navigation drawer traps the focus and closes on Escape', async ({
    page,
  }, testInfo) => {
    // The drawer is a `lg:hidden` control, so the spec only applies below
    // the large breakpoint.
    test.skip(
      (testInfo.project.use.viewport?.width ?? 0) >= 1024,
      'the mobile navigation only exists below the large breakpoint',
    );
    await page.goto('/admin/v2/overview');
    await expect(page.locator('#main-content')).toBeVisible();

    // The drawer is only there at the mobile width.
    const menuButton = page.getByLabel('Open navigation menu');
    await expect(menuButton).toBeVisible();

    await menuButton.click();
    const dialog = page.getByRole('dialog');
    await expect(dialog).toBeVisible();

    // The focus moved INTO the drawer, not stayed on the trigger behind it.
    const inside = await page.evaluate(() => {
      const d = document.querySelector('[role="dialog"]');
      return Boolean(d && d.contains(document.activeElement));
    });
    expect(inside, 'the focus did not move into the drawer').toBe(true);

    // Tab several times: the focus must STAY in the drawer. A drawer that
    // lets the focus walk out into the page behind is a drawer an operator
    // can lose.
    for (let i = 0; i < 8; i += 1) {
      await page.keyboard.press('Tab');
      const stillInside = await page.evaluate(() => {
        const d = document.querySelector('[role="dialog"]');
        return Boolean(d && d.contains(document.activeElement));
      });
      expect(stillInside, `the focus escaped the drawer after ${i + 1} tabs`).toBe(true);
    }

    // Escape closes it.
    await page.keyboard.press('Escape');
    await expect(page.getByRole('dialog')).toHaveCount(0);
  });

  test('the command palette opens with the keyboard and closes on Escape', async ({
    page,
  }, testInfo) => {
    // The palette's trigger is a `lg:hidden` control; above the large
    // breakpoint the palette is opened with the keyboard shortcut instead.
    test.skip(
      (testInfo.project.use.viewport?.width ?? 0) >= 1024,
      'the search trigger only exists below the large breakpoint',
    );
    await page.goto('/admin/v2/overview');
    await expect(page.locator('#main-content')).toBeVisible();

    // The palette's trigger is a button, so it is reachable with Tab.
    const trigger = page.getByLabel('Search or jump to page');
    await expect(trigger).toBeVisible();
    await trigger.focus();
    await page.keyboard.press('Enter');

    const input = page.getByPlaceholder(/search|jump/i).first();
    await expect(input).toBeVisible();
    await expect(input).toBeFocused();

    await page.keyboard.press('Escape');
    await expect(input).toHaveCount(0);
  });

  test('the table sort is operable from the keyboard', async ({ page }, testInfo) => {
    // At the mobile width the table is replaced by the card view, so there
    // is no header cell to sort.
    test.skip(
      (testInfo.project.use.viewport?.width ?? 0) < 768,
      'the table is replaced by the card view below the medium breakpoint',
    );
    // The default mock answers every GET with an empty array, so the table
    // would render its EMPTY state and have no sort control at all.
    await installApiMocks(page, [
      {
        match: (url) => url.pathname === '/admin/api/events',
        body: {
          events: [
            {
              id: 1,
              ts: '2026-10-22T12:00:00Z',
              action: 1,
              src_ip: '198.51.100.1',
              src_port: 1234,
              dst_ip: '203.0.113.5',
              dst_port: 443,
              proto: 6,
              bytes_in: 100,
              bytes_out: 200,
              device_id: 1,
              device_name: 'FW-1',
            },
            {
              id: 2,
              ts: '2026-10-22T12:01:00Z',
              action: 2,
              src_ip: '198.51.100.2',
              src_port: 2345,
              dst_ip: '203.0.113.6',
              dst_port: 80,
              proto: 6,
              bytes_in: 10,
              bytes_out: 20,
              device_id: 1,
              device_name: 'FW-1',
            },
          ],
          total: 2,
          total_capped: false,
        },
      },
    ]);
    await page.goto('/admin/v2/events?tab=stream');
    await expect(page.locator('#main-content')).toBeVisible();

    // The sort control is a real button, so it is in the tab order and it
    // announces its state.
    const sortButton = page.locator('th button').first();
    await expect(sortButton).toBeVisible();
    await sortButton.focus();
    await expect(sortButton).toBeFocused();

    const before = await page.locator('th[aria-sort]').first().getAttribute('aria-sort');
    await page.keyboard.press('Enter');
    await expect
      .poll(async () => page.locator('th[aria-sort]').first().getAttribute('aria-sort'))
      .not.toBe(before);
  });
});
