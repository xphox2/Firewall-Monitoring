import { expect, type Locator, type Page } from '@playwright/test';

/**
 * The data view's rows, whichever view the viewport shows.
 *
 * The shared data view renders BOTH a mobile card stack and a desktop
 * table, and CSS hides one of them. A locator for the desktop table is
 * therefore invisible at the mobile width, and the spec SKIPS rather than
 * testing anything — which is how a whole interaction went untested at the
 * phone size.
 */
export function dataRows(page: Page, text: string | RegExp): Locator {
  const width = page.viewportSize()?.width ?? 0;
  return width < 768
    ? page.getByTestId('responsive-mobile-cards').getByText(text).first()
    : page.getByTestId('responsive-desktop-table').getByText(text).first();
}

/** The data view's rows, as a whole. */
export function dataView(page: Page): Locator {
  const width = page.viewportSize()?.width ?? 0;
  return page.getByTestId(width < 768 ? 'responsive-mobile-cards' : 'responsive-desktop-table');
}

/**
 * The workspace navigation link.
 *
 * Below the large breakpoint the navigation lives in the mobile drawer, so
 * the link has to be reached through the drawer rather than the sidebar.
 */
export async function navTo(page: Page, label: string | RegExp): Promise<void> {
  const width = page.viewportSize()?.width ?? 0;
  if (width < 1024) {
    const menu = page.getByLabel('Open navigation menu');
    if (await menu.isVisible()) {
      await menu.click();
      await expect(page.getByRole('dialog')).toBeVisible();
      await page.getByRole('dialog').getByText(label, { exact: false }).first().click();
      await expect(page.getByRole('dialog')).toHaveCount(0);
      return;
    }
  }
  await page.getByRole('link', { name: label }).first().click();
}

/**
 * One row of the data view, whichever view the viewport shows.
 *
 * The desktop table's rows are `role="row"`; the mobile card stack's are
 * plain divs, so a role-based locator finds nothing there.
 */
export function dataRow(page: Page, text: string | RegExp): Locator {
  const width = page.viewportSize()?.width ?? 0;
  if (width < 768) {
    // The card is a direct child of the stack, and it has no row role — so
    // the locator is the card itself, not the text inside it: a spec that
    // looks for the row's BUTTONS needs the card, not the label.
    return page
      .getByTestId('responsive-mobile-cards')
      .locator(':scope > div')
      .filter({ hasText: text })
      .first();
  }
  return page.getByTestId('responsive-desktop-table').getByRole('row').filter({ hasText: text });
}

/**
 * One row, found by an EXACT cell value.
 *
 * A substring match is ambiguous: the admin row contains the word
 * "operator" somewhere in its capability list, so `filter({ hasText })`
 * matched two rows.
 */
export function dataRowByName(page: Page, name: string): Locator {
  const width = page.viewportSize()?.width ?? 0;
  if (width < 768) {
    return page
      .getByTestId('responsive-mobile-cards')
      .locator(':scope > div')
      .filter({ has: page.getByText(name, { exact: true }) })
      .first();
  }
  return page
    .getByTestId('responsive-desktop-table')
    .getByRole('row')
    .filter({ has: page.getByText(name, { exact: true }) });
}
