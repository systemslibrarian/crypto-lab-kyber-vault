import AxeBuilder from '@axe-core/playwright';
import { expect, test, type Page } from '@playwright/test';

/**
 * WCAG regression gate. The demo is a tabbed single page: only one panel is
 * visible at a time (the others carry `hidden`), so we scan the page once per
 * tab to cover every panel's content. We do this in both themes and assert
 * zero WCAG A/AA violations.
 */

const TAGS = ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa'];

const TAB_IDS = ['encaps', 'lattice', 'params', 'compare', 'how'] as const;

/**
 * Neutralize animations/transitions/opacity so nothing is mid-fade (which can
 * flag contrast) while axe reads computed styles, and expand any collapsibles.
 */
async function prepare(page: Page): Promise<void> {
  await page.addStyleTag({
    content: `*,*::before,*::after{animation:none!important;transition:none!important;}
      .panel,.card,.shell{opacity:1!important;}`,
  });
  await page.evaluate(() => {
    for (const details of Array.from(document.querySelectorAll('details'))) {
      (details as HTMLDetailsElement).open = true;
    }
  });
}

async function scan(page: Page, context: string): Promise<void> {
  const results = await new AxeBuilder({ page }).withTags(TAGS).analyze();
  const summary = results.violations.map((v) => ({
    id: v.id,
    impact: v.impact,
    help: v.help,
    nodes: v.nodes.map((n) => n.target.join(' ')).slice(0, 5),
  }));
  expect(summary, `violations in ${context}`).toEqual([]);
}

async function scanEveryTab(page: Page, themeLabel: string): Promise<void> {
  for (const id of TAB_IDS) {
    await page.locator(`#tab-${id}`).click();
    // Re-render swaps the visible panel; wait for it to be shown.
    await expect(page.locator(`#panel-${id}`)).toBeVisible();
    await prepare(page);
    await scan(page, `${themeLabel} / tab ${id}`);
  }
}

test('no WCAG A/AA violations in dark theme', async ({ page }) => {
  await page.goto('.');
  await expect(page.locator('html')).toHaveAttribute('data-theme', 'dark');
  await prepare(page);
  await scan(page, 'dark / default');
  await scanEveryTab(page, 'dark');
});

test('no WCAG A/AA violations in light theme', async ({ page }) => {
  await page.goto('.');
  await page.locator('#cl-theme-toggle').click();
  await expect(page.locator('html')).toHaveAttribute('data-theme', 'light');
  await prepare(page);
  await scan(page, 'light / default');
  await scanEveryTab(page, 'light');
});
