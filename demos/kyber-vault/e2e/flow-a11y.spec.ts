import AxeBuilder from '@axe-core/playwright';
import { expect, test, type Page } from '@playwright/test';

/**
 * WCAG regression gate for DYNAMIC states. The sibling a11y.spec.ts scans each
 * tab in its initial render; this spec drives the interactions so the states
 * that only appear after user action are also covered:
 *  - the completed Encaps/Decaps stepper (`.step.done`) and the byte-by-byte
 *    shared-secret comparison,
 *  - the LWE Gaussian-elimination solve results (clean + noisy),
 *  - the NTT butterfly dataflow diagram and the schoolbook `.match` badge.
 * Runs in both themes and asserts zero WCAG A/AA violations.
 */

const TAGS = ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa'];

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

async function driveAndScan(page: Page, theme: string): Promise<void> {
  // Encaps flow → completed stepper + shared-secret comparison.
  await page.locator('#next-step').click(); // KeyGen
  await page.locator('#next-step').click(); // Encaps
  await page.locator('#next-step').click(); // Decaps
  await expect(page.locator('.secret-compare')).toBeVisible();
  await prepare(page);
  await scan(page, `${theme} / encaps completed`);

  // Lattice: run both Gaussian-elimination solves.
  await page.locator('#tab-lattice').click();
  await expect(page.locator('#panel-lattice')).toBeVisible();
  await page.locator('#solve-clean').click();
  await prepare(page);
  await scan(page, `${theme} / lattice solve clean`);
  await page.locator('#solve-noisy').click();
  await prepare(page);
  await scan(page, `${theme} / lattice solve noisy`);

  // NTT: run the multiply then step a butterfly in the dataflow diagram.
  await page.locator('#ntt-run').click();
  await expect(page.locator('.bf-diagram')).toBeVisible();
  await page.locator('#bf-next').click();
  await prepare(page);
  await scan(page, `${theme} / ntt butterfly`);
}

test('no WCAG A/AA violations across dynamic states (dark)', async ({ page }) => {
  await page.goto('.');
  await expect(page.locator('html')).toHaveAttribute('data-theme', 'dark');
  await driveAndScan(page, 'dark');
});

test('no WCAG A/AA violations across dynamic states (light)', async ({ page }) => {
  await page.goto('.');
  await page.locator('#cl-theme-toggle').click();
  await expect(page.locator('html')).toHaveAttribute('data-theme', 'light');
  await driveAndScan(page, 'light');
});
