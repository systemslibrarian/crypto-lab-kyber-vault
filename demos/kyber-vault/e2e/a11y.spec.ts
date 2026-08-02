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

/**
 * WCAG 1.4.11 (non-text contrast) regression for text-entry control boundaries.
 * Axe does not flag low-contrast control borders, so we measure them directly:
 * every visible textarea's rendered border color must reach 3:1 against both
 * the control's own fill and the first opaque ancestor surface behind it.
 * Translucent colors are composited against those real surfaces first.
 * Returns Infinity when no textarea is visible on the current tab.
 */
async function minimumControlBoundaryRatio(page: Page): Promise<number> {
  return page.locator('textarea:visible').evaluateAll((elements) => {
    const parse = (value: string): { c: number[]; a: number } => {
      const n = (value.match(/[\d.]+/g) ?? ['0', '0', '0']).map(Number);
      return { c: n.slice(0, 3), a: n[3] ?? 1 };
    };
    const luminance = (parts: number[]): number => {
      const c = parts.map((part) => {
        const v = part / 255;
        return v <= 0.04045 ? v / 12.92 : ((v + 0.055) / 1.055) ** 2.4;
      });
      return 0.2126 * (c[0] ?? 0) + 0.7152 * (c[1] ?? 0) + 0.0722 * (c[2] ?? 0);
    };
    const ratio = (a: number[], b: number[]): number => {
      const [la, lb] = [luminance(a), luminance(b)];
      return (Math.max(la, lb) + 0.05) / (Math.min(la, lb) + 0.05);
    };
    const composite = (fg: number[], alpha: number, bg: number[]): number[] =>
      fg.map((v, i) => v * alpha + (bg[i] ?? 0) * (1 - alpha));
    const surfaceBehind = (el: Element): number[] => {
      for (let node = el.parentElement; node; node = node.parentElement) {
        const bg = parse(getComputedStyle(node).backgroundColor);
        if (bg.a >= 1) return bg.c;
      }
      return [255, 255, 255];
    };
    return Math.min(
      ...elements.map((el) => {
        const style = getComputedStyle(el);
        const exterior = surfaceBehind(el);
        const bg = parse(style.backgroundColor);
        const fill = bg.a >= 1 ? bg.c : composite(bg.c, bg.a, exterior);
        const b = parse(style.borderTopColor);
        const border = b.a >= 1 ? b.c : composite(b.c, b.a, fill);
        return Math.min(ratio(border, fill), ratio(border, exterior));
      }),
    );
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
    expect(
      await minimumControlBoundaryRatio(page),
      `control boundary contrast in ${themeLabel} / tab ${id}`,
    ).toBeGreaterThanOrEqual(3);
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
