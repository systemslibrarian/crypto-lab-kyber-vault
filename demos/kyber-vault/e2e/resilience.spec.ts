import AxeBuilder from '@axe-core/playwright';
import { expect, test } from '@playwright/test';

const TAB_IDS = ['encaps', 'lattice', 'params', 'compare', 'how'] as const;

test('every panel fits narrow, tablet, and wide viewports without page overflow', async ({ page }) => {
  for (const viewport of [
    { width: 320, height: 568 },
    { width: 768, height: 1024 },
    { width: 1440, height: 900 },
  ]) {
    await page.setViewportSize(viewport);
    await page.goto('.');
    for (const tab of TAB_IDS) {
      await page.locator(`#tab-${tab}`).click();
      await expect(page.locator(`#panel-${tab}`)).toBeVisible();
      const overflow = await page.evaluate(() =>
        Math.max(document.body.scrollWidth, document.documentElement.scrollWidth) - window.innerWidth,
      );
      expect(overflow, `${tab} at ${viewport.width}px`).toBeLessThanOrEqual(1);
    }
  }
});

test('forced-colors mode preserves semantics and has no WCAG A/AA violations', async ({ page }) => {
  await page.emulateMedia({ forcedColors: 'active', reducedMotion: 'reduce' });
  await page.goto('.');
  await page.locator('#tab-params').click();

  const activeTab = page.locator('#tab-params');
  await expect(activeTab).toHaveAttribute('aria-selected', 'true');
  const styles = await activeTab.evaluate((element) => {
    const computed = getComputedStyle(element);
    return { borderStyle: computed.borderStyle, borderWidth: computed.borderWidth };
  });
  expect(styles.borderStyle).toBe('solid');
  expect(Number.parseFloat(styles.borderWidth)).toBeGreaterThanOrEqual(2);

  const results = await new AxeBuilder({ page })
    .withTags(['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa'])
    .analyze();
  expect(results.violations.map(({ id }) => id)).toEqual([]);
});

test('reduced-motion mode collapses animation and transition durations', async ({ page }) => {
  await page.emulateMedia({ reducedMotion: 'reduce' });
  await page.goto('.');
  const durations = await page.locator('#panel-encaps').evaluate((element) => {
    const panel = getComputedStyle(element);
    const tab = getComputedStyle(document.querySelector('#tab-encaps')!);
    return {
      animationMs: Number.parseFloat(panel.animationDuration) * 1000,
      transitionMs: Number.parseFloat(tab.transitionDuration) * 1000,
    };
  });
  expect(durations.animationMs).toBeLessThanOrEqual(0.01);
  expect(durations.transitionMs).toBeLessThanOrEqual(0.01);
});

test('security, threat-model, and limitation documents are discoverable from the site', async ({ page }) => {
  await page.goto('.');
  const assurance = page.locator('.footer-assurance');
  await expect(assurance.getByRole('link', { name: 'security policy' })).toHaveAttribute(
    'href',
    /SECURITY\.md$/,
  );
  await expect(assurance.getByRole('link', { name: 'threat model' })).toHaveAttribute(
    'href',
    /THREAT-MODEL\.md$/,
  );
  await expect(assurance.getByRole('link', { name: 'known limitations' })).toHaveAttribute(
    'href',
    /KNOWN-LIMITATIONS\.md$/,
  );
});
