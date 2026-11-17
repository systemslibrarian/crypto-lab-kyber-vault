import { test, expect } from '@playwright/test';

test('ML-KEM guidance is visible and makes no browser erasure guarantee', async ({ page }) => {
  await page.goto('.');
  await page.locator('#tab-params').click();
  const note = page.locator('#mlkem-protocol-guidance');
  await expect(note).toBeVisible();
  for (const text of ['16 November 2026', 'work in progress', 'not a final standard', 'static-static DH', 'seed like the private key', 'cannot guarantee secure memory erasure', 'decapsulator', 'not a disclosure of m to every eavesdropper', 'crypto.getRandomValues']) {
    await expect(note).toContainText(text);
  }
  await expect(note.locator('a')).toHaveAttribute('href', 'https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-ml-kem-security-considerations-00');
});
