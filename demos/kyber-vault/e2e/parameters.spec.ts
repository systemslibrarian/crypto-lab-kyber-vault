import { expect, test } from '@playwright/test';

const PROFILES = [
  { label: 'ML-KEM-512', category: 1, publicKey: 800, ciphertext: 768 },
  { label: 'ML-KEM-768', category: 3, publicKey: 1184, ciphertext: 1088 },
  { label: 'ML-KEM-1024', category: 5, publicKey: 1568, ciphertext: 1568 },
] as const;

test('every selector runs the matching real FIPS 203 profile end to end', async ({ page }) => {
  await page.goto('.');

  for (const profile of PROFILES) {
    await page.getByRole('button', { name: profile.label, exact: true }).click();

    const choice = page.locator('.parameter-choice');
    await expect(choice.getByRole('heading', { name: profile.label })).toBeVisible();
    await expect(choice).toContainText(`NIST category ${profile.category}`);
    await expect(choice).toContainText(`Public key ${profile.publicKey} B`);
    await expect(choice).toContainText(`Ciphertext ${profile.ciphertext} B`);

    await page.locator('#next-step').click();
    await expect(page.locator('#kem-status')).toContainText(
      `KeyGen complete (${profile.publicKey}B public`,
    );
    await page.locator('#next-step').click();
    await expect(page.locator('#kem-status')).toContainText(
      `Encaps complete (${profile.ciphertext}B ciphertext)`,
    );
    await page.locator('#next-step').click();
    await expect(page.locator('.ss-verdict')).toContainText('All 32 bytes match');
  }
});

test('parameter guidance treats categories as requirements rather than exact bits', async ({ page }) => {
  await page.goto('.');

  await expect(page.locator('.parameter-choice')).toContainText(
    'not exact classical or quantum bit-strength measurements',
  );

  await page.locator('#tab-params').click();
  await expect(page.locator('.category-explainer')).toContainText(
    'Category is a requirement, not a scoreboard',
  );
  await expect(page.locator('.category-explainer')).toContainText(
    'select the smallest profile that satisfies',
  );
});
