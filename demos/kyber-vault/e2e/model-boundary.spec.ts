import { expect, test } from '@playwright/test';

test('toy models are explicitly separated from the real FIPS 203 implementation', async ({ page }) => {
  await page.goto('.');
  await page.locator('#tab-lattice').click();

  const boundary = page.locator('.model-boundary');
  await expect(boundary).toContainText('Two primers, one real implementation');
  const modulusRow = boundary.locator('tr').filter({ hasText: 'Modulus q' });
  await expect(modulusRow.locator('td')).toHaveText(['17', '3329', '3329']);
  await expect(boundary).toContainText('4×4 scalar matrix');
  await expect(boundary).toContainText('8 coefficients');
  await expect(boundary).toContainText('256 coefficients per polynomial');
  await expect(boundary).toContainText('2 / 3 / 4 for ML-KEM-512 / 768 / 1024');
  await expect(boundary).toContainText('Math.random for visualization only');
  await expect(boundary).toContainText('crypto.getRandomValues');

  const primer = page.locator('#panel-lattice .card').filter({
    has: page.getByRole('heading', { name: 'Cyclic NTT polynomial multiplication' }),
  });
  await expect(primer).toContainText("Concept primer · not ML-KEM's transform");
  await expect(primer).toContainText('X^8 - 1');
  await expect(primer).toContainText('specialized incomplete transform');
  await expect(primer).toContainText('Algorithms 9–11');
  await expect(primer).not.toContainText('512th roots of unity');

  await page.locator('#bruteforce').click();
  await expect(page.locator('#panel-lattice .status')).toContainText('83,521 candidates');
  await expect(page.locator('#panel-lattice .status')).toContainText('at most 625 vectors');
  await expect(page.locator('#panel-lattice .status')).toContainText(
    'neither number is an ML-KEM security estimate',
  );
});
