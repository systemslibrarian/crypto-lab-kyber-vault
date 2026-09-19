import { expect, test } from '@playwright/test';

test('wire costs are comparable and benchmark evidence is exportable', async ({ page }) => {
  test.setTimeout(90_000);
  await page.goto('.');
  await page.locator('#tab-compare').click();

  const wireTable = page.locator('.wire-cost-card');
  await expect(wireTable.locator('tr').filter({ hasText: 'X25519 ephemeral ECDH' })).toContainText(
    '64 B',
  );
  await expect(wireTable.locator('tr').filter({ hasText: 'ML-KEM-768' }).first()).toContainText(
    '2272 B',
  );
  await expect(wireTable.locator('tr').filter({ hasText: 'X25519 + ML-KEM-768' })).toContainText(
    '2336 B',
  );
  await expect(wireTable).toContainText('excluding protocol framing');

  await page.locator('#run-benchmark').click();
  await expect(page.locator('.benchmark-progress')).toHaveText('Benchmark complete', {
    timeout: 80_000,
  });

  const benchmark = page.locator('.benchmark-card');
  await expect(benchmark).toContainText('@noble/post-quantum@0.7.1');
  await expect(benchmark).toContainText('Median');
  await expect(benchmark).toContainText('p95');
  await expect(benchmark).toContainText('50');

  const jsonDownload = page.waitForEvent('download');
  await page.locator('#download-benchmark-json').click();
  await expect((await jsonDownload).suggestedFilename()).toBe('kyber-vault-benchmark.json');

  const csvDownload = page.waitForEvent('download');
  await page.locator('#download-benchmark-csv').click();
  await expect((await csvDownload).suggestedFilename()).toBe('kyber-vault-benchmark.csv');
});
