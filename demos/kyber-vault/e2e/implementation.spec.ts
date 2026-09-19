import { expect, test } from '@playwright/test';

test('implementation identity and security limitations are visible and exact', async ({ page }) => {
  await page.goto('.');
  await page.locator('#tab-params').click();

  const disclosure = page.locator('.implementation-card');
  await expect(disclosure).toContainText('@noble/post-quantum@0.7.1');
  await expect(disclosure).toContainText('Pure JavaScript ML-KEM');
  await expect(disclosure).toContainText('crypto.getRandomValues');
  await expect(disclosure).toContainText('No independent audit');
  await expect(disclosure).toContainText('No constant-time claim');
  await expect(disclosure).toContainText('No guaranteed secret erasure');
  await expect(disclosure).toContainText('No peer authentication');
  await expect(disclosure).toContainText('No certification');
  await expect(disclosure).toContainText('Educational use only');

  await disclosure.getByText('Show the locked npm artifact receipt').click();
  await expect(disclosure).toContainText(
    'sha512-+P9981IiAnVh+rmcubozzVwrEy3XsN/tMhTnvsjV9VDaYpOnNCqWqKo2FLWxbu92YHfjGIlE5XnW175UK+ln+Q==',
  );
});
