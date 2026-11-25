import { expect, test } from '@playwright/test';

test('LWE results use centered representatives and the displayed toy parameters', async ({ page }) => {
  await page.goto('.');
  await page.locator('#tab-lattice').click();

  const result = page.locator('.solve-result');
  let shownSecret = '';
  for (let attempt = 0; attempt < 8; attempt += 1) {
    shownSecret = (await page.locator('.vec-line code').textContent())?.replace('s = ', '') ?? '';
    await page.locator('#solve-clean').click();
    if (!(await result.getByText(/singular over the field/).count())) break;
    await page.locator('#new-lwe').click();
  }
  await expect(result).toContainText(`Recovered s = ${shownSecret}`);
  await expect(result).toContainText('residues converted to centered representatives');
  await expect(result).toContainText('Exactly the true secret');

  await page.locator('#bruteforce').click();
  const status = page.locator('#panel-lattice .status');
  await expect(status).toContainText('n=4, q=17');
  await expect(status).toContainText('83,521 candidates');
  await expect(status).toContainText('neither number is an ML-KEM security estimate');
  await expect(status).not.toContainText('q=3329');
});

test('tampering reports authentication only after decryption actually runs', async ({ page }) => {
  await page.goto('.');
  await page.locator('#hybrid-encrypt').click();
  await expect(page.locator('#hybrid-tamper')).toBeEnabled();
  await page.locator('#hybrid-tamper').click();

  await expect(page.locator('#hybrid-status')).toContainText('Authentication has not run yet');
  await expect(page.locator('#panel-encaps .bad-text')).toBeEmpty();

  await page.locator('#hybrid-decrypt').click();
  await expect(page.locator('#panel-encaps .bad-text')).toHaveText('Authentication failed');
  await expect(page.locator('#hybrid-status')).toBeEmpty();
});

test('a draft edit retires the packet and its verdict, including an in-flight decryption', async ({ page }) => {
  await page.goto('.');
  const draft = page.locator('#hybrid-message');
  const encrypt = page.locator('#hybrid-encrypt');
  const decrypt = page.locator('#hybrid-decrypt');
  const plaintext = page.locator('#hybrid-record .ok-text');
  await draft.fill('First draft');
  await encrypt.click();
  await decrypt.click();
  await expect(plaintext).toHaveText('Decrypted plaintext: First draft');

  // Pause the real decryption so the learner can edit before its result returns.
  await page.evaluate(() => {
    const decryptBytes = crypto.subtle.decrypt.bind(crypto.subtle);
    crypto.subtle.decrypt = async (...args) => {
      const bytes = await decryptBytes(...args);
      document.dispatchEvent(new Event('decrypt-ready'));
      await new Promise<void>(resolve => document.addEventListener('release-decrypt', () => resolve(), { once: true }));
      crypto.subtle.decrypt = decryptBytes;
      return bytes;
    };
    document.addEventListener('decrypt-ready', () => {
      document.documentElement.dataset.decryptReady = 'true';
    }, { once: true });
  });
  await decrypt.click();
  await expect(page.locator('html')).toHaveAttribute('data-decrypt-ready', 'true');
  await draft.fill('Another draft');
  await page.evaluate(() => document.dispatchEvent(new Event('release-decrypt')));
  await expect(draft).toBeFocused();
  await expect(decrypt).toBeDisabled();
  await expect(page.locator('#hybrid-tamper')).toBeDisabled();
  await expect(plaintext).toBeEmpty();
  await expect(page.locator('#hybrid-status')).toContainText('Draft changed');

  await draft.fill('');
  await encrypt.click();
  await decrypt.click();
  await expect(plaintext).toHaveText('Authenticated empty message (0 bytes).');
});
